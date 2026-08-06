package neo4j

import (
	"context"
	"fmt"
	"strings"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type infrastructureRepo struct {
	driver neo4j.DriverWithContext
}

// NewInfrastructureRepository crea un repositorio para operaciones agregadas de infraestructura en Neo4j.
func NewInfrastructureRepository(driver neo4j.DriverWithContext) ports.InfrastructurePort {
	return &infrastructureRepo{driver: driver}
}

// GetGraphData recupera todos los nodos y relaciones de la base de datos Neo4j en un formato estructurado.
func (r *infrastructureRepo) GetGraphData(ctx context.Context) (*domain.GraphData, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta de lectura optimizada para obtener los nodos, relaciones y mapeos TTP de la infraestructura
	query := `
		MATCH (n)
		WHERE NOT n:ThreatActor AND NOT n:TTP AND NOT n:IPAddress
		WITH collect({id: elementId(n), labels: labels(n), properties: properties(n)}) AS nodes
		OPTIONAL MATCH (s)-[rel]->(t)
		WHERE NOT s:ThreatActor AND NOT s:TTP AND NOT s:IPAddress
		  AND NOT t:ThreatActor AND NOT t:TTP AND NOT t:IPAddress
		WITH nodes, collect(case when rel is null then null else {id: elementId(rel), type: type(rel), source: elementId(s), target: elementId(t), properties: properties(rel)} end) AS relationships
		OPTIONAL MATCH (ttp:TTP)-[:TARGETS_VULN]->(v:Vulnerability)
		WITH nodes, relationships, collect(case when ttp is null or v is null then null else {ttp_id: coalesce(ttp.ttp_id, ttp.id), cve_id: coalesce(v.cve_id, v.id)} end) AS ttpMaps
		RETURN nodes, [r in relationships WHERE r IS NOT NULL] AS relationships, [m in ttpMaps WHERE m IS NOT NULL] AS ttp_mappings
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().AsMap(), nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}

	graphData := &domain.GraphData{
		Nodes:         []domain.GraphNode{},
		Relationships: []domain.GraphRelationship{},
	}

	if res == nil {
		return graphData, nil
	}

	recordMap := res.(map[string]interface{})

	// Parsear Nodos
	if nodesRaw, ok := recordMap["nodes"].([]interface{}); ok {
		for _, nodeRaw := range nodesRaw {
			if nodeMap, ok := nodeRaw.(map[string]interface{}); ok {
				id, _ := nodeMap["id"].(string)
				labelsRaw, _ := nodeMap["labels"].([]interface{})
				labels := make([]string, len(labelsRaw))
				for i, l := range labelsRaw {
					labels[i], _ = l.(string)
				}
				props, _ := nodeMap["properties"].(map[string]interface{})
				if props == nil {
					props = make(map[string]interface{})
				}

				graphData.Nodes = append(graphData.Nodes, domain.GraphNode{
					ID:         id,
					Labels:     labels,
					Properties: props,
				})
			}
		}
	}

	// Mapear TTPs encontradas en la infraestructura a las propiedades de los nodos Vulnerability
	if ttpMapsRaw, ok := recordMap["ttp_mappings"].([]interface{}); ok {
		cveToTTPs := make(map[string][]string)
		for _, rawMap := range ttpMapsRaw {
			if m, ok := rawMap.(map[string]interface{}); ok {
				ttpID, _ := m["ttp_id"].(string)
				cveID, _ := m["cve_id"].(string)
				if ttpID != "" && cveID != "" {
					cveToTTPs[cveID] = append(cveToTTPs[cveID], ttpID)
				}
			}
		}

		if len(cveToTTPs) > 0 {
			for i := range graphData.Nodes {
				n := &graphData.Nodes[i]
				var cveID string
				if n.Properties != nil {
					if c, ok := n.Properties["cve_id"].(string); ok && c != "" {
						cveID = c
					} else if c, ok := n.Properties["id"].(string); ok && c != "" {
						cveID = c
					}
				}
				if cveID != "" {
					if ttps, exists := cveToTTPs[cveID]; exists {
						if n.Properties == nil {
							n.Properties = make(map[string]interface{})
						}
						n.Properties["ttps"] = ttps
					}
				}
			}
		}
	}

	// Parsear Relaciones
	if relsRaw, ok := recordMap["relationships"].([]interface{}); ok {
		for _, relRaw := range relsRaw {
			if relMap, ok := relRaw.(map[string]interface{}); ok {
				id, _ := relMap["id"].(string)
				relType, _ := relMap["type"].(string)
				source, _ := relMap["source"].(string)
				target, _ := relMap["target"].(string)
				props, _ := relMap["properties"].(map[string]interface{})

				graphData.Relationships = append(graphData.Relationships, domain.GraphRelationship{
					ID:         id,
					Type:       relType,
					Source:     source,
					Target:     target,
					Properties: props,
				})
			}
		}
	}

	return graphData, nil
}


// GetTopAPTsByInfrastructureTTPs recorre el grafo completo desde la infraestructura del usuario
// hasta los actores de amenaza, calculando qué APTs cubren más TTPs vinculadas a las CVEs detectadas.
// Cadena de traversal: Project → Endpoint → SoftwareInstallation → Finding → Vulnerability ← TTP ← ThreatActor
func (r *infrastructureRepo) GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int) ([]domain.APTThreatResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta Cypher que:
	// 1. Encuentra todas las TTPs únicas vinculadas a las vulnerabilidades de la infraestructura
	// 2. Para cada ThreatActor, cuenta cuántas de esas TTPs utiliza
	// 3. Calcula el porcentaje de cobertura y ordena descendentemente
	query := `
		// Paso 1: Obtener todas las TTPs únicas que apuntan a CVEs de la infraestructura
		MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		      -[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)<-[:TARGETS_VULN]-(ttp:TTP)
		WITH collect(DISTINCT ttp) AS infraTTPs

		// Paso 2: Para cada ThreatActor, calcular solapamiento con las TTPs de la infraestructura
		UNWIND infraTTPs AS infraTTP
		WITH infraTTPs, infraTTP
		MATCH (ta:ThreatActor)-[:USES_TTP]->(infraTTP)
		WITH ta, infraTTPs,
		     collect(DISTINCT infraTTP) AS matchedTTPs

		// Paso 3: Calcular métricas y ordenar
		WITH ta,
		     size(infraTTPs) AS totalInfraTTPs,
		     size(matchedTTPs) AS matchedCount,
		     [t IN matchedTTPs | t.name] AS matchedNames,
		     [t IN matchedTTPs | coalesce(t.ttp_id, t.id)] AS matchedIDs
		RETURN ta.id AS actor_id,
		       ta.name AS actor_name,
		       ta.origin AS origin,
		       ta.motivation AS motivation,
		       matchedCount AS matched_ttp_count,
		       totalInfraTTPs AS total_infra_ttps,
		       round(toFloat(matchedCount) / totalInfraTTPs * 10000) / 100 AS coverage_percent,
		       matchedNames AS matched_ttp_names,
		       matchedIDs AS matched_ttp_ids
		ORDER BY matchedCount DESC, ta.name ASC
		LIMIT $limit
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"limit": limit})
		if err != nil {
			return nil, err
		}

		var results []domain.APTThreatResult
		for result.Next(ctx) {
			record := result.Record()
			actorID, _ := record.Get("actor_id")
			actorName, _ := record.Get("actor_name")
			origin, _ := record.Get("origin")
			motivation, _ := record.Get("motivation")
			matchedCount, _ := record.Get("matched_ttp_count")
			totalInfra, _ := record.Get("total_infra_ttps")
			coverage, _ := record.Get("coverage_percent")
			namesRaw, _ := record.Get("matched_ttp_names")
			idsRaw, _ := record.Get("matched_ttp_ids")

			// Parsear listas de strings
			var matchedNames []string
			if namesList, ok := namesRaw.([]interface{}); ok {
				for _, n := range namesList {
					if s, ok := n.(string); ok {
						matchedNames = append(matchedNames, s)
					}
				}
			}

			var matchedIDs []string
			if idsList, ok := idsRaw.([]interface{}); ok {
				for _, n := range idsList {
					if s, ok := n.(string); ok {
						matchedIDs = append(matchedIDs, s)
					}
				}
			}

			results = append(results, domain.APTThreatResult{
				ActorID:         actorID.(string),
				ActorName:       actorName.(string),
				Origin:          origin.(string),
				Motivation:      motivation.(string),
				MatchedTTPCount: int(matchedCount.(int64)),
				TotalInfraTTPs:  int(totalInfra.(int64)),
				CoveragePercent: coverage.(float64),
				MatchedTTPNames: matchedNames,
				MatchedTTPIDs:   matchedIDs,
			})
		}

		return results, result.Err()
	})

	if err != nil {
		return nil, err
	}

	if res == nil {
		return []domain.APTThreatResult{}, nil
	}

	return res.([]domain.APTThreatResult), nil
}

// GetExploitationPaths busca rutas lógicas de ataque en la infraestructura.
// Una ruta de ataque comienza en un Endpoint expuesto a internet y con un
// servicio vulnerable a ejecución remota de código (RCE). A partir de ahí,
// simula el movimiento lateral a través de la red explotando otras vulnerabilidades.
func (r *infrastructureRepo) GetExploitationPaths(ctx context.Context) ([]domain.ExploitationPath, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// La consulta busca:
	// 1. Punto de entrada (e1): Expuesto a internet.
	// 2. Movimiento lateral sin límite de saltos: Buscando cualquier camino hasta otro endpoint.
	// 3. Condición de salto: Todos los Endpoints intermedios deben tener vulnerabilidades de red (AV:N o AV:A).
	// 4. Privilegios (Root): Si la vuln de red tiene C:H, I:H, A:H, o si hay una vuln local (AV:L) con impacto alto.
	query := `
		MATCH path = (e1:Endpoint)-[:CONNECTED_TO*]-(eTarget:Endpoint)
		WHERE e1.internet_exposed = true
		  AND e1.id <> eTarget.id
		  // Asegurar que todos los nodos son Network o Endpoints explotables remotamente (host o container)
		  AND all(n IN nodes(path) WHERE 
		    (n:Network) OR 
		    (n:Endpoint AND (
		      EXISTS {
		        MATCH (n)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(v:Vulnerability)
		        WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		      } OR EXISTS {
		        MATCH (n)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(v:Vulnerability)
		        WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		      } OR EXISTS {
		        MATCH (n)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		        WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		      }
		    ))
		  )
		// Extraer sólo los endpoints del path manteniendo el orden
		WITH path, e1, eTarget, [n IN nodes(path) WHERE n:Endpoint] AS endpoints
		WITH path, e1, [i IN range(0, size(endpoints)-1) | {index: i, endpoint: endpoints[i]}] AS indexed
		
		UNWIND indexed AS ie
		WITH path, e1, indexed, ie, ie.endpoint AS ep
		
		// Obtener la vulnerabilidad de red para saltar a este endpoint (puede estar en el host o en un contenedor)
		CALL {
			WITH ep
			MATCH (ep)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN si, f, v, false AS is_container, null AS container
			UNION
			WITH ep
			MATCH (ep)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN si, f, v, true AS is_container, c AS container
			UNION
			WITH ep
			MATCH (ep)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			// Como Scout no crea nodos Finding, simulamos uno con score basado en CVSS
			RETURN null AS si, {risk_score: 9.8} AS f, v, true AS is_container, c AS container
		}
		WITH path, e1, indexed, ie, ep, si, f, v, is_container, container ORDER BY f.risk_score DESC
		
		// Seleccionar la peor vulnerabilidad de red
		WITH path, e1, indexed, ie, ep, collect({si: si, f: f, v: v, is_container: is_container, container: container})[0] AS bestNet
		
		// Comprobar si hay una vulnerabilidad local para escalar privilegios
		WITH path, e1, indexed, ie, ep, bestNet,
		  EXISTS {
		    MATCH (ep)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vLocal:Vulnerability)
		    WHERE vLocal.cvss_vector CONTAINS 'AV:L' AND vLocal.cvss_vector CONTAINS 'C:H' AND vLocal.cvss_vector CONTAINS 'I:H'
		  } AS hasHostLPE,
		  EXISTS {
		    MATCH (ep)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
		    WHERE (vContLocal.cvss_vector CONTAINS 'AV:L' AND vContLocal.cvss_vector CONTAINS 'C:H' AND vContLocal.cvss_vector CONTAINS 'I:H') 
		       OR toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation'
		  } AS hasContLPE,
		  EXISTS {
		    MATCH (ep)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(vContLocal:Vulnerability)
		    WHERE (vContLocal.cvss_vector CONTAINS 'AV:L' AND vContLocal.cvss_vector CONTAINS 'C:H' AND vContLocal.cvss_vector CONTAINS 'I:H')
		       OR toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation'
		  } AS hasImageContLPE
		
		WITH path, e1, indexed, ie, ep, bestNet, hasHostLPE, hasContLPE, hasImageContLPE
		
		// Un atacante es root si obtiene un LPE en el host o si el container tiene escape (hasContLPE o hasImageContLPE)
		WITH path, e1, indexed, ie, ep, bestNet, 
		  CASE 
		    WHEN bestNet.is_container THEN (hasContLPE OR hasImageContLPE)
		    ELSE (hasHostLPE OR hasContLPE OR hasImageContLPE)
		  END AS hasLPE
		ORDER BY ie.index ASC
		
		// Reagrupar los pasos de esta ruta
		WITH path, e1, collect({
		    index: ie.index,
		    endpoint: ep,
		    software: bestNet.si,
		    finding: bestNet.f,
		    vuln: bestNet.v,
		    is_container: bestNet.is_container,
		    container: bestNet.container,
		    hasLPE: hasLPE
		}) AS steps
		
		// Validar que el pivotaje sea posible: si un nodo intermedio es un contenedor, DEBE tener un escape (LPE) para poder saltar al siguiente nodo de la ruta.
		// (No evaluamos el último paso porque es el destino final y no necesita pivotar más allá).
		WHERE size(steps) < 2 OR all(i IN range(0, size(steps)-2) WHERE 
		    (NOT steps[i].is_container) OR (steps[i].hasLPE)
		)

		RETURN e1.id AS entry_id, steps
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		paths := make([]domain.ExploitationPath, 0)
		pathCounter := 1

		getBool := func(val any) bool {
			if val == nil { return false }
			if b, ok := val.(bool); ok { return b }
			return false
		}
		getString := func(val any) string {
			if val == nil { return "" }
			if s, ok := val.(string); ok { return s }
			return ""
		}
		getFloat := func(val any) float64 {
			if val == nil { return 0.0 }
			if f, ok := val.(float64); ok { return f }
			if i, ok := val.(int64); ok { return float64(i) }
			return 0.0
		}
		getInt := func(val any) int64 {
			if val == nil { return 0 }
			if i, ok := val.(int64); ok { return i }
			return 0
		}
		getMap := func(val any) map[string]any {
			if val == nil { return nil }
			if m, ok := val.(map[string]any); ok { return m }
			return nil
		}
		getNodeProps := func(val any) map[string]any {
			if val == nil { return nil }
			if n, ok := val.(neo4j.Node); ok { return n.GetProperties() }
			return nil
		}

		for result.Next(ctx) {
			record := result.Record()
			
			entryIDVal, _ := record.Get("entry_id")
			entryID := getInt(entryIDVal)
			
			stepsRaw, _ := record.Get("steps")
			stepsList, ok := stepsRaw.([]any)
			if !ok || len(stepsList) == 0 {
				continue
			}

			// Construir el objeto ExploitationPath
			firstStepMap := getMap(stepsList[0])
			firstEndpointProps := getNodeProps(firstStepMap["endpoint"])
			
			ep := domain.ExploitationPath{
				PathID:          fmt.Sprintf("path-entry-%d-route-%d", entryID, pathCounter),
				InitialEndpoint: getString(firstEndpointProps["hostname"]),
				TotalRiskScore:  0.0,
				Steps:           make([]domain.AttackStep, 0, len(stepsList)),
			}
			pathCounter++

			var prevEndpoint string = "Internet"

			for _, stepAny := range stepsList {
				stepMap := getMap(stepAny)
				if stepMap == nil { continue }

				index := getInt(stepMap["index"])
				endpointProps := getNodeProps(stepMap["endpoint"])
				softwareProps := getNodeProps(stepMap["software"])
				findingProps := getNodeProps(stepMap["finding"])
				vulnProps := getNodeProps(stepMap["vuln"])
				hasLPE := getBool(stepMap["hasLPE"])
				isContainer := getBool(stepMap["is_container"])

				var containerID, containerName string
				if isContainer {
					containerProps := getNodeProps(stepMap["container"])
					containerID = getString(containerProps["id"])
					containerName = getString(containerProps["name"])
				}

				hostname := getString(endpointProps["hostname"])
				cvss := getString(vulnProps["cvss_vector"])
				risk := getFloat(findingProps["risk_score"])
				cwe := getString(vulnProps["cwe"])
				
				// Lógica de RCE
				isRCE := false
				if cwe == "CWE-94" || cwe == "CWE-78" || cwe == "CWE-77" || getBool(vulnProps["exploit"]) {
					isRCE = true
				}
				// Lógica de RootObtained
				rootObtained := hasLPE
				// Si la propia vuln de red da control total (ej: todo High)
				if cvss != "" && strings.Contains(cvss, "C:H") && strings.Contains(cvss, "I:H") && strings.Contains(cvss, "A:H") {
					// Si vulneramos un contenedor con AV:N y es C:H,I:H,A:H -> conseguimos root en el contenedor, NO en el host
					// Solo conseguimos root en el host si NO es container, o si es container pero el C:H impacta al host (lo cual cubrimos con hasLPE)
					if !isContainer {
						rootObtained = true
					}
				}

				ep.Steps = append(ep.Steps, domain.AttackStep{
					StepIndex:        int(index),
					SourceEndpoint:   prevEndpoint,
					TargetEndpoint:   hostname,
					TargetEndpointID: getInt(endpointProps["id"]),
					IsContainer:      isContainer,
					ContainerID:      containerID,
					ContainerName:    containerName,
					Vulnerability:    getString(vulnProps["cve_id"]),
					SoftwareAffected: getString(softwareProps["install_path"]),
					RiskScore:        risk,
					RCE:              isRCE,
					RootObtained:     rootObtained,
					Exploitable:      getBool(vulnProps["exploit"]) || getBool(vulnProps["kev"]),
					CVSSVector:       cvss,
				})

				ep.TotalRiskScore += risk
				prevEndpoint = hostname
			}

			paths = append(paths, ep)
		}

		return paths, result.Err()
	})

	if err != nil {
		return nil, err
	}

	if res == nil {
		return []domain.ExploitationPath{}, nil
	}

	return res.([]domain.ExploitationPath), nil
}

type nodeMatchTarget struct {
	Label    string
	MatchKey string
	MatchVal interface{}
}

func normalizeProperties(props map[string]interface{}) map[string]interface{} {
	if props == nil {
		return make(map[string]interface{})
	}
	cleaned := make(map[string]interface{}, len(props))
	for k, v := range props {
		if floatVal, ok := v.(float64); ok {
			if floatVal == float64(int64(floatVal)) {
				cleaned[k] = int64(floatVal)
				continue
			}
		}
		cleaned[k] = v
	}
	return cleaned
}

// ImportGraphData procesa e ingesta dinámicamente un conjunto de nodos y relaciones en la base de datos Neo4j.
func (r *infrastructureRepo) ImportGraphData(ctx context.Context, data *domain.GraphData) error {
	if data == nil || len(data.Nodes) == 0 {
		return nil
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		// Mapa de identificador del JSON -> elementId asignado por Neo4j
		nodeLookup := make(map[string]string)

		// 1. Ingestar nodos
		for _, node := range data.Nodes {
			if len(node.Labels) == 0 {
				continue
			}

			// Determinar etiqueta primaria y construir la cláusula Cypher
			primaryLabel := node.Labels[0]
			for _, l := range node.Labels {
				if l != "BaseNode" && l != "Persistable" {
					primaryLabel = l
					break
				}
			}

			props := normalizeProperties(node.Properties)

			// Asegurar que existe una clave ID única
			var matchKey string
			var matchVal interface{}

			if idVal, exists := props["id"]; exists && idVal != nil {
				matchKey = "id"
				matchVal = idVal
			} else if cveVal, exists := props["cve_id"]; exists && cveVal != nil {
				matchKey = "cve_id"
				matchVal = cveVal
			} else if ttpVal, exists := props["ttp_id"]; exists && ttpVal != nil {
				matchKey = "ttp_id"
				matchVal = ttpVal
			} else if actorVal, exists := props["actor_id"]; exists && actorVal != nil {
				matchKey = "actor_id"
				matchVal = actorVal
			} else {
				matchKey = "id"
				matchVal = node.ID
				props["id"] = node.ID
			}

			// Construir query MERGE dinámico y aplicar todas las etiquetas del nodo
			var labelStr strings.Builder
			for _, l := range node.Labels {
				labelStr.WriteString(":")
				labelStr.WriteString(l)
			}

			query := fmt.Sprintf(`
				MERGE (n:%s {%s: $matchVal})
				SET n%s, n += $properties
				RETURN elementId(n) AS elemId
			`, primaryLabel, matchKey, labelStr.String())

			res, err := tx.Run(ctx, query, map[string]interface{}{
				"matchVal":   matchVal,
				"properties": props,
			})
			if err != nil {
				return nil, fmt.Errorf("error al importar nodo %s (%v): %w", primaryLabel, matchVal, err)
			}

			if res.Next(ctx) {
				if elemIdVal, ok := res.Record().Get("elemId"); ok && elemIdVal != nil {
					elemIdStr := fmt.Sprint(elemIdVal)
					if node.ID != "" {
						nodeLookup[node.ID] = elemIdStr
					}
					if matchValStr := fmt.Sprint(matchVal); matchValStr != "" {
						nodeLookup[matchValStr] = elemIdStr
					}
				}
			}
		}

		// 2. Ingestar relaciones
		for _, rel := range data.Relationships {
			if rel.Type == "" || rel.Source == "" || rel.Target == "" {
				continue
			}

			relProps := normalizeProperties(rel.Properties)

			sourceElemId, sourceOk := nodeLookup[rel.Source]
			targetElemId, targetOk := nodeLookup[rel.Target]

			if sourceOk && targetOk {
				query := fmt.Sprintf(`
					MATCH (s), (t)
					WHERE elementId(s) = $sourceElemId AND elementId(t) = $targetElemId
					MERGE (s)-[r:%s]->(t)
					SET r += $properties
				`, rel.Type)

				_, err := tx.Run(ctx, query, map[string]interface{}{
					"sourceElemId": sourceElemId,
					"targetElemId": targetElemId,
					"properties":   relProps,
				})
				if err != nil {
					fmt.Printf("Aviso: no se pudo relacionar %s -[%s]-> %s: %v\n", rel.Source, rel.Type, rel.Target, err)
				}
			} else {
				// Fallback si origen o destino no estaban en la lista de nodos importados
				query := fmt.Sprintf(`
					MATCH (s), (t)
					WHERE (elementId(s) = $source OR s.id = $source OR toString(s.id) = $source OR s.cve_id = $source OR s.ttp_id = $source)
					  AND (elementId(t) = $target OR t.id = $target OR toString(t.id) = $target OR t.cve_id = $target OR t.ttp_id = $target)
					MERGE (s)-[r:%s]->(t)
					SET r += $properties
				`, rel.Type)

				_, err := tx.Run(ctx, query, map[string]interface{}{
					"source":     rel.Source,
					"target":     rel.Target,
					"properties": relProps,
				})
				if err != nil {
					fmt.Printf("Aviso: no se pudo relacionar %s -[%s]-> %s: %v\n", rel.Source, rel.Type, rel.Target, err)
				}
			}
		}

		return nil, nil
	})

	return err
}


