package neo4j

import (
	"context"
	"encoding/json"
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
		WHERE NOT (n:ThreatActor OR n:TTP OR n:IPAddress)
		OPTIONAL MATCH (n)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t1:TTP) WHERE "Vulnerability" IN labels(n)
		WITH n, collect(DISTINCT t1) AS t1List
		OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t2:TTP) WHERE "Vulnerability" IN labels(n)
		WITH n, t1List, collect(DISTINCT t2) AS t2List
		OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t3:TTP) WHERE "Vulnerability" IN labels(n)
		WITH n, t1List, t2List, collect(DISTINCT t3) AS t3List
		WITH n, t1List + t2List + t3List AS combinedTTPs
		UNWIND case when size(combinedTTPs) > 0 then combinedTTPs else [null] end AS t
		WITH n, collect(DISTINCT case when t is not null and t.ttp_id is not null then {ttp_id: t.ttp_id, name: coalesce(t.name, ''), tactic: coalesce(t.tactic, ''), description: coalesce(t.description, '')} else null end) AS inferredTTPs
		WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs
		WITH collect({
			id: elementId(n), 
			labels: labels(n), 
			properties: n {.*, ttps: cleanTTPs}, 
			hasVuln: COUNT { (n)-[:OF_VULNERABILITY]->(:Vulnerability) } > 0
		}) AS nodes
		OPTIONAL MATCH (s)-[rel]->(t)
		WHERE NOT (startNode(rel):ThreatActor OR startNode(rel):TTP OR startNode(rel):IPAddress OR endNode(rel):ThreatActor OR endNode(rel):TTP OR endNode(rel):IPAddress)
		WITH nodes, collect({
			id: elementId(rel),
			type: type(rel),
			source: elementId(startNode(rel)),
			target: elementId(endNode(rel)),
			properties: properties(rel)
		}) AS cleanRels
		OPTIONAL MATCH (n)-[:HAS_IP]->(ip:IPAddress) WHERE n:Endpoint OR n:Container
		WITH nodes, cleanRels, collect(case when n is null or ip is null then null else {node_id: elementId(n), ip: coalesce(ip.ip, ""), vlan_id: coalesce(ip.vlan_id, 0)} end) AS ipMaps
		RETURN nodes, cleanRels AS relationships, [] AS ttp_mappings, [i in ipMaps WHERE i IS NOT NULL] AS ip_mappings
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
				isFinding := false
				for _, l := range labels {
					if l == "Finding" {
						isFinding = true
						break
					}
				}
				if isFinding {
					if hasVuln, ok := nodeMap["hasVuln"].(bool); ok && hasVuln {
						props["has_vulnerabilities"] = true
					}
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

	// Mapear direcciones IP y VLANs a las propiedades de los nodos Endpoint y Container
	if ipMapsRaw, ok := recordMap["ip_mappings"].([]interface{}); ok {
		endpointToIPs := make(map[string][]map[string]interface{})
		for _, rawMap := range ipMapsRaw {
			if m, ok := rawMap.(map[string]interface{}); ok {
				endpointID, _ := m["node_id"].(string)
				ip, _ := m["ip"].(string)
				var vlanID int64
				switch v := m["vlan_id"].(type) {
				case int64:
					vlanID = v
				case int:
					vlanID = int64(v)
				case float64:
					vlanID = int64(v)
				}
				if endpointID != "" && (ip != "" || vlanID > 0) {
					endpointToIPs[endpointID] = append(endpointToIPs[endpointID], map[string]interface{}{
						"ip":      ip,
						"vlan_id": vlanID,
					})
				}
			}
		}

		if len(endpointToIPs) > 0 {
			for i := range graphData.Nodes {
				n := &graphData.Nodes[i]
				if ips, exists := endpointToIPs[n.ID]; exists {
					if n.Properties == nil {
						n.Properties = make(map[string]interface{})
					}
					n.Properties["ips"] = ips
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

	// Mapear VLANs de CONNECTED_TO a las IPs de los Endpoints como IPs virtuales
	// Mapear HAS_INSTALLATION e INSTANCE_OF a las propiedades del SoftwareInstallation
	for _, rel := range graphData.Relationships {
		if rel.Type == "CONNECTED_TO" {
			// Encontrar el Network (target) para coger el vlan_id
			var vlanID int64
			for _, n := range graphData.Nodes {
				if n.ID == rel.Target {
					if v, ok := n.Properties["vlan_id"]; ok {
						switch val := v.(type) {
						case int64:
							vlanID = val
						case int:
							vlanID = int64(val)
						case float64:
							vlanID = int64(val)
						}
					}
					break
				}
			}

			// Si la red tiene VLAN ID, añadirla al Endpoint (source) si no la tiene ya
			if vlanID > 0 {
				for i := range graphData.Nodes {
					if graphData.Nodes[i].ID == rel.Source {
						n := &graphData.Nodes[i]
						if n.Properties == nil {
							n.Properties = make(map[string]interface{})
						}

						var existingIPs []map[string]interface{}
						if ips, ok := n.Properties["ips"].([]map[string]interface{}); ok {
							existingIPs = ips
						} else {
							existingIPs = []map[string]interface{}{}
						}

						exists := false
						for _, ipMap := range existingIPs {
							if vid, ok := ipMap["vlan_id"]; ok {
								var existingVlanID int64
								switch val := vid.(type) {
								case int64:
									existingVlanID = val
								case int:
									existingVlanID = int64(val)
								case float64:
									existingVlanID = int64(val)
								}
								if existingVlanID == vlanID {
									exists = true
									break
								}
							}
						}

						if !exists {
							existingIPs = append(existingIPs, map[string]interface{}{
								"ip":      "",
								"vlan_id": vlanID,
							})
							n.Properties["ips"] = existingIPs
						}
						break
					}
				}
			}
		} else if rel.Type == "HAS_INSTALLATION" {
			// El source es un Endpoint, el target es un SoftwareInstallation
			for i := range graphData.Nodes {
				if graphData.Nodes[i].ID == rel.Target {
					n := &graphData.Nodes[i]
					if n.Properties == nil {
						n.Properties = make(map[string]interface{})
					}
					// Buscar el nombre o ID del endpoint
					var endpointName string
					for _, src := range graphData.Nodes {
						if src.ID == rel.Source {
							if hn, ok := src.Properties["hostname"].(string); ok {
								endpointName = hn
							} else if idStr, ok := src.Properties["id"].(string); ok {
								endpointName = idStr
							}
							break
						}
					}
					n.Properties["associated_endpoint"] = endpointName
					n.Properties["associated_endpoint_node_id"] = rel.Source
					break
				}
			}
		} else if rel.Type == "INSTANCE_OF" {
			// El source es SoftwareInstallation, target es Software
			for i := range graphData.Nodes {
				if graphData.Nodes[i].ID == rel.Source {
					n := &graphData.Nodes[i]
					if n.Properties == nil {
						n.Properties = make(map[string]interface{})
					}
					// Buscar nombre del software
					var swName string
					for _, tgt := range graphData.Nodes {
						if tgt.ID == rel.Target {
							if name, ok := tgt.Properties["name"].(string); ok {
								swName = name
							}
							break
						}
					}
					n.Properties["associated_software"] = swName
					n.Properties["associated_software_node_id"] = rel.Target
					break
				}
			}
		}
	}

	return graphData, nil
}

func (r *infrastructureRepo) GetTotalMitreTTPs(ctx context.Context) (int, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (t:TTP) RETURN count(t) AS total`
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return 0, err
		}
		if result.Next(ctx) {
			record := result.Record()
			total, _ := record.Get("total")
			if t, ok := total.(int64); ok {
				return int(t), nil
			}
		}
		return 0, nil
	})
	if err != nil {
		return 0, err
	}
	return res.(int), nil
}

// GetTopAPTsByInfrastructureTTPs recorre el grafo completo desde la infraestructura del usuario
// hasta los actores de amenaza, calculando qué APTs cubren más TTPs vinculadas a las CVEs detectadas.
//
// FIX 2026-08-23: Corregidos dos bugs que provocaban una discrepancia numérica respecto a GetTTPMatrix:
//   Bug A (coalesce): coalesce(t1,t2,t3) solo devuelve el primer nodo no nulo por fila,
//          descartando silenciosamente TTPs de rutas alternativas. Corregido usando
//          combinación explícita: [t IN [t1,t2,t3] WHERE t IS NOT NULL].
//          Diagnóstico diferencial: en el proyecto Simon (id=1787471430021), el Bug A
//          NO contribuía a la discrepancia observada (67 con coalesce = 67 con combinación,
//          ambos sobre ruta rígida). El 100% del hueco lo causaba el Bug B.
//   Bug B (ruta rígida inicial): la cadena fija HAS_ENDPOINT→…→OF_VULNERABILITY no alcanzaba
//          vulnerabilidades vinculadas por rutas alternativas (ej. contenedores).
//   Bug C (fuga lateral por traversal dinámico): el intento de arreglar el Bug B usando un
//          traversal de longitud variable sin restricción de tipo de relación ([*1..6])
//          causó contaminación cruzada entre proyectos, saltando a través de nodos TTP 
//          (vía TARGETS_VULN, datos de demo de cmd/Pruebas/Poblar_repo/main.go) hacia
//          vulnerabilidades ajenas al proyecto.
//          Fix Final: Se reemplazó el traversal genérico por 7 rutas EXACTAS de pertenencia
//          usando EXISTS. Esto garantiza aislamiento criptográfico entre proyectos.
//          Verificación final (Proyecto Simon, id=1787471430021): Tras aplicar las rutas
//          exactas, el conteo purgado devuelve 16 vulnerabilidades legítimas (sin las 2
//          de demo filtradas) y total_infra_ttps=67, que es el número correcto real.
//          Ambos GetTopAPTs y GetTTPMatrix coinciden ahora en este valor corregido.
func (r *infrastructureRepo) GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int, projectID int64) ([]domain.APTThreatResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta Cypher que:
	// 1. Encuentra todas las TTPs únicas vinculadas a las vulnerabilidades de la infraestructura
	// 2. Para cada ThreatActor, cuenta cuántas de esas TTPs utiliza
	// 3. Calcula el porcentaje de cobertura y ordena descendentemente
	query := `
		// Paso 1: Obtener todas las TTPs únicas que apuntan a CVEs de la infraestructura
		// Usa traversal dinámico [*1..6] para alcanzar vulnerabilidades por cualquier ruta
		// (incluidos contenedores, relaciones TARGETS_VULN, etc.)
		MATCH (v:Vulnerability)
		WHERE $project_id = 0 OR toString($project_id) = "0" OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) }

		// Recoger TTPs por las tres rutas de mapeo posibles
		OPTIONAL MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t1:TTP)
		OPTIONAL MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t2:TTP)
		OPTIONAL MATCH (v)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t3:TTP)

		// Combinar TTPs de todas las rutas SIN coalesce (que descarta valores)
		WITH v, [t IN [t1, t2, t3] WHERE t IS NOT NULL] AS ttps_raw
		UNWIND (CASE WHEN size(ttps_raw) > 0 THEN ttps_raw ELSE [null] END) AS t
		WITH t WHERE t IS NOT NULL
		WITH collect(DISTINCT t) AS infraTTPs

		// Paso 2: Para cada ThreatActor, calcular solapamiento con las TTPs de la infraestructura
		UNWIND infraTTPs AS infraTTP
		WITH infraTTPs, infraTTP
		MATCH (ta:ThreatActor)-[:USES|USES_TTP]->(infraTTP)
		WITH ta, infraTTPs,
		     collect(DISTINCT infraTTP) AS matchedTTPs

		// Paso 3: Calcular métricas y ordenar
		WITH ta,
		     size(infraTTPs) AS totalInfraTTPs,
		     size(matchedTTPs) AS matchedCount,
		     [t IN matchedTTPs | t.name] AS matchedNames,
		     [t IN matchedTTPs | coalesce(t.ttp_id, t.id)] AS matchedIDs
		RETURN coalesce(ta.actor_id, ta.id, 'UNKNOWN') AS actor_id,
		       coalesce(ta.name, 'Unknown') AS actor_name,
		       coalesce(ta.origin, 'Unknown') AS origin,
		       coalesce(ta.motivation, 'Unknown') AS motivation,
		       matchedCount AS matched_ttp_count,
		       totalInfraTTPs AS total_infra_ttps,
		       round(toFloat(matchedCount) / totalInfraTTPs * 10000) / 100 AS coverage_percent,
		       matchedNames AS matched_ttp_names,
		       matchedIDs AS matched_ttp_ids
		ORDER BY matchedCount DESC, ta.name ASC
		LIMIT $limit
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"limit": limit, "project_id": projectID})
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
// Si projectID > 0, filtra solo los endpoints pertenecientes a ese proyecto.
func (r *infrastructureRepo) GetExploitationPaths(ctx context.Context, projectID int64) ([]domain.ExploitationPath, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// La consulta busca:
	// 1. Punto de entrada (e1): Expuesto a internet, perteneciente al proyecto (si projectID > 0).
	// 2. Movimiento lateral sin límite de saltos: Buscando cualquier camino hasta otro endpoint.
	// 3. Condición de salto: Todos los Endpoints intermedios deben tener vulnerabilidades de red (AV:N o AV:A).
	// 4. Privilegios (Root): Si la vuln de red tiene C:H, I:H, A:H, o si hay una vuln local (AV:L) con impacto alto.
	query := `
		MATCH path = (e1)-[:CONNECTED_TO|HOSTS*1..5]-(eTarget)
		WHERE (e1:Endpoint OR (e1:Container AND toLower(e1.state) = 'running')) AND e1.internet_exposed = true
		  AND (eTarget:Endpoint OR (eTarget:Container AND toLower(eTarget.state) = 'running'))
		  AND e1.id <> coalesce(eTarget.id, "0")
		  AND ($projectID = 0 OR 
		    EXISTS { MATCH (proj:Project {id: $projectID})-[:HAS_ENDPOINT]->(e1) } OR
		    (e1:Container AND EXISTS { MATCH (proj:Project {id: $projectID})-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(e1) }))
		  AND all(n IN nodes(path) WHERE 
		    (n:Network) OR 
		    (n:Endpoint AND (
			  EXISTS { MATCH (n)-[:HOSTS]-(c2:Container) WHERE c2 IN nodes(path) } OR
		      EXISTS {
		        MATCH (n)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(v:Vulnerability)
		        WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		      } OR EXISTS {
		        MATCH (n)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(v:Vulnerability)
		        WHERE toLower(c.state) = 'running' AND (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A')
		      } OR EXISTS {
		        MATCH (n)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(v:Vulnerability)
		        WHERE toLower(c.state) = 'running' AND (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A')
		      }
		    )) OR
		    (n:Container AND toLower(n.state) = 'running' AND (
		      elementId(n) = elementId(e1)
			  OR
			  EXISTS { MATCH (ep:Endpoint)-[:HOSTS]->(n) WHERE ep IN nodes(path) }
		      OR
		      (EXISTS { MATCH (n)-[:CONNECTED_TO]->(:Network) } AND (
		        EXISTS {
		          MATCH (n)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(v:Vulnerability)
		          WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		        } OR EXISTS {
		          MATCH (n)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(v:Vulnerability)
		          WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		        }
		      ))
		    ))
		  )
		WITH path, e1, eTarget, [n IN nodes(path) WHERE n:Endpoint OR n:Container OR n:Network] AS asset_nodes
		WHERE NOT any(i IN range(0, size(asset_nodes)-2) WHERE 
		    asset_nodes[i]:Endpoint AND asset_nodes[i+1]:Container AND 
		    EXISTS { MATCH (a)-[:CONNECTED_TO]->(:Network)<-[:CONNECTED_TO]-(b) WHERE a = asset_nodes[i] AND b = asset_nodes[i+1] }
		)
		WITH path, e1, eTarget, asset_nodes, [i IN range(0, size(asset_nodes)-1) | {index: i, asset: asset_nodes[i]}] AS indexed
		
		UNWIND indexed AS ie
		WITH path, e1, eTarget, indexed, ie, ie.asset AS ep
		
		CALL {
			WITH ep
			// Caso 1: ep es Endpoint y la vuln está en un software nativo
			MATCH (ep:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN si, null AS ci, f, elementId(f) AS f_id, v, false AS is_container, null AS container, 1 AS priority
			UNION
			// Caso 2: ep es Endpoint, con vuln en software de un contenedor hosteado
			WITH ep
			MATCH (ep:Endpoint)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE toLower(c.state) = 'running' AND (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A')
			RETURN si, null AS ci, f, elementId(f) AS f_id, v, true AS is_container, c AS container, 2 AS priority
			UNION
			// Caso 3a: ep es Endpoint, con vuln en imagen de un contenedor hosteado (con nodo Finding)
			WITH ep
			MATCH (ep:Endpoint)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE toLower(c.state) = 'running' AND (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A')
			RETURN null AS si, ci, f, elementId(f) AS f_id, v, true AS is_container, c AS container, 3 AS priority
			UNION
			// Caso 3b: ep es Endpoint, con vuln directa en imagen de contenedor hosteado sin finding
			WITH ep
			MATCH (ep:Endpoint)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
			WHERE toLower(c.state) = 'running' AND (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A')
			RETURN null AS si, ci, {risk_score: coalesce(v.base_score / 10.0, 0.98), severity: coalesce(v.severity, "CRITICAL"), status: "OPEN"} AS f, elementId(v) AS f_id, v, true AS is_container, c AS container, 4 AS priority
			UNION
			// Caso 4: ep es Container directamente enrutado, con vuln en software (AV:N RCE - MAYOR PRIORIDAD PARA CONTENEDORES)
			WITH ep
			MATCH (ep:Container)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN si, null AS ci, f, elementId(f) AS f_id, v, true AS is_container, ep AS container, 1 AS priority
			UNION
			// Caso 5a: ep es Container directamente enrutado, con vuln en imagen (con nodo Finding)
			WITH ep
			MATCH (ep:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN null AS si, ci, f, elementId(f) AS f_id, v, true AS is_container, ep AS container, 1 AS priority
			UNION
			// Caso 5b: ep es Container, con vuln directa sin nodo Finding
			WITH ep
			MATCH (ep:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN null AS si, ci, {risk_score: coalesce(v.base_score / 10.0, 0.98), severity: coalesce(v.severity, "CRITICAL"), status: "OPEN"} AS f, elementId(v) AS f_id, v, true AS is_container, ep AS container, 2 AS priority
			UNION
			// Caso 6: Endpoint (host) atravesado por HOSTS - solo aplica a Endpoints, no a Containers
			WITH ep, path
			MATCH (ep:Endpoint)
			WHERE EXISTS { MATCH (ep)-[:HOSTS]->(c2:Container) WHERE c2 IN nodes(path) }
			RETURN null AS si, null AS ci, {risk_score: 8.8} AS f, "" AS f_id, {cve_id: "LPE / Movement", cvss_vector: "AV:L/AC:L", exploit: true} AS v, false AS is_container, null AS container, 99 AS priority
			UNION
			// Caso 7: ep es Network, se usa para mostrar el paso por la red explícitamente
			WITH ep
			MATCH (ep:Network)
			RETURN null AS si, null AS ci, {risk_score: 0.0} AS f, "" AS f_id, {cve_id: "Conexión de Red", cvss_vector: "AV:N/AC:L", exploit: false} AS v, false AS is_container, null AS container, 1 AS priority
		}
		// Ordenar: primero por prioridad ASC (1=mejor), luego por risk_score DESC dentro de esa prioridad
		WITH path, e1, indexed, ie, ep, si, ci, f, f_id, v, is_container, container, priority ORDER BY priority ASC, coalesce(f.risk_score, 0.0) DESC
		
		WITH path, e1, indexed, ie, ep, collect({si: si, ci: ci, f: f, f_id: f_id, v: v, is_container: is_container, container: container}) AS allNetsRaw
		WITH path, e1, indexed, ie, ep, [net IN allNetsRaw WHERE ie.index > 0 OR net.v.cvss_vector CONTAINS 'AV:N' OR net.v.nvd_vector CONTAINS 'AV:N' OR net.v.cvss_vector CONTAINS 'AV:A'] AS allNets
		
		WITH path, e1, indexed, ie, ep, allNets,
		  EXISTS { MATCH (ep)-[:CONNECTED_TO]->(:Network)<-[:CONNECTED_TO]-(lastNode) WHERE lastNode = last(nodes(path)) } AS canReachTargetDirectly,
		  EXISTS {
		    MATCH (ep)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vLocal:Vulnerability)
		    WHERE vLocal.cvss_vector CONTAINS 'AV:L' AND vLocal.cvss_vector CONTAINS 'C:H' AND vLocal.cvss_vector CONTAINS 'I:H'
		  } AS hasHostLPE,
		  EXISTS {
		    MATCH (ep)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(vContLocal:Vulnerability)
		    WHERE toLower(c.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation')
		  } AS hasContLPE,
		  EXISTS {
		    MATCH (ep)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(vContLocal:Vulnerability)
		    WHERE toLower(c.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation')
		  } AS hasImageContLPE,
		  EXISTS {
		    MATCH (ep:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(vContLocal:Vulnerability)
		    WHERE toLower(ep.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation')
		  } AS hasDirectContLPE,
		  EXISTS {
		    MATCH (ep:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(vContLocal:Vulnerability)
		    WHERE toLower(ep.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation')
		  } AS hasDirectImageContLPE
		
		WITH path, e1, indexed, ie, ep, allNets, 
		  CASE 
		    WHEN ep:Container THEN
		      CASE 
		        WHEN ie.index + 1 < size(indexed) AND "Network" IN labels(indexed[ie.index + 1].asset) THEN false
		        ELSE (ep.privileged = true OR hasDirectContLPE OR hasDirectImageContLPE)
		      END
		    WHEN size(allNets) > 0 AND allNets[0].is_container THEN (allNets[0].container.privileged = true OR hasContLPE OR hasImageContLPE)
		    ELSE (hasHostLPE OR hasContLPE OR hasImageContLPE)
		  END AS hasLPE
		ORDER BY ie.index ASC
		
		WITH path, e1, collect({
		  index: ie.index,
		  endpoint: ep,
		  allNets: allNets,
		  hasLPE: hasLPE,
		  is_container: CASE WHEN size(allNets) > 0 THEN allNets[0].is_container ELSE (ep:Container) END
		}) AS steps
		
		WHERE (size(steps) < 2 OR all(i IN range(0, size(steps)-2) WHERE 
		    (NOT steps[i].is_container) OR (steps[i].hasLPE)
		))
		AND (
		    NOT (e1:Container) OR 
		    size(steps) = 0 OR 
		    e1.privileged = true OR
		    (
		      EXISTS { MATCH (e1)-[:HAS_INSTALLATION]->()-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(v1:Vulnerability) WHERE (toLower(v1.description) CONTAINS 'escape' OR toLower(v1.description) CONTAINS 'privilege escalation') }
		      OR
		      EXISTS { MATCH (e1)-[:USES_IMAGE]->()-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(v2:Vulnerability) WHERE (toLower(v2.description) CONTAINS 'escape' OR toLower(v2.description) CONTAINS 'privilege escalation') }
		    )
		)
		AND size(steps) > 0
		AND size(steps[0].allNets) > 0
		AND (
		    steps[0].allNets[0].v.cvss_vector CONTAINS 'AV:N' OR 
		    steps[0].allNets[0].v.nvd_vector CONTAINS 'AV:N' OR 
		    steps[0].allNets[0].v.cvss_vector CONTAINS 'AV:A'
		)

		RETURN e1.id AS entry_id, steps
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"projectID": projectID})
		if err != nil {
			return nil, err
		}

		paths := make([]domain.ExploitationPath, 0)
		bestPathPerTarget := make(map[string]domain.ExploitationPath)
		pathCounter := 1

		getBoolLocal := func(val any) bool {
			if val == nil {
				return false
			}
			if b, ok := val.(bool); ok {
				return b
			}
			return false
		}
		getStringLocal := func(val any) string {
			if val == nil {
				return ""
			}
			if s, ok := val.(string); ok {
				return s
			}
			return ""
		}
		getFloatLocal := func(val any) float64 {
			if val == nil {
				return 0.0
			}
			if f, ok := val.(float64); ok {
				return f
			}
			if i, ok := val.(int64); ok {
				return float64(i)
			}
			return 0.0
		}
		getIntLocal := func(val any) int64 {
			if val == nil {
				return 0
			}
			if i, ok := val.(int64); ok {
				return i
			}
			return 0
		}
		getMap := func(val any) map[string]any {
			if val == nil {
				return nil
			}
			if m, ok := val.(map[string]any); ok {
				return m
			}
			return nil
		}
		getNodeProps := func(val any) map[string]any {
			if val == nil {
				return nil
			}
			if n, ok := val.(neo4j.Node); ok {
				return n.GetProperties()
			}
			if m, ok := val.(map[string]any); ok {
				return m
			}
			return nil
		}

		for result.Next(ctx) {
			record := result.Record()

			entryIDVal, _ := record.Get("entry_id")
			entryIDStr := fmt.Sprintf("%v", entryIDVal)

			stepsRaw, _ := record.Get("steps")
			stepsList, ok := stepsRaw.([]any)
			if !ok || len(stepsList) == 0 {
				continue
			}

			// Construir el objeto ExploitationPath
			firstStepMap := getMap(stepsList[0])
			firstEndpointProps := getNodeProps(firstStepMap["endpoint"])

			initialEndpointName := getStringLocal(firstEndpointProps["hostname"])
			if initialEndpointName == "" {
				initialEndpointName = getStringLocal(firstEndpointProps["name"])
			}
			if initialEndpointName == "" {
				initialEndpointName = getStringLocal(firstEndpointProps["nombre"])
			}
			if initialEndpointName == "" {
				initialEndpointName = "Unknown"
			}

			ep := domain.ExploitationPath{
				PathID:          fmt.Sprintf("path-entry-%s-route-%d", entryIDStr, pathCounter),
				InitialEndpoint: initialEndpointName,
				TotalRiskScore:  0.0,
				Steps:           make([]domain.AttackStep, 0, len(stepsList)),
			}
			pathCounter++

			type activePathState struct {
				Path         domain.ExploitationPath
				PrevEndpoint string
				Offset       int
				JustEscaped  bool
			}
			e1Raw, _ := record.Get("e1")
			e1Name := getStringLocal(getNodeProps(e1Raw)["hostname"])
			if e1Name == "" {
				e1Name = getStringLocal(getNodeProps(e1Raw)["name"])
			}

			activePaths := []activePathState{
				{
					Path:         ep,
					PrevEndpoint: e1Name,
					Offset:       0,
					JustEscaped:  false,
				},
			}

			for _, stepAny := range stepsList {
				stepMap := getMap(stepAny)
				if stepMap == nil {
					continue
				}

				allNetsRaw, _ := stepMap["allNets"].([]any)
				if len(allNetsRaw) == 0 {
					continue
				}

				index := getIntLocal(stepMap["index"])
				endpointProps := getNodeProps(stepMap["endpoint"])
				hasLPE := getBoolLocal(stepMap["hasLPE"])

				hostname := getStringLocal(endpointProps["hostname"])
				targetName := hostname
				targetID := getIntLocal(endpointProps["id"])

				// Determinar si es contenedor basado en el primer allNets (todos comparten el endpoint)
				firstNetMap := getMap(allNetsRaw[0])
				isContainer := getBoolLocal(firstNetMap["is_container"])
				if isContainer {
					containerProps := getNodeProps(firstNetMap["container"])
					targetName = getStringLocal(containerProps["name"])
					targetID = 0
				} else if targetName == "" {
					targetName = getStringLocal(endpointProps["name"])
					if targetName == "" {
						targetName = getStringLocal(endpointProps["nombre"])
					}
				}

				var nextActivePaths []activePathState

				for _, state := range activePaths {
					if state.JustEscaped {
						if len(state.Path.Steps) > 0 {
							last := &state.Path.Steps[len(state.Path.Steps)-1]
							if last.Vulnerability == "Container Escape (LPE)" {
								last.TargetEndpoint = targetName
								last.TargetEndpointID = targetID
							}
						}
						state.PrevEndpoint = targetName
						state.Offset--
						state.JustEscaped = false
						nextActivePaths = append(nextActivePaths, state)
						continue
					}

					if targetName == state.PrevEndpoint {
						state.Offset--
						nextActivePaths = append(nextActivePaths, state)
						continue
					}

					var chosenNets []any
					if len(allNetsRaw) > 0 {
						if isContainer {
							var bestSoftware, bestImage any
							for _, netAny := range allNetsRaw {
								netMap := getMap(netAny)
								if netMap != nil {
									if netMap["si"] != nil && bestSoftware == nil {
										bestSoftware = netAny
									}
									if netMap["ci"] != nil && bestImage == nil {
										bestImage = netAny
									}
								}
							}
							if bestSoftware != nil {
								chosenNets = append(chosenNets, bestSoftware)
							}
							if bestImage != nil {
								chosenNets = append(chosenNets, bestImage)
							}
						}
						if len(chosenNets) == 0 {
							chosenNets = append(chosenNets, allNetsRaw[0])
						}
					}

					for _, netAny := range chosenNets {
						netMap := getMap(netAny)
						if netMap != nil {
							softwareProps := getNodeProps(netMap["si"])
							findingProps := getNodeProps(netMap["f"])
							vulnProps := getNodeProps(netMap["v"])

							var containerID, containerName string
							if isContainer {
								containerProps := getNodeProps(netMap["container"])
								containerID = getStringLocal(containerProps["id"])
								containerName = getStringLocal(containerProps["name"])
							}

							cvss := getStringLocal(vulnProps["cvss_vector"])
							risk := getFloatLocal(findingProps["risk_score"])

							isRCE := false
							cwes := getStringSlice(vulnProps, "cwe")
							for _, cwe := range cwes {
								if cwe == "CWE-94" || cwe == "CWE-78" || cwe == "CWE-77" {
									isRCE = true
									break
								}
							}
							if getBoolLocal(vulnProps["exploit"]) {
								isRCE = true
							}

							rootObtained := hasLPE
							if cvss != "" && strings.Contains(cvss, "C:H") && strings.Contains(cvss, "I:H") && strings.Contains(cvss, "A:H") {
								if !isContainer {
									rootObtained = true
								}
							}

							findingElementID := getStringLocal(netMap["f_id"])
							vulnCVE := getStringLocal(vulnProps["cve_id"])

							// Clonar la ruta actual
							clonedPath := domain.ExploitationPath{
								PathID:          state.Path.PathID,
								InitialEndpoint: state.Path.InitialEndpoint,
								TotalRiskScore:  state.Path.TotalRiskScore,
								Steps:           make([]domain.AttackStep, len(state.Path.Steps)),
							}
							copy(clonedPath.Steps, state.Path.Steps)

							clonedPath.Steps = append(clonedPath.Steps, domain.AttackStep{
								StepIndex:        int(index) + state.Offset,
								SourceEndpoint:   state.PrevEndpoint,
								TargetEndpoint:   targetName,
								TargetEndpointID: targetID,
								IsContainer:      isContainer,
								ContainerID:      containerID,
								ContainerName:    containerName,
								FindingID:        findingElementID,
								Vulnerability:    vulnCVE,
								SoftwareAffected: getStringLocal(softwareProps["install_path"]),
								RiskScore:        risk,
								RCE:              isRCE,
								RootObtained:     rootObtained,
								Exploitable:      getBoolLocal(vulnProps["exploit"]) || getBoolLocal(vulnProps["kev"]),
								CVSSVector:       cvss,
							})

							clonedPath.TotalRiskScore += risk

							newState := activePathState{
								Path:         clonedPath,
								PrevEndpoint: targetName,
								Offset:       state.Offset,
								JustEscaped:  false,
							}

							if isContainer && hasLPE && int(index) < len(stepsList)-1 {
								newState.Offset++
								newState.Path.Steps = append(newState.Path.Steps, domain.AttackStep{
									StepIndex:        int(index) + newState.Offset,
									SourceEndpoint:   targetName,
									TargetEndpoint:   "", // se rellena en la siguiente iteración
									TargetEndpointID: 0,
									IsContainer:      false,
									Vulnerability:    "Container Escape (LPE)",
									SoftwareAffected: "Container Runtime/Kernel",
									RiskScore:        8.8,
									RCE:              true,
									RootObtained:     true,
									Exploitable:      true,
									CVSSVector:       "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
								})
								newState.Path.TotalRiskScore += 8.8
								newState.JustEscaped = true
							}

							nextActivePaths = append(nextActivePaths, newState)
						}
					}
				}
				activePaths = nextActivePaths
			}

			for _, state := range activePaths {
				if len(state.Path.Steps) == 0 {
					continue
				}
				lastStep := state.Path.Steps[len(state.Path.Steps)-1]
				firstStep := state.Path.Steps[0]

				vectorType := "Endpoint"
				if lastStep.IsContainer {
					if lastStep.SoftwareAffected != "" {
						vectorType = "Software"
					} else {
						vectorType = "Image"
					}
				}

				initialVectorType := "Endpoint"
				if firstStep.IsContainer {
					if firstStep.SoftwareAffected != "" {
						initialVectorType = "Software"
					} else {
						initialVectorType = "Image"
					}
				}

				targetKey := fmt.Sprintf("%s-VIA-%s-TO-%d-%s-VIA-%s", state.Path.InitialEndpoint, initialVectorType, lastStep.TargetEndpointID, lastStep.TargetEndpoint, vectorType)

				existing, ok := bestPathPerTarget[targetKey]
				if !ok || state.Path.TotalRiskScore > existing.TotalRiskScore {
					bestPathPerTarget[targetKey] = state.Path
				}
			}
		}

		for _, p := range bestPathPerTarget {
			paths = append(paths, p)
		}

		for i := range paths {
			paths[i].PathID = fmt.Sprintf("path-%d", i+1)
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

		switch val := v.(type) {
		case map[string]interface{}, []interface{}:
			if b, err := json.Marshal(val); err == nil {
				cleaned[k] = string(b)
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

			// Seleccionar la clave canónica de MERGE según el tipo de nodo,
			// para respetar las constraints UNIQUE existentes en la BD.
			var matchKey string
			var matchVal interface{}

			switch primaryLabel {
			case "Vulnerability":
				if cveVal, exists := props["cve_id"]; exists && cveVal != nil {
					matchKey = "cve_id"
					matchVal = cveVal
				} else if idVal, exists := props["id"]; exists && idVal != nil {
					matchKey = "id"
					matchVal = idVal
				}
			case "TTP":
				if ttpVal, exists := props["ttp_id"]; exists && ttpVal != nil {
					matchKey = "ttp_id"
					matchVal = ttpVal
				} else if idVal, exists := props["id"]; exists && idVal != nil {
					matchKey = "id"
					matchVal = idVal
				}
			case "ThreatActor":
				if actorVal, exists := props["actor_id"]; exists && actorVal != nil {
					matchKey = "actor_id"
					matchVal = actorVal
				} else if idVal, exists := props["id"]; exists && idVal != nil {
					matchKey = "id"
					matchVal = idVal
				}
			case "CWE":
				if cweVal, exists := props["cwe_id"]; exists && cweVal != nil {
					matchKey = "cwe_id"
					matchVal = cweVal
				} else if idVal, exists := props["id"]; exists && idVal != nil {
					matchKey = "id"
					matchVal = idVal
				}
			case "CAPEC":
				if capecVal, exists := props["capec_id"]; exists && capecVal != nil {
					matchKey = "capec_id"
					matchVal = capecVal
				} else if idVal, exists := props["id"]; exists && idVal != nil {
					matchKey = "id"
					matchVal = idVal
				}
			default:
				if idVal, exists := props["id"]; exists && idVal != nil {
					matchKey = "id"
					matchVal = idVal
				}
			}

			if matchKey == "" {
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

func (r *infrastructureRepo) GetTTPMatrix(ctx context.Context, projectID *int64) ([]domain.TTPMatrixItem, error) {
	var pid int64 = 0
	if projectID != nil {
		pid = *projectID
	}
	params := map[string]interface{}{"project_id": pid}

	query := `
		MATCH (v:Vulnerability)
		WHERE $project_id = 0 OR toString($project_id) = "0" OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) }

		OPTIONAL MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t1:TTP)
		OPTIONAL MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t2:TTP)
		OPTIONAL MATCH (v)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t3:TTP)

		WITH v, [t IN [t1, t2, t3] WHERE t IS NOT NULL] AS ttps_raw
		UNWIND (CASE WHEN size(ttps_raw) > 0 THEN ttps_raw ELSE [null] END) AS t
		WITH v, t WHERE t IS NOT NULL

		WITH t, collect(DISTINCT {
			id: coalesce(v.cve_id, v.id, ''),
			cvss: coalesce(v.cvss_score, v.base_score, 'N/A'),
			desc: coalesce(v.description, '')
		}) AS cves

		RETURN coalesce(t.ttp_id, t.id, '') AS ttp_id, 
		       coalesce(t.name, '') AS name, 
		       coalesce(t.tactic, t.tactics, '') AS tactic, 
		       coalesce(t.description, '') AS desc, 
		       cves
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		var matrix []domain.TTPMatrixItem
		for result.Next(ctx) {
			record := result.Record()

			id, _ := record.Get("ttp_id")
			name, _ := record.Get("name")
			tactic, _ := record.Get("tactic")
			desc, _ := record.Get("desc")
			cvesRaw, _ := record.Get("cves")

			var cves []domain.TTPMatrixCVE
			if cvesRaw != nil {
				if cvesList, ok := cvesRaw.([]interface{}); ok {
					for _, c := range cvesList {
						if cMap, ok := c.(map[string]interface{}); ok {
							cveID := fmt.Sprint(cMap["id"])
							cveCVSS := fmt.Sprintf("%v", cMap["cvss"])
							cveDesc := fmt.Sprint(cMap["desc"])
							cves = append(cves, domain.TTPMatrixCVE{
								ID:   cveID,
								CVSS: cveCVSS,
								Desc: cveDesc,
							})
						}
					}
				}
			}

			matrix = append(matrix, domain.TTPMatrixItem{
				ID:     fmt.Sprint(id),
				Name:   fmt.Sprint(name),
				Tactic: fmt.Sprint(tactic),
				Desc:   fmt.Sprint(desc),
				CVEs:   cves,
			})
		}
		return matrix, nil
	})

	if err != nil {
		return nil, err
	}

	return res.([]domain.TTPMatrixItem), nil
}
