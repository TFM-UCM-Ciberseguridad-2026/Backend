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
		OPTIONAL MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE) WHERE ("Vulnerability" IN labels(n)) AND ((n)-[:HAS_CWE]->(w) OR w.cwe_id IN n.cwe)
		OPTIONAL MATCH (c)-[:MAPS_TO_TTP]->(t:TTP)
		WITH n, collect(DISTINCT case when t.ttp_id is not null then {ttp_id: t.ttp_id, name: coalesce(t.name, ''), tactic: coalesce(t.tactic, ''), description: coalesce(t.description, '')} else null end) AS inferredTTPs
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
// Cadena de traversal: Project → Endpoint → SoftwareInstallation → Finding → Vulnerability ← TTP ← ThreatActor
func (r *infrastructureRepo) GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int, projectID int64) ([]domain.APTThreatResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Consulta Cypher que:
	// 1. Encuentra todas las TTPs únicas vinculadas a las vulnerabilidades de la infraestructura
	// 2. Para cada ThreatActor, cuenta cuántas de esas TTPs utiliza
	// 3. Calcula el porcentaje de cobertura y ordena descendentemente
	query := `
		// Paso 1: Obtener todas las TTPs únicas que apuntan a CVEs de la infraestructura a través de CWE y CAPEC
		MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		      -[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE $project_id = 0 OR p.id = $project_id
		MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE)
		WHERE (v)-[:HAS_CWE]->(w) OR w.cwe_id IN v.cwe
		MATCH (c)-[:MAPS_TO_TTP]->(ttp:TTP)
		WITH collect(DISTINCT ttp) AS infraTTPs

		// Paso 2: Para cada ThreatActor, calcular solapamiento con las TTPs de la infraestructura
		UNWIND infraTTPs AS infraTTP
		WITH infraTTPs, infraTTP
		MATCH (ta:ThreatActor)-[:USES]->(infraTTP)
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
func (r *infrastructureRepo) GetExploitationPaths(ctx context.Context) ([]domain.ExploitationPath, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// La consulta busca:
	// 1. Punto de entrada (e1): Expuesto a internet.
	// 2. Movimiento lateral sin límite de saltos: Buscando cualquier camino hasta otro endpoint.
	// 3. Condición de salto: Todos los Endpoints intermedios deben tener vulnerabilidades de red (AV:N o AV:A).
	// 4. Privilegios (Root): Si la vuln de red tiene C:H, I:H, A:H, o si hay una vuln local (AV:L) con impacto alto.
	query := `
		MATCH path = (e1)-[:CONNECTED_TO|HOSTS*1..8]-(eTarget)
		WHERE (e1:Endpoint OR (e1:Container AND toLower(e1.state) = 'running')) AND e1.internet_exposed = true
		  AND (eTarget:Endpoint OR (eTarget:Container AND toLower(eTarget.state) = 'running'))
		  AND e1.id <> coalesce(eTarget.id, "0")
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
		        MATCH (n)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		        WHERE toLower(c.state) = 'running' AND (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A')
		      }
		    )) OR
		    (n:Container AND toLower(n.state) = 'running' AND (
		      elementId(n) = elementId(e1)
		      OR
		      (EXISTS { MATCH (n)-[:CONNECTED_TO]->(:Network) } AND (
		        EXISTS {
		          MATCH (n)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(v:Vulnerability)
		          WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
		        } OR EXISTS {
		          MATCH (n)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
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
			RETURN si, f, elementId(f) AS f_id, v, false AS is_container, null AS container, 1 AS priority
			UNION
			// Caso 4: ep es Container directamente enrutado, con vuln en software (AV:N RCE - MAYOR PRIORIDAD PARA CONTENEDORES)
			WITH ep
			MATCH (ep:Container)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN si, f, elementId(f) AS f_id, v, true AS is_container, ep AS container, 1 AS priority
			UNION
			// Caso 5a: ep es Container directamente enrutado, con vuln en imagen (con nodo Finding)
			WITH ep
			MATCH (ep:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN null AS si, f, elementId(f) AS f_id, v, true AS is_container, ep AS container, 0 AS priority
			UNION
			// Caso 5b: ep es Container, con vuln directa sin nodo Finding
			WITH ep
			MATCH (ep:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
			WHERE v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A'
			RETURN null AS si, {risk_score: coalesce(v.base_score, 9.8), title: "Vulnerabilidad en Imagen (" + v.cve_id + ")", severity: coalesce(v.severity, "CRITICAL"), status: "OPEN"} AS f, elementId(v) AS f_id, v, true AS is_container, ep AS container, 0 AS priority
			UNION
			// Caso 6: Endpoint (host) atravesado por HOSTS - solo aplica a Endpoints, no a Containers
			WITH ep, path
			MATCH (ep:Endpoint)
			WHERE EXISTS { MATCH (ep)-[:HOSTS]->(c2:Container) WHERE c2 IN nodes(path) }
			RETURN null AS si, {risk_score: 8.8} AS f, "" AS f_id, {cve_id: "LPE / Movement", cvss_vector: "AV:L/AC:L", exploit: true} AS v, false AS is_container, null AS container, 99 AS priority
			UNION
			// Caso 7: ep es Network, se usa para mostrar el paso por la red explícitamente
			WITH ep
			MATCH (ep:Network)
			RETURN null AS si, {risk_score: 0.0} AS f, "" AS f_id, {cve_id: "Conexión de Red", cvss_vector: "AV:N/AC:L", exploit: false} AS v, false AS is_container, null AS container, 1 AS priority
		}
		// Ordenar: primero por prioridad ASC (1=mejor), luego por risk_score DESC dentro de esa prioridad
		WITH path, e1, indexed, ie, ep, si, f, f_id, v, is_container, container, priority ORDER BY priority ASC, coalesce(f.risk_score, 0.0) DESC
		
		WITH path, e1, indexed, ie, ep, collect({si: si, f: f, f_id: f_id, v: v, is_container: is_container, container: container}) AS allNetsRaw
		WITH path, e1, indexed, ie, ep, [net IN allNetsRaw WHERE ie.index > 0 OR net.v.cvss_vector CONTAINS 'AV:N' OR net.v.nvd_vector CONTAINS 'AV:N' OR net.v.cvss_vector CONTAINS 'AV:A'] AS allNets
		
		WITH path, e1, indexed, ie, ep, allNets,
		  EXISTS { MATCH (ep)-[:CONNECTED_TO]->(:Network)<-[:CONNECTED_TO]-(lastNode) WHERE lastNode = last(nodes(path)) } AS canReachTargetDirectly,
		  EXISTS {
		    MATCH (ep)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vLocal:Vulnerability)
		    WHERE vLocal.cvss_vector CONTAINS 'AV:L' AND vLocal.cvss_vector CONTAINS 'C:H' AND vLocal.cvss_vector CONTAINS 'I:H'
		  } AS hasHostLPE,
		  EXISTS {
		    MATCH (ep)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
		    WHERE toLower(c.state) = 'running' AND ((vContLocal.cvss_vector CONTAINS 'AV:L' AND vContLocal.cvss_vector CONTAINS 'C:H' AND vContLocal.cvss_vector CONTAINS 'I:H') 
		       OR toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation')
		  } AS hasContLPE,
		  EXISTS {
		    MATCH (ep)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(vContLocal:Vulnerability)
		    WHERE toLower(c.state) = 'running' AND ((vContLocal.cvss_vector CONTAINS 'AV:L' AND vContLocal.cvss_vector CONTAINS 'C:H' AND vContLocal.cvss_vector CONTAINS 'I:H')
		       OR toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation')
		  } AS hasImageContLPE,
		  EXISTS {
		    MATCH (ep:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
		    WHERE (vContLocal.cvss_vector CONTAINS 'AV:L' AND vContLocal.cvss_vector CONTAINS 'C:H' AND vContLocal.cvss_vector CONTAINS 'I:H') 
		       OR toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation'
		  } AS hasDirectContLPE,
		  EXISTS {
		    MATCH (ep:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(vContLocal:Vulnerability)
		    WHERE (vContLocal.cvss_vector CONTAINS 'AV:L' AND vContLocal.cvss_vector CONTAINS 'C:H' AND vContLocal.cvss_vector CONTAINS 'I:H')
		       OR toLower(vContLocal.description) CONTAINS 'escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation'
		  } AS hasDirectImageContLPE,
		  EXISTS {
		    MATCH (ep:Container)<-[:HOSTS]-(host:Endpoint)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->()-[:OF_VULNERABILITY]->(vHostLocal:Vulnerability)
		    WHERE (vHostLocal.cvss_vector CONTAINS 'AV:L' AND vHostLocal.cvss_vector CONTAINS 'C:H' AND vHostLocal.cvss_vector CONTAINS 'I:H')
		       OR toLower(vHostLocal.description) CONTAINS 'escape' OR toLower(vHostLocal.description) CONTAINS 'privilege escalation'
		  } AS hasParentHostLPE
		
		WITH path, e1, indexed, ie, ep, allNets, 
		  CASE 
		    WHEN ep:Container THEN
		      CASE 
		        WHEN ie.index + 1 < size(indexed) AND "Network" IN labels(indexed[ie.index + 1].asset) THEN false
		        ELSE (hasDirectContLPE OR hasDirectImageContLPE OR hasParentHostLPE)
		      END
		    WHEN size(allNets) > 0 AND allNets[0].is_container THEN (hasContLPE OR hasImageContLPE)
		    ELSE (hasHostLPE OR hasContLPE OR hasImageContLPE)
		  END AS hasLPE
		ORDER BY ie.index ASC
		
		WITH path, e1, collect({
		    index: ie.index,
		    endpoint: ep,
		    allNets: allNets,
		    is_container: (size(allNets) > 0 AND allNets[0].is_container),
		    hasLPE: hasLPE
		}) AS steps
		
		WHERE (size(steps) < 2 OR all(i IN range(0, size(steps)-2) WHERE 
		    (NOT steps[i].is_container) OR (steps[i].hasLPE) OR (steps[i].endpoint:Container)
		))
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
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		paths := make([]domain.ExploitationPath, 0)
		pathCounter := 1

		getBoolLocal := func(val any) bool {
			if val == nil { return false }
			if b, ok := val.(bool); ok { return b }
			return false
		}
		getStringLocal := func(val any) string {
			if val == nil { return "" }
			if s, ok := val.(string); ok { return s }
			return ""
		}
		getFloatLocal := func(val any) float64 {
			if val == nil { return 0.0 }
			if f, ok := val.(float64); ok { return f }
			if i, ok := val.(int64); ok { return float64(i) }
			return 0.0
		}
		getIntLocal := func(val any) int64 {
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
			if m, ok := val.(map[string]any); ok { return m }
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

			activePaths := []activePathState{
				{
					Path:         ep,
					PrevEndpoint: "Internet",
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
						// Parchear el TargetEndpoint del último paso LPE
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

					for netIdx, netAny := range allNetsRaw {
						netMap := getMap(netAny)
						if netMap == nil {
							continue
						}

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

						if netIdx > 0 {
							clonedPath.PathID = fmt.Sprintf("%s-branch-%d-%d", state.Path.PathID, index, netIdx)
						}

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
				activePaths = nextActivePaths
			}

			for _, state := range activePaths {
				paths = append(paths, state.Path)
			}
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


