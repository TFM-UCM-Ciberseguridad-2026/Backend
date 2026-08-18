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
		OPTIONAL MATCH (e:Endpoint)-[:HAS_IP]->(ip:IPAddress)
		WITH nodes, cleanRels, collect(case when e is null or ip is null then null else {endpoint_id: elementId(e), ip: coalesce(ip.ip, ""), vlan_id: coalesce(ip.vlan_id, 0)} end) AS ipMaps
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

	// Mapear direcciones IP y VLANs a las propiedades de los nodos Endpoint
	if ipMapsRaw, ok := recordMap["ip_mappings"].([]interface{}); ok {
		endpointToIPs := make(map[string][]map[string]interface{})
		for _, rawMap := range ipMapsRaw {
			if m, ok := rawMap.(map[string]interface{}); ok {
				endpointID, _ := m["endpoint_id"].(string)
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

// Estructuras auxiliares internas para el cálculo en memoria
type rawEndpointData struct {
	ID              int64
	Hostname        string
	InternetExposed bool
	NetworkVulns    []rawVulnInfo
	LPEVulns        []rawVulnInfo
}

type rawVulnInfo struct {
	CVEID         string
	CVSSVector    string
	RiskScore     float64
	FindingID     string
	InstallPath   string
	IsContainer   bool
	ContainerID   string
	ContainerName string
	IsRCE         bool
	IsExploitable bool
	HasLPE        bool
}

// Estado de cada paso en el recorrido de la ruta de ataque: Par (Endpoint, Vulnerabilidad/Finding)
type pathStepState struct {
	EndpointID int64
	Vuln       rawVulnInfo
}

// GetExploitationPaths calcula TODAS las rutas de explotación posibles en la memoria de Go.
// Cada combinación de (CVE de entrada, CVEs de pivote) genera una ruta de ataque independiente.
func (r *infrastructureRepo) GetExploitationPaths(ctx context.Context) ([]domain.ExploitationPath, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// 1. Consulta Cypher plana ultrarrápida: Lee la topología de red y todas las vulnerabilidades registradas
	queryData := `
		MATCH (e:Endpoint)
		WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
		
		OPTIONAL MATCH (e)-[:CONNECTED_TO]->(net:Network)
		
		OPTIONAL MATCH (e)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WITH e, net, collect(DISTINCT {
			cve_id: v.cve_id,
			cvss_vector: coalesce(v.cvss_vector, v.nvd_vector, ''),
			cwe: coalesce(v.cwe, []),
			exploit: coalesce(v.exploit, false),
			kev: coalesce(v.kev, false),
			risk_score: coalesce(f.risk_score, 0.0),
			finding_id: elementId(f),
			install_path: coalesce(si.install_path, ''),
			is_container: false,
			container_id: '',
			container_name: '',
			description: coalesce(v.description, '')
		}) AS hostVulns
		
		OPTIONAL MATCH (e)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->(siC:SoftwareInstallation)-[:HAS_FINDING]->(fC:Finding)-[:OF_VULNERABILITY]->(vC:Vulnerability)
		WITH e, net, hostVulns, collect(DISTINCT {
			cve_id: vC.cve_id,
			cvss_vector: coalesce(vC.cvss_vector, vC.nvd_vector, ''),
			cwe: coalesce(vC.cwe, []),
			exploit: coalesce(vC.exploit, false),
			kev: coalesce(vC.kev, false),
			risk_score: coalesce(fC.risk_score, 0.0),
			finding_id: elementId(fC),
			install_path: coalesce(siC.install_path, ''),
			is_container: true,
			container_id: c.id,
			container_name: c.name,
			description: coalesce(vC.description, '')
		}) AS contVulns

		OPTIONAL MATCH (e)-[:HOSTS]->(cImg:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(vImg:Vulnerability)
		WITH e, net, hostVulns, contVulns, collect(DISTINCT {
			cve_id: vImg.cve_id,
			cvss_vector: coalesce(vImg.cvss_vector, vImg.nvd_vector, ''),
			cwe: coalesce(vImg.cwe, []),
			exploit: coalesce(vImg.exploit, false),
			kev: coalesce(vImg.kev, false),
			risk_score: 9.8,
			finding_id: '',
			install_path: ci.name,
			is_container: true,
			container_id: cImg.id,
			container_name: cImg.name,
			description: coalesce(vImg.description, '')
		}) AS imgVulns

		RETURN e.id AS endpoint_id,
		       coalesce(e.hostname, '') AS hostname,
		       coalesce(e.internet_exposed, false) AS internet_exposed,
		       collect(DISTINCT net.id) AS network_ids,
		       hostVulns + contVulns + imgVulns AS all_vulns
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, queryData, nil)
		if err != nil {
			return nil, err
		}

		endpoints := make(map[int64]*rawEndpointData)
		adj := make(map[int64]setInt64)
		networkEndpoints := make(map[any]setInt64)

		for result.Next(ctx) {
			rec := result.Record()
			epID := toInt64(rec.Values[0])
			if epID == 0 {
				continue
			}

			hostname := toStr(rec.Values[1])
			exposed := toBool(rec.Values[2])

			epData, exists := endpoints[epID]
			if !exists {
				epData = &rawEndpointData{
					ID:              epID,
					Hostname:        hostname,
					InternetExposed: exposed,
					NetworkVulns:    make([]rawVulnInfo, 0),
					LPEVulns:        make([]rawVulnInfo, 0),
				}
				endpoints[epID] = epData
			}

			if netList, ok := rec.Values[3].([]any); ok {
				for _, netID := range netList {
					if netID != nil {
						if _, ok := networkEndpoints[netID]; !ok {
							networkEndpoints[netID] = make(setInt64)
						}
						networkEndpoints[netID][epID] = struct{}{}
					}
				}
			}

			if vulnsList, ok := rec.Values[4].([]any); ok {
				for _, vAny := range vulnsList {
					vMap, ok := vAny.(map[string]any)
					if !ok || vMap["cve_id"] == nil || toStr(vMap["cve_id"]) == "" {
						continue
					}

					cvss := toStr(vMap["cvss_vector"])
					cvssUpper := strings.ToUpper(cvss)
					cweSlice := getStringSliceFromMap(vMap, "cwe")
					desc := strings.ToLower(toStr(vMap["description"]))
					exploit := toBool(vMap["exploit"])
					kev := toBool(vMap["kev"])

					isNetVuln := strings.Contains(cvssUpper, "AV:N") || strings.Contains(cvssUpper, "AV:A")
					isRCE := false
					for _, cwe := range cweSlice {
						if cwe == "CWE-94" || cwe == "CWE-78" || cwe == "CWE-77" {
							isRCE = true
							break
						}
					}
					if exploit {
						isRCE = true
					}

					hasLPE := false
					if (strings.Contains(cvssUpper, "AV:L") && strings.Contains(cvssUpper, "C:H") && strings.Contains(cvssUpper, "I:H")) ||
						strings.Contains(desc, "escape") || strings.Contains(desc, "privilege escalation") {
						hasLPE = true
					}

					vInfo := rawVulnInfo{
						CVEID:         toStr(vMap["cve_id"]),
						CVSSVector:    cvss,
						RiskScore:     toFloat64(vMap["risk_score"]),
						FindingID:     toStr(vMap["finding_id"]),
						InstallPath:   toStr(vMap["install_path"]),
						IsContainer:   toBool(vMap["is_container"]),
						ContainerID:   toStr(vMap["container_id"]),
						ContainerName: toStr(vMap["container_name"]),
						IsRCE:         isRCE,
						IsExploitable: exploit || kev,
						HasLPE:        hasLPE,
					}

					if isNetVuln {
						epData.NetworkVulns = append(epData.NetworkVulns, vInfo)
					}
					if hasLPE {
						epData.LPEVulns = append(epData.LPEVulns, vInfo)
					}
				}
			}
		}

		// Adyacencia entre equipos que comparten subred
		for _, epSet := range networkEndpoints {
			for epA := range epSet {
				if _, ok := adj[epA]; !ok {
					adj[epA] = make(setInt64)
				}
				for epB := range epSet {
					if epA != epB {
						adj[epA][epB] = struct{}{}
					}
				}
			}
		}

		return struct {
			Endpoints map[int64]*rawEndpointData
			Adj       map[int64]setInt64
		}{Endpoints: endpoints, Adj: adj}, nil
	})

	if err != nil || res == nil {
		return []domain.ExploitationPath{}, err
	}

	graphInfo := res.(struct {
		Endpoints map[int64]*rawEndpointData
		Adj       map[int64]setInt64
	})

	endpointsMap := graphInfo.Endpoints
	adjMap := graphInfo.Adj

	// 2. Definir Puntos de Entrada: Cada combinación (Endpoint Expuesto, CVE de Red) es un inicio distinto
	type entryPointState struct {
		Endpoint *rawEndpointData
		Vuln     rawVulnInfo
	}

	entryPoints := make([]entryPointState, 0)
	for _, ep := range endpointsMap {
		if ep.InternetExposed {
			for _, v := range ep.NetworkVulns {
				entryPoints = append(entryPoints, entryPointState{
					Endpoint: ep,
					Vuln:     v,
				})
			}
		}
	}

	exploitationPaths := make([]domain.ExploitationPath, 0)
	pathCounter := 1

	// 3. Algoritmo DFS con Backtracking sobre pares (Endpoint, Vulnerabilidad/Finding)
	var dfs func(currStep pathStepState, currentPath []pathStepState, visitedEndpoints map[int64]bool)
	dfs = func(currStep pathStepState, currentPath []pathStepState, visitedEndpoints map[int64]bool) {
		// Guardar como ruta de explotación cualquier combinación válida de >= 2 saltos (o ataques directos)
		if len(currentPath) >= 2 {
			pathObj := buildExploitationPath(pathCounter, currentPath, endpointsMap)
			if len(pathObj.Steps) > 0 {
				exploitationPaths = append(exploitationPaths, pathObj)
				pathCounter++
			}
		}

		// Límite conservador de seguridad (máximo 6 saltos y 250 rutas totales para acotar consumo)
		if len(currentPath) >= 6 || len(exploitationPaths) >= 250 {
			return
		}

		currEp := endpointsMap[currStep.EndpointID]
		if currEp == nil {
			return
		}

		// Si el paso actual ocurre dentro de un contenedor y NO tiene escape/LPE, no puede pivotar al resto del equipo/red
		if currStep.Vuln.IsContainer && !hasLPEOrRoot(currEp) {
			return
		}

		// Explorar vecinos de la subred
		neighbors := adjMap[currStep.EndpointID]
		for neighborID := range neighbors {
			if visitedEndpoints[neighborID] {
				continue // Evitar ciclos de equipos en la misma ruta
			}

			neighborEp := endpointsMap[neighborID]
			if neighborEp == nil || len(neighborEp.NetworkVulns) == 0 {
				continue // El equipo vecino debe tener vulnerabilidades de red para poder ser comprometido
			}

			// Cada vulnerabilidad de red del vecino genera una variante de ruta distinta
			for _, nbrVuln := range neighborEp.NetworkVulns {
				nextStep := pathStepState{
					EndpointID: neighborID,
					Vuln:       nbrVuln,
				}

				visitedEndpoints[neighborID] = true
				dfs(nextStep, append(currentPath, nextStep), visitedEndpoints)
				visitedEndpoints[neighborID] = false // Backtracking
			}
		}
	}

	for _, entry := range entryPoints {
		startStep := pathStepState{
			EndpointID: entry.Endpoint.ID,
			Vuln:       entry.Vuln,
		}

		visited := map[int64]bool{entry.Endpoint.ID: true}
		dfs(startStep, []pathStepState{startStep}, visited)
	}

	return exploitationPaths, nil
}

type setInt64 map[int64]struct{}

func hasLPEOrRoot(ep *rawEndpointData) bool {
	if len(ep.LPEVulns) > 0 {
		return true
	}
	for _, v := range ep.NetworkVulns {
		cvssUpper := strings.ToUpper(v.CVSSVector)
		if strings.Contains(cvssUpper, "C:H") && strings.Contains(cvssUpper, "I:H") && strings.Contains(cvssUpper, "A:H") {
			return true
		}
	}
	return false
}

func getStringSliceFromMap(m map[string]any, key string) []string {
	if val, ok := m[key]; ok && val != nil {
		if slice, ok := val.([]any); ok {
			res := make([]string, 0, len(slice))
			for _, item := range slice {
				if s, ok := item.(string); ok {
					res = append(res, s)
				}
			}
			return res
		}
	}
	return []string{}
}

func buildExploitationPath(counter int, steps []pathStepState, endpointsMap map[int64]*rawEndpointData) domain.ExploitationPath {
	firstEp := endpointsMap[steps[0].EndpointID]
	initialHostname := ""
	if firstEp != nil {
		initialHostname = firstEp.Hostname
	}
	entryCVE := steps[0].Vuln.CVEID

	pathObj := domain.ExploitationPath{
		PathID:          fmt.Sprintf("path-cve-%s-route-%d", entryCVE, counter),
		InitialEndpoint: initialHostname,
		TotalRiskScore:  0.0,
		Steps:           make([]domain.AttackStep, 0, len(steps)),
	}

	prevHostname := "Internet"

	for idx, stepState := range steps {
		ep := endpointsMap[stepState.EndpointID]
		if ep == nil {
			continue
		}

		vuln := stepState.Vuln
		hasLPE := hasLPEOrRoot(ep)

		rootObtained := hasLPE
		cvssUpper := strings.ToUpper(vuln.CVSSVector)
		if !vuln.IsContainer && strings.Contains(cvssUpper, "C:H") && strings.Contains(cvssUpper, "I:H") && strings.Contains(cvssUpper, "A:H") {
			rootObtained = true
		}

		step := domain.AttackStep{
			StepIndex:        idx,
			SourceEndpoint:   prevHostname,
			TargetEndpoint:   ep.Hostname,
			TargetEndpointID: ep.ID,
			IsContainer:      vuln.IsContainer,
			ContainerID:      vuln.ContainerID,
			ContainerName:    vuln.ContainerName,
			FindingID:        vuln.FindingID,
			Vulnerability:    vuln.CVEID,
			SoftwareAffected: vuln.InstallPath,
			RiskScore:        vuln.RiskScore,
			RCE:              vuln.IsRCE,
			RootObtained:     rootObtained,
			Exploitable:      vuln.IsExploitable,
			CVSSVector:       vuln.CVSSVector,
		}

		pathObj.Steps = append(pathObj.Steps, step)
		pathObj.TotalRiskScore += vuln.RiskScore
		prevHostname = ep.Hostname
	}

	return pathObj
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


