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
	for _, rel := range graphData.Relationships {
		if rel.Type == "CONNECTED_TO" {
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
			for i := range graphData.Nodes {
				if graphData.Nodes[i].ID == rel.Target {
					n := &graphData.Nodes[i]
					if n.Properties == nil {
						n.Properties = make(map[string]interface{})
					}
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
			for i := range graphData.Nodes {
				if graphData.Nodes[i].ID == rel.Source {
					n := &graphData.Nodes[i]
					if n.Properties == nil {
						n.Properties = make(map[string]interface{})
					}
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
func (r *infrastructureRepo) GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int, projectID int64) ([]domain.APTThreatResult, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		      -[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE $project_id = 0 OR p.id = $project_id
		MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE)
		WHERE (v)-[:HAS_CWE]->(w) OR w.cwe_id IN v.cwe
		MATCH (c)-[:MAPS_TO_TTP]->(ttp:TTP)
		WITH collect(DISTINCT ttp) AS infraTTPs

		UNWIND infraTTPs AS infraTTP
		WITH infraTTPs, infraTTP
		MATCH (ta:ThreatActor)-[:USES]->(infraTTP)
		WITH ta, infraTTPs,
		     collect(DISTINCT infraTTP) AS matchedTTPs

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

// Structs auxiliares para el cómputo combinatorio en memoria Go
type internalAsset struct {
	ID              string
	Name            string
	Type            string // "Endpoint", "Container", "Network"
	InternetExposed bool
	State           string
	Privileged      bool
	NumericID       int64
}

type internalVuln struct {
	FindingID     string
	CVEID         string
	RiskScore     float64
	CVSSVector    string
	NVDVector     string
	Description   string
	Exploit       bool
	KEV           bool
	CWEs          []string
	SoftwarePath  string
	IsContainer   bool
	ContainerID   string
	ContainerName string
}

// Genera una firma única para la secuencia completa de la ruta: [TargetAsset:Vulnerabilidad]
func getPathSignature(steps []domain.AttackStep) string {
	var parts []string
	for _, s := range steps {
		parts = append(parts, fmt.Sprintf("%s:%s", s.TargetEndpoint, s.Vulnerability))
	}
	return strings.Join(parts, "->")
}

// GetExploitationPaths extrae el subgrafo de Neo4j y calcula TODAS las combinaciones posibles de rutas en memoria (Go).
func (r *infrastructureRepo) GetExploitationPaths(ctx context.Context, projectID int64) ([]domain.ExploitationPath, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Extracción liviana de subgrafo desde Neo4j
	query := `
		MATCH (p:Project)
		WHERE $projectID = 0 OR p.id = $projectID
		MATCH (p)-[:HAS_ENDPOINT]->(e:Endpoint)
		OPTIONAL MATCH (e)-[:CONNECTED_TO]->(net:Network)
		OPTIONAL MATCH (e)-[:HOSTS]->(c:Container)
		OPTIONAL MATCH (c)-[:CONNECTED_TO]->(cnet:Network)

		OPTIONAL MATCH (e)-[:HAS_INSTALLATION]->(esi:SoftwareInstallation)-[:HAS_FINDING]->(ef:Finding)-[:OF_VULNERABILITY]->(ev:Vulnerability)
		OPTIONAL MATCH (c)-[:HAS_INSTALLATION]->(csi:SoftwareInstallation)-[:HAS_FINDING]->(cf:Finding)-[:OF_VULNERABILITY]->(cv:Vulnerability)
		OPTIONAL MATCH (c)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING]->(cif:Finding)-[:OF_VULNERABILITY]->(civ:Vulnerability)
		OPTIONAL MATCH (c)-[:USES_IMAGE]->(ci2:ContainerImage)-[:HAS_VULNERABILITY]->(civ2:Vulnerability)

		RETURN e {.*, elementId: elementId(e)} AS endpoint,
		       collect(DISTINCT net {.*, elementId: elementId(net)}) AS e_networks,
		       collect(DISTINCT c {.*, elementId: elementId(c)}) AS containers,
		       collect(DISTINCT cnet {.*, elementId: elementId(cnet)}) AS c_networks,
		       collect(DISTINCT {si: esi {.*}, f: ef {.*, elementId: elementId(ef)}, v: ev {.*, elementId: elementId(ev)}}) AS e_vulns,
		       collect(DISTINCT {c_id: elementId(c), si: csi {.*}, f: cf {.*, elementId: elementId(cf)}, v: cv {.*, elementId: elementId(cv)}}) AS c_sw_vulns,
		       collect(DISTINCT {c_id: elementId(c), ci: ci {.*}, f: cif {.*, elementId: elementId(cif)}, v: civ {.*, elementId: elementId(civ)}}) AS c_img_vulns,
		       collect(DISTINCT {c_id: elementId(c), ci: ci2 {.*}, v: civ2 {.*, elementId: elementId(civ2)}}) AS c_direct_img_vulns
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"projectID": projectID})
		if err != nil {
			return nil, err
		}

		assets := make(map[string]internalAsset)
		assetVulns := make(map[string][]internalVuln)
		networkNeighbors := make(map[string]map[string]bool)
		containerHosts := make(map[string]string)

		addAdjacency := func(a, b string) {
			if a == "" || b == "" || a == b {
				return
			}
			if networkNeighbors[a] == nil {
				networkNeighbors[a] = make(map[string]bool)
			}
			if networkNeighbors[b] == nil {
				networkNeighbors[b] = make(map[string]bool)
			}
			networkNeighbors[a][b] = true
			networkNeighbors[b][a] = true
		}

		getBool := func(m map[string]any, key string) bool {
			if m == nil {
				return false
			}
			if b, ok := m[key].(bool); ok {
				return b
			}
			return false
		}
		getString := func(m map[string]any, key string) string {
			if m == nil {
				return ""
			}
			if s, ok := m[key].(string); ok {
				return s
			}
			return ""
		}
		getFloat := func(m map[string]any, key string) float64 {
			if m == nil {
				return 0.0
			}
			if f, ok := m[key].(float64); ok {
				return f
			}
			if i, ok := m[key].(int64); ok {
				return float64(i)
			}
			return 0.0
		}
		getInt := func(m map[string]any, key string) int64 {
			if m == nil {
				return 0
			}
			if i, ok := m[key].(int64); ok {
				return i
			}
			return 0
		}

		for result.Next(ctx) {
			record := result.Record()

			epMap, _ := record.Get("endpoint")
			epProps, _ := epMap.(map[string]any)
			if epProps == nil {
				continue
			}

			epElemID := getString(epProps, "elementId")
			epName := getString(epProps, "hostname")
			if epName == "" {
				epName = getString(epProps, "name")
			}

			endpointAsset := internalAsset{
				ID:              epElemID,
				Name:            epName,
				Type:            "Endpoint",
				InternetExposed: getBool(epProps, "internet_exposed"),
				NumericID:       getInt(epProps, "id"),
			}
			assets[epElemID] = endpointAsset

			// Process Endpoint Networks
			if netsRaw, ok := record.Get("e_networks"); ok && netsRaw != nil {
				if netList, ok := netsRaw.([]any); ok {
					for _, netAny := range netList {
						netMap, _ := netAny.(map[string]any)
						if netMap == nil {
							continue
						}
						netElemID := getString(netMap, "elementId")
						netName := getString(netMap, "name")
						if netElemID != "" {
							assets[netElemID] = internalAsset{
								ID:   netElemID,
								Name: netName,
								Type: "Network",
							}
							addAdjacency(epElemID, netElemID)
						}
					}
				}
			}

			// Process Containers
			if containersRaw, ok := record.Get("containers"); ok && containersRaw != nil {
				if contList, ok := containersRaw.([]any); ok {
					for _, cAny := range contList {
						cMap, _ := cAny.(map[string]any)
						if cMap == nil {
							continue
						}
						cElemID := getString(cMap, "elementId")
						cName := getString(cMap, "name")
						cState := strings.ToLower(getString(cMap, "state"))
						if cElemID != "" {
							assets[cElemID] = internalAsset{
								ID:         cElemID,
								Name:       cName,
								Type:       "Container",
								State:      cState,
								Privileged: getBool(cMap, "privileged"),
							}
							containerHosts[cElemID] = epElemID
						}
					}
				}
			}

			// Process Container Networks
			if cnetsRaw, ok := record.Get("c_networks"); ok && cnetsRaw != nil {
				if cnetList, ok := cnetsRaw.([]any); ok {
					for _, cnetAny := range cnetList {
						cnetMap, _ := cnetAny.(map[string]any)
						if cnetMap == nil {
							continue
						}
						cnetElemID := getString(cnetMap, "elementId")
						cnetName := getString(cnetMap, "name")
						if cnetElemID != "" {
							assets[cnetElemID] = internalAsset{
								ID:   cnetElemID,
								Name: cnetName,
								Type: "Network",
							}
						}
					}
				}
			}

			// Parse Vulnerabilities function
			parseVulnRecord := func(assetID string, siMap, fMap, vMap map[string]any, isContainer bool, containerID, containerName string) {
				if vMap == nil {
					return
				}
				cveID := getString(vMap, "cve_id")
				if cveID == "" {
					cveID = getString(vMap, "cpe_id")
				}
				if cveID == "" {
					cveID = getString(vMap, "cpe")
				}
				if cveID == "" {
					cveID = getString(vMap, "id")
				}

				v := internalVuln{
					FindingID:     getString(fMap, "elementId"),
					CVEID:         cveID,
					RiskScore:     getFloat(fMap, "risk_score"),
					CVSSVector:    getString(vMap, "cvss_vector"),
					NVDVector:     getString(vMap, "nvd_vector"),
					Description:   getString(vMap, "description"),
					Exploit:       getBool(vMap, "exploit"),
					KEV:           getBool(vMap, "kev"),
					CWEs:          getStringSlice(vMap, "cwe"),
					SoftwarePath:  getString(siMap, "install_path"),
					IsContainer:   isContainer,
					ContainerID:   containerID,
					ContainerName: containerName,
				}
				assetVulns[assetID] = append(assetVulns[assetID], v)
			}

			// Parse Endpoint native Vulns
			if eVulnsRaw, ok := record.Get("e_vulns"); ok && eVulnsRaw != nil {
				if list, ok := eVulnsRaw.([]any); ok {
					for _, item := range list {
						m, _ := item.(map[string]any)
						if m == nil {
							continue
						}
						siMap, _ := m["si"].(map[string]any)
						fMap, _ := m["f"].(map[string]any)
						vMap, _ := m["v"].(map[string]any)
						parseVulnRecord(epElemID, siMap, fMap, vMap, false, "", "")
					}
				}
			}

			// Parse Container Software Vulns
			if cSwVulnsRaw, ok := record.Get("c_sw_vulns"); ok && cSwVulnsRaw != nil {
				if list, ok := cSwVulnsRaw.([]any); ok {
					for _, item := range list {
						m, _ := item.(map[string]any)
						if m == nil {
							continue
						}
						cID, _ := m["c_id"].(string)
						siMap, _ := m["si"].(map[string]any)
						fMap, _ := m["f"].(map[string]any)
						vMap, _ := m["v"].(map[string]any)
						cAsset := assets[cID]
						if cID != "" {
							parseVulnRecord(cID, siMap, fMap, vMap, true, cID, cAsset.Name)
							parseVulnRecord(epElemID, siMap, fMap, vMap, true, cID, cAsset.Name)
						}
					}
				}
			}

			// Parse Container Image Vulns
			if cImgVulnsRaw, ok := record.Get("c_img_vulns"); ok && cImgVulnsRaw != nil {
				if list, ok := cImgVulnsRaw.([]any); ok {
					for _, item := range list {
						m, _ := item.(map[string]any)
						if m == nil {
							continue
						}
						cID, _ := m["c_id"].(string)
						fMap, _ := m["f"].(map[string]any)
						vMap, _ := m["v"].(map[string]any)
						cAsset := assets[cID]
						if cID != "" {
							parseVulnRecord(cID, nil, fMap, vMap, true, cID, cAsset.Name)
							parseVulnRecord(epElemID, nil, fMap, vMap, true, cID, cAsset.Name)
						}
					}
				}
			}

			// Parse Container Direct Image Vulns
			if cDirImgVulnsRaw, ok := record.Get("c_direct_img_vulns"); ok && cDirImgVulnsRaw != nil {
				if list, ok := cDirImgVulnsRaw.([]any); ok {
					for _, item := range list {
						m, _ := item.(map[string]any)
						if m == nil {
							continue
						}
						cID, _ := m["c_id"].(string)
						vMap, _ := m["v"].(map[string]any)
						cAsset := assets[cID]
						if cID != "" && vMap != nil {
							baseScore := getFloat(vMap, "base_score")
							fMap := map[string]any{
								"risk_score": baseScore / 10.0,
								"severity":   getString(vMap, "severity"),
								"status":     "OPEN",
							}
							parseVulnRecord(cID, nil, fMap, vMap, true, cID, cAsset.Name)
							parseVulnRecord(epElemID, nil, fMap, vMap, true, cID, cAsset.Name)
						}
					}
				}
			}
		}

		// REGLAS DE SEGURIDAD
		isAVNetwork := func(v internalVuln) bool {
			cvss := strings.ToUpper(v.CVSSVector)
			nvd := strings.ToUpper(v.NVDVector)
			return strings.Contains(cvss, "AV:N") || strings.Contains(cvss, "AV:A") ||
				strings.Contains(nvd, "AV:N") || strings.Contains(nvd, "AV:A")
		}

		isRCEVuln := func(v internalVuln) bool {
			rceCWEs := map[string]bool{
				"CWE-94": true, "CWE-78": true, "CWE-77": true,
				"CWE-502": true, "CWE-434": true, "CWE-95": true, "CWE-20": true,
			}
			for _, cwe := range v.CWEs {
				if rceCWEs[cwe] {
					return true
				}
			}
			if v.Exploit || v.KEV {
				return true
			}
			desc := strings.ToLower(v.Description)
			return strings.Contains(desc, "remote code execution") ||
				strings.Contains(desc, "rce") ||
				strings.Contains(desc, "command injection") ||
				strings.Contains(desc, "code injection")
		}

		isContainerLPE := func(v internalVuln, cAsset internalAsset) bool {
			if cAsset.Privileged {
				return true
			}
			cvss := strings.ToUpper(v.CVSSVector)
			if strings.Contains(cvss, "AV:L") && strings.Contains(cvss, "C:H") && strings.Contains(cvss, "I:H") {
				return true
			}
			desc := strings.ToLower(v.Description)
			if strings.Contains(desc, "escape") || strings.Contains(desc, "privilege escalation") {
				return true
			}
			return false
		}

		isHostLPE := func(v internalVuln) bool {
			cvss := strings.ToUpper(v.CVSSVector)
			return strings.Contains(cvss, "AV:L") && strings.Contains(cvss, "C:H") && strings.Contains(cvss, "I:H")
		}

		// Puntos de Entrada Candidatos (Internet + Running + RCE en Red)
		type entryCandidate struct {
			Asset internalAsset
			Vuln  internalVuln
		}
		var entryCandidates []entryCandidate

		for assetID, asset := range assets {
			if !asset.InternetExposed {
				continue
			}
			if asset.Type == "Container" && asset.State != "running" {
				continue
			}
			vulns := assetVulns[assetID]
			for _, v := range vulns {
				if isAVNetwork(v) && isRCEVuln(v) {
					entryCandidates = append(entryCandidates, entryCandidate{
						Asset: asset,
						Vuln:  v,
					})
				}
			}
		}

		type bfsPathState struct {
			CurrentAssetID string
			VisitedAssets  map[string]bool
			Steps          []domain.AttackStep
			TotalRisk      float64
		}

		bestPathsMap := make(map[string]domain.ExploitationPath)

		// EXPLORACIÓN BFS COMBINATORIA COMPLETA
		for entryIdx, entry := range entryCandidates {
			initialStep := domain.AttackStep{
				StepIndex:        1,
				SourceEndpoint:   "INTERNET",
				TargetEndpoint:   entry.Asset.Name,
				TargetEndpointID: entry.Asset.NumericID,
				IsContainer:      entry.Asset.Type == "Container",
				ContainerID:      entry.Vuln.ContainerID,
				ContainerName:    entry.Vuln.ContainerName,
				FindingID:        entry.Vuln.FindingID,
				Vulnerability:    entry.Vuln.CVEID,
				SoftwareAffected: entry.Vuln.SoftwarePath,
				RiskScore:        entry.Vuln.RiskScore,
				RCE:              true,
				RootObtained:     strings.Contains(entry.Vuln.CVSSVector, "C:H") && strings.Contains(entry.Vuln.CVSSVector, "I:H"),
				Exploitable:      entry.Vuln.Exploit || entry.Vuln.KEV,
				CVSSVector:       entry.Vuln.CVSSVector,
			}

			initialState := bfsPathState{
				CurrentAssetID: entry.Asset.ID,
				VisitedAssets:  map[string]bool{entry.Asset.ID: true},
				Steps:          []domain.AttackStep{initialStep},
				TotalRisk:      entry.Vuln.RiskScore,
			}

			queue := []bfsPathState{initialState}

			for len(queue) > 0 {
				curr := queue[0]
				queue = queue[1:]

				if len(curr.Steps) >= 5 { // Límite de seguridad de 5 saltos topológicos
					continue
				}

				currAsset := assets[curr.CurrentAssetID]

				// Transición 1: Contenedor con Escape LPE -> Host Endpoint
				if currAsset.Type == "Container" {
					hostID := containerHosts[curr.CurrentAssetID]
					if hostID != "" && !curr.VisitedAssets[hostID] {
						hostAsset := assets[hostID]

						// Evaluar TODAS las vulnerabilidades de escape (sin break)
						for _, v := range assetVulns[curr.CurrentAssetID] {
							if isContainerLPE(v, currAsset) {
								escapeStep := domain.AttackStep{
									StepIndex:        len(curr.Steps) + 1,
									SourceEndpoint:   currAsset.Name,
									TargetEndpoint:   hostAsset.Name,
									TargetEndpointID: hostAsset.NumericID,
									IsContainer:      false,
									Vulnerability:    "Container Escape (LPE)",
									SoftwareAffected: "Container Runtime/Kernel",
									RiskScore:        8.8,
									RCE:              true,
									RootObtained:     true,
									Exploitable:      true,
									CVSSVector:       "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
								}

								newVisited := make(map[string]bool)
								for k, val := range curr.VisitedAssets {
									newVisited[k] = val
								}
								newVisited[hostID] = true

								nextSteps := append([]domain.AttackStep{}, curr.Steps...)
								nextSteps = append(nextSteps, escapeStep)

								queue = append(queue, bfsPathState{
									CurrentAssetID: hostID,
									VisitedAssets:  newVisited,
									Steps:          nextSteps,
									TotalRisk:      curr.TotalRisk + 8.8,
								})
							}
						}
					}
				}

				// Transición 2: Endpoint -> Contenedores alojados
				if currAsset.Type == "Endpoint" {
					for cID, hID := range containerHosts {
						if hID == curr.CurrentAssetID && !curr.VisitedAssets[cID] {
							cAsset := assets[cID]
							if cAsset.State == "running" {
								// Evaluar TODAS las vulnerabilidades de red del contenedor (sin break)
								for _, v := range assetVulns[cID] {
									if isAVNetwork(v) {
										contStep := domain.AttackStep{
											StepIndex:        len(curr.Steps) + 1,
											SourceEndpoint:   currAsset.Name,
											TargetEndpoint:   cAsset.Name,
											TargetEndpointID: 0,
											IsContainer:      true,
											ContainerID:      cID,
											ContainerName:    cAsset.Name,
											FindingID:        v.FindingID,
											Vulnerability:    v.CVEID,
											SoftwareAffected: v.SoftwarePath,
											RiskScore:        v.RiskScore,
											RCE:              isRCEVuln(v),
											RootObtained:     isContainerLPE(v, cAsset),
											Exploitable:      v.Exploit || v.KEV,
											CVSSVector:       v.CVSSVector,
										}

										newVisited := make(map[string]bool)
										for k, val := range curr.VisitedAssets {
											newVisited[k] = val
										}
										newVisited[cID] = true

										nextSteps := append([]domain.AttackStep{}, curr.Steps...)
										nextSteps = append(nextSteps, contStep)

										queue = append(queue, bfsPathState{
											CurrentAssetID: cID,
											VisitedAssets:  newVisited,
											Steps:          nextSteps,
											TotalRisk:      curr.TotalRisk + v.RiskScore,
										})
									}
								}
							}
						}
					}
				}

				// Transición 3: Movimiento lateral vía Redes Conectadas
				neighbors := networkNeighbors[curr.CurrentAssetID]
				for neighborID := range neighbors {
					if curr.VisitedAssets[neighborID] {
						continue
					}
					neighborAsset := assets[neighborID]

					if neighborAsset.Type == "Network" {
						netStep := domain.AttackStep{
							StepIndex:        len(curr.Steps) + 1,
							SourceEndpoint:   currAsset.Name,
							TargetEndpoint:   neighborAsset.Name,
							TargetEndpointID: 0,
							IsContainer:      false,
							Vulnerability:    "Conexión de Red",
							SoftwareAffected: "Network Interface",
							RiskScore:        0.0,
							RCE:              false,
							RootObtained:     false,
							Exploitable:      false,
							CVSSVector:       "AV:N/AC:L",
						}

						newVisited := make(map[string]bool)
						for k, val := range curr.VisitedAssets {
							newVisited[k] = val
						}
						newVisited[neighborID] = true

						nextSteps := append([]domain.AttackStep{}, curr.Steps...)
						nextSteps = append(nextSteps, netStep)

						queue = append(queue, bfsPathState{
							CurrentAssetID: neighborID,
							VisitedAssets:  newVisited,
							Steps:          nextSteps,
							TotalRisk:      curr.TotalRisk,
						})
					} else {
						if neighborAsset.Type == "Container" && neighborAsset.State != "running" {
							continue
						}

						// Evaluar TODAS las vulnerabilidades de red del activo destino (SIN BREAK)
						targetVulns := assetVulns[neighborID]
						for _, v := range targetVulns {
							if isAVNetwork(v) {
								hasRoot := false
								if neighborAsset.Type == "Container" {
									hasRoot = isContainerLPE(v, neighborAsset)
								} else {
									hasRoot = isHostLPE(v)
								}

								hopStep := domain.AttackStep{
									StepIndex:        len(curr.Steps) + 1,
									SourceEndpoint:   currAsset.Name,
									TargetEndpoint:   neighborAsset.Name,
									TargetEndpointID: neighborAsset.NumericID,
									IsContainer:      neighborAsset.Type == "Container",
									ContainerID:      v.ContainerID,
									ContainerName:    v.ContainerName,
									FindingID:        v.FindingID,
									Vulnerability:    v.CVEID,
									SoftwareAffected: v.SoftwarePath,
									RiskScore:        v.RiskScore,
									RCE:              isRCEVuln(v),
									RootObtained:     hasRoot,
									Exploitable:      v.Exploit || v.KEV,
									CVSSVector:       v.CVSSVector,
								}

								newVisited := make(map[string]bool)
								for k, val := range curr.VisitedAssets {
									newVisited[k] = val
								}
								newVisited[neighborID] = true

								nextSteps := append([]domain.AttackStep{}, curr.Steps...)
								nextSteps = append(nextSteps, hopStep)

								queue = append(queue, bfsPathState{
									CurrentAssetID: neighborID,
									VisitedAssets:  newVisited,
									Steps:          nextSteps,
									TotalRisk:      curr.TotalRisk + v.RiskScore,
								})
							}
						}
					}
				}

				// Si el camino tiene al menos 1 salto válido, registrarlo
				if len(curr.Steps) > 1 {
					// Firma basada en la SECUENCIA COMPLETA de [Activo:CVE] de toda la ruta
					signature := getPathSignature(curr.Steps)

					pathObj := domain.ExploitationPath{
						PathID:          fmt.Sprintf("path-entry-%d", entryIdx+1),
						InitialEndpoint: curr.Steps[0].SourceEndpoint,
						TotalRiskScore:  curr.TotalRisk,
						Steps:           curr.Steps,
					}

					existing, ok := bestPathsMap[signature]
					if !ok || curr.TotalRisk > existing.TotalRiskScore {
						bestPathsMap[signature] = pathObj
					}
				}
			}
		}

		var computedPaths []domain.ExploitationPath
		for _, p := range bestPathsMap {
			computedPaths = append(computedPaths, p)
		}

		for i := range computedPaths {
			computedPaths[i].PathID = fmt.Sprintf("path-%d", i+1)
		}

		return computedPaths, nil
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
		nodeLookup := make(map[string]string)

		// 1. Ingestar nodos
		for _, node := range data.Nodes {
			if len(node.Labels) == 0 {
				continue
			}

			primaryLabel := node.Labels[0]
			for _, l := range node.Labels {
				if l != "BaseNode" && l != "Persistable" {
					primaryLabel = l
					break
				}
			}

			props := normalizeProperties(node.Properties)

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