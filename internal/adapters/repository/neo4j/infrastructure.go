package neo4j

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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

func parseGraphID(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatInt(int64(val), 10)
	case int:
		return strconv.Itoa(val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// GetGraphData recupera todos los nodos y relaciones de la base de datos Neo4j en un formato estructurado.
func (r *infrastructureRepo) GetGraphData(ctx context.Context, projectID int64) (*domain.GraphData, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	params := map[string]any{
		"projectID": projectID,
	}

	var matchClause string
	if projectID > 0 {
		matchClause = `
			MATCH (proj:Project)
			WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID)
			MATCH (proj)-[:HAS_ENDPOINT]->(e)
			OPTIONAL MATCH (e)-[:CONNECTED_TO]->(net:Network)
			OPTIONAL MATCH (e)-[:HAS_HARDWARE]->(hw:Hardware)
			OPTIONAL MATCH (e)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
			OPTIONAL MATCH (si)-[:INSTANCE_OF]->(sw:Software)
			OPTIONAL MATCH (si)-[:HAS_FINDING]->(f1:Finding)
			OPTIONAL MATCH (f1)-[:OF_VULNERABILITY]->(v1:Vulnerability)
			OPTIONAL MATCH (e)-[:HOSTS]->(c:Container)
			OPTIONAL MATCH (c)-[:USES_IMAGE]-(ci:ContainerImage)
			OPTIONAL MATCH (c)-[:HAS_INSTALLATION]->(csi:SoftwareInstallation)
			OPTIONAL MATCH (csi)-[:INSTANCE_OF]->(csw:Software)
			OPTIONAL MATCH (csi)-[:HAS_FINDING]->(cf1:Finding)
			OPTIONAL MATCH (cf1)-[:OF_VULNERABILITY]->(cv1:Vulnerability)
			OPTIONAL MATCH (c)-[:HAS_FINDING]->(cf2:Finding)
			OPTIONAL MATCH (cf2)-[:OF_VULNERABILITY]->(cv2:Vulnerability)
			OPTIONAL MATCH (ci)-[:HAS_FINDING]->(cif:Finding)
			OPTIONAL MATCH (cif)-[:OF_VULNERABILITY]->(civ:Vulnerability)
			OPTIONAL MATCH (ci)-[:HAS_VULNERABILITY]->(iv1:Vulnerability)
			WITH DISTINCT proj, e, net, hw, si, sw, f1, v1, c, ci, csi, csw, cf1, cv1, cf2, cv2, cif, civ, iv1
			UNWIND [proj, e, net, hw, si, sw, f1, v1, c, ci, csi, csw, cf1, cv1, cf2, cv2, cif, civ, iv1] AS nodeItem
			WITH nodeItem AS n WHERE n IS NOT NULL
			WITH DISTINCT n
		`
	} else {
		matchClause = `
			MATCH (n)
			WHERE NOT (n:ThreatActor OR n:TTP OR n:IPAddress)
		`
	}

	query := matchClause + `
			OPTIONAL MATCH (n)-[:MAPS_TO]->(t1:TTP)
			WHERE "Vulnerability" IN labels(n)
			WITH n, collect(DISTINCT t1) AS t1List

			OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t2:TTP)
			WHERE "Vulnerability" IN labels(n)
			WITH n, t1List, collect(DISTINCT t2) AS t2List

			OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t3:TTP)
			WHERE "Vulnerability" IN labels(n)
			WITH n, t1List, t2List, collect(DISTINCT t3) AS t3List

			WITH n, t1List + t2List + t3List AS combinedTTPs
			UNWIND CASE WHEN size(combinedTTPs) > 0 THEN combinedTTPs ELSE [null] END AS t

			WITH n,
				collect(DISTINCT CASE
				WHEN t IS NOT NULL AND t.ttp_id IS NOT NULL
				THEN {
					ttp_id: t.ttp_id,
					name: coalesce(t.name, ''),
					tactic: coalesce(t.tactic, ''),
					description: coalesce(t.description, '')
				}
				ELSE null
				END) AS inferredTTPs

			WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs

			OPTIONAL MATCH (n)-[:OF_VULNERABILITY]->(v:Vulnerability)
			OPTIONAL MATCH (n)-[:HAS_REMEDIATION]->(rem:Remediation)
			OPTIONAL MATCH (p:Patch)-[:FIXES]->(v)

			WITH n,
				cleanTTPs,
				v,
				rem,
				collect(p.url) AS patchUrls

			WITH n,
				cleanTTPs,
				patchUrls,
				coalesce(rem.fixed_version, v.fixed_version, '') AS fixedVersion

			WITH collect({
					id: elementId(n),
					labels: labels(n),
					properties: n {
							.*,
							ttps: cleanTTPs,
							patch_available: CASE
									WHEN "Finding" IN labels(n)
									THEN size(patchUrls) > 0 OR fixedVersion <> ''
									ELSE null
							END,
							fixed_version: CASE
									WHEN "Finding" IN labels(n)
									THEN fixedVersion
									ELSE null
							END,
							remediation_kind: CASE
									WHEN NOT "Finding" IN labels(n) THEN null
									WHEN size(patchUrls) > 0 AND all(url IN patchUrls WHERE url STARTS WITH 'fixed-version://') THEN 'WORKAROUND'
									WHEN size(patchUrls) > 0 THEN 'OFFICIAL_FIX'
									WHEN fixedVersion <> '' THEN 'WORKAROUND'
									ELSE 'UNAVAILABLE'
							END
					},
					hasVuln: COUNT { (n)-[:OF_VULNERABILITY]->(:Vulnerability) } > 0
			}) AS nodes
			WITH nodes, [nodeObj IN nodes | nodeObj.id] AS nodeIds

			OPTIONAL MATCH (s)-[rel]->(t)
			WHERE elementId(s) IN nodeIds
			  AND elementId(t) IN nodeIds
			  AND NOT (
					startNode(rel):ThreatActor OR
					startNode(rel):TTP OR
					startNode(rel):IPAddress OR
					endNode(rel):ThreatActor OR
					endNode(rel):TTP OR
					endNode(rel):IPAddress
			)

			WITH nodes, collect({
					id: elementId(rel),
					type: type(rel),
					source: elementId(startNode(rel)),
					target: elementId(endNode(rel)),
					properties: properties(rel)
			}) AS cleanRels

			WITH nodes, cleanRels, [nodeObj IN nodes | nodeObj.id] AS scopedIds
			OPTIONAL MATCH (n)-[:HAS_IP]->(ip:IPAddress)
			WHERE (n:Endpoint OR n:Container) AND elementId(n) IN scopedIds

			WITH nodes,
				cleanRels,
				collect(
				CASE
					WHEN n IS NULL OR ip IS NULL THEN null
					ELSE {
					node_id: elementId(n),
					ip: coalesce(ip.ip, ""),
					vlan_id: coalesce(ip.vlan_id, 0)
					}
				END
				) AS ipMaps

			RETURN nodes,
				cleanRels AS relationships,
				[] AS ttp_mappings,
				[i IN ipMaps WHERE i IS NOT NULL] AS ip_mappings
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, params)
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
				id := parseGraphID(nodeMap["id"])
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
				endpointID := parseGraphID(m["node_id"])
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
				id := parseGraphID(relMap["id"])
				relType, _ := relMap["type"].(string)
				source := parseGraphID(relMap["source"])
				target := parseGraphID(relMap["target"])
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

// GetATTACKCatalogInfo lee la versión del catálogo MITRE ATT&CK cargada.
//
// El recuento de técnicas se cuenta en vivo en lugar de leer el que se guardó al
// sincronizar: si alguien purga o modifica nodos TTP, el valor almacenado se
// queda obsoleto y el publicado dejaría de corresponderse con el grafo.
//
// Si no hay nodo de catálogo —grafo poblado antes de que existiera este
// registro— se devuelve la versión vacía en vez de un error: quien consume debe
// poder distinguir "no lo sé" y actuar en consecuencia, no recibir un fallo.
func (r *infrastructureRepo) GetATTACKCatalogInfo(ctx context.Context) (*domain.ATTACKCatalogInfo, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		OPTIONAL MATCH (c:ATTACKCatalog {name: 'enterprise-attack'})
		RETURN coalesce(c.version, '')      AS version,
		       coalesce(c.spec_version, '') AS spec_version,
		       coalesce(c.updated_at, 0)    AS updated_at,
		       count { (t:TTP) }            AS total_ttps
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		registro, err := result.Single(ctx)
		if err != nil {
			return nil, err
		}

		info := &domain.ATTACKCatalogInfo{}
		datos := registro.AsMap()
		info.Version, _ = datos["version"].(string)
		info.SpecVersion, _ = datos["spec_version"].(string)
		if v, ok := datos["updated_at"].(int64); ok {
			info.UpdatedAt = v
		}
		if v, ok := datos["total_ttps"].(int64); ok {
			info.TotalTTPs = int(v)
		}
		return info, nil
	})
	if err != nil {
		return nil, err
	}

	info, _ := res.(*domain.ATTACKCatalogInfo)
	return info, nil
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
//
//	Bug A (coalesce): coalesce(t1,t2,t3) solo devuelve el primer nodo no nulo por fila,
//	       descartando silenciosamente TTPs de rutas alternativas. Corregido usando
//	       combinación explícita: [t IN [t1,t2,t3] WHERE t IS NOT NULL].
//	       Diagnóstico diferencial: en el proyecto Simon (id=1787471430021), el Bug A
//	       NO contribuía a la discrepancia observada (67 con coalesce = 67 con combinación,
//	       ambos sobre ruta rígida). El 100% del hueco lo causaba el Bug B.
//	Bug B (ruta rígida inicial): la cadena fija HAS_ENDPOINT→…→OF_VULNERABILITY no alcanzaba
//	       vulnerabilidades vinculadas por rutas alternativas (ej. contenedores).
//	Bug C (fuga lateral por traversal dinámico): el intento de arreglar el Bug B usando un
//	       traversal de longitud variable sin restricción de tipo de relación ([*1..6])
//	       causó contaminación cruzada entre proyectos, saltando a través de nodos TTP
//	       (vía TARGETS_VULN, datos de demo de cmd/Pruebas/Poblar_repo/main.go) hacia
//	       vulnerabilidades ajenas al proyecto.
//	       Fix Final: Se reemplazó el traversal genérico por 7 rutas EXACTAS de pertenencia
//	       usando EXISTS. Esto garantiza aislamiento criptográfico entre proyectos.
//	       Verificación final (Proyecto Simon, id=1787471430021): Tras aplicar las rutas
//	       exactas, el conteo purgado devuelve 16 vulnerabilidades legítimas (sin las 2
//	       de demo filtradas) y total_infra_ttps=67, que es el número correcto real.
//	       Ambos GetTopAPTs y GetTTPMatrix coinciden ahora en este valor corregido.
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
		OPTIONAL MATCH (v)-[:MAPS_TO]->(t3:TTP)

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
		MATCH path = (e1)-[:CONNECTED_TO|HOSTS*0..]-(eTarget)
		WHERE ((e1:Endpoint AND NOT toLower(coalesce(e1.estado, e1.status, '')) IN ['decomisado', 'decommissioned'] AND (
		        EXISTS {
		          MATCH (e1)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fE1:Finding)-[:OF_VULNERABILITY]->(vE1:Vulnerability)
		          WHERE (vE1.cvss_vector CONTAINS 'AV:N' OR vE1.nvd_vector CONTAINS 'AV:N' OR vE1.cvss_vector CONTAINS 'AV:A' OR coalesce(vE1.base_score, 0.0) >= 4.0)
		            AND NOT (toUpper(coalesce(fE1.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
		        } OR EXISTS {
		          MATCH (e1)-[:HOSTS]-(cE1:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fHostE1:Finding)-[:OF_VULNERABILITY]->(vHostE1:Vulnerability)
		          WHERE toLower(cE1.state) = 'running'
		        }
		      )) OR (e1:Container AND toLower(e1.state) = 'running')) AND e1.internet_exposed = true
		  AND ((eTarget:Endpoint AND NOT toLower(coalesce(eTarget.estado, eTarget.status, '')) IN ['decomisado', 'decommissioned']) OR (eTarget:Container AND toLower(eTarget.state) = 'running'))
		  AND ($projectID = 0 OR toString($projectID) = "0" OR 
		    EXISTS { MATCH (proj:Project)-[:HAS_ENDPOINT]-(e1) WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID) OR proj.name = toString($projectID) } OR
		    (e1:Container AND EXISTS { MATCH (proj:Project)-[:HAS_ENDPOINT]-(:Endpoint)-[:HOSTS]-(e1) WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID) OR proj.name = toString($projectID) }))
		  AND ($projectID = 0 OR toString($projectID) = "0" OR 
		    EXISTS { MATCH (proj:Project)-[:HAS_ENDPOINT]-(eTarget) WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID) OR proj.name = toString($projectID) } OR
		    (eTarget:Container AND EXISTS { MATCH (proj:Project)-[:HAS_ENDPOINT]-(:Endpoint)-[:HOSTS]-(eTarget) WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID) OR proj.name = toString($projectID) }))
		  AND all(n IN nodes(path) WHERE 
		    (n:Network) OR 
		    (($projectID = 0 OR toString($projectID) = "0" OR 
		      EXISTS { MATCH (proj:Project)-[:HAS_ENDPOINT]-(n) WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID) OR proj.name = toString($projectID) } OR
		      (n:Container AND EXISTS { MATCH (proj:Project)-[:HAS_ENDPOINT]-(:Endpoint)-[:HOSTS]-(n) WHERE proj.id = $projectID OR toString(proj.id) = toString($projectID) OR proj.name = toString($projectID) }))
		     AND
		     ((n:Endpoint AND NOT toLower(coalesce(n.estado, n.status, '')) IN ['decomisado', 'decommissioned'] AND (
			      EXISTS {
			        MATCH (n)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fNative:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			        WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(c IN coalesce(v.cwe, []) WHERE c IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
			          AND NOT (toUpper(coalesce(fNative.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			          AND coalesce(fNative.remediation_factor, 1.0) > 0.0
			          AND coalesce(fNative.risk_score, 0.0) > 0.0
			      } OR EXISTS {
			        MATCH (n)-[:HOSTS]-(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fHosted:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			        WHERE toLower(c.state) = 'running' AND ((v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cwe IN coalesce(v.cwe, []) WHERE cwe IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269'])))
			          AND NOT (toUpper(coalesce(fHosted.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			          AND coalesce(fHosted.remediation_factor, 1.0) > 0.0
			          AND coalesce(fHosted.risk_score, 0.0) > 0.0
		      } OR EXISTS {
		        MATCH (n)-[:HOSTS]-(c:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(v:Vulnerability)
		        WHERE toLower(c.state) = 'running' AND ((v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cwe IN coalesce(v.cwe, []) WHERE cwe IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269'])))
		      }
		    )) OR
		    (n:Container AND toLower(n.state) = 'running' AND (
		      elementId(n) = elementId(e1)
			  OR
			  EXISTS { MATCH (ep:Endpoint)-[:HOSTS]-(n) WHERE ep IN nodes(path) }
		      OR
		      (EXISTS { MATCH (n)-[:CONNECTED_TO]->(:Network) } AND (
			        EXISTS {
			          MATCH (n)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fDirect:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			          WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(c IN coalesce(v.cwe, []) WHERE c IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
			            AND NOT (toUpper(coalesce(fDirect.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			            AND coalesce(fDirect.remediation_factor, 1.0) > 0.0
			            AND coalesce(fDirect.risk_score, 0.0) > 0.0
		        } OR EXISTS {
		          MATCH (n)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_FINDING|HAS_VULNERABILITY*1..2]->(v:Vulnerability)
		          WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A' OR coalesce(v.base_score, 0.0) >= 4.0)
		        }
		      ))
		    ))
		  )))
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
			WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
			  AND NOT (toUpper(coalesce(f.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			  AND coalesce(f.remediation_factor, 1.0) > 0.0
			  AND coalesce(f.risk_score, 0.0) > 0.0
			RETURN si, null AS ci, f, toString(coalesce(f.id, elementId(f))) AS f_id, v, false AS is_container, null AS container, 1 AS priority
			UNION
			// Caso 2: ep es Endpoint, con vuln en software de un contenedor hosteado
			WITH ep
			MATCH (ep:Endpoint)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE toLower(c.state) = 'running' AND ((v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269'])))
			  AND NOT (toUpper(coalesce(f.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			  AND coalesce(f.remediation_factor, 1.0) > 0.0
			  AND coalesce(f.risk_score, 0.0) > 0.0
			RETURN si, null AS ci, f, toString(coalesce(f.id, elementId(f))) AS f_id, v, true AS is_container, c AS container, 2 AS priority
			UNION
			// Caso 3a: ep es Endpoint, con vuln en imagen de un contenedor hosteado (con nodo Finding)
			WITH ep
			MATCH (ep:Endpoint)-[:HOSTS]-(c:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE toLower(c.state) = 'running' AND ((v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A' OR coalesce(v.base_score, 0.0) >= 4.0) AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269'])))
			  AND NOT (toUpper(coalesce(f.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			  AND coalesce(f.remediation_factor, 1.0) > 0.0
			  AND coalesce(f.risk_score, 0.0) > 0.0
			RETURN null AS si, ci, f, toString(coalesce(f.id, elementId(f))) AS f_id, v, true AS is_container, c AS container, 3 AS priority
			UNION
			// Caso 3b: ep es Endpoint, con vuln directa en imagen de contenedor hosteado sin finding
			WITH ep
			MATCH (ep:Endpoint)-[:HOSTS]-(c:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
			WHERE toLower(c.state) = 'running' AND ((v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A' OR coalesce(v.base_score, 0.0) >= 4.0) AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269'])))
			RETURN null AS si, ci, {risk_score: coalesce(v.base_score / 10.0, 0.0), severity: coalesce(v.severity, "UNKNOWN"), status: "LEGACY_UNCONTEXTUALIZED", risk_source: "LEGACY_VULNERABILITY_BASE_SCORE"} AS f, elementId(v) AS f_id, v, true AS is_container, c AS container, 4 AS priority
			UNION
			// Caso 4: ep es Container directamente enrutado, con vuln en software (AV:N RCE - MAYOR PRIORIDAD PARA CONTENEDORES)
			WITH ep
			MATCH (ep:Container)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A' OR coalesce(v.base_score, 0.0) >= 4.0) AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
			  AND NOT (toUpper(coalesce(f.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			  AND coalesce(f.risk_score, 0.0) > 0.0
			RETURN si, null AS ci, f, toString(coalesce(f.id, elementId(f))) AS f_id, v, true AS is_container, ep AS container, 1 AS priority
			UNION
			// Caso 5a: ep es Container directamente enrutado, con vuln en imagen (con nodo Finding)
			WITH ep
			MATCH (ep:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A' OR coalesce(v.base_score, 0.0) >= 4.0) AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
			  AND NOT (toUpper(coalesce(f.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			  AND coalesce(f.remediation_factor, 1.0) > 0.0
			  AND coalesce(f.risk_score, 0.0) > 0.0
			RETURN null AS si, ci, f, toString(coalesce(f.id, elementId(f))) AS f_id, v, true AS is_container, ep AS container, 1 AS priority
			UNION
			// Caso 5b: ep es Container, con vuln directa sin nodo Finding
			WITH ep
			MATCH (ep:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
			WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.nvd_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A' OR coalesce(v.base_score, 0.0) >= 4.0) AND (v.exploit = true OR coalesce(v.kev, false) = true OR any(cweItem IN coalesce(v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
			RETURN null AS si, ci, {risk_score: coalesce(v.base_score / 10.0, 0.0), severity: coalesce(v.severity, "UNKNOWN"), status: "LEGACY_UNCONTEXTUALIZED", risk_source: "LEGACY_VULNERABILITY_BASE_SCORE"} AS f, elementId(v) AS f_id, v, true AS is_container, ep AS container, 2 AS priority
			UNION
			// Caso 6: Endpoint (host) atravesado por HOSTS - solo aplica a Endpoints, no a Containers
			WITH ep, path, indexed, ie
			MATCH (ep:Endpoint)-[:HOSTS]->(c2:Container)
			WHERE c2 IN nodes(path) AND ie.index > 0 AND elementId(indexed[ie.index-1].asset) = elementId(c2)
			OPTIONAL MATCH (c2)-[:HAS_INSTALLATION|USES_IMAGE*1..2]->()-[:HAS_FINDING]->(fLPE:Finding)-[:OF_VULNERABILITY]->(vLPE:Vulnerability)
			WHERE (toLower(vLPE.description) CONTAINS 'container escape' OR toLower(vLPE.description) CONTAINS 'sandbox escape' OR toLower(vLPE.description) CONTAINS 'escape container' OR toLower(vLPE.description) CONTAINS 'runc escape' OR toLower(vLPE.description) CONTAINS 'docker escape' OR toLower(vLPE.description) CONTAINS 'privilege escalation' OR toLower(vLPE.description) CONTAINS 'privilege' OR toLower(vLPE.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vLPE.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			  AND NOT (toUpper(coalesce(fLPE.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			  AND coalesce(fLPE.remediation_factor, 1.0) > 0.0
			  AND coalesce(fLPE.risk_score, 0.0) > 0.0
			WITH ep, vLPE, fLPE, c2
			ORDER BY vLPE.base_score DESC
			WITH ep, collect(vLPE)[0] as bestLPE, collect(fLPE)[0] as bestFinding, c2
			RETURN null AS si, null AS ci, {risk_score: coalesce(bestLPE.base_score / 10.0, 0.88), risk_source: "LEGACY_LPE_BASE_SCORE"} AS f, coalesce(elementId(bestFinding), "") AS f_id,
			       CASE WHEN bestLPE IS NOT NULL THEN bestLPE 
			       ELSE {cve_id: CASE WHEN coalesce(c2.privileged, false) = true THEN "Privileged Container" ELSE "LPE / Movement" END, cvss_vector: "AV:L/AC:L", exploit: true} 
			       END AS v, false AS is_container, null AS container, 0 AS priority
			UNION
			// Caso 7: ep es Network, se usa para mostrar el paso por la red explícitamente
			WITH ep
			MATCH (ep:Network)
			RETURN null AS si, null AS ci, {risk_score: 0.0} AS f, "" AS f_id, {cve_id: "Conexión de Red", cvss_vector: "AV:N/AC:L", exploit: false} AS v, false AS is_container, null AS container, 1 AS priority
		}
		// Ordenar: primero por prioridad ASC (1=mejor), luego por risk_score DESC dentro de esa prioridad
		WITH path, e1, indexed, ie, ep, si, ci, f, f_id, v, is_container, container, priority ORDER BY priority ASC, coalesce(f.risk_score, 0.0) DESC
		
		WITH path, e1, indexed, ie, ep, collect({si: si, ci: ci, f: f, f_id: f_id, v: v, is_container: is_container, container: container}) AS allNetsRaw
		WITH path, e1, indexed, ie, ep, [net IN allNetsRaw WHERE ie.index > 0 OR NOT net.is_container OR (net.container IS NOT NULL OR net.ci IS NOT NULL) AND (net.v.cvss_vector CONTAINS 'AV:N' OR net.v.nvd_vector CONTAINS 'AV:N' OR net.v.cvss_vector CONTAINS 'AV:A' OR coalesce(net.v.base_score, 0.0) >= 4.0)] AS allNets
		
		WITH path, e1, indexed, ie, ep, allNets,
		  EXISTS { MATCH (ep)-[:CONNECTED_TO]->(:Network)<-[:CONNECTED_TO]-(lastNode) WHERE lastNode = last(nodes(path)) } AS canReachTargetDirectly,
			  EXISTS {
			    MATCH (ep)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fLocal:Finding)-[:OF_VULNERABILITY]->(vLocal:Vulnerability)
			    WHERE vLocal.cvss_vector CONTAINS 'AV:L' AND vLocal.cvss_vector CONTAINS 'C:H' AND vLocal.cvss_vector CONTAINS 'I:H'
			      AND NOT (toUpper(coalesce(fLocal.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			      AND coalesce(fLocal.remediation_factor, 1.0) > 0.0
			      AND coalesce(fLocal.risk_score, 0.0) > 0.0
			  } AS hasHostLPE,
			  EXISTS {
			    MATCH (ep)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fContLocal:Finding)-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
			    WHERE toLower(c.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'container escape' OR toLower(vContLocal.description) CONTAINS 'sandbox escape' OR toLower(vContLocal.description) CONTAINS 'escape container' OR toLower(vContLocal.description) CONTAINS 'runc escape' OR toLower(vContLocal.description) CONTAINS 'docker escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation' OR toLower(vContLocal.description) CONTAINS 'privilege' OR toLower(vContLocal.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vContLocal.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			      AND NOT (toUpper(coalesce(fContLocal.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			      AND coalesce(fContLocal.remediation_factor, 1.0) > 0.0
			      AND coalesce(fContLocal.risk_score, 0.0) > 0.0
			  } AS hasContLPE,
			  EXISTS {
			    MATCH (ep)-[:HOSTS]->(c:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_FINDING]->(fImageLocal:Finding)-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
			    WHERE toLower(c.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'container escape' OR toLower(vContLocal.description) CONTAINS 'sandbox escape' OR toLower(vContLocal.description) CONTAINS 'escape container' OR toLower(vContLocal.description) CONTAINS 'runc escape' OR toLower(vContLocal.description) CONTAINS 'docker escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation' OR toLower(vContLocal.description) CONTAINS 'privilege' OR toLower(vContLocal.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vContLocal.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			      AND NOT (toUpper(coalesce(fImageLocal.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			      AND coalesce(fImageLocal.remediation_factor, 1.0) > 0.0
			      AND coalesce(fImageLocal.risk_score, 0.0) > 0.0
			  } AS hasImageContLPE,
			  EXISTS {
			    MATCH (ep:Container)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fDirectContLocal:Finding)-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
			    WHERE toLower(ep.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'container escape' OR toLower(vContLocal.description) CONTAINS 'sandbox escape' OR toLower(vContLocal.description) CONTAINS 'escape container' OR toLower(vContLocal.description) CONTAINS 'runc escape' OR toLower(vContLocal.description) CONTAINS 'docker escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation' OR toLower(vContLocal.description) CONTAINS 'privilege' OR toLower(vContLocal.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vContLocal.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			      AND NOT (toUpper(coalesce(fDirectContLocal.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			      AND coalesce(fDirectContLocal.remediation_factor, 1.0) > 0.0
			      AND coalesce(fDirectContLocal.risk_score, 0.0) > 0.0
			  } AS hasDirectContLPE,
			  EXISTS {
			    MATCH (ep:Container)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_FINDING]->(fDirectImageLocal:Finding)-[:OF_VULNERABILITY]->(vContLocal:Vulnerability)
			    WHERE toLower(ep.state) = 'running' AND (toLower(vContLocal.description) CONTAINS 'container escape' OR toLower(vContLocal.description) CONTAINS 'sandbox escape' OR toLower(vContLocal.description) CONTAINS 'escape container' OR toLower(vContLocal.description) CONTAINS 'runc escape' OR toLower(vContLocal.description) CONTAINS 'docker escape' OR toLower(vContLocal.description) CONTAINS 'privilege escalation' OR toLower(vContLocal.description) CONTAINS 'privilege' OR toLower(vContLocal.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vContLocal.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			      AND NOT (toUpper(coalesce(fDirectImageLocal.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			      AND coalesce(fDirectImageLocal.remediation_factor, 1.0) > 0.0
			      AND coalesce(fDirectImageLocal.risk_score, 0.0) > 0.0
			  } AS hasDirectImageContLPE,
		  EXISTS { MATCH (ep)-[:CONNECTED_TO]-(:Network) } AS epHasNet,
		  EXISTS { MATCH (ep)-[:HOSTS]-(cNet:Container)-[:CONNECTED_TO]-(:Network) } AS hostedContHasNet
		
		WITH path, e1, indexed, ie, ep, allNets, 
		  CASE 
		    WHEN ep:Container THEN (epHasNet OR ep.privileged = true OR hasDirectContLPE OR hasDirectImageContLPE)
		    WHEN size(allNets) > 0 AND allNets[0].is_container THEN (hostedContHasNet OR epHasNet OR allNets[0].container.privileged = true OR hasContLPE OR hasImageContLPE)
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
		
		WHERE size(steps) > 0
		AND size(steps[0].allNets) > 0
		// Si hay un paso intermedio de contenedor que NO puede escapar, bloquear la ruta (el nodo objetivo final no requiere escape)
		AND all(i IN range(0, size(steps)-2) WHERE
		    NOT steps[i].is_container OR steps[i].hasLPE
		)
		AND (
		    (steps[0].allNets[0].v.cvss_vector CONTAINS 'AV:N' OR 
		    steps[0].allNets[0].v.nvd_vector CONTAINS 'AV:N' OR 
		    steps[0].allNets[0].v.cvss_vector CONTAINS 'AV:A')
		    AND (steps[0].allNets[0].v.exploit = true OR coalesce(steps[0].allNets[0].v.kev, false) = true OR any(cweItem IN coalesce(steps[0].allNets[0].v.cwe, []) WHERE cweItem IN ['CWE-94', 'CWE-78', 'CWE-77', 'CWE-502', 'CWE-434', 'CWE-95', 'CWE-20', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-269']))
		)

		RETURN e1 AS e1_node, e1.id AS entry_id, steps,
			  // ¿Tiene el entry container un LPE real (CVE) sin depender de privileged=true?
			  CASE
			    WHEN e1:Container THEN (
			      EXISTS {
			        MATCH (e1)-[:HAS_INSTALLATION]->()-[:HAS_FINDING]->(fEntryLPE:Finding)-[:OF_VULNERABILITY]->(vLPE:Vulnerability)
			        WHERE (toLower(vLPE.description) CONTAINS 'container escape' OR toLower(vLPE.description) CONTAINS 'sandbox escape' OR toLower(vLPE.description) CONTAINS 'escape container' OR toLower(vLPE.description) CONTAINS 'runc escape' OR toLower(vLPE.description) CONTAINS 'docker escape' OR toLower(vLPE.description) CONTAINS 'privilege escalation' OR toLower(vLPE.description) CONTAINS 'privilege' OR toLower(vLPE.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vLPE.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			          AND NOT (toUpper(coalesce(fEntryLPE.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			          AND coalesce(fEntryLPE.remediation_factor, 1.0) > 0.0
			          AND coalesce(fEntryLPE.risk_score, 0.0) > 0.0
			      }
			      OR EXISTS {
			        MATCH (e1)-[:USES_IMAGE]-(ci:ContainerImage)-[:HAS_FINDING]->(fEntryImageLPE:Finding)-[:OF_VULNERABILITY]->(vLPE2:Vulnerability)
			        WHERE (toLower(vLPE2.description) CONTAINS 'container escape' OR toLower(vLPE2.description) CONTAINS 'sandbox escape' OR toLower(vLPE2.description) CONTAINS 'escape container' OR toLower(vLPE2.description) CONTAINS 'runc escape' OR toLower(vLPE2.description) CONTAINS 'docker escape' OR toLower(vLPE2.description) CONTAINS 'privilege escalation' OR toLower(vLPE2.description) CONTAINS 'privilege' OR toLower(vLPE2.description) CONTAINS 'overflow' OR any(cweInList IN coalesce(vLPE2.cwe, []) WHERE cweInList IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			          AND NOT (toUpper(coalesce(fEntryImageLPE.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED', 'SUPERSEDED'])
			          AND coalesce(fEntryImageLPE.remediation_factor, 1.0) > 0.0
			          AND coalesce(fEntryImageLPE.risk_score, 0.0) > 0.0
			      }
			    )
		    ELSE true
		  END AS hasRealLPE
		ORDER BY hasRealLPE DESC
	`

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, map[string]any{"projectID": projectID})
		if err != nil {
			return nil, err
		}

		paths := make([]domain.ExploitationPath, 0)
		bestPathPerTarget := make(map[string]domain.ExploitationPath)
		pathCounter := 1
		rawRecordCount := 0

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
			rawRecordCount++
			record := result.Record()

			entryIDVal, _ := record.Get("entry_id")
			entryIDStr := fmt.Sprintf("%v", entryIDVal)

			stepsRaw, _ := record.Get("steps")
			stepsList, ok := stepsRaw.([]any)
			if !ok || len(stepsList) == 0 {
				continue
			}

			hasRealLPEVal, _ := record.Get("hasRealLPE")
			hasRealLPE := getBoolLocal(hasRealLPEVal)

			// Usar el nodo e1 directamente para obtener el nombre correcto
			e1RawForName, _ := record.Get("e1_node")
			e1NodeProps := getNodeProps(e1RawForName)
			e1IsPrivileged := getBoolLocal(e1NodeProps["privileged"])
			if !e1IsPrivileged {
				for _, sAny := range stepsList {
					sm := getMap(sAny)
					if sm != nil {
						allNetsRaw, _ := sm["allNets"].([]any)
						if len(allNetsRaw) > 0 {
							firstNetMap := getMap(allNetsRaw[0])
							if getBoolLocal(firstNetMap["is_container"]) {
								cProps := getNodeProps(firstNetMap["container"])
								if getBoolLocal(cProps["privileged"]) {
									e1IsPrivileged = true
									break
								}
							}
						}
					}
				}
			}

			initialEndpointName := getStringLocal(e1NodeProps["name"])
			if initialEndpointName == "" {
				initialEndpointName = getStringLocal(e1NodeProps["hostname"])
			}
			if initialEndpointName == "" {
				// Fallback: usar el primer step
				firstStepMap := getMap(stepsList[0])
				firstEndpointProps := getNodeProps(firstStepMap["endpoint"])
				initialEndpointName = getStringLocal(firstEndpointProps["name"])
				if initialEndpointName == "" {
					initialEndpointName = getStringLocal(firstEndpointProps["hostname"])
				}
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
			}

			activePaths := []activePathState{
				{
					Path:         ep,
					PrevEndpoint: "Acceso Perimetral",
					Offset:       0,
				},
			}

			// Pre-calcular el índice máximo del path para saber si un step es el último
			maxStepIndex := int64(-1)
			for _, sAny := range stepsList {
				sm := getMap(sAny)
				if sm != nil {
					if idx := getIntLocal(sm["index"]); idx > maxStepIndex {
						maxStepIndex = idx
					}
				}
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
				endpointType := getStringLocal(endpointProps["primaryLabel"])

				// Si el nodo actual del paso es un nodo de red puro (Network), omitirlo como paso independiente
				// para que no tape las vulnerabilidades reales de los endpoints expuestos
				if endpointType == "Network" {
					continue
				}

				var nextActivePaths []activePathState

				for _, state := range activePaths {
					hostname := getStringLocal(endpointProps["hostname"])
					targetName := hostname
					targetID := getIntLocal(endpointProps["id"])

					// Determinar si es contenedor basado en el primer allNets
					firstNetMap := getMap(allNetsRaw[0])
					isContainer := getBoolLocal(firstNetMap["is_container"])
					containerIsSource := false
					if isContainer {
						containerProps := getNodeProps(firstNetMap["container"])
						contName := getStringLocal(containerProps["name"])
						if contName != "" && contName != state.PrevEndpoint {
							targetName = contName
							targetID = 0
						} else if contName != "" && contName == state.PrevEndpoint {
							// El contenedor es la fuente. Determinar si es escape real o tránsito hacia red
							isLastStep := (index == maxStepIndex)
							if !isLastStep {
								// Paso intermedio: el path continúa más allá del host del contenedor (pivote de red).
								// No generar un step de "escape" — mantener el container como previo y saltar.
								nextActivePaths = append(nextActivePaths, state)
								continue
							}
							// Es el último paso: escape real del contenedor a su host
							containerIsSource = true
							hostEndpointName := getStringLocal(endpointProps["hostname"])
							if hostEndpointName == "" {
								hostEndpointName = getStringLocal(endpointProps["name"])
							}
							if hostEndpointName != "" && hostEndpointName != contName {
								targetName = hostEndpointName
							} else if hostname != "" && hostname != contName {
								targetName = hostname
							} else {
								targetName = getStringLocal(endpointProps["name"])
							}
						}
					}

					if !containerIsSource && (targetName == "" || (!isContainer && targetName == state.PrevEndpoint)) {
						targetName = getStringLocal(endpointProps["name"])
						if targetName == "" || targetName == state.PrevEndpoint {
							targetName = getStringLocal(endpointProps["nombre"])
						}
						if targetName == "" || targetName == state.PrevEndpoint {
							targetName = hostname
						}
					}

					if !isContainer && targetName == state.PrevEndpoint {
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
							} else if bestImage != nil {
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
							if risk < 0 {
								risk = 0
							}
							if risk > 1 {
								risk /= 10.0
							}
							if risk > 1 {
								risk = 1
							}

							findingElementID := getStringLocal(netMap["f_id"])
							vulnCVE := getStringLocal(vulnProps["cve_id"])

							isRCE := false
							cwes := getStringSlice(vulnProps, "cwe")
							for _, cwe := range cwes {
								if cwe == "CWE-94" || cwe == "CWE-78" || cwe == "CWE-77" || cwe == "CWE-502" || cwe == "CWE-434" || cwe == "CWE-95" || cwe == "CWE-20" || cwe == "CWE-787" || cwe == "CWE-119" || cwe == "CWE-120" || cwe == "CWE-269" {
									isRCE = true
									break
								}
							}
							if getBoolLocal(vulnProps["exploit"]) && vulnCVE != "Privileged Container" && vulnCVE != "LPE / Movement" {
								isRCE = true
							}

							rootObtained := false

							descLower := strings.ToLower(getStringLocal(vulnProps["description"]))
							cweList, _ := vulnProps["cwe"].([]any)
							hasLPECWE := false
							for _, c := range cweList {
								if cStr, ok := c.(string); ok {
									if cStr == "CWE-269" || cStr == "CWE-250" || cStr == "CWE-270" || cStr == "CWE-787" || cStr == "CWE-119" || cStr == "CWE-120" || cStr == "CWE-190" || cStr == "CWE-125" {
										hasLPECWE = true
										break
									}
								}
							}

							if vulnCVE == "Privileged Container" ||
								strings.Contains(descLower, "container escape") ||
								strings.Contains(descLower, "sandbox escape") ||
								strings.Contains(descLower, "privilege escalation") ||
								strings.Contains(descLower, "privilege") ||
								strings.Contains(descLower, "overflow") ||
								hasLPECWE {
								rootObtained = true
							}

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
								ContainerEscape:  containerIsSource, // true solo si es el escape real al host
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

							// Si el contenedor es el origen, el siguiente paso parte del container name
							nextPrev := targetName
							if containerIsSource {
								nextPrev = state.PrevEndpoint // mantener el container name como previo para siguientes saltos
							}

							newState := activePathState{
								Path:         clonedPath,
								PrevEndpoint: nextPrev,
								Offset:       state.Offset,
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
				firstStep := state.Path.Steps[0]
				lastStep := state.Path.Steps[len(state.Path.Steps)-1]

				// Ajustar InitialEndpoint si el primer paso inicia en un contenedor
				if firstStep.IsContainer && firstStep.ContainerName != "" {
					state.Path.InitialEndpoint = firstStep.ContainerName
				}

				// Descartar rutas circulares, autosaltos o pseudo-escapes sin avance lateral real (salvo rutas directas de 1 solo paso sobre el propio nodo expuesto)
				if lastStep.TargetEndpoint == "Escape de Contenedor (Host)" || (len(state.Path.Steps) > 1 && lastStep.TargetEndpoint == state.Path.InitialEndpoint) || lastStep.TargetEndpoint == "" {
					continue
				}

				// Post-procesar pasos: detectar si un paso es un escape al host físico
				// Ocurre cuando el paso sale de un contenedor y el destino es el host que lo aloja.
				hasInvalidEscape := false
				hostNameOfE1 := getStringLocal(e1NodeProps["hostname"])
				if hostNameOfE1 == "" {
					hostNameOfE1 = getStringLocal(e1NodeProps["name"])
				}

				for si := range state.Path.Steps {
					step := &state.Path.Steps[si]
					if step.ContainerEscape {
						if !e1IsPrivileged && !hasRealLPE {
							hasInvalidEscape = true
						}
						continue
					}
					if si > 0 {
						prev := state.Path.Steps[si-1]
						isNetworkPivot := step.Vulnerability == "Conexión de Red"
						// Si el paso previo es un contenedor y este paso sale de él directamente a un Endpoint
						if prev.IsContainer && prev.ContainerName != "" && step.SourceEndpoint == prev.ContainerName && !step.IsContainer && !isNetworkPivot {
							if e1IsPrivileged || hasRealLPE {
								step.ContainerEscape = true
							} else {
								hasInvalidEscape = true
							}
						}
					}
				}

				if hasInvalidEscape {
					continue // Descartar esta ruta porque intenta un escape a host sin privilegios ni CVE LPE
				}

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
		if v == nil {
			continue
		}
		switch val := v.(type) {
		case float64:
			// JSON unmarshals all numbers as float64.
			// Preserve booleans-as-float (0.0/1.0 for bool props) and int conversions.
			if val == float64(int64(val)) {
				cleaned[k] = int64(val)
			} else {
				cleaned[k] = val
			}
		case bool:
			// Keep booleans as booleans — Neo4j stores them natively.
			cleaned[k] = val
		case []interface{}:
			// Keep arrays as native slices so Cypher `any(x IN list WHERE ...)` works.
			// Neo4j driver accepts []interface{} directly as a list property.
			cleaned[k] = val
		case string:
			// Detect JSON-encoded arrays from previous exports (round-trip safety)
			// e.g. "[\"CWE-94\",\"CWE-787\"]" → []interface{}{"CWE-94","CWE-787"}
			trimmed := strings.TrimSpace(val)
			if len(trimmed) > 1 && trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']' {
				var arr []interface{}
				if err := json.Unmarshal([]byte(trimmed), &arr); err == nil {
					cleaned[k] = arr
					continue
				}
			}
			cleaned[k] = val
		case map[string]interface{}:
			// Nested maps: serialize to JSON string (Neo4j doesn't support nested maps as props)
			if b, err := json.Marshal(val); err == nil {
				cleaned[k] = string(b)
			} else {
				cleaned[k] = fmt.Sprint(val)
			}
		default:
			cleaned[k] = v
		}
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
			//
			// matchProps admite clave compuesta porque no todos los nodos se identifican por
			// una sola propiedad: SLAConfig no tiene `id` y su identidad es el par
			// (category, severity).
			var matchKey string
			var matchVal interface{}
			var matchProps map[string]interface{}

			switch primaryLabel {
			case "SLAConfig":
				// Sin `id`: la identidad es el par (categoría de activo, severidad). Si se
				// tratara con la clave por defecto se crearía un `id` sintético con el
				// elementId de origen y, al reimportar en otra base, saldrían duplicados en
				// lugar de reutilizar la configuración existente.
				cat, hasCat := props["category"]
				sev, hasSev := props["severity"]
				if hasCat && hasSev && cat != nil && sev != nil {
					matchProps = map[string]interface{}{"category": cat, "severity": sev}
				}
			case "IPAddress":
				// Mismo caso que SLAConfig: SaveIPs las crea como {ip, vlan_id} y sin `id`,
				// así que esa pareja es su identidad. Sin esto, cada importación duplicaba
				// las direcciones del inventario en vez de reutilizarlas.
				ip, hasIP := props["ip"]
				if hasIP && ip != nil {
					matchProps = map[string]interface{}{"ip": ip}
					if vlan, ok := props["vlan_id"]; ok && vlan != nil {
						matchProps["vlan_id"] = vlan
					}
				}
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

			// Los nodos de clave simple se normalizan al mismo mapa que los de clave compuesta,
			// para que la construcción del MERGE sea única.
			if matchProps == nil {
				if matchKey == "" {
					matchKey = "id"
					matchVal = node.ID
					props["id"] = node.ID
				}
				matchProps = map[string]interface{}{matchKey: matchVal}
			}

			// Construir query MERGE dinámico y aplicar todas las etiquetas del nodo
			var labelStr strings.Builder
			for _, l := range node.Labels {
				labelStr.WriteString(":")
				labelStr.WriteString(l)
			}

			// Patrón de MERGE y parámetros, con las claves ordenadas para que la consulta sea
			// determinista y el plan de ejecución se reutilice entre nodos del mismo tipo.
			matchKeys := make([]string, 0, len(matchProps))
			for k := range matchProps {
				matchKeys = append(matchKeys, k)
			}
			sort.Strings(matchKeys)

			var patron strings.Builder
			params := map[string]interface{}{"properties": props}
			for i, k := range matchKeys {
				if i > 0 {
					patron.WriteString(", ")
				}
				alias := fmt.Sprintf("m_%d", i)
				patron.WriteString(k)
				patron.WriteString(": $")
				patron.WriteString(alias)
				params[alias] = matchProps[k]
			}

			query := fmt.Sprintf(`
				MERGE (n:%s {%s})
				SET n%s, n += $properties
				RETURN elementId(n) AS elemId
			`, primaryLabel, patron.String(), labelStr.String())

			res, err := tx.Run(ctx, query, params)
			if err != nil {
				return nil, fmt.Errorf("error al importar nodo %s (%v): %w", primaryLabel, matchProps, err)
			}

			if res.Next(ctx) {
				if elemIdVal, ok := res.Record().Get("elemId"); ok && elemIdVal != nil {
					elemIdStr := fmt.Sprint(elemIdVal)
					if node.ID != "" {
						nodeLookup[node.ID] = elemIdStr
					}
					// Los nodos de clave simple se indexan además por su valor de clave, que es
					// como los referencian las relaciones del fichero exportado.
					if matchVal != nil {
						if matchValStr := fmt.Sprint(matchVal); matchValStr != "" {
							nodeLookup[matchValStr] = elemIdStr
						}
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

// IsAnalysisPending comprueba si hay vulnerabilidades de red asociadas a contenedores
// (o imágenes) que aún no han sido enriquecidas (carecen de CWE y Exploit), lo cual indica
// que el escaneo asíncrono de NVD aún podría estar procesando datos.
func (r *infrastructureRepo) IsAnalysisPending(ctx context.Context, projectID int64) (bool, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (v:Vulnerability)<-[:OF_VULNERABILITY]-(:Finding)<-[:HAS_FINDING]-(c:ContainerImage)
		WHERE (v.cvss_vector CONTAINS 'AV:N' OR v.cvss_vector CONTAINS 'AV:A') 
		  AND (v.exploit = false AND coalesce(size(v.cwe), 0) = 0)
		  AND coalesce(v.nvd_enriched, false) = false
	`
	if projectID > 0 {
		query += `
		  AND EXISTS { MATCH (proj:Project {id: $projectID})-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(c) }
		`
	}
	query += `
		RETURN count(v) > 0 AS is_analyzing
	`

	params := map[string]any{
		"projectID": projectID,
	}

	res, err := session.Run(ctx, query, params)
	if err != nil {
		return false, fmt.Errorf("error verificando análisis pendiente: %w", err)
	}

	if res.Next(ctx) {
		record := res.Record()
		isAnalyzing, _ := record.Get("is_analyzing")
		if b, ok := isAnalyzing.(bool); ok {
			return b, nil
		}
	}

	if err = res.Err(); err != nil {
		return false, fmt.Errorf("error iterando resultado de análisis pendiente: %w", err)
	}

	return false, nil
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
		OPTIONAL MATCH (v)-[:MAPS_TO]->(t3:TTP)

		WITH v, [t IN [t1, t2, t3] WHERE t IS NOT NULL] AS ttps_raw
		UNWIND (CASE WHEN size(ttps_raw) > 0 THEN ttps_raw ELSE [null] END) AS t
		WITH v, t WHERE t IS NOT NULL

		// La descripción se recorta a 160 caracteres: una misma CVE cuelga de
		// varias técnicas, así que su texto completo viajaba repetido y suponía el
		// 71% de una respuesta de ~1 MB que el frontend recarga con frecuencia.
		WITH t, collect(DISTINCT {
			id: coalesce(v.cve_id, v.id, ''),
			cvss: coalesce(v.cvss_score, v.base_score, 'N/A'),
			desc: CASE
			        WHEN v.description IS NULL THEN ''
			        WHEN size(v.description) > 160 THEN left(v.description, 160) + '…'
			        ELSE v.description
			      END
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

// GetTTPStats devuelve las métricas agregadas para el dashboard de inteligencia de amenazas.
func (r *infrastructureRepo) GetTTPStats(ctx context.Context, projectID int64) (*domain.TTPStats, error) {
	params := map[string]interface{}{"project_id": projectID}

	baseWhere := `
		MATCH (v:Vulnerability)
		WHERE $project_id = 0 OR toString($project_id) = "0" OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) } OR
		  EXISTS { MATCH (p:Project)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v) WHERE p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id) }
	`

	// Una CVE está mapeada cuando el pipeline ha escrito una arista de mapeo para
	// ella. Que su CWE sea alcanzable desde el catálogo CAPEC NO es un mapeo: se
	// cumple sin que el sistema haya hecho nada, y contarlo como tal daba un KPI
	// de cobertura del 100% con el trabajo sin hacer. Esa alcanzabilidad se
	// publica ahora como métrica propia (capec_pending), que es justamente la
	// cifra de trabajo determinista que queda por delante.
	totalQuery := baseWhere + `
		WITH v,
		  EXISTS { MATCH (v)-[:MAPS_TO]->(:TTP) } AS mapeo_directo,
		  EXISTS { MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(:TTP) } AS mapeo_via_cwe,
		  EXISTS { MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(:TTP) } AS capec_alcanzable
		WITH v, (mapeo_directo OR mapeo_via_cwe) AS is_mapped, capec_alcanzable
		RETURN
		  count(v) AS total,
		  count(CASE WHEN is_mapped THEN 1 END) AS mapped,
		  count(CASE WHEN NOT is_mapped THEN 1 END) AS unmapped,
		  count(CASE WHEN NOT is_mapped AND capec_alcanzable THEN 1 END) AS capec_pending
	`

	// La procedencia y la confianza se leen de las propiedades que escribe
	// LinkTTPsToVulnerability. No hay rama que las invente: la vía CAPEC aparece
	// aquí porque el worker la ejecutó y dejó source='capec_static', no por el
	// mero hecho de existir la ruta en el catálogo.
	//
	// Se cuenta por MAPEO (par CVE-técnica), no por técnica: "88 de alta
	// confianza" son 88 mapeos, que es lo que la interfaz dice medir.
	confidenceQuery := baseWhere + `
		CALL {
			WITH v
			MATCH (v)-[r:MAPS_TO]->(t:TTP)
			RETURN t, coalesce(r.confidence, 'medium') AS conf, coalesce(r.source, 'llm_enriched') AS src
			UNION
			WITH v
			MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[r:MAPS_TO]->(t:TTP)
			RETURN t, coalesce(r.confidence, 'medium') AS conf, coalesce(r.source, 'llm_enriched') AS src
		}
		// Un mismo par (CVE, técnica) puede llegar por las dos rutas. El empate se
		// resuelve con una regla explícita —el determinista gana al inferido— en
		// lugar de con collect(...)[0], que elegía un elemento arbitrario y hacía
		// que dos ejecuciones sobre los mismos datos pudieran diferir.
		WITH v, t, collect(DISTINCT {conf: conf, src: src}) AS candidatos
		WITH
		  CASE WHEN any(c IN candidatos WHERE c.src = 'capec_static') THEN 'capec_static' ELSE 'llm_enriched' END AS src,
		  CASE WHEN any(c IN candidatos WHERE c.conf = 'high')        THEN 'high'         ELSE 'medium'        END AS conf
		RETURN
		  count(CASE WHEN conf = 'high' THEN 1 END) AS high_confidence,
		  count(CASE WHEN conf = 'medium' THEN 1 END) AS medium_confidence,
		  count(CASE WHEN src = 'capec_static' THEN 1 END) AS capec_static,
		  count(CASE WHEN src = 'llm_enriched' THEN 1 END) AS llm_enriched
	`

	topTTPsQuery := baseWhere + `
		CALL {
			WITH v MATCH (v)-[:MAPS_TO]->(t:TTP) RETURN t
			UNION
			WITH v MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t:TTP) RETURN t
			UNION
			WITH v MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t:TTP) RETURN t
		}
		WITH t, count(DISTINCT v) AS cnt
		RETURN
		  coalesce(t.ttp_id, t.id, '') AS id,
		  coalesce(t.name, '')          AS name,
		  coalesce(t.tactic, '')        AS tactic,
		  cnt
		ORDER BY cnt DESC
		LIMIT 10
	`

	// La misma confianza contada por VULNERABILIDAD en lugar de por mapeo. Una
	// CVE cuenta como de confianza alta si tiene AL MENOS una técnica deducida
	// del catálogo; el resto de las mapeadas son de confianza media.
	//
	// Las dos lecturas divergen porque la vía determinista es mucho más densa
	// (6,35 técnicas por CVE frente a 2,04), de modo que un 30% de las CVE
	// aporta el 58% de las aristas. Sin esta cifra, el panel sugiere una
	// fiabilidad que no se sostiene a nivel de vulnerabilidad.
	confidenceCVEQuery := baseWhere + `
		WITH DISTINCT v
		WITH v,
		  EXISTS {
		    MATCH (v)-[r:MAPS_TO]->(:TTP) WHERE r.confidence = 'high'
		    UNION
		    MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[r2:MAPS_TO]->(:TTP) WHERE r2.confidence = 'high'
		  } AS tieneAlta,
		  EXISTS {
		    MATCH (v)-[:MAPS_TO]->(:TTP)
		    UNION
		    MATCH (v)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(:TTP)
		  } AS mapeada
		RETURN
		  count(CASE WHEN mapeada AND tieneAlta THEN 1 END)     AS high_cves,
		  count(CASE WHEN mapeada AND NOT tieneAlta THEN 1 END) AS medium_cves
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	stats := &domain.TTPStats{}

	_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		resCVE, err := tx.Run(ctx, confidenceCVEQuery, params)
		if err != nil {
			return nil, fmt.Errorf("ttp-stats confidenceCVEQuery: %w", err)
		}
		if resCVE.Next(ctx) {
			rec := resCVE.Record()
			if v, ok := rec.Get("high_cves"); ok && v != nil {
				stats.HighConfidenceCVEs = int(v.(int64))
			}
			if v, ok := rec.Get("medium_cves"); ok && v != nil {
				stats.MediumConfidenceCVEs = int(v.(int64))
			}
		}
		_, _ = resCVE.Consume(ctx)

		res1, err := tx.Run(ctx, totalQuery, params)
		if err != nil { return nil, fmt.Errorf("ttp-stats totalQuery: %w", err) }
		if res1.Next(ctx) {
			rec := res1.Record()
			if v, ok := rec.Get("total"); ok && v != nil { stats.TotalCVEs = int(v.(int64)) }
			if v, ok := rec.Get("mapped"); ok && v != nil { stats.MappedCVEs = int(v.(int64)) }
			if v, ok := rec.Get("unmapped"); ok && v != nil { stats.UnmappedCVEs = int(v.(int64)) }
			if v, ok := rec.Get("capec_pending"); ok && v != nil { stats.CapecPendingCVEs = int(v.(int64)) }
		}
		_, _ = res1.Consume(ctx)

		res2, err := tx.Run(ctx, confidenceQuery, params)
		if err != nil { return nil, fmt.Errorf("ttp-stats confidenceQuery: %w", err) }
		if res2.Next(ctx) {
			rec := res2.Record()
			if v, ok := rec.Get("high_confidence"); ok && v != nil { stats.HighConfidence = int(v.(int64)) }
			if v, ok := rec.Get("medium_confidence"); ok && v != nil { stats.MediumConfidence = int(v.(int64)) }
			if v, ok := rec.Get("capec_static"); ok && v != nil { stats.CapecStatic = int(v.(int64)) }
			if v, ok := rec.Get("llm_enriched"); ok && v != nil { stats.LlmEnriched = int(v.(int64)) }
		}
		_, _ = res2.Consume(ctx)

		res3, err := tx.Run(ctx, topTTPsQuery, params)
		if err != nil { return nil, fmt.Errorf("ttp-stats topTTPsQuery: %w", err) }
		for res3.Next(ctx) {
			rec := res3.Record()
			item := domain.TTPTopItem{}
			if v, ok := rec.Get("id"); ok && v != nil { item.ID = fmt.Sprint(v) }
			if v, ok := rec.Get("name"); ok && v != nil { item.Name = fmt.Sprint(v) }
			if v, ok := rec.Get("tactic"); ok && v != nil { item.Tactic = fmt.Sprint(v) }
			if v, ok := rec.Get("cnt"); ok && v != nil { item.Count = int(v.(int64)) }
			if item.ID != "" { stats.TopTTPs = append(stats.TopTTPs, item) }
		}
		_, _ = res3.Consume(ctx)

		return nil, nil
	})

	if err != nil {
		return nil, err
	}
	if stats.TopTTPs == nil {
		stats.TopTTPs = []domain.TTPTopItem{}
	}
	return stats, nil
}

