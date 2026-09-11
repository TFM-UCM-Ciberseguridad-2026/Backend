package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type projectRepo struct {
	driver neo4j.DriverWithContext
}

func (r *projectRepo) Save(ctx context.Context, p *domain.Project) error {

	var riskComputedAt any
	if p.RiskComputedAt != nil {
		riskComputedAt = *p.RiskComputedAt
	}

	var priorityComputedAt any
	if p.PriorityComputedAt != nil {
		priorityComputedAt = *p.PriorityComputedAt
	}

	query := `
		MERGE (n:Project {id: $id})
		ON CREATE SET n.nombre = $name,
			n.risk_score = $risk_score,
			n.risk_tier = $risk_tier,
			n.risk_computed_at = $risk_computed_at,
			n.priority_score = $priority_score,
			n.priority_tier = $priority_tier,
			n.priority_computed_at = $priority_computed_at,
			n.technical_driver_endpoint_id = $technical_driver_endpoint_id,
			n.technical_driver_endpoint_hostname = $technical_driver_endpoint_hostname,
			n.technical_driver_risk_score = $technical_driver_risk_score,
			n.technical_driver_software_name = $technical_driver_software_name,
			n.technical_driver_cve_id = $technical_driver_cve_id,
			n.priority_driver_endpoint_id = $priority_driver_endpoint_id,
			n.priority_driver_endpoint_hostname = $priority_driver_endpoint_hostname,
			n.priority_driver_priority_score = $priority_driver_priority_score,
			n.priority_driver_software_name = $priority_driver_software_name,
			n.priority_driver_cve_id = $priority_driver_cve_id,
			n.risky_endpoint_count = $risky_endpoint_count
	`
	params := map[string]any{
		"id":                                 p.ProjectID,
		"name":                               p.Nombre,
		"risk_score":                         p.RiskScore,
		"risk_tier":                          p.RiskTier,
		"risk_computed_at":                   riskComputedAt,
		"priority_score":                     p.PriorityScore,
		"priority_tier":                      p.PriorityTier,
		"priority_computed_at":               priorityComputedAt,
		"technical_driver_endpoint_id":       p.TechnicalDriverEndpointID,
		"technical_driver_endpoint_hostname": p.TechnicalDriverEndpointHostname,
		"technical_driver_risk_score":        p.TechnicalDriverRiskScore,
		"technical_driver_software_name":     p.TechnicalDriverSoftwareName,
		"technical_driver_cve_id":            p.TechnicalDriverCVEID,
		"priority_driver_endpoint_id":        p.PriorityDriverEndpointID,
		"priority_driver_endpoint_hostname":  p.PriorityDriverEndpointHostname,
		"priority_driver_priority_score":     p.PriorityDriverPriorityScore,
		"priority_driver_software_name":      p.PriorityDriverSoftwareName,
		"priority_driver_cve_id":             p.PriorityDriverCVEID,
		"risky_endpoint_count":               p.RiskyEndpointCount,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *projectRepo) Update(ctx context.Context, p *domain.Project) error {

	var riskComputedAt any
	if p.RiskComputedAt != nil {
		riskComputedAt = *p.RiskComputedAt
	}

	var priorityComputedAt any
	if p.PriorityComputedAt != nil {
		priorityComputedAt = *p.PriorityComputedAt
	}

	query := `
		MATCH (n:Project {id: $id})
		SET n.nombre = $name,
			n.risk_score = $risk_score,
			n.risk_tier = $risk_tier,
			n.risk_computed_at = $risk_computed_at,
			n.priority_score = $priority_score,
			n.priority_tier = $priority_tier,
			n.priority_computed_at = $priority_computed_at,
			n.technical_driver_endpoint_id = $technical_driver_endpoint_id,
			n.technical_driver_endpoint_hostname = $technical_driver_endpoint_hostname,
			n.technical_driver_risk_score = $technical_driver_risk_score,
			n.technical_driver_software_name = $technical_driver_software_name,
			n.technical_driver_cve_id = $technical_driver_cve_id,
			n.priority_driver_endpoint_id = $priority_driver_endpoint_id,
			n.priority_driver_endpoint_hostname = $priority_driver_endpoint_hostname,
			n.priority_driver_priority_score = $priority_driver_priority_score,
			n.priority_driver_software_name = $priority_driver_software_name,
			n.priority_driver_cve_id = $priority_driver_cve_id,
			n.risky_endpoint_count = $risky_endpoint_count
	`
	params := map[string]any{
		"id":                                 p.ProjectID,
		"name":                               p.Nombre,
		"risk_score":                         p.RiskScore,
		"risk_tier":                          p.RiskTier,
		"risk_computed_at":                   riskComputedAt,
		"priority_score":                     p.PriorityScore,
		"priority_tier":                      p.PriorityTier,
		"priority_computed_at":               priorityComputedAt,
		"technical_driver_endpoint_id":       p.TechnicalDriverEndpointID,
		"technical_driver_endpoint_hostname": p.TechnicalDriverEndpointHostname,
		"technical_driver_risk_score":        p.TechnicalDriverRiskScore,
		"technical_driver_software_name":     p.TechnicalDriverSoftwareName,
		"technical_driver_cve_id":            p.TechnicalDriverCVEID,
		"priority_driver_endpoint_id":        p.PriorityDriverEndpointID,
		"priority_driver_endpoint_hostname":  p.PriorityDriverEndpointHostname,
		"priority_driver_priority_score":     p.PriorityDriverPriorityScore,
		"priority_driver_software_name":      p.PriorityDriverSoftwareName,
		"priority_driver_cve_id":             p.PriorityDriverCVEID,
		"risky_endpoint_count":               p.RiskyEndpointCount,
	}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *projectRepo) RenameProject(ctx context.Context, id int64, newName string) error {
	query := `
		MATCH (p:Project)
		WHERE toString(p.id) = toString($id)
		SET p.name = $name, p.nombre = $name
	`
	params := map[string]any{
		"id":   id,
		"name": newName,
	}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *projectRepo) GetByID(ctx context.Context, id int64) (*domain.Project, error) {
	query := `MATCH (n:Project {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Project{
		ProjectID:                       getInt64(props, "id"),
		Nombre:                          getString(props, "nombre"),
		RiskScore:                       getFloat64(props, "risk_score"),
		RiskTier:                        getString(props, "risk_tier"),
		RiskComputedAt:                  getTimePtr(props, "risk_computed_at"),
		PriorityScore:                   getFloat64(props, "priority_score"),
		PriorityTier:                    getString(props, "priority_tier"),
		PriorityComputedAt:              getTimePtr(props, "priority_computed_at"),
		TechnicalDriverEndpointID:       getInt64(props, "technical_driver_endpoint_id"),
		TechnicalDriverEndpointHostname: getString(props, "technical_driver_endpoint_hostname"),
		TechnicalDriverRiskScore:        getFloat64(props, "technical_driver_risk_score"),
		TechnicalDriverSoftwareName:     getString(props, "technical_driver_software_name"),
		TechnicalDriverCVEID:            getString(props, "technical_driver_cve_id"),
		PriorityDriverEndpointID:        getInt64(props, "priority_driver_endpoint_id"),
		PriorityDriverEndpointHostname:  getString(props, "priority_driver_endpoint_hostname"),
		PriorityDriverPriorityScore:     getFloat64(props, "priority_driver_priority_score"),
		PriorityDriverSoftwareName:      getString(props, "priority_driver_software_name"),
		PriorityDriverCVEID:             getString(props, "priority_driver_cve_id"),
		RiskyEndpointCount:              int(getInt64(props, "risky_endpoint_count")),
	}, nil
}

func (r *projectRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `
		MATCH (p:Project)
		WHERE toString(p.id) = toString($id) OR elementId(p) = toString($id)
		OPTIONAL MATCH (p)-[:HAS_ENDPOINT]->(e:Endpoint)
		OPTIONAL MATCH (e)-[:CONNECTED_TO|HAS_HARDWARE|HOSTS|HAS_INSTALLATION|HAS_IP]->(sub1)
		OPTIONAL MATCH (sub1)-[:HAS_INSTALLATION|HAS_FINDING|USES_IMAGE|INSTANCE_OF]->(sub2)
		OPTIONAL MATCH (sub2)-[:HAS_FINDING|OF_VULNERABILITY|HAS_REMEDIATION|HAS_EXPLOIT]->(sub3)
		OPTIONAL MATCH (sub3)-[:HAS_REMEDIATION|HAS_EXPLOIT|HAS_PATCH]->(sub4)
		WHERE NOT (sub1:ThreatActor OR sub1:TTP) AND NOT (sub2:ThreatActor OR sub2:TTP) AND NOT (sub3:ThreatActor OR sub3:TTP) AND NOT (sub4:ThreatActor OR sub4:TTP)
		DETACH DELETE p, e, sub1, sub2, sub3, sub4
	`
	// El marco de gobierno cuelga del proyecto por [:BELONGS_TO], que no forma parte del
	// recorrido de la consulta anterior: sin esto, al borrar un proyecto sus políticas,
	// procedimientos, roles, actividades RACI y configuración de SLA quedaban huérfanos.
	//
	// Va ANTES de borrar el proyecto, y ese orden es la razón de que exista este bloque:
	// su MATCH parte del nodo Project, así que ejecutado después no encontraba nada y el
	// marco sobrevivía suelto en el grafo a cada borrado.
	//
	// Se borra solo lo que no pertenece a ningún OTRO proyecto. Desde que cada proyecto
	// tiene sus propios nodos eso ya no debería ocurrir, pero los grafos creados antes de
	// ese cambio sí pueden tener nodos compartidos, y borrarlos dejaría al otro proyecto
	// sin su marco normativo.
	governanceQuery := `
		MATCH (g)-[:BELONGS_TO]->(p:Project)
		WHERE (toString(p.id) = toString($id) OR elementId(p) = toString($id))
		  AND (g:PolicyDocument OR g:Procedure OR g:Role OR g:RACIActivity OR g:SLAConfig)
		  AND NOT EXISTS {
		      MATCH (g)-[:BELONGS_TO]->(otro:Project)
		      WHERE toString(otro.id) <> toString($id) AND elementId(otro) <> toString($id)
		  }
		DETACH DELETE g
	`
	_ = executeWriteHelper(ctx, r.driver, governanceQuery, map[string]any{"id": id})

	_ = executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})

	// Limpieza exhaustiva de cualquier nodo huérfano (redes sueltas, softwares, vulnerabilidades)
	cleanupQuery := `
		MATCH (n)
		WHERE (n:Software OR n:Network OR n:Hardware OR n:IPAddress OR n:SoftwareInstallation OR n:Finding OR n:Remediation OR n:Exploit OR n:Patch OR n:Container OR n:ContainerImage OR n:Vulnerability)
		  AND NOT EXISTS((n)-[*1..5]-(:Endpoint)) AND NOT EXISTS((n)-[*1..5]-(:Project))
		DETACH DELETE n
	`
	return executeWriteHelper(ctx, r.driver, cleanupQuery, nil)
}

// ExportGraph exporta todo el subgrafo de un proyecto, incluyendo IPs, de forma nativa.
func (r *projectRepo) ExportGraph(ctx context.Context, id int64) (*domain.GraphData, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Utilizamos apoc.path.subgraphAll con relationshipFilter para extraer todo el grafo conexo desde el Proyecto,
	// pero asegurando que NUNCA navega hacia atrás desde nodos compartidos (Vulnerabilities, TTPs, CWEs),
	// evitando así que se fusione con otros proyectos.
	//
	// El filtro incluye dos aristas del marco de gobierno:
	//   · <BELONGS_TO  recoge PolicyDocument, Procedure, Role, RACIActivity y SLAConfig, que
	//     cuelgan del proyecto en sentido entrante. Solo se recorre hacia dentro, así que
	//     desde un nodo de gobierno no se puede volver a salir a otro proyecto.
	//   · INVOLVES>    recoge la asignación RACI, que vive en la arista
	//     (:RACIActivity)-[:INVOLVES {role_type}]->(:Role). Sin ella se exportarían las
	//     actividades y los roles pero se perdería quién es R, A, C o I en cada una.
	//
	// HAS_CWE> y MAPS_TO> son las aristas que escribe realmente el pipeline de
	// TTPs (LinkTTPsToVulnerability). Antes el filtro solo listaba
	// EXPLOITS_VIA_TTP>, que nunca llegó a crearse, así que el mapeo de TTPs no
	// viajaba en el export.
	//
	// HAS_WEAKNESS> se conserva en el filtro aunque el pipeline ya no la escriba:
	// duplicaba a HAS_CWE y se eliminó (ver cmd/Pruebas/migrate_ttp_cve_scope).
	// Mantenerla listada permite seguir importando exports generados antes de esa
	// migración, y no tiene coste sobre un grafo donde ya no existe.
	//
	// <FIXES se recorre hacia atrás porque la arista va (:Patch)-[:FIXES]->(:Vulnerability):
	// desde la vulnerabilidad hay que ir en sentido contrario para alcanzar el parche.
	// Sin ella los nodos Patch no salían en el export y el informe no podía listarlos.
	// IMPORTANTE: FIXES> no debe incluirse; de lo contrario, al alcanzar un Patch que resuelve
	// múltiples CVEs globales, el recorrido saltaría hacia adelante incorporando al export
	// CVEs adicionales que no están presentes en los activos de este proyecto.
	// <APPLIED_TO permite alcanzar parches declarados sobre instalaciones o contenedores.
	query := `
		MATCH (p:Project)
		WHERE toString(p.id) = toString($id) OR elementId(p) = toString($id)
		CALL apoc.path.subgraphAll(p, {
			maxLevel: 10,
			relationshipFilter: "HAS_ENDPOINT>|CONTAINS_NETWORK>|HAS_IP>|HAS_HARDWARE>|CONNECTED_TO>|HAS_INSTALLATION>|INSTANCE_OF>|HOSTS>|USES_IMAGE>|HAS_FINDING>|OF_VULNERABILITY>|HAS_EXPLOIT>|HAS_REMEDIATION>|USES_PATCH>|HAS_CWE>|HAS_WEAKNESS>|MAPS_TO>|<FIXES|<APPLIED_TO|<MAPS_TO_CWE|<MAPS_TO_TTP|<USES|<BELONGS_TO|INVOLVES>"
		}) YIELD nodes, relationships
		
		WITH 
			[node IN nodes WHERE node IS NOT NULL | {id: elementId(node), labels: labels(node), properties: properties(node)}] AS exportedNodes,
			[rel IN relationships WHERE rel IS NOT NULL | {id: elementId(rel), type: type(rel), source: elementId(startNode(rel)), target: elementId(endNode(rel)), properties: properties(rel)}] AS exportedRels
			
		RETURN exportedNodes AS nodes, exportedRels AS relationships
	`
	params := map[string]any{"id": id}

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
	if res == nil {
		return &domain.GraphData{Nodes: []domain.GraphNode{}, Relationships: []domain.GraphRelationship{}}, nil
	}

	recordMap := res.(map[string]interface{})
	graphData := &domain.GraphData{
		Nodes:         []domain.GraphNode{},
		Relationships: []domain.GraphRelationship{},
	}

	// Parsear Nodos
	if nodesRaw, ok := recordMap["nodes"].([]interface{}); ok {
		for _, nodeRaw := range nodesRaw {
			if nodeMap, ok := nodeRaw.(map[string]interface{}); ok {
				id, _ := nodeMap["id"].(string)
				labelsRaw, _ := nodeMap["labels"].([]interface{})
				var labels []string
				for _, l := range labelsRaw {
					if str, ok := l.(string); ok {
						labels = append(labels, str)
					}
				}
				props, _ := nodeMap["properties"].(map[string]interface{})
				graphData.Nodes = append(graphData.Nodes, domain.GraphNode{
					ID:         id,
					Labels:     labels,
					Properties: props,
				})
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
