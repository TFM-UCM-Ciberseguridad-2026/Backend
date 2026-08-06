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

