package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type governanceRepository struct {
	driver neo4j.DriverWithContext
}

func NewGovernanceRepository(driver neo4j.DriverWithContext) ports.GovernanceRepository {
	return &governanceRepository{driver: driver}
}

func (r *governanceRepository) IsSeeded(ctx context.Context, projectID int64) (bool, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (n)-[:BELONGS_TO]->(:Project {id: $projectID}) 
		WHERE n:PolicyDocument OR n:Procedure OR n:Role OR n:RACIActivity
		RETURN count(n) AS cnt
	`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return false, err
	}

	if res.Next(ctx) {
		cnt := res.Record().Values[0].(int64)
		return cnt > 0, nil
	}
	return false, res.Err()
}

// Policies
func (r *governanceRepository) SavePolicy(ctx context.Context, projectID int64, policy *domain.PolicyDocument) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MATCH (proj:Project {id: $projectID})
		MERGE (p:PolicyDocument {id: $id})
		MERGE (p)-[:BELONGS_TO]->(proj)
		SET p.name = $name,
		    p.version = $version,
		    p.status = $status,
		    p.status_label = $status_label,
		    p.owner = $owner,
		    p.next_review_date = $next_review_date,
		    p.document_url = $document_url,
		    p.under_review = $under_review
	`
	params := map[string]interface{}{
		"id":               policy.ID,
		"name":             policy.Name,
		"version":          policy.Version,
		"status":           policy.Status,
		"status_label":     policy.StatusLabel,
		"owner":            policy.Owner,
		"next_review_date": policy.NextReviewDate,
		"document_url":     policy.DocumentURL,
		"under_review":     policy.UnderReview,
		"projectID":        projectID,
	}

	_, err := session.Run(ctx, query, params)
	return err
}

func (r *governanceRepository) GetPolicies(ctx context.Context, projectID int64) ([]domain.PolicyDocument, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (p:PolicyDocument)-[:BELONGS_TO]->(:Project {id: $projectID}) RETURN p`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return nil, err
	}

	var policies []domain.PolicyDocument
	for res.Next(ctx) {
		node := res.Record().Values[0].(neo4j.Node)
		props := node.GetProperties()
		
		underReview := false
		if val, ok := props["under_review"].(bool); ok {
			underReview = val
		}

		var id, name, version, status, statusLabel, owner, nextReviewDate, docURL string
		if val, ok := props["id"].(string); ok { id = val }
		if val, ok := props["name"].(string); ok { name = val }
		if val, ok := props["version"].(string); ok { version = val }
		if val, ok := props["status"].(string); ok { status = val }
		if val, ok := props["status_label"].(string); ok { statusLabel = val }
		if val, ok := props["owner"].(string); ok { owner = val }
		if val, ok := props["next_review_date"].(string); ok { nextReviewDate = val }
		if val, ok := props["document_url"].(string); ok { docURL = val }

		policies = append(policies, domain.PolicyDocument{
			ID:             id,
			Name:           name,
			Version:        version,
			Status:         status,
			StatusLabel:    statusLabel,
			Owner:          owner,
			NextReviewDate: nextReviewDate,
			DocumentURL:    docURL,
			UnderReview:    underReview,
		})
	}
	return policies, nil
}

func (r *governanceRepository) DeletePolicy(ctx context.Context, projectID int64, id string) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `MATCH (p:PolicyDocument {id: $id})-[:BELONGS_TO]->(:Project {id: $projectID}) DETACH DELETE p`
	_, err := session.Run(ctx, query, map[string]interface{}{"id": id, "projectID": projectID})
	return err
}

// Procedures
func (r *governanceRepository) SaveProcedure(ctx context.Context, projectID int64, procedure *domain.Procedure) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MATCH (proj:Project {id: $projectID})
		MERGE (p:Procedure {id: $id})
		MERGE (p)-[:BELONGS_TO]->(proj)
		SET p.name = $name,
		    p.meta = $meta,
		    p.steps = $steps
	`
	params := map[string]interface{}{
		"id":        procedure.ID,
		"name":      procedure.Name,
		"meta":      procedure.Meta,
		"steps":     procedure.Steps,
		"projectID": projectID,
	}

	_, err := session.Run(ctx, query, params)
	return err
}

func (r *governanceRepository) GetProcedures(ctx context.Context, projectID int64) ([]domain.Procedure, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (p:Procedure)-[:BELONGS_TO]->(:Project {id: $projectID}) RETURN p ORDER BY p.id ASC`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return nil, err
	}

	var procedures []domain.Procedure
	for res.Next(ctx) {
		node := res.Record().Values[0].(neo4j.Node)
		props := node.GetProperties()
		
		var steps []string
		if stepsInterface, ok := props["steps"].([]interface{}); ok {
			for _, s := range stepsInterface {
				steps = append(steps, s.(string))
			}
		}

		procedures = append(procedures, domain.Procedure{
			ID:    props["id"].(string),
			Name:  props["name"].(string),
			Meta:  props["meta"].(string),
			Steps: steps,
		})
	}
	return procedures, nil
}

func (r *governanceRepository) DeleteProcedure(ctx context.Context, projectID int64, id string) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `MATCH (p:Procedure {id: $id})-[:BELONGS_TO]->(:Project {id: $projectID}) DETACH DELETE p`
	_, err := session.Run(ctx, query, map[string]interface{}{"id": id, "projectID": projectID})
	return err
}

// Roles
func (r *governanceRepository) SaveRole(ctx context.Context, projectID int64, role *domain.Role) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MATCH (proj:Project {id: $projectID})
		MERGE (role:Role {id: $id})
		MERGE (role)-[:BELONGS_TO]->(proj)
		SET role.name = $name,
		    role.contact = $contact
	`
	_, err := session.Run(ctx, query, map[string]interface{}{
		"id":        role.ID,
		"name":      role.Name,
		"contact":   role.Contact,
		"projectID": projectID,
	})
	return err
}

func (r *governanceRepository) GetRoles(ctx context.Context, projectID int64) ([]domain.Role, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (role:Role)-[:BELONGS_TO]->(:Project {id: $projectID}) RETURN role ORDER BY role.id ASC`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return nil, err
	}

	var roles []domain.Role
	for res.Next(ctx) {
		node := res.Record().Values[0].(neo4j.Node)
		props := node.GetProperties()
		
		contact := ""
		if val, ok := props["contact"].(string); ok {
			contact = val
		}

		roles = append(roles, domain.Role{
			ID:      props["id"].(string),
			Name:    props["name"].(string),
			Contact: contact,
		})
	}
	return roles, nil
}

func (r *governanceRepository) DeleteRole(ctx context.Context, projectID int64, id string) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `MATCH (role:Role {id: $id})-[:BELONGS_TO]->(:Project {id: $projectID}) DETACH DELETE role`
	_, err := session.Run(ctx, query, map[string]interface{}{"id": id, "projectID": projectID})
	return err
}

// RACI Activities
func (r *governanceRepository) SaveRACIActivity(ctx context.Context, projectID int64, activity *domain.RACIActivity) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	// Transform the roles map to a slice of maps for UNWIND
	var roleMappings []map[string]interface{}
	for roleID, roleType := range activity.Roles {
		if roleType != "" { // Only save non-empty RACI roles
			roleMappings = append(roleMappings, map[string]interface{}{
				"role_id":   roleID,
				"role_type": roleType,
			})
		}
	}

	query := `
		MATCH (a:RACIActivity {id: $id})
		SET a.name = $name, a.order = $order
		WITH a
		OPTIONAL MATCH (a)-[r:INVOLVES]->()
		DELETE r
		WITH a
		UNWIND $roles AS roleMapping
		MATCH (role:Role {id: roleMapping.role_id})
		MERGE (a)-[newRel:INVOLVES]->(role)
		SET newRel.role_type = roleMapping.role_type
	`
	
	// If the node doesn't exist yet, we must create it first
	createIfNeededQuery := `
		MATCH (proj:Project {id: $projectID})
		MERGE (a:RACIActivity {id: $id})
		MERGE (a)-[:BELONGS_TO]->(proj)
		SET a.name = $name, a.order = $order
	`
	_, err := session.Run(ctx, createIfNeededQuery, map[string]interface{}{
		"id":        activity.ID,
		"name":      activity.Name,
		"order":     activity.Order,
		"projectID": projectID,
	})
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		"id":    activity.ID,
		"name":  activity.Name,
		"order": activity.Order,
		"roles": roleMappings,
	}

	_, err = session.Run(ctx, query, params)
	return err
}

func (r *governanceRepository) GetRACIActivities(ctx context.Context, projectID int64) ([]domain.RACIActivity, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (a:RACIActivity)-[:BELONGS_TO]->(:Project {id: $projectID})
		OPTIONAL MATCH (a)-[r:INVOLVES]->(role:Role)
		RETURN a, collect({role_id: role.id, role_type: r.role_type}) AS roles
		ORDER BY a.order ASC
	`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return nil, err
	}

	var activities []domain.RACIActivity
	for res.Next(ctx) {
		record := res.Record()
		node := record.Values[0].(neo4j.Node)
		props := node.GetProperties()
		
		rolesList := record.Values[1].([]interface{})
		rolesMap := make(map[string]string)
		
		for _, v := range rolesList {
			m := v.(map[string]interface{})
			if roleID, ok := m["role_id"]; ok && roleID != nil {
				roleType := m["role_type"].(string)
				rolesMap[roleID.(string)] = roleType
			}
		}

		activities = append(activities, domain.RACIActivity{
			ID:    props["id"].(string),
			Name:  props["name"].(string),
			Order: int(props["order"].(int64)),
			Roles: rolesMap,
		})
	}
	return activities, nil
}

func (r *governanceRepository) DeleteRACIActivity(ctx context.Context, projectID int64, id string) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `MATCH (a:RACIActivity {id: $id})-[:BELONGS_TO]->(:Project {id: $projectID}) DETACH DELETE a`
	_, err := session.Run(ctx, query, map[string]interface{}{"id": id, "projectID": projectID})
	return err
}

func (r *governanceRepository) GetSLAConfigs(ctx context.Context, projectID int64) ([]domain.SLAConfig, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (s:SLAConfig)-[:BELONGS_TO]->(:Project {id: $projectID}) RETURN s`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return nil, err
	}

	var configs []domain.SLAConfig
	for res.Next(ctx) {
		node := res.Record().Values[0].(neo4j.Node)
		props := node.GetProperties()
		configs = append(configs, domain.SLAConfig{
			Severity: props["severity"].(string),
			Days:     int(props["days"].(int64)),
		})
	}
	
	if len(configs) == 0 {
		return []domain.SLAConfig{
			{Severity: "Critical", Days: 15},
			{Severity: "High", Days: 30},
			{Severity: "Medium", Days: 60},
			{Severity: "Low", Days: 90},
		}, nil
	}
	
	return configs, nil
}

func (r *governanceRepository) SaveSLAConfigs(ctx context.Context, projectID int64, configs []domain.SLAConfig) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		for _, conf := range configs {
			query := `
				MATCH (proj:Project {id: $projectID})
				MERGE (s:SLAConfig {severity: $severity})-[:BELONGS_TO]->(proj)
				SET s.days = $days
			`
			_, err := tx.Run(ctx, query, map[string]interface{}{
				"severity":  conf.Severity,
				"days":      conf.Days,
				"projectID": projectID,
			})
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (r *governanceRepository) GetSLABreaches(ctx context.Context, projectID int64) ([]domain.SLABreach, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	// Obtener vulnerabilidades activas (asociadas a hallazgos OPEN de este proyecto en concreto)
	query := `
		MATCH (:Project {id: $projectID})-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(s:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding {status: 'OPEN'})-[:OF_VULNERABILITY]->(v:Vulnerability)
		RETURN DISTINCT v.cve_id, v.base_score, coalesce(v.first_detected_at, timestamp())
	`
	res, err := session.Run(ctx, query, map[string]interface{}{"projectID": projectID})
	if err != nil {
		return nil, err
	}

	var breaches []domain.SLABreach
	for res.Next(ctx) {
		rec := res.Record()
		
		var baseScore float64
		switch v := rec.Values[1].(type) {
		case float64:
			baseScore = v
		case int64:
			baseScore = float64(v)
		}

		breaches = append(breaches, domain.SLABreach{
			CVEID:           rec.Values[0].(string),
			BaseScore:       baseScore,
			FirstDetectedAt: rec.Values[2].(int64),
		})
	}
	return breaches, nil
}
