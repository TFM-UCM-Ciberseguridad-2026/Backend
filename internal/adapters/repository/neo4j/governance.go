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

// ProjectsWithoutFramework lista los proyectos sin marco de gobierno.
//
// Una consulta para todo el grafo en lugar de preguntar proyecto a proyecto: el barrido
// del arranque solo tiene que sembrar los que salgan de aquí, y en una base ya sembrada
// no devuelve ninguno.
func (r *governanceRepository) ProjectsWithoutFramework(ctx context.Context) ([]int64, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (p:Project)
		WHERE NOT EXISTS {
		        MATCH (n)-[:BELONGS_TO]->(p)
		        WHERE n:PolicyDocument OR n:Procedure OR n:Role OR n:RACIActivity
		      }
		RETURN p.id AS id
		ORDER BY id
	`

	res, err := session.Run(ctx, query, nil)
	if err != nil {
		return nil, err
	}

	ids := make([]int64, 0)
	for res.Next(ctx) {
		if id, ok := res.Record().Values[0].(int64); ok {
			ids = append(ids, id)
		}
	}
	return ids, res.Err()
}

// Policies
func (r *governanceRepository) SavePolicy(ctx context.Context, projectID int64, policy *domain.PolicyDocument) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	// El MERGE va sobre el patrón entero —nodo Y pertenencia— y no sobre el nodo suelto.
	// Con dos MERGE separados, el primero encontraba cualquier nodo del grafo con ese id y
	// el segundo le colgaba otra pertenencia: dos proyectos sembrados compartían literalmente
	// los mismos nodos, porque la semilla usa ids fijos (pol-1, role-1, act-1, proc-1), y
	// editar el marco de uno cambiaba el del otro.
	query := `
		MATCH (proj:Project {id: $projectID})
		MERGE (p:PolicyDocument {id: $id})-[:BELONGS_TO]->(proj)
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

	// El MERGE va sobre el patrón entero —nodo Y pertenencia— y no sobre el nodo suelto.
	// Con dos MERGE separados, el primero encontraba cualquier nodo del grafo con ese id y
	// el segundo le colgaba otra pertenencia: dos proyectos sembrados compartían literalmente
	// los mismos nodos, porque la semilla usa ids fijos (pol-1, role-1, act-1, proc-1), y
	// editar el marco de uno cambiaba el del otro.
	query := `
		MATCH (proj:Project {id: $projectID})
		MERGE (p:Procedure {id: $id})-[:BELONGS_TO]->(proj)
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

	// El MERGE va sobre el patrón entero —nodo Y pertenencia— y no sobre el nodo suelto.
	// Con dos MERGE separados, el primero encontraba cualquier nodo del grafo con ese id y
	// el segundo le colgaba otra pertenencia: dos proyectos sembrados compartían literalmente
	// los mismos nodos, porque la semilla usa ids fijos (pol-1, role-1, act-1, proc-1), y
	// editar el marco de uno cambiaba el del otro.
	query := `
		MATCH (proj:Project {id: $projectID})
		MERGE (role:Role {id: $id})-[:BELONGS_TO]->(proj)
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

	// La actividad y los roles se buscan dentro del proyecto: sin acotar, una actividad
	// podía acabar enlazada al rol homónimo de otro proyecto, o a varios a la vez.
	query := `
		MATCH (a:RACIActivity {id: $id})-[:BELONGS_TO]->(proj:Project {id: $projectID})
		SET a.name = $name, a.order = $order
		WITH a, proj
		OPTIONAL MATCH (a)-[r:INVOLVES]->()
		DELETE r
		WITH a, proj
		UNWIND $roles AS roleMapping
		MATCH (role:Role {id: roleMapping.role_id})-[:BELONGS_TO]->(proj)
		MERGE (a)-[newRel:INVOLVES]->(role)
		SET newRel.role_type = roleMapping.role_type
	`
	
	// If the node doesn't exist yet, we must create it first
	createIfNeededQuery := `
		MATCH (proj:Project {id: $projectID})
		MERGE (a:RACIActivity {id: $id})-[:BELONGS_TO]->(proj)
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
		"id":        activity.ID,
		"name":      activity.Name,
		"order":     activity.Order,
		"roles":     roleMappings,
		"projectID": projectID,
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

	// Se indexa por par (categoría, severidad) para poder detectar qué falta y completarlo
	// con los valores por defecto sin pisar lo que el usuario ya haya configurado.
	stored := make(map[string]domain.SLAConfig)
	var sinCategoria []domain.SLAConfig

	for res.Next(ctx) {
		node := res.Record().Values[0].(neo4j.Node)
		props := node.GetProperties()

		severity, _ := props["severity"].(string)
		days64, _ := props["days"].(int64)
		category, _ := props["category"].(string)

		conf := domain.SLAConfig{
			Category: domain.EndpointCategory(category),
			Severity: severity,
			Days:     int(days64),
		}

		if category == "" {
			// Configuración anterior a la separación por tipo de activo.
			sinCategoria = append(sinCategoria, conf)
			continue
		}
		stored[category+"|"+severity] = conf
	}

	// Los plazos configurados cuando el SLA era único se heredan como los de SERVIDOR, que
	// es la lectura conservadora: el compromiso antiguo se aplicaba a todo, así que
	// asignarlo al grupo exigente no relaja nada que ya estuviera comprometido. Los puestos
	// arrancan con los valores por defecto, más laxos.
	for _, legacy := range sinCategoria {
		key := string(domain.CategoryServer) + "|" + legacy.Severity
		if _, ok := stored[key]; !ok {
			legacy.Category = domain.CategoryServer
			stored[key] = legacy
		}
	}

	// Completar los huecos con la política por defecto del dominio, para que la respuesta
	// siempre traiga la matriz entera y la pantalla no tenga que inventar valores.
	configs := make([]domain.SLAConfig, 0, 8)
	for _, def := range domain.DefaultSLAConfigs() {
		if conf, ok := stored[string(def.Category)+"|"+def.Severity]; ok && conf.Days > 0 {
			configs = append(configs, conf)
			continue
		}
		configs = append(configs, def)
	}

	return configs, nil
}

func (r *governanceRepository) SaveSLAConfigs(ctx context.Context, projectID int64, configs []domain.SLAConfig) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		// Los nodos antiguos no tienen `category` y su clave MERGE era solo la severidad. Se
		// eliminan antes de escribir para que no queden duplicados compitiendo con los
		// nuevos: sus valores ya se heredaron al leer (ver GetSLAConfigs).
		if _, err := tx.Run(ctx, `
			MATCH (s:SLAConfig)-[:BELONGS_TO]->(:Project {id: $projectID})
			WHERE s.category IS NULL OR s.category = ''
			DETACH DELETE s
		`, map[string]interface{}{"projectID": projectID}); err != nil {
			return nil, err
		}

		for _, conf := range configs {
			query := `
				MATCH (proj:Project {id: $projectID})
				MERGE (s:SLAConfig {severity: $severity, category: $category})-[:BELONGS_TO]->(proj)
				SET s.days = $days
			`
			_, err := tx.Run(ctx, query, map[string]interface{}{
				"severity":  conf.Severity,
				"category":  string(conf.Category),
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

	// Vulnerabilidades activas de este proyecto, agrupadas por CVE Y por categoría del
	// activo afectado: el plazo depende de dónde está la vulnerabilidad, así que la misma
	// CVE presente en un servidor y en un puesto son dos compromisos distintos y se
	// devuelven como dos filas.
	//
	// Una CVE ya parcheada no tiene plazo que incumplir, así que los hallazgos cerrados
	// quedan fuera con el mismo criterio que usan la cola de parcheo y el motor de riesgo.
	// Las MITIGADAS sí siguen contando: una mitigación temporal o un workaround dejan el
	// software vulnerable instalado y el reloj del SLA tiene que seguir corriendo.
	//
	// La fecha de detección de cada grupo es la MÁS ANTIGUA de sus hallazgos: el reloj del
	// SLA empieza a contar la primera vez que se supo, no la última.
	query := `
		MATCH (:Project {id: $projectID})-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_INSTALLATION]->(s:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED']
		WITH v, coalesce(e.category, '') AS category, e,
		     coalesce(v.first_detected_at, timestamp()) AS detected
		RETURN v.cve_id           AS cve_id,
		       v.base_score       AS base_score,
		       category           AS category,
		       min(detected)      AS first_detected_at,
		       count(DISTINCT e)  AS asset_count
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

		cveID, _ := rec.Values[0].(string)
		category, _ := rec.Values[2].(string)
		detected, _ := rec.Values[3].(int64)
		assetCount, _ := rec.Values[4].(int64)

		breaches = append(breaches, domain.SLABreach{
			CVEID:           cveID,
			BaseScore:       baseScore,
			Category:        domain.EndpointCategory(category),
			FirstDetectedAt: detected,
			AssetCount:      int(assetCount),
		})
	}
	return breaches, nil
}
