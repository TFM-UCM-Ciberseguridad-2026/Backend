package neo4j

import (
	"context"
	"fmt"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type findingRepo struct {
	driver neo4j.DriverWithContext
}

func (r *findingRepo) Save(ctx context.Context, f *domain.Finding) error {
	query := `
		MERGE (n:Finding {id: $id})
		ON CREATE SET n.status = $status,
		    n.first_seen = $first_seen,
		    n.last_seen = $last_seen,
		    n.resolved_at = $resolved_at,
		    n.impact_score = $impact_score,
		    n.likelihood = $likelihood,
			n.exposure_factor = $exposure_factor,
		    n.remediation_factor = $remediation_factor,
		    n.risk_score = $risk_score,
			n.asset_criticality = $asset_criticality,
			n.urgency_boost = $urgency_boost,
		    n.priority_score = $priority_score,
		    n.risk_computed_at = $risk_computed_at
	`

	var lastSeen, resolvedAt, riskComputedAt any
	if f.LastSeen != nil {
		lastSeen = *f.LastSeen
	}
	if f.ResolvedAt != nil {
		resolvedAt = *f.ResolvedAt
	}
	if f.RiskComputedAt != nil {
		riskComputedAt = *f.RiskComputedAt
	}

	params := map[string]any{
		"id":                 f.FindingID,
		"status":             f.Status,
		"first_seen":         f.FirstSeen,
		"last_seen":          lastSeen,
		"resolved_at":        resolvedAt,
		"impact_score":       f.ImpactScore,
		"likelihood":         f.Likelihood,
		"exposure_factor":    f.ExposureFactor,
		"remediation_factor": f.RemediationFactor,
		"risk_score":         f.RiskScore,
		"asset_criticality":  f.AssetCriticality,
		"urgency_boost":      f.UrgencyBoost,
		"priority_score":     f.PriorityScore,
		"risk_computed_at":   riskComputedAt,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *findingRepo) Update(ctx context.Context, f *domain.Finding) error {
	query := `
		MATCH (n:Finding {id: $id})
		SET n.status = $status,
		    n.first_seen = $first_seen,
		    n.last_seen = $last_seen,
		    n.resolved_at = $resolved_at,
		    n.impact_score = $impact_score,
		    n.likelihood = $likelihood,
			n.exposure_factor = $exposure_factor,
		    n.remediation_factor = $remediation_factor,
		    n.risk_score = $risk_score,
			n.asset_criticality = $asset_criticality,
			n.urgency_boost = $urgency_boost,
		    n.priority_score = $priority_score,
		    n.risk_computed_at = $risk_computed_at
	`

	var lastSeen, resolvedAt, riskComputedAt any
	if f.LastSeen != nil {
		lastSeen = *f.LastSeen
	}
	if f.ResolvedAt != nil {
		resolvedAt = *f.ResolvedAt
	}
	if f.RiskComputedAt != nil {
		riskComputedAt = *f.RiskComputedAt
	}

	params := map[string]any{
		"id":                 f.FindingID,
		"status":             f.Status,
		"first_seen":         f.FirstSeen,
		"last_seen":          lastSeen,
		"resolved_at":        resolvedAt,
		"impact_score":       f.ImpactScore,
		"likelihood":         f.Likelihood,
		"exposure_factor":    f.ExposureFactor,
		"remediation_factor": f.RemediationFactor,
		"risk_score":         f.RiskScore,
		"asset_criticality":  f.AssetCriticality,
		"urgency_boost":      f.UrgencyBoost,
		"priority_score":     f.PriorityScore,
		"risk_computed_at":   riskComputedAt,
	}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *findingRepo) GetByID(ctx context.Context, id int64) (*domain.Finding, error) {
	query := `MATCH (n:Finding {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Finding{
		FindingID:         getInt64(props, "id"),
		Status:            getString(props, "status"),
		FirstSeen:         getTime(props, "first_seen"),
		LastSeen:          getTimePtr(props, "last_seen"),
		ResolvedAt:        getTimePtr(props, "resolved_at"),
		ImpactScore:       getFloat64(props, "impact_score"),
		Likelihood:        getFloat64(props, "likelihood"),
		ExposureFactor:    getFloat64(props, "exposure_factor"),
		RemediationFactor: getFloat64(props, "remediation_factor"),
		RiskScore:         getFloat64(props, "risk_score"),
		AssetCriticality:  getFloat64(props, "asset_criticality"),
		UrgencyBoost:      getFloat64(props, "urgency_boost"),
		PriorityScore:     getFloat64(props, "priority_score"),
		RiskComputedAt:    getTimePtr(props, "risk_computed_at"),
	}, nil
}

func (r *findingRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Finding {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}

// EnsureForInstallationAndCVE ensures that a finding exists for the given installation and CVE.
// If the finding does not exist, it will be created with the provided details.
// If the finding already exists, its last_seen timestamp will be updated to the current time.
// The function returns the finding, a boolean indicating whether it was created (true) or already existed (false), and an error if any occurred.
func (r *findingRepo) EnsureForInstallationAndCVE(ctx context.Context, installationID string, cveID string, f *domain.Finding) (*domain.Finding, bool, error) {
	now := time.Now().UTC()
	findingKey := installationID + "|" + cveID

	query := `
		MATCH (si:SoftwareInstallation {id: $installation_id})
		MATCH (v:Vulnerability {cve_id: $cve_id})
		MERGE (n:Finding {finding_key: $finding_key})
		ON CREATE SET
			n.id = $id,
			n.status = $status,
			n.first_seen = $first_seen,
			n.last_seen = $last_seen,
			n.resolved_at = $resolved_at,
			n.impact_score = $impact_score,
			n.likelihood = $likelihood,
			n.exposure_factor = $exposure_factor,
			n.remediation_factor = $remediation_factor,
			n.risk_score = $risk_score,
			n.asset_criticality = $asset_criticality,
			n.urgency_boost = $urgency_boost,
			n.priority_score = $priority_score,
			n.risk_computed_at = $risk_computed_at,
			n._ensure_created = true
		ON MATCH SET
			n.last_seen = $now,
			n._ensure_created = false
		MERGE (si)-[:HAS_FINDING]->(n)
		MERGE (n)-[:OF_VULNERABILITY]->(v)
		WITH n, n._ensure_created AS created
		REMOVE n._ensure_created
		RETURN properties(n) AS props, created
	`

	var lastSeen, resolvedAt, riskComputedAt any
	if f.LastSeen != nil {
		lastSeen = *f.LastSeen
	}
	if f.ResolvedAt != nil {
		resolvedAt = *f.ResolvedAt
	}
	if f.RiskComputedAt != nil {
		riskComputedAt = *f.RiskComputedAt
	}

	params := map[string]any{
		"installation_id":    installationID,
		"cve_id":             cveID,
		"finding_key":        findingKey,
		"id":                 f.FindingID,
		"status":             f.Status,
		"first_seen":         f.FirstSeen,
		"last_seen":          lastSeen,
		"resolved_at":        resolvedAt,
		"impact_score":       f.ImpactScore,
		"likelihood":         f.Likelihood,
		"exposure_factor":    f.ExposureFactor,
		"remediation_factor": f.RemediationFactor,
		"risk_score":         f.RiskScore,
		"asset_criticality":  f.AssetCriticality,
		"urgency_boost":      f.UrgencyBoost,
		"priority_score":     f.PriorityScore,
		"risk_computed_at":   riskComputedAt,
		"now":                now,
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	res, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}

		rec := result.Record()
		propsRaw, _ := rec.Get("props")
		createdRaw, _ := rec.Get("created")

		props, ok := propsRaw.(map[string]any)
		if !ok {
			return nil, domain.ErrNodeNotFound
		}

		created := false
		if value, ok := createdRaw.(bool); ok {
			created = value
		}

		finding := &domain.Finding{
			FindingID:         getInt64(props, "id"),
			Status:            getString(props, "status"),
			FirstSeen:         getTime(props, "first_seen"),
			LastSeen:          getTimePtr(props, "last_seen"),
			ResolvedAt:        getTimePtr(props, "resolved_at"),
			ImpactScore:       getFloat64(props, "impact_score"),
			Likelihood:        getFloat64(props, "likelihood"),
			ExposureFactor:    getFloat64(props, "exposure_factor"),
			RemediationFactor: getFloat64(props, "remediation_factor"),
			RiskScore:         getFloat64(props, "risk_score"),
			AssetCriticality:  getFloat64(props, "asset_criticality"),
			UrgencyBoost:      getFloat64(props, "urgency_boost"),
			PriorityScore:     getFloat64(props, "priority_score"),
			RiskComputedAt:    getTimePtr(props, "risk_computed_at"),
		}

		return struct {
			finding *domain.Finding
			created bool
		}{finding: finding, created: created}, result.Err()
	})

	if err != nil {
		return nil, false, err
	}
	if res == nil {
		return nil, false, domain.ErrNodeNotFound
	}

	out := res.(struct {
		finding *domain.Finding
		created bool
	})
	return out.finding, out.created, nil
}

// ApplyRemediationByInstallationAndCVE fija el factor de remediación y el estado de los
// findings abiertos de una instalación que apuntan al CVE indicado.
//
// Cuando el factor es 0 (parche oficial) pone además risk_score y priority_score a cero:
// el finding sale de las agregaciones, y sin esta limpieza conservaría indefinidamente la
// última puntuación calculada, que se seguiría mostrando en la API y en el front.
func (r *findingRepo) ApplyRemediationByInstallationAndCVE(ctx context.Context, installationID, cveID string, remediationFactor float64, status string) ([]int64, error) {
	query := `
		MATCH (:SoftwareInstallation {id: $installation_id})-[:HAS_FINDING]->(f:Finding)
		      -[:OF_VULNERABILITY]->(:Vulnerability {cve_id: $cve_id})
		SET f.remediation_factor = $remediation_factor,
		    f.status             = $status,
		    f.last_seen          = $now
		FOREACH (_ IN CASE WHEN $remediation_factor = 0.0 THEN [1] ELSE [] END |
		    SET f.risk_score     = 0.0,
		        f.priority_score = 0.0,
		        f.resolved_at    = $now
		)
		RETURN f.id AS finding_id
	`

	params := map[string]any{
		"installation_id":    installationID,
		"cve_id":             cveID,
		"remediation_factor": remediationFactor,
		"status":             status,
		"now":                time.Now().UTC(),
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	res, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		ids := make([]int64, 0)
		for result.Next(ctx) {
			id, _ := result.Record().Get("finding_id")
			ids = append(ids, toInt64(id))
		}
		return ids, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []int64{}, nil
	}
	return res.([]int64), nil
}

func (r *findingRepo) GetVulnerabilitiesByFinding(ctx context.Context, findingID any) ([]domain.Vulnerability, error) {
	query := `
		MATCH (f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE f.id = $finding_id OR elementId(f) = toString($finding_id) OR toString(f.id) = toString($finding_id)
		OPTIONAL MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE) WHERE (v)-[:HAS_CWE]->(w) OR w.cwe_id IN v.cwe
		OPTIONAL MATCH (c)-[:MAPS_TO_TTP]->(t:TTP)
		WITH v, collect(DISTINCT {
			ttp_id: t.ttp_id,
			name: coalesce(t.name, ''),
			tactic: coalesce(t.tactic, ''),
			description: coalesce(t.description, '')
		}) AS rawTTPs
		RETURN properties(v) AS props, [x IN rawTTPs WHERE x.ttp_id IS NOT NULL] AS ttps
		ORDER BY v.base_score DESC
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"finding_id": findingID})
		if err != nil {
			return nil, err
		}

		vulns := make([]domain.Vulnerability, 0)
		for result.Next(ctx) {
			rec := result.Record()
			propsRaw, _ := rec.Get("props")
			props, ok := propsRaw.(map[string]any)
			if !ok {
				continue
			}

			var ttpsList []domain.TTP
			if ttpsRaw, ok := rec.Get("ttps"); ok && ttpsRaw != nil {
				if items, ok := ttpsRaw.([]any); ok {
					for _, item := range items {
						if m, ok := item.(map[string]any); ok {
							ttpsList = append(ttpsList, domain.TTP{
								TTPID:       getString(m, "ttp_id"),
								Name:        getString(m, "name"),
								Tactic:      getString(m, "tactic"),
								Description: getString(m, "description"),
							})
						}
					}
				}
			}

			vulns = append(vulns, domain.Vulnerability{
				CVEID:       getString(props, "cve_id"),
				Description: getString(props, "description"),
				BaseScore:   getFloat64(props, "base_score"),
				CVSSVector:  getString(props, "cvss_vector"),
				NVDVector:   getString(props, "nvd_vector"),
				CWE:         getStringSlice(props, "cwe"),
				CPE:         getString(props, "cpe"),
				TTPs:        ttpsList,
				Exploit:     getBool(props, "exploit"),
				KEV:         getBool(props, "kev"),
				EPSSScore:   getFloat64(props, "epss_score"),
			})
		}
		return vulns, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.Vulnerability{}, nil
	}
	return res.([]domain.Vulnerability), nil
}

// EnsureForContainerImageAndCVE ensures that a finding exists for the given ContainerImage and CVE.
func (r *findingRepo) EnsureForContainerImageAndCVE(ctx context.Context, imageID string, cveID string, f *domain.Finding) (*domain.Finding, bool, error) {
	now := time.Now().UTC()
	findingKey := imageID + "|" + cveID

	query := `
		MATCH (ci:ContainerImage {id: $image_id})
		MATCH (v:Vulnerability {cve_id: $cve_id})
		MERGE (n:Finding {finding_key: $finding_key})
		ON CREATE SET
			n.id = $id,
			n.status = $status,
			n.first_seen = $first_seen,
			n.last_seen = $last_seen,
			n.resolved_at = $resolved_at,
			n.impact_score = $impact_score,
			n.likelihood = $likelihood,
			n.exposure_factor = $exposure_factor,
			n.remediation_factor = $remediation_factor,
			n.risk_score = $risk_score,
			n.asset_criticality = $asset_criticality,
			n.urgency_boost = $urgency_boost,
			n.priority_score = $priority_score,
			n.risk_computed_at = $risk_computed_at,
			n._ensure_created = true
		ON MATCH SET
			n.last_seen = $now,
			n._ensure_created = false
		MERGE (ci)-[:HAS_FINDING]->(n)
		MERGE (n)-[:OF_VULNERABILITY]->(v)
		WITH n, n._ensure_created AS created
		REMOVE n._ensure_created
		RETURN properties(n) AS props, created
	`

	var lastSeen, resolvedAt, riskComputedAt any
	if f.LastSeen != nil {
		lastSeen = *f.LastSeen
	}
	if f.ResolvedAt != nil {
		resolvedAt = *f.ResolvedAt
	}
	if f.RiskComputedAt != nil {
		riskComputedAt = *f.RiskComputedAt
	}

	params := map[string]any{
		"image_id":           imageID,
		"cve_id":             cveID,
		"finding_key":        findingKey,
		"id":                 f.FindingID,
		"status":             f.Status,
		"first_seen":         f.FirstSeen,
		"last_seen":          lastSeen,
		"resolved_at":        resolvedAt,
		"impact_score":       f.ImpactScore,
		"likelihood":         f.Likelihood,
		"exposure_factor":    f.ExposureFactor,
		"remediation_factor": f.RemediationFactor,
		"risk_score":         f.RiskScore,
		"asset_criticality":  f.AssetCriticality,
		"urgency_boost":      f.UrgencyBoost,
		"priority_score":     f.PriorityScore,
		"risk_computed_at":   riskComputedAt,
		"now":                now,
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			record := res.Record()
			props, _ := record.Get("props")
			created, _ := record.Get("created")
			return map[string]any{
				"props":   props,
				"created": created,
			}, nil
		}
		return nil, fmt.Errorf("no se pudo asegurar/crear el finding")
	})

	if err != nil {
		return nil, false, err
	}

	resMap := result.(map[string]any)
	props := resMap["props"].(map[string]any)
	created := resMap["created"].(bool)

	return &domain.Finding{
		FindingID:         getInt64(props, "id"),
		Status:            getString(props, "status"),
		FirstSeen:         getTime(props, "first_seen"),
		LastSeen:          getTimePtr(props, "last_seen"),
		ResolvedAt:        getTimePtr(props, "resolved_at"),
		ImpactScore:       getFloat64(props, "impact_score"),
		Likelihood:        getFloat64(props, "likelihood"),
		ExposureFactor:    getFloat64(props, "exposure_factor"),
		RemediationFactor: getFloat64(props, "remediation_factor"),
		RiskScore:         getFloat64(props, "risk_score"),
		AssetCriticality:  getFloat64(props, "asset_criticality"),
		UrgencyBoost:      getFloat64(props, "urgency_boost"),
		PriorityScore:     getFloat64(props, "priority_score"),
		RiskComputedAt:    getTimePtr(props, "risk_computed_at"),
	}, created, nil
}
