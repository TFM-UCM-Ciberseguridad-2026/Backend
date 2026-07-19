package neo4j

import (
	"context"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type riskRepo struct {
	driver neo4j.DriverWithContext
}

func NewRiskRepository(driver neo4j.DriverWithContext) ports.RiskPort {
	return &riskRepo{driver: driver}
}

// Devuelve el contexto completo de cada finding abierto para calcular su riesgo.
func (r *riskRepo) GetFindingContextsByEndpoint(ctx context.Context, endpointID int64) ([]domain.FindingRiskContext, error) {
	query := `
		MATCH (e:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		      -[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE f.status <> 'RESOLVED'
		OPTIONAL MATCH (f)-[:HAS_REMEDIATION]->(rem:Remediation)-[:USES_PATCH]->(p:Patch)
		RETURN
		    f.id                    AS finding_id,
		    f.status                AS finding_status,
		    f.remediation_factor    AS remediation_factor,
		    f.exposure_factor       AS exposure_factor,
		    p IS NOT NULL           AS has_patch,
		    v.cve_id                AS cve_id,
		    v.cvss_vector           AS cvss_vector,
		    v.base_score            AS cached_base_score,
		    v.epss_score            AS cached_epss,
		    v.kev                   AS cached_kev,
		    v.exploit               AS has_exploit,
			e.internet_exposed      AS internet_exposed,
			e.environment            AS environment,
		    e.confidentiality_req   AS cr,
		    e.integrity_req         AS ir,
		    e.availability_req      AS ar
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}

		var contexts []domain.FindingRiskContext
		for result.Next(ctx) {
			rec := result.Record()

			findingID, _ := rec.Get("finding_id")
			findingStatus, _ := rec.Get("finding_status")
			remFactor, _ := rec.Get("remediation_factor")
			hasPatch, _ := rec.Get("has_patch")
			cveID, _ := rec.Get("cve_id")
			cvssVec, _ := rec.Get("cvss_vector")
			baseScore, _ := rec.Get("cached_base_score")
			epss, _ := rec.Get("cached_epss")
			kev, _ := rec.Get("cached_kev")
			exploit, _ := rec.Get("has_exploit")
			internetExposed, _ := rec.Get("internet_exposed")
			environment, _ := rec.Get("environment")
			cr, _ := rec.Get("cr")
			ir, _ := rec.Get("ir")
			ar, _ := rec.Get("ar")

			contexts = append(contexts, domain.FindingRiskContext{
				FindingID:          toInt64(findingID),
				FindingStatus:      toStr(findingStatus),
				RemediationFactor:  toFloat64(remFactor),
				PatchAvailable:     toBool(hasPatch),
				CVEID:              toStr(cveID),
				CVSSVector:         toStr(cvssVec),
				CachedBaseScore:    toFloat64(baseScore),
				CachedEPSS:         toFloat64(epss),
				CachedKEV:          toBool(kev),
				HasExploit:         toBool(exploit),
				InternetExposed:    toBool(internetExposed),
				Environment:        toStr(environment),
				ConfidentialityReq: toStr(cr),
				IntegrityReq:       toStr(ir),
				AvailabilityReq:    toStr(ar),
			})
		}

		return contexts, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.FindingRiskContext{}, nil
	}
	return res.([]domain.FindingRiskContext), nil
}

// UpdateFindingScores persiste los scores calculados en el nodo Finding.
func (r *riskRepo) UpdateFindingScores(ctx context.Context, findingID int64, impactScore, likelihood, exposureFactor, remediationFactor, riskScore, assetCriticality, urgencyBoost, priorityScore float64) error {
	query := `
		MATCH (f:Finding {id: $id})
		SET f.impact_score       = $impact_score,
		    f.likelihood         = $likelihood,
			f.exposure_factor     = $exposure_factor,
		    f.remediation_factor = $remediation_factor,
		    f.risk_score         = $risk_score,
		    f.asset_criticality  = $asset_criticality,
		    f.urgency_boost      = $urgency_boost,
		    f.priority_score     = $priority_score,
		    f.risk_computed_at   = $now
	`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"id":                 findingID,
		"impact_score":       impactScore,
		"likelihood":         likelihood,
		"exposure_factor":    exposureFactor,
		"remediation_factor": remediationFactor,
		"risk_score":         riskScore,
		"asset_criticality":  assetCriticality,
		"urgency_boost":      urgencyBoost,
		"priority_score":     priorityScore,
		"now":                time.Now().UTC(),
	})
}

// UpdateEndpointRisk persiste el riesgo agregado y el tier en el nodo Endpoint.
func (r *riskRepo) UpdateEndpointRisk(ctx context.Context, endpointID int64, riskScore float64, riskTier string) error {
	query := `
		MATCH (e:Endpoint {id: $id})
		SET e.risk_score       = $risk_score,
		    e.risk_tier        = $risk_tier,
		    e.risk_computed_at = $now
	`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"id":         endpointID,
		"risk_score": riskScore,
		"risk_tier":  riskTier,
		"now":        time.Now().UTC(),
	})
}

// GetAllEndpointIDs devuelve los IDs de todos los endpoints para el recálculo diario masivo.
func (r *riskRepo) GetAllEndpointIDs(ctx context.Context) ([]int64, error) {
	query := `MATCH (e:Endpoint) RETURN e.id AS id`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		var ids []int64
		for result.Next(ctx) {
			rec := result.Record()
			id, _ := rec.Get("id")
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

// helpers de conversión de tipos para valores any de Neo4j
func toInt64(v any) int64 {
	if i, ok := v.(int64); ok {
		return i
	}
	return 0
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toFloat64(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0.0
}

func toBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// GetFindingScoresByInstallation devuelve los scores de riesgo de todos los findings asociados a una instalación de software.
func (r *riskRepo) GetFindingScoresByInstallation(ctx context.Context, installationID string) ([]domain.FindingRiskSummary, error) {
	query := `
        MATCH (:SoftwareInstallation {id: $installation_id})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
        WHERE NOT coalesce(f.status, 'OPEN') IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED']
        RETURN f.id AS finding_id,
               v.cve_id AS cve_id,
               f.risk_score AS risk_score,
               f.status AS status
        ORDER BY risk_score DESC
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"installation_id": installationID})
		if err != nil {
			return nil, err
		}

		var summaries []domain.FindingRiskSummary
		for result.Next(ctx) {
			rec := result.Record()
			findingID, _ := rec.Get("finding_id")
			cveID, _ := rec.Get("cve_id")
			riskScore, _ := rec.Get("risk_score")
			status, _ := rec.Get("status")

			summaries = append(summaries, domain.FindingRiskSummary{
				FindingID: toInt64(findingID),
				CVEID:     toStr(cveID),
				RiskScore: toFloat64(riskScore),
				Status:    toStr(status),
			})
		}

		return summaries, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.FindingRiskSummary{}, nil
	}
	return res.([]domain.FindingRiskSummary), nil
}

// UpdateSoftwareInstallationRisk actualiza el riesgo agregado y el tier en el nodo SoftwareInstallation.
func (r *riskRepo) UpdateSoftwareInstallationRisk(ctx context.Context, installationID string, riskScore float64, riskTier string, driverFindingID int64, driverCVEID string) error {
	query := `
        MATCH (si:SoftwareInstallation {id: $installation_id})
        SET si.risk_score = $risk_score,
            si.risk_tier = $risk_tier,
            si.driver_finding_id = $driver_finding_id,
            si.driver_cve_id = $driver_cve_id,
            si.risk_computed_at = $now
    `

	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"installation_id":   installationID,
		"risk_score":        riskScore,
		"risk_tier":         riskTier,
		"driver_finding_id": driverFindingID,
		"driver_cve_id":     driverCVEID,
		"now":               time.Now().UTC(),
	})
}

// GetInstallationIDsByEndpoint devuelve los IDs de todas las instalaciones de software asociadas a un endpoint.
func (r *riskRepo) GetInstallationIDsByEndpoint(ctx context.Context, endpointID int64) ([]string, error) {
	query := `
        MATCH (:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
        RETURN si.id AS installation_id
        ORDER BY installation_id
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}

		var ids []string
		for result.Next(ctx) {
			rec := result.Record()
			installationID, _ := rec.Get("installation_id")
			ids = append(ids, toStr(installationID))
		}

		return ids, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []string{}, nil
	}
	return res.([]string), nil
}
