package neo4j

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
		// Rama A: Software nativo del Endpoint
		MATCH (e:Endpoint {id: $endpoint_id})
		WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
		MATCH (e)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		MATCH (si)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED']
		  AND coalesce(f.remediation_factor, 1.0) > 0.0
		RETURN
		    f.id                    AS finding_id,
		    f.status                AS finding_status,
		    f.remediation_factor    AS remediation_factor,
		    f.exposure_factor       AS exposure_factor,
		    (
		        EXISTS { (f)-[:HAS_REMEDIATION]->(:Remediation)-[:USES_PATCH]->(:Patch) }
		        OR
		        EXISTS { (:Patch)-[:FIXES]->(v) }
		    )                       AS has_patch,
		    v.cve_id                AS cve_id,
		    v.cvss_vector           AS cvss_vector,
		    v.base_score            AS cached_base_score,
		    v.epss_score            AS cached_epss,
		    v.kev                   AS cached_kev,
		    v.exploit               AS has_exploit,
		    coalesce(e.internet_exposed, false) AS internet_exposed,
		    coalesce(e.environment, '') AS environment,
		    e.confidentiality_req   AS cr,
		    e.integrity_req         AS ir,
		    e.availability_req      AS ar,
		    'SOFTWARE_INSTALLATION' AS asset_type,
		    si.id                   AS asset_id,
		    coalesce(si.name, si.id) AS asset_name,
		    ''                      AS container_id,
		    ''                      AS container_name,
		    ''                      AS image_id,
		    false                   AS in_container

		UNION ALL

		// Rama B: Software dentro de contenedor alojado en el Endpoint
		MATCH (e:Endpoint {id: $endpoint_id})-[:HOSTS]->(c:Container)
		WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
		MATCH (c)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		MATCH (si)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED']
		  AND coalesce(f.remediation_factor, 1.0) > 0.0
		RETURN
		    f.id                    AS finding_id,
		    f.status                AS finding_status,
		    f.remediation_factor    AS remediation_factor,
		    f.exposure_factor       AS exposure_factor,
		    (
		        EXISTS { (f)-[:HAS_REMEDIATION]->(:Remediation)-[:USES_PATCH]->(:Patch) }
		        OR
		        EXISTS { (:Patch)-[:FIXES]->(v) }
		    )                       AS has_patch,
		    v.cve_id                AS cve_id,
		    v.cvss_vector           AS cvss_vector,
		    v.base_score            AS cached_base_score,
		    v.epss_score            AS cached_epss,
		    v.kev                   AS cached_kev,
		    v.exploit               AS has_exploit,
		    (coalesce(e.internet_exposed, false) OR coalesce(c.internet_exposed, false)) AS internet_exposed,
		    coalesce(e.environment, '') AS environment,
		    e.confidentiality_req   AS cr,
		    e.integrity_req         AS ir,
		    e.availability_req      AS ar,
		    'SOFTWARE_INSTALLATION' AS asset_type,
		    si.id                   AS asset_id,
		    coalesce(si.name, si.id) AS asset_name,
		    c.id                    AS container_id,
		    c.name                  AS container_name,
		    c.image_id              AS image_id,
		    true                    AS in_container

		UNION ALL

		// Rama C: Finding contextual de imagen de contenedor
		MATCH (e:Endpoint {id: $endpoint_id})-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)
		WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
		MATCH (ci)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE f.context_type = 'CONTAINER_IMAGE'
		  AND f.image_id = ci.id
		  AND NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED']
		  AND coalesce(f.remediation_factor, 1.0) > 0.0
		RETURN
		    f.id                    AS finding_id,
		    f.status                AS finding_status,
		    f.remediation_factor    AS remediation_factor,
		    f.exposure_factor       AS exposure_factor,
		    (
		        EXISTS { (f)-[:HAS_REMEDIATION]->(:Remediation)-[:USES_PATCH]->(:Patch) }
		        OR
		        EXISTS { (:Patch)-[:FIXES]->(v) }
		    )                       AS has_patch,
		    v.cve_id                AS cve_id,
		    v.cvss_vector           AS cvss_vector,
		    v.base_score            AS cached_base_score,
		    v.epss_score            AS cached_epss,
		    v.kev                   AS cached_kev,
		    v.exploit               AS has_exploit,
		    (coalesce(e.internet_exposed, false) OR coalesce(c.internet_exposed, false)) AS internet_exposed,
		    coalesce(e.environment, '') AS environment,
		    e.confidentiality_req   AS cr,
		    e.integrity_req         AS ir,
		    e.availability_req      AS ar,
		    'CONTAINER_IMAGE_FINDING' AS asset_type,
		    c.id                    AS asset_id,
		    c.name                  AS asset_name,
		    c.id                    AS container_id,
		    c.name                  AS container_name,
		    ci.id                   AS image_id,
		    true                    AS in_container
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}

		var contexts []domain.FindingRiskContext
		seenFindings := make(map[int64]bool)
		for result.Next(ctx) {
			rec := result.Record()

			findingID := toInt64(rec.Values[0])
			if seenFindings[findingID] {
				continue
			}
			seenFindings[findingID] = true

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

			assetType, _ := rec.Get("asset_type")
			assetID, _ := rec.Get("asset_id")
			assetName, _ := rec.Get("asset_name")
			containerID, _ := rec.Get("container_id")
			containerName, _ := rec.Get("container_name")
			imageID, _ := rec.Get("image_id")
			inContainer, _ := rec.Get("in_container")

			contexts = append(contexts, domain.FindingRiskContext{
				FindingID:          findingID,
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
				AssetType:          toStr(assetType),
				AssetID:            toStr(assetID),
				AssetName:          toStr(assetName),
				ContainerID:        toStr(containerID),
				ContainerName:      toStr(containerName),
				ImageID:            toStr(imageID),
				InContainer:        toBool(inContainer),
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
// Los tiers se guardan aquí igual que en Endpoint, Installation y Project: sin ellos
// el finding tenía score pero no etiqueta, y el front mostraba UNKNOWN.
func (r *riskRepo) UpdateFindingScores(ctx context.Context, findingID int64, impactScore, likelihood, exposureFactor, remediationFactor, riskScore, assetCriticality, urgencyBoost, priorityScore float64, riskTier, priorityTier string) error {
	query := `
		MATCH (f:Finding {id: $id})
		SET f.impact_score       = $impact_score,
		    f.likelihood         = $likelihood,
			f.exposure_factor     = $exposure_factor,
		    f.remediation_factor = $remediation_factor,
		    f.risk_score         = $risk_score,
		    f.risk_tier          = $risk_tier,
		    f.asset_criticality  = $asset_criticality,
		    f.urgency_boost      = $urgency_boost,
		    f.priority_score     = $priority_score,
		    f.priority_tier      = $priority_tier,
		    f.risk_computed_at   = $now
	`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"id":                 findingID,
		"impact_score":       impactScore,
		"likelihood":         likelihood,
		"exposure_factor":    exposureFactor,
		"remediation_factor": remediationFactor,
		"risk_score":         riskScore,
		"risk_tier":          riskTier,
		"asset_criticality":  assetCriticality,
		"urgency_boost":      urgencyBoost,
		"priority_score":     priorityScore,
		"priority_tier":      priorityTier,
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

// GetAllEndpointIDs devuelve los IDs de todos los endpoints activos para el recálculo diario masivo.
func (r *riskRepo) GetAllEndpointIDs(ctx context.Context) ([]int64, error) {
	query := `
		MATCH (e:Endpoint)
		WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
		RETURN e.id AS id
	`

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
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case int16:
		return float64(n)
	case int8:
		return float64(n)
	case uint:
		return float64(n)
	case uint64:
		return float64(n)
	case uint32:
		return float64(n)
	case uint16:
		return float64(n)
	case uint8:
		return float64(n)
	default:
		return 0.0
	}
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
        MATCH (si:SoftwareInstallation {id: $installation_id})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
        WHERE NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED']
          // El endpoint se comprueba con EXISTS y no en el patrón principal: la instalación
          // puede colgar de un contenedor, y meter el endpoint en el MATCH dejaba fuera ese
          // caso además de multiplicar filas.
          AND EXISTS {
              MATCH (e:Endpoint)-[:HAS_INSTALLATION|HOSTS*1..2]->(si)
              WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
          }
        RETURN f.id AS finding_id,
			v.cve_id AS cve_id,
			f.risk_score AS risk_score,
			f.priority_score AS priority_score,
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
			priorityScore, _ := rec.Get("priority_score")
			status, _ := rec.Get("status")

			summaries = append(summaries, domain.FindingRiskSummary{
				FindingID:     toInt64(findingID),
				CVEID:         toStr(cveID),
				RiskScore:     toFloat64(riskScore),
				PriorityScore: toFloat64(priorityScore),
				Status:        toStr(status),
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

// GetInstallationIDsByEndpoint devuelve los IDs de todas las instalaciones de software asociadas a un endpoint activo.
func (r *riskRepo) GetInstallationIDsByEndpoint(ctx context.Context, endpointID int64) ([]string, error) {
	query := `
		MATCH (e:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
        WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
        RETURN DISTINCT si.id AS installation_id
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

// GetNativeInstallationIDsByEndpoint devuelve exclusivamente instalaciones
// colgadas directamente del endpoint, sin atravesar contenedores.
func (r *riskRepo) GetNativeInstallationIDsByEndpoint(ctx context.Context, endpointID string) ([]string, error) {
	query := `
		MATCH (e:Endpoint)
		WHERE toString(e.id) = toString($endpoint_id)
		MATCH (e)-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		RETURN collect(DISTINCT coalesce(si.installation_id, si.id)) AS installation_ids
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return []string{}, result.Err()
		}
		value, _ := result.Record().Get("installation_ids")
		ids := make([]string, 0)
		switch values := value.(type) {
		case []any:
			for _, item := range values {
				if id, ok := item.(string); ok && id != "" {
					ids = append(ids, id)
				}
			}
		case []string:
			ids = append(ids, values...)
		}
		return ids, result.Err()
	})
	if err != nil {
		return nil, err
	}
	return res.([]string), nil
}

// GetNativeSoftwareRiskSummariesByEndpoint devuelve solo el resumen de las
// instalaciones conectadas directamente al endpoint.
func (r *riskRepo) GetNativeSoftwareRiskSummariesByEndpoint(ctx context.Context, endpointID string) ([]domain.SoftwareRiskSummary, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(endpointID), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("endpoint_id inválido %q: %w", endpointID, err)
	}
	return r.GetSoftwareRiskSummariesByEndpoint(ctx, id)
}

// GetContainerRiskSummariesByEndpoint devuelve los resúmenes ya persistidos
// de los contenedores alojados en un endpoint.
func (r *riskRepo) GetContainerRiskSummariesByEndpoint(ctx context.Context, endpointID string) ([]domain.ContainerRiskSummary, error) {
	query := `
		MATCH (e:Endpoint)-[:HOSTS]->(c:Container)
		WHERE toString(e.id) = toString($endpoint_id)
		RETURN c.id AS container_id,
		       coalesce(c.name, c.id) AS container_name,
		       coalesce(c.state, '') AS state,
		       coalesce(c.risk_score, 0.0) AS risk_score,
		       coalesce(c.risk_tier, 'LOW') AS risk_tier,
		       coalesce(c.priority_score, 0.0) AS priority_score,
		       coalesce(c.priority_tier, 'LOW') AS priority_tier,
		       coalesce(c.technical_driver_type, '') AS technical_driver_type,
		       coalesce(c.technical_driver_asset_id, '') AS technical_driver_asset_id,
		       coalesce(c.technical_driver_asset_name, '') AS technical_driver_asset_name,
		       coalesce(c.technical_driver_finding_id, 0) AS technical_driver_finding_id,
		       coalesce(c.technical_driver_cve_id, '') AS technical_driver_cve_id,
		       coalesce(c.technical_driver_risk_score, 0.0) AS technical_driver_risk_score,
		       coalesce(c.priority_driver_type, '') AS priority_driver_type,
		       coalesce(c.priority_driver_asset_id, '') AS priority_driver_asset_id,
		       coalesce(c.priority_driver_asset_name, '') AS priority_driver_asset_name,
		       coalesce(c.priority_driver_finding_id, 0) AS priority_driver_finding_id,
		       coalesce(c.priority_driver_cve_id, '') AS priority_driver_cve_id,
		       coalesce(c.priority_driver_priority_score, 0.0) AS priority_driver_priority_score,
		       coalesce(c.risky_asset_count, 0) AS risky_asset_count,
		       coalesce(c.direct_finding_count, 0) AS direct_finding_count,
		       coalesce(c.risky_installation_count, 0) AS risky_installation_count
		ORDER BY priority_score DESC
	`
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}
		summaries := make([]domain.ContainerRiskSummary, 0)
		for result.Next(ctx) {
			record := result.Record()
			get := func(key string) any { value, _ := record.Get(key); return value }
			summaries = append(summaries, domain.ContainerRiskSummary{
				ContainerID: toStr(get("container_id")), ContainerName: toStr(get("container_name")), State: toStr(get("state")),
				RiskScore: toFloat64(get("risk_score")), RiskTier: toStr(get("risk_tier")),
				PriorityScore: toFloat64(get("priority_score")), PriorityTier: toStr(get("priority_tier")),
				TechnicalDriverType: toStr(get("technical_driver_type")), TechnicalDriverAssetID: toStr(get("technical_driver_asset_id")), TechnicalDriverAssetName: toStr(get("technical_driver_asset_name")),
				TechnicalDriverFindingID: toInt64(get("technical_driver_finding_id")), TechnicalDriverCVEID: toStr(get("technical_driver_cve_id")), TechnicalDriverRiskScore: toFloat64(get("technical_driver_risk_score")),
				PriorityDriverType: toStr(get("priority_driver_type")), PriorityDriverAssetID: toStr(get("priority_driver_asset_id")), PriorityDriverAssetName: toStr(get("priority_driver_asset_name")),
				PriorityDriverFindingID: toInt64(get("priority_driver_finding_id")), PriorityDriverCVEID: toStr(get("priority_driver_cve_id")), PriorityDriverPriorityScore: toFloat64(get("priority_driver_priority_score")),
				RiskyAssetCount: int(toInt64(get("risky_asset_count"))), DirectFindingCount: int(toInt64(get("direct_finding_count"))), RiskyInstallationCount: int(toInt64(get("risky_installation_count"))),
			})
		}
		return summaries, result.Err()
	})
	if err != nil {
		return nil, err
	}
	return res.([]domain.ContainerRiskSummary), nil
}

// UpdateSoftwareInstallationPriority actualiza el score de prioridad y el tier en el nodo SoftwareInstallation.
func (r *riskRepo) UpdateSoftwareInstallationPriority(ctx context.Context, installationID string, criticalityLevel string, criticalityMultiplier float64, priorityScore float64, priorityTier string) error {
	query := `
        MATCH (si:SoftwareInstallation {id: $installation_id})
        SET si.criticality_level = $criticality_level,
            si.criticality_multiplier = $criticality_multiplier,
            si.priority_score = $priority_score,
            si.priority_tier = $priority_tier,
            si.priority_computed_at = $now
    `

	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"installation_id":        installationID,
		"criticality_level":      criticalityLevel,
		"criticality_multiplier": criticalityMultiplier,
		"priority_score":         priorityScore,
		"priority_tier":          priorityTier,
		"now":                    time.Now().UTC(),
	})
}

// GetSoftwareCriticalityLevel devuelve el nivel de criticidad de una instalación de software.
func (r *riskRepo) GetSoftwareCriticalityLevel(ctx context.Context, installationID string) (string, error) {
	query := `
        MATCH (si:SoftwareInstallation {id: $installation_id})
        RETURN coalesce(si.criticality_level, 'STANDARD') AS criticality_level
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"installation_id": installationID})
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			value, _ := result.Record().Get("criticality_level")
			return toStr(value), result.Err()
		}
		return "STANDARD", result.Err()
	})
	if err != nil {
		return "", err
	}
	if res == nil {
		return "STANDARD", nil
	}
	return res.(string), nil
}

// GetPatchQueue devuelve los findings pendientes ordenados por prioridad y paginados con soporte para filtrado avanzado.
func (r *riskRepo) GetPatchQueue(ctx context.Context, query domain.PatchQueueQuery) (*domain.PatchQueueResponse, error) {
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.Limit <= 0 {
		query.Limit = 20
	}
	offset := (query.Page - 1) * query.Limit

	var projectParam any
	if query.ProjectID != nil {
		projectParam = *query.ProjectID
	}

	sortDir := "DESC"
	if strings.ToUpper(query.SortDirection) == "ASC" {
		sortDir = "ASC"
	}

	var orderExpr string
	switch strings.ToLower(query.SortField) {
	case "cve_id", "cve":
		orderExpr = "toLower(coalesce(item.cve_id, ''))"
	case "software_name", "software":
		orderExpr = "toLower(coalesce(item.software_name, ''))"
	case "hostname", "asset":
		orderExpr = "toLower(coalesce(item.hostname, ''))"
	case "risk_score", "risk":
		orderExpr = "coalesce(item.risk_score, 0.0)"
	case "asset_criticality", "criticality":
		orderExpr = "coalesce(item.asset_criticality, 0.0)"
	case "urgency_boost", "urgency":
		orderExpr = "coalesce(item.urgency_boost, 0.0)"
	case "priority_score", "priority":
		orderExpr = "coalesce(item.priority_score, 0.0)"
	default:
		orderExpr = "coalesce(item.priority_score, 0.0) " + sortDir + ", coalesce(item.risk_score, 0.0)"
	}

	cypherQuery := fmt.Sprintf(`
		MATCH (e:Endpoint)
		MATCH path = (e)-[:HAS_INSTALLATION|HOSTS|USES_IMAGE*1..3]->(asset)
		WHERE ('SoftwareInstallation' IN labels(asset) OR 'ContainerImage' IN labels(asset) OR 'Container' IN labels(asset))
		MATCH (asset)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED', 'MITIGATED']
		  AND ($project_id IS NULL OR EXISTS { (:Project {id: $project_id})-[:HAS_ENDPOINT]->(e) })
		OPTIONAL MATCH (asset)-[:INSTANCE_OF]->(s:Software)
		// El contenedor se acota al endpoint YA scopeado al proyecto. Las ContainerImage
		// se deduplican de forma global (un nodo por imagen, compartido entre proyectos),
		// así que sin este (e)-[:HOSTS]-> un finding sobre una imagen compartida enganchaba
		// TODOS los contenedores que la usan —incluidos los de otros proyectos, p. ej. una
		// copia importada— y duplicaba la fila atribuyéndola al contenedor ajeno.
		OPTIONAL MATCH (e)-[:HOSTS]->(c:Container)-[:HAS_INSTALLATION|USES_IMAGE]->(asset)
		OPTIONAL MATCH (f)-[:HAS_REMEDIATION]->(rem:Remediation)
		OPTIONAL MATCH (p:Patch)-[:FIXES]->(v)
		WITH DISTINCT f, v, asset, s, e, c, rem,
			collect(CASE WHEN p IS NOT NULL THEN {
				url: coalesce(p.url, ''),
				official: coalesce(p.official, false),
				reference_type: coalesce(p.reference_type, ''),
				fixed_version: coalesce(p.fixed_version, '')
			} ELSE null END) AS raw_patch_refs
		WITH f, v, asset, s, e, c, rem,
			[patch IN raw_patch_refs WHERE patch IS NOT NULL] AS patch_refs
		WITH f, v, asset, s, e, c, rem, patch_refs,
			coalesce(rem.fixed_version, v.fixed_version, '') AS fixed_version,
			coalesce(s.name, asset.name, asset.id) AS software_name,
			coalesce(s.version, 'N/A') AS software_version,
			s.vendor AS software_vendor,
			s.cpe AS software_cpe,
			e.id AS endpoint_id,
			e.hostname AS hostname,
			e.environment AS environment,
			(c IS NOT NULL OR 'Container' IN labels(asset)) AS in_container,
			coalesce(c.name, CASE WHEN 'Container' IN labels(asset) THEN asset.name ELSE null END) AS container_name,
			f.id AS finding_id,
			f.status AS status,
			v.cve_id AS cve_id,
			f.risk_score AS risk_score,
			f.asset_criticality AS asset_criticality,
			f.urgency_boost AS urgency_boost,
			f.priority_score AS priority_score,
			(size(patch_refs) > 0 OR coalesce(rem.fixed_version, v.fixed_version, '') <> '') AS patch_available,
			CASE
				WHEN any(patch IN patch_refs
				         WHERE patch.fixed_version <> '')
				     OR coalesce(rem.fixed_version, v.fixed_version, '') <> '' THEN 'OFFICIAL_FIX'
				WHEN size(patch_refs) > 0 THEN 'MITIGATION'
				ELSE 'UNAVAILABLE'
			END AS remediation_kind,
			CASE
				WHEN coalesce(f.priority_score, 0.0) >= 0.9 THEN 'CRITICAL'
				WHEN coalesce(f.priority_score, 0.0) >= 0.7 THEN 'HIGH'
				WHEN coalesce(f.priority_score, 0.0) >= 0.4 THEN 'MEDIUM'
				ELSE 'LOW'
			END AS priority_tier
			,CASE WHEN f.context_type = 'CONTAINER_IMAGE' OR 'Container' IN labels(asset) THEN 'CONTAINER' ELSE 'SOFTWARE_INSTALLATION' END AS asset_type
			,CASE WHEN f.context_type = 'CONTAINER_IMAGE' OR 'Container' IN labels(asset) THEN coalesce(c.id, asset.id) ELSE asset.id END AS asset_id
			,CASE WHEN f.context_type = 'CONTAINER_IMAGE' OR 'Container' IN labels(asset) THEN coalesce(c.id, asset.id) ELSE null END AS container_id
			,CASE WHEN f.context_type = 'CONTAINER_IMAGE' OR 'Container' IN labels(asset) THEN coalesce(f.image_id, c.image_id, asset.id) ELSE null END AS image_id
			,CASE WHEN f.context_type = 'CONTAINER_IMAGE' OR 'Container' IN labels(asset) THEN null ELSE asset.id END AS installation_id
		WHERE ($search = "" OR 
		       toLower(coalesce(cve_id, "")) CONTAINS toLower($search) OR
		       toLower(coalesce(software_name, "")) CONTAINS toLower($search) OR
		       toLower(coalesce(hostname, "")) CONTAINS toLower($search) OR
		       toLower(coalesce(container_name, "")) CONTAINS toLower($search)
		      )
		  AND ($vendor_search = "" OR toLower(coalesce(software_vendor, "")) CONTAINS toLower($vendor_search))
		  AND ($hostname_search = "" OR 
		       toLower(coalesce(hostname, "")) CONTAINS toLower($hostname_search) OR
		       toLower(coalesce(container_name, "")) CONTAINS toLower($hostname_search)
		      )
		  AND ($environment = "" OR $environment = "ALL" OR toLower(coalesce(environment, "")) = toLower($environment))
		  AND ($internet_exposed = "" OR $internet_exposed = "ALL" OR 
		       ($internet_exposed = "TRUE" AND (e.internet_exposed = true OR toString(e.internet_exposed) = "true")) OR 
		       ($internet_exposed = "FALSE" AND (e.internet_exposed IS NULL OR e.internet_exposed = false OR toString(e.internet_exposed) = "false"))
		      )
		  AND ($in_container = "" OR $in_container = "ALL" OR 
		       ($in_container = "TRUE" AND in_container = true) OR 
		       ($in_container = "FALSE" AND in_container = false)
		      )
		  AND ($priority_tier = "" OR $priority_tier = "ALL" OR toLower(priority_tier) = toLower($priority_tier))
		  AND ($patch_available = "" OR $patch_available = "ALL" OR 
		       ($patch_available = "TRUE" AND patch_available = true) OR 
		       ($patch_available = "FALSE" AND patch_available = false)
		      )
		  AND ($remediation_kind = "" OR $remediation_kind = "ALL"
		       OR toLower(remediation_kind) = toLower($remediation_kind))

		WITH collect({
			finding_id: finding_id,
			asset_type: asset_type,
			asset_id: asset_id,
			container_id: container_id,
			image_id: image_id,
			status: status,
			cve_id: cve_id,
			installation_id: installation_id,
			software_name: software_name,
			software_version: software_version,
			software_vendor: software_vendor,
			software_cpe: software_cpe,
			fixed_version: fixed_version,
			endpoint_id: endpoint_id,
			hostname: hostname,
			environment: environment,
			in_container: in_container,
			container_name: container_name,
			risk_score: risk_score,
			asset_criticality: asset_criticality,
			urgency_boost: urgency_boost,
			priority_score: priority_score,
			priority_tier: priority_tier,
			patch_available: patch_available,
			remediation_kind: remediation_kind
		}) AS matchedItems, count(finding_id) AS totalCount

		UNWIND (CASE WHEN size(matchedItems) > 0 THEN matchedItems ELSE [null] END) AS item
		WITH matchedItems, totalCount, item WHERE item IS NOT NULL

		WITH matchedItems, totalCount, item.priority_tier AS tierLabel, collect(item) AS tierItems
		WITH matchedItems, totalCount, collect({tier: tierLabel, count: size(tierItems)}) AS tierMetrics

		UNWIND matchedItems AS item
		WITH totalCount, tierMetrics, item
		ORDER BY %s %s
		SKIP $offset LIMIT $limit

		RETURN totalCount, tierMetrics, collect(item) AS pagedItems
	`, orderExpr, sortDir)

	params := map[string]any{
		"project_id":       projectParam,
		"search":           strings.TrimSpace(query.Search),
		"vendor_search":    strings.TrimSpace(query.VendorSearch),
		"hostname_search":  strings.TrimSpace(query.HostnameSearch),
		"environment":      strings.TrimSpace(query.Environment),
		"internet_exposed": strings.ToUpper(strings.TrimSpace(query.InternetExposed)),
		"in_container":     strings.ToUpper(strings.TrimSpace(query.InContainer)),
		"priority_tier":    strings.TrimSpace(query.PriorityTier),
		"patch_available":  strings.ToUpper(strings.TrimSpace(query.PatchAvailable)),
		"remediation_kind": strings.TrimSpace(query.RemediationKind),
		"offset":           int64(offset),
		"limit":            int64(query.Limit),
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	response := &domain.PatchQueueResponse{
		Queue:              []domain.PatchQueueItem{},
		Total:              0,
		Page:               query.Page,
		Limit:              query.Limit,
		TotalPages:         0,
		PriorityTierCounts: make(map[string]int64),
	}

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, cypherQuery, params)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().AsMap(), nil
		}
		return nil, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error al consultar cola de parcheo en Neo4j: %w", err)
	}

	if res == nil {
		return response, nil
	}

	recordMap := res.(map[string]interface{})

	if tc, ok := recordMap["totalCount"].(int64); ok {
		response.Total = int(tc)
		if tc > 0 && query.Limit > 0 {
			response.TotalPages = int((tc + int64(query.Limit) - 1) / int64(query.Limit))
		}
	}

	if metricsRaw, ok := recordMap["tierMetrics"].([]interface{}); ok {
		var grandTotal int64 = 0
		for _, item := range metricsRaw {
			if m, ok := item.(map[string]interface{}); ok {
				tier, _ := m["tier"].(string)
				cnt, _ := m["count"].(int64)
				if tier != "" {
					response.PriorityTierCounts[tier] = cnt
					grandTotal += cnt
				}
			}
		}
		response.PriorityTierCounts["ALL"] = grandTotal
	}

	if itemsRaw, ok := recordMap["pagedItems"].([]interface{}); ok {
		for _, raw := range itemsRaw {
			if m, ok := raw.(map[string]interface{}); ok {
				response.Queue = append(response.Queue, domain.PatchQueueItem{
					Position:         offset + len(response.Queue) + 1,
					AssetType:        getString(m, "asset_type"),
					AssetID:          getString(m, "asset_id"),
					FindingID:        getInt64(m, "finding_id"),
					CVEID:            getString(m, "cve_id"),
					Status:           getString(m, "status"),
					InstallationID:   getString(m, "installation_id"),
					ContainerID:      getString(m, "container_id"),
					ImageID:          getString(m, "image_id"),
					SoftwareName:     getString(m, "software_name"),
					SoftwareVersion:  getString(m, "software_version"),
					SoftwareVendor:   getString(m, "software_vendor"),
					SoftwareCPE:      getString(m, "software_cpe"),
					FixedVersion:     getString(m, "fixed_version"),
					EndpointID:       getInt64(m, "endpoint_id"),
					Hostname:         getString(m, "hostname"),
					Environment:      getString(m, "environment"),
					InContainer:      getBool(m, "in_container"),
					ContainerName:    getString(m, "container_name"),
					RiskScore:        getFloat64(m, "risk_score"),
					AssetCriticality: getFloat64(m, "asset_criticality"),
					UrgencyBoost:     getFloat64(m, "urgency_boost"),
					PriorityScore:    getFloat64(m, "priority_score"),
					PriorityTier:     getString(m, "priority_tier"),
					PatchAvailable:   getBool(m, "patch_available"),
					RemediationKind:  getString(m, "remediation_kind"),
				})
			}
		}
	}

	return response, nil
}

// GetEndpointIDsByInstallation es el recorrido inverso de GetInstallationIDsByEndpoint.
// Devuelve lista porque el grafo no impide que una instalación cuelgue de varios endpoints.
func (r *riskRepo) GetEndpointIDsByInstallation(ctx context.Context, installationID string) ([]int64, error) {
	query := `
        MATCH (e:Endpoint)-[:HAS_INSTALLATION|HOSTS*1..2]->(:SoftwareInstallation {id: $installation_id})
        RETURN DISTINCT e.id AS endpoint_id
        ORDER BY endpoint_id
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"installation_id": installationID})
		if err != nil {
			return nil, err
		}

		ids := make([]int64, 0)
		for result.Next(ctx) {
			id, _ := result.Record().Get("endpoint_id")
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

func (r *riskRepo) GetSoftwareRiskSummariesByEndpoint(ctx context.Context, endpointID int64) ([]domain.SoftwareRiskSummary, error) {
	query := `
        // Recorre también las instalaciones que cuelgan de un contenedor del endpoint.
        MATCH (e:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION|HOSTS*1..2]->(si:SoftwareInstallation)
        OPTIONAL MATCH (si)-[:INSTANCE_OF]->(s:Software)
        WHERE NOT coalesce(si.status, 'INSTALLED') IN ['REMOVED', 'UNINSTALLED', 'DELETED']
          AND NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
        RETURN si.id AS installation_id,
               s.id AS software_id,
               s.name AS software_name,
               si.risk_score AS risk_score,
               si.risk_tier AS risk_tier,
               coalesce(si.criticality_level, 'STANDARD') AS criticality_level,
               coalesce(si.criticality_multiplier, 1.0) AS criticality_multiplier,
               si.priority_score AS priority_score,
               si.priority_tier AS priority_tier,
               si.driver_cve_id AS driver_cve_id,
               si.status AS status
        ORDER BY priority_score DESC
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}

		summaries := make([]domain.SoftwareRiskSummary, 0)
		for result.Next(ctx) {
			rec := result.Record()
			installationID, _ := rec.Get("installation_id")
			softwareID, _ := rec.Get("software_id")
			softwareName, _ := rec.Get("software_name")
			riskScore, _ := rec.Get("risk_score")
			riskTier, _ := rec.Get("risk_tier")
			criticalityLevel, _ := rec.Get("criticality_level")
			criticalityMultiplier, _ := rec.Get("criticality_multiplier")
			priorityScore, _ := rec.Get("priority_score")
			priorityTier, _ := rec.Get("priority_tier")
			driverCVEID, _ := rec.Get("driver_cve_id")
			status, _ := rec.Get("status")

			summaries = append(summaries, domain.SoftwareRiskSummary{
				InstallationID:        toStr(installationID),
				SoftwareID:            toInt64(softwareID),
				SoftwareName:          toStr(softwareName),
				RiskScore:             toFloat64(riskScore),
				RiskTier:              toStr(riskTier),
				CriticalityLevel:      toStr(criticalityLevel),
				CriticalityMultiplier: toFloat64(criticalityMultiplier),
				PriorityScore:         toFloat64(priorityScore),
				PriorityTier:          toStr(priorityTier),
				DriverCVEID:           toStr(driverCVEID),
				Status:                toStr(status),
			})
		}

		return summaries, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.SoftwareRiskSummary{}, nil
	}
	return res.([]domain.SoftwareRiskSummary), nil
}

func (r *riskRepo) UpdateEndpointRiskAndPriority(ctx context.Context, endpointID int64, riskScore float64, riskTier string, priorityScore float64, priorityTier string, technicalDriverInstallationID string, technicalDriverSoftwareName string, technicalDriverRiskScore float64, technicalDriverCVEID string, priorityDriverInstallationID string, priorityDriverSoftwareName string, priorityDriverPriorityScore float64, priorityDriverCVEID string, riskySoftwareCount int) error {
	query := `
		MATCH (e:Endpoint {id: $id})
		SET e.risk_score = $risk_score,
			e.risk_tier = $risk_tier,
			e.risk_computed_at = $now,
			e.priority_score = $priority_score,
			e.priority_tier = $priority_tier,
			e.priority_computed_at = $now,
			e.technical_driver_installation_id = $technical_driver_installation_id,
			e.technical_driver_software_name = $technical_driver_software_name,
			e.technical_driver_risk_score = $technical_driver_risk_score,
			e.technical_driver_cve_id = $technical_driver_cve_id,
			e.priority_driver_installation_id = $priority_driver_installation_id,
			e.priority_driver_software_name = $priority_driver_software_name,
			e.priority_driver_priority_score = $priority_driver_priority_score,
			e.priority_driver_cve_id = $priority_driver_cve_id,
			e.risky_software_count = $risky_software_count
	`

	params := map[string]any{
		"id":                               endpointID,
		"risk_score":                       riskScore,
		"risk_tier":                        riskTier,
		"priority_score":                   priorityScore,
		"priority_tier":                    priorityTier,
		"technical_driver_installation_id": technicalDriverInstallationID,
		"technical_driver_software_name":   technicalDriverSoftwareName,
		"technical_driver_risk_score":      technicalDriverRiskScore,
		"technical_driver_cve_id":          technicalDriverCVEID,
		"priority_driver_installation_id":  priorityDriverInstallationID,
		"priority_driver_software_name":    priorityDriverSoftwareName,
		"priority_driver_priority_score":   priorityDriverPriorityScore,
		"priority_driver_cve_id":           priorityDriverCVEID,
		"risky_software_count":             riskySoftwareCount,
		"now":                              time.Now().UTC(),
	}

	return executeWriteHelper(ctx, r.driver, query, params)
}

// UpdateEndpointRiskAndPrioritySummary persiste los drivers genéricos de una
// instalación nativa o de un contenedor, manteniendo también los campos legacy.
func (r *riskRepo) UpdateEndpointRiskAndPrioritySummary(ctx context.Context, summary domain.EndpointRiskSummary) error {
	query := `
		MATCH (e:Endpoint {id: $endpoint_id})
		SET e.risk_score = $risk_score,
		    e.risk_tier = $risk_tier,
		    e.risk_computed_at = $now,
		    e.priority_score = $priority_score,
		    e.priority_tier = $priority_tier,
		    e.priority_computed_at = $now,
		    e.technical_driver_type = $technical_driver_type,
		    e.technical_driver_asset_id = $technical_driver_asset_id,
		    e.technical_driver_asset_name = $technical_driver_asset_name,
		    e.priority_driver_type = $priority_driver_type,
		    e.priority_driver_asset_id = $priority_driver_asset_id,
		    e.priority_driver_asset_name = $priority_driver_asset_name,
		    e.technical_driver_installation_id = $technical_driver_installation_id,
		    e.technical_driver_software_name = $technical_driver_software_name,
		    e.technical_driver_risk_score = $technical_driver_risk_score,
		    e.technical_driver_cve_id = $technical_driver_cve_id,
		    e.priority_driver_installation_id = $priority_driver_installation_id,
		    e.priority_driver_software_name = $priority_driver_software_name,
		    e.priority_driver_priority_score = $priority_driver_priority_score,
		    e.priority_driver_cve_id = $priority_driver_cve_id,
		    e.risky_software_count = $risky_asset_count
	`
	params := map[string]any{
		"endpoint_id": summary.EndpointID, "risk_score": summary.RiskScore, "risk_tier": summary.RiskTier,
		"priority_score": summary.PriorityScore, "priority_tier": summary.PriorityTier,
		"technical_driver_type": summary.TechnicalDriverType, "technical_driver_asset_id": summary.TechnicalDriverAssetID,
		"technical_driver_asset_name": summary.TechnicalDriverAssetName, "priority_driver_type": summary.PriorityDriverType,
		"priority_driver_asset_id": summary.PriorityDriverAssetID, "priority_driver_asset_name": summary.PriorityDriverAssetName,
		"technical_driver_installation_id": summary.TechnicalDriverInstallationID, "technical_driver_software_name": summary.TechnicalDriverSoftwareName,
		"technical_driver_risk_score": summary.TechnicalDriverRiskScore, "technical_driver_cve_id": summary.TechnicalDriverCVEID,
		"priority_driver_installation_id": summary.PriorityDriverInstallationID, "priority_driver_software_name": summary.PriorityDriverSoftwareName,
		"priority_driver_priority_score": summary.PriorityDriverPriorityScore, "priority_driver_cve_id": summary.PriorityDriverCVEID,
		"risky_asset_count": summary.RiskySoftwareCount, "now": time.Now().UTC(),
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

// GetEndpointIDsByProject devuelve los IDs de todos los endpoints activos asociados a un proyecto.
func (r *riskRepo) GetEndpointIDsByProject(ctx context.Context, projectID int64) ([]int64, error) {
	query := `
        MATCH (:Project {id: $project_id})-[:HAS_ENDPOINT]->(e:Endpoint)
        WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
        RETURN e.id AS endpoint_id
        ORDER BY endpoint_id
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"project_id": projectID})
		if err != nil {
			return nil, err
		}

		ids := make([]int64, 0)
		for result.Next(ctx) {
			endpointID, _ := result.Record().Get("endpoint_id")
			ids = append(ids, toInt64(endpointID))
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

// GetEndpointRiskSummariesByProject devuelve los resúmenes de riesgo de todos los endpoints activos asociados a un proyecto.
func (r *riskRepo) GetEndpointRiskSummariesByProject(ctx context.Context, projectID int64) ([]domain.EndpointRiskSummary, error) {
	query := `
        MATCH (:Project {id: $project_id})-[:HAS_ENDPOINT]->(e:Endpoint)
        WHERE NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
        RETURN e.id AS endpoint_id,
               e.hostname AS hostname,
               e.status AS status,
               e.risk_score AS risk_score,
               e.risk_tier AS risk_tier,
               e.priority_score AS priority_score,
               e.priority_tier AS priority_tier,
               e.technical_driver_installation_id AS technical_driver_installation_id,
               e.technical_driver_software_name AS technical_driver_software_name,
               e.technical_driver_risk_score AS technical_driver_risk_score,
               e.technical_driver_cve_id AS technical_driver_cve_id,
               e.priority_driver_installation_id AS priority_driver_installation_id,
               e.priority_driver_software_name AS priority_driver_software_name,
               e.priority_driver_priority_score AS priority_driver_priority_score,
               e.priority_driver_cve_id AS priority_driver_cve_id,
               e.risky_software_count AS risky_software_count
        ORDER BY priority_score DESC
    `

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"project_id": projectID})
		if err != nil {
			return nil, err
		}

		summaries := make([]domain.EndpointRiskSummary, 0)
		for result.Next(ctx) {
			rec := result.Record()
			endpointID, _ := rec.Get("endpoint_id")
			hostname, _ := rec.Get("hostname")
			status, _ := rec.Get("status")
			riskScore, _ := rec.Get("risk_score")
			riskTier, _ := rec.Get("risk_tier")
			priorityScore, _ := rec.Get("priority_score")
			priorityTier, _ := rec.Get("priority_tier")
			technicalDriverInstallationID, _ := rec.Get("technical_driver_installation_id")
			technicalDriverSoftwareName, _ := rec.Get("technical_driver_software_name")
			technicalDriverRiskScore, _ := rec.Get("technical_driver_risk_score")
			technicalDriverCVEID, _ := rec.Get("technical_driver_cve_id")
			priorityDriverInstallationID, _ := rec.Get("priority_driver_installation_id")
			priorityDriverSoftwareName, _ := rec.Get("priority_driver_software_name")
			priorityDriverPriorityScore, _ := rec.Get("priority_driver_priority_score")
			priorityDriverCVEID, _ := rec.Get("priority_driver_cve_id")
			riskySoftwareCount, _ := rec.Get("risky_software_count")

			summaries = append(summaries, domain.EndpointRiskSummary{
				EndpointID:                    toInt64(endpointID),
				Hostname:                      toStr(hostname),
				Status:                        toStr(status),
				RiskScore:                     toFloat64(riskScore),
				RiskTier:                      toStr(riskTier),
				PriorityScore:                 toFloat64(priorityScore),
				PriorityTier:                  toStr(priorityTier),
				TechnicalDriverInstallationID: toStr(technicalDriverInstallationID),
				TechnicalDriverSoftwareName:   toStr(technicalDriverSoftwareName),
				TechnicalDriverRiskScore:      toFloat64(technicalDriverRiskScore),
				TechnicalDriverCVEID:          toStr(technicalDriverCVEID),
				PriorityDriverInstallationID:  toStr(priorityDriverInstallationID),
				PriorityDriverSoftwareName:    toStr(priorityDriverSoftwareName),
				PriorityDriverPriorityScore:   toFloat64(priorityDriverPriorityScore),
				PriorityDriverCVEID:           toStr(priorityDriverCVEID),
				RiskySoftwareCount:            int(toInt64(riskySoftwareCount)),
			})
		}

		return summaries, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.EndpointRiskSummary{}, nil
	}
	return res.([]domain.EndpointRiskSummary), nil
}

// UpdateProjectRiskAndPriority actualiza los scores de riesgo y prioridad, así como los drivers, en el nodo Project.
func (r *riskRepo) UpdateProjectRiskAndPriority(ctx context.Context, projectID int64, riskScore float64, riskTier string, priorityScore float64, priorityTier string, technicalDriverEndpointID int64, technicalDriverEndpointHostname string, technicalDriverRiskScore float64, technicalDriverSoftwareName string, technicalDriverCVEID string, priorityDriverEndpointID int64, priorityDriverEndpointHostname string, priorityDriverPriorityScore float64, priorityDriverSoftwareName string, priorityDriverCVEID string, riskyEndpointCount int) error {
	query := `
        MATCH (p:Project {id: $id})
        SET p.risk_score = $risk_score,
            p.risk_tier = $risk_tier,
            p.risk_computed_at = $now,
            p.priority_score = $priority_score,
            p.priority_tier = $priority_tier,
            p.priority_computed_at = $now,
            p.technical_driver_endpoint_id = $technical_driver_endpoint_id,
            p.technical_driver_endpoint_hostname = $technical_driver_endpoint_hostname,
            p.technical_driver_risk_score = $technical_driver_risk_score,
            p.technical_driver_software_name = $technical_driver_software_name,
            p.technical_driver_cve_id = $technical_driver_cve_id,
            p.priority_driver_endpoint_id = $priority_driver_endpoint_id,
            p.priority_driver_endpoint_hostname = $priority_driver_endpoint_hostname,
            p.priority_driver_priority_score = $priority_driver_priority_score,
            p.priority_driver_software_name = $priority_driver_software_name,
            p.priority_driver_cve_id = $priority_driver_cve_id,
            p.risky_endpoint_count = $risky_endpoint_count
    `

	return executeWriteHelper(ctx, r.driver, query, map[string]any{
		"id":                                 projectID,
		"risk_score":                         riskScore,
		"risk_tier":                          riskTier,
		"priority_score":                     priorityScore,
		"priority_tier":                      priorityTier,
		"technical_driver_endpoint_id":       technicalDriverEndpointID,
		"technical_driver_endpoint_hostname": technicalDriverEndpointHostname,
		"technical_driver_risk_score":        technicalDriverRiskScore,
		"technical_driver_software_name":     technicalDriverSoftwareName,
		"technical_driver_cve_id":            technicalDriverCVEID,
		"priority_driver_endpoint_id":        priorityDriverEndpointID,
		"priority_driver_endpoint_hostname":  priorityDriverEndpointHostname,
		"priority_driver_priority_score":     priorityDriverPriorityScore,
		"priority_driver_software_name":      priorityDriverSoftwareName,
		"priority_driver_cve_id":             priorityDriverCVEID,
		"risky_endpoint_count":               riskyEndpointCount,
		"now":                                time.Now().UTC(),
	})
}

// GetAllProjectIDs devuelve los IDs de todos los proyectos para el recálculo diario masivo.
func (r *riskRepo) GetAllProjectIDs(ctx context.Context) ([]int64, error) {
	query := `MATCH (p:Project) RETURN p.id AS id ORDER BY id`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		ids := make([]int64, 0)
		for result.Next(ctx) {
			id, _ := result.Record().Get("id")
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

// GetProjectIDByEndpoint devuelve el ID del proyecto asociado a un endpoint activo.
func (r *riskRepo) GetProjectIDByEndpoint(ctx context.Context, endpointID int64) (int64, error) {
	query := `
			MATCH (p:Project)-[:HAS_ENDPOINT]->(e:Endpoint {id: $endpoint_id})
			RETURN p.id AS project_id
			LIMIT 1
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{
			"endpoint_id": endpointID,
		})
		if err != nil {
			return int64(0), err
		}

		if result.Next(ctx) {
			projectID, _ := result.Record().Get("project_id")
			return toInt64(projectID), result.Err()
		}

		if err := result.Err(); err != nil {
			return int64(0), err
		}

		return int64(0), nil
	})

	if err != nil {
		return 0, err
	}

	return res.(int64), nil
}

func (r *riskRepo) GetEndpointIDByContainer(ctx context.Context, containerID string) (int64, error) {
	query := `
		MATCH (e:Endpoint)-[:HOSTS]->(c:Container {id: $container_id})
		RETURN e.id AS endpoint_id
		LIMIT 1
	`
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"container_id": containerID})
		if err != nil {
			return int64(0), err
		}
		if result.Next(ctx) {
			value, _ := result.Record().Get("endpoint_id")
			return toInt64(value), result.Err()
		}
		return int64(0), result.Err()
	})
	if err != nil {
		return 0, err
	}
	if res == nil {
		return 0, nil
	}
	return res.(int64), nil
}

// GetOpenFindingCVEsByProject devuelve la lista de CVEs de todos los findings abiertos asociados a un proyecto.
func (r *riskRepo) GetOpenFindingCVEsByProject(ctx context.Context, projectID int64) ([]string, error) {
	query := `
		MATCH (:Project {id: $project_id})-[:HAS_ENDPOINT]->(e:Endpoint)
		MATCH path = (e)-[:HAS_INSTALLATION|HOSTS|USES_IMAGE*1..3]->(asset)
		WHERE ('SoftwareInstallation' IN labels(asset) OR 'ContainerImage' IN labels(asset))
		MATCH (asset)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED', 'MITIGATED']
		RETURN DISTINCT v.cve_id AS cve_id
		ORDER BY cve_id ASC
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"project_id": projectID})
		if err != nil {
			return nil, err
		}

		cves := make([]string, 0)
		for result.Next(ctx) {
			value, _ := result.Record().Get("cve_id")
			if cve, ok := value.(string); ok && strings.TrimSpace(cve) != "" {
				cves = append(cves, cve)
			}
		}
		return cves, result.Err()
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return []string{}, nil
	}
	return res.([]string), nil
}

// GetContainerIDsByEndpoint devuelve los IDs de los contenedores alojados en un endpoint.
func (r *riskRepo) GetContainerIDsByEndpoint(ctx context.Context, endpointID int64) ([]string, error) {
	query := `
		MATCH (e:Endpoint {id: $endpoint_id})-[:HOSTS]->(c:Container)
		RETURN c.id AS container_id
		ORDER BY container_id
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
			cid, _ := rec.Get("container_id")
			if s, ok := cid.(string); ok {
				ids = append(ids, s)
			}
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

// GetDirectFindingScoresByContainer devuelve los scores de findings contextuales directos de la imagen del contenedor.
func (r *riskRepo) GetDirectFindingScoresByContainer(ctx context.Context, containerID string) ([]domain.FindingRiskSummary, error) {
	query := `
		MATCH (c:Container {id: $container_id})-[:USES_IMAGE]->(ci:ContainerImage)
		MATCH (ci)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE f.container_id = c.id
		  AND f.image_id = ci.id
		  AND NOT toUpper(coalesce(f.status, 'OPEN')) IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED', 'SUPERSEDED']
		  AND coalesce(f.remediation_factor, 1.0) > 0.0
		  AND coalesce(f.risk_score, 0.0) > 0.0
		RETURN f.id AS finding_id,
		       v.cve_id AS cve_id,
		       coalesce(f.risk_score, 0.0) AS risk_score,
		       coalesce(f.priority_score, 0.0) AS priority_score,
		       coalesce(f.status, 'OPEN') AS status
		ORDER BY risk_score DESC
	`
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"container_id": containerID})
		if err != nil {
			return nil, err
		}
		var summaries []domain.FindingRiskSummary
		for result.Next(ctx) {
			rec := result.Record()
			fid, _ := rec.Get("finding_id")
			cve, _ := rec.Get("cve_id")
			rs, _ := rec.Get("risk_score")
			ps, _ := rec.Get("priority_score")
			st, _ := rec.Get("status")
			summaries = append(summaries, domain.FindingRiskSummary{
				FindingID:     toInt64(fid),
				CVEID:         toStr(cve),
				RiskScore:     toFloat64(rs),
				PriorityScore: toFloat64(ps),
				Status:        toStr(st),
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

// GetInstallationIDsByContainer devuelve las instalaciones de software internas
// de un contenedor para recalcularlas antes de agregar su riesgo.
func (r *riskRepo) GetInstallationIDsByContainer(ctx context.Context, containerID string) ([]string, error) {
	query := `
		MATCH (c:Container {id: $container_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		RETURN collect(DISTINCT coalesce(si.installation_id, si.id)) AS installation_ids
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"container_id": containerID})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return []string{}, result.Err()
		}
		values, ok := result.Record().Get("installation_ids")
		if !ok || values == nil {
			return []string{}, result.Err()
		}
		ids := make([]string, 0)
		switch items := values.(type) {
		case []any:
			for _, item := range items {
				if value, ok := item.(string); ok && value != "" {
					ids = append(ids, value)
				}
			}
		case []string:
			ids = append(ids, items...)
		default:
			return []string{}, result.Err()
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

// GetSoftwareRiskSummariesByContainer devuelve el resumen de riesgo de software instalado dentro de un contenedor.
func (r *riskRepo) GetSoftwareRiskSummariesByContainer(ctx context.Context, containerID string) ([]domain.SoftwareRiskSummary, error) {
	query := `
		MATCH (c:Container {id: $container_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		OPTIONAL MATCH (si)-[:INSTANCE_OF]->(s:Software)
		WHERE NOT coalesce(si.status, 'INSTALLED') IN ['REMOVED', 'UNINSTALLED', 'DELETED']
		RETURN si.id AS installation_id,
		       s.id AS software_id,
		       coalesce(s.name, si.name, si.id) AS software_name,
		       coalesce(si.risk_score, 0.0) AS risk_score,
		       coalesce(si.risk_tier, 'LOW') AS risk_tier,
		       coalesce(si.criticality_level, 'STANDARD') AS criticality_level,
		       coalesce(si.criticality_multiplier, 1.0) AS criticality_multiplier,
		       coalesce(si.priority_score, 0.0) AS priority_score,
		       coalesce(si.priority_tier, 'LOW') AS priority_tier,
		       si.driver_finding_id AS driver_finding_id,
		       si.driver_cve_id AS driver_cve_id,
		       si.status AS status
		ORDER BY priority_score DESC
	`
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"container_id": containerID})
		if err != nil {
			return nil, err
		}
		var summaries []domain.SoftwareRiskSummary
		for result.Next(ctx) {
			rec := result.Record()
			instID, _ := rec.Get("installation_id")
			swID, _ := rec.Get("software_id")
			swName, _ := rec.Get("software_name")
			riskScore, _ := rec.Get("risk_score")
			riskTier, _ := rec.Get("risk_tier")
			critLvl, _ := rec.Get("criticality_level")
			critMult, _ := rec.Get("criticality_multiplier")
			prioScore, _ := rec.Get("priority_score")
			prioTier, _ := rec.Get("priority_tier")
			driverFindingID, _ := rec.Get("driver_finding_id")
			driverCVEID, _ := rec.Get("driver_cve_id")
			st, _ := rec.Get("status")

			summaries = append(summaries, domain.SoftwareRiskSummary{
				InstallationID:        toStr(instID),
				SoftwareID:            toInt64(swID),
				SoftwareName:          toStr(swName),
				RiskScore:             toFloat64(riskScore),
				RiskTier:              toStr(riskTier),
				CriticalityLevel:      toStr(critLvl),
				CriticalityMultiplier: toFloat64(critMult),
				PriorityScore:         toFloat64(prioScore),
				PriorityTier:          toStr(prioTier),
				DriverFindingID:       toInt64(driverFindingID),
				DriverCVEID:           toStr(driverCVEID),
				DriverRiskScore:       toFloat64(riskScore),
				Status:                toStr(st),
			})
		}
		return summaries, result.Err()
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.SoftwareRiskSummary{}, nil
	}
	return res.([]domain.SoftwareRiskSummary), nil
}

// UpdateContainerRiskAndPriority persiste las puntuaciones agregadas, tiers y drivers en el nodo Container.
func (r *riskRepo) UpdateContainerRiskAndPriority(ctx context.Context, summary domain.ContainerRiskSummary) error {
	query := `
		MATCH (c:Container {id: $container_id})
		SET c.risk_score = $risk_score,
		    c.risk_tier = $risk_tier,
		    c.risk_computed_at = $now,
		    c.priority_score = $priority_score,
		    c.priority_tier = $priority_tier,
		    c.priority_computed_at = $now,
		    c.technical_driver_type = $technical_driver_type,
		    c.technical_driver_asset_id = $technical_driver_asset_id,
		    c.technical_driver_asset_name = $technical_driver_asset_name,
		    c.technical_driver_finding_id = $technical_driver_finding_id,
		    c.technical_driver_cve_id = $technical_driver_cve_id,
		    c.technical_driver_risk_score = $technical_driver_risk_score,
		    c.priority_driver_type = $priority_driver_type,
		    c.priority_driver_asset_id = $priority_driver_asset_id,
		    c.priority_driver_asset_name = $priority_driver_asset_name,
		    c.priority_driver_finding_id = $priority_driver_finding_id,
		    c.priority_driver_cve_id = $priority_driver_cve_id,
		    c.priority_driver_priority_score = $priority_driver_priority_score,
		    c.risky_asset_count = $risky_asset_count,
		    c.direct_finding_count = $direct_finding_count,
		    c.risky_installation_count = $risky_installation_count
	`
	params := map[string]any{
		"container_id":                   summary.ContainerID,
		"risk_score":                     summary.RiskScore,
		"risk_tier":                      summary.RiskTier,
		"priority_score":                 summary.PriorityScore,
		"priority_tier":                  summary.PriorityTier,
		"technical_driver_type":          summary.TechnicalDriverType,
		"technical_driver_asset_id":      summary.TechnicalDriverAssetID,
		"technical_driver_asset_name":    summary.TechnicalDriverAssetName,
		"technical_driver_finding_id":    summary.TechnicalDriverFindingID,
		"technical_driver_cve_id":        summary.TechnicalDriverCVEID,
		"technical_driver_risk_score":    summary.TechnicalDriverRiskScore,
		"priority_driver_type":           summary.PriorityDriverType,
		"priority_driver_asset_id":       summary.PriorityDriverAssetID,
		"priority_driver_asset_name":     summary.PriorityDriverAssetName,
		"priority_driver_finding_id":     summary.PriorityDriverFindingID,
		"priority_driver_cve_id":         summary.PriorityDriverCVEID,
		"priority_driver_priority_score": summary.PriorityDriverPriorityScore,
		"risky_asset_count":              summary.RiskyAssetCount,
		"direct_finding_count":           summary.DirectFindingCount,
		"risky_installation_count":       summary.RiskyInstallationCount,
		"now":                            time.Now().UTC(),
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}
