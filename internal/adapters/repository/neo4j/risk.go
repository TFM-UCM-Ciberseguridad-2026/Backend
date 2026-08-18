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
		// El software o imagen cuelga del endpoint o de un contenedor que este aloja; el recorrido
		// variable cubre ambos caminos.
		MATCH (e:Endpoint {id: $endpoint_id})
		MATCH path = (e)-[:HAS_INSTALLATION|HOSTS|USES_IMAGE*1..3]->(asset)
		WHERE ('SoftwareInstallation' IN labels(asset) OR 'ContainerImage' IN labels(asset))
		MATCH (asset)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT coalesce(f.status, 'OPEN') IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED']
		  AND NOT toLower(coalesce(e.estado, e.status, '')) IN ['decomisado', 'decommissioned']
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
        WHERE NOT coalesce(f.status, 'OPEN') IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED']
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
        // Recorre también las instalaciones que cuelgan de un contenedor del endpoint.
        MATCH (e:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION|HOSTS*1..2]->(si:SoftwareInstallation)
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

// GetPatchQueue devuelve los findings pendientes ordenados por prioridad. projectID nulo
// recorre toda la infraestructura.
func (r *riskRepo) GetPatchQueue(ctx context.Context, projectID *int64, limit int) ([]domain.PatchQueueItem, error) {
	query := `
		MATCH (e:Endpoint)
		MATCH path = (e)-[:HAS_INSTALLATION|HOSTS|USES_IMAGE*1..3]->(asset)
		WHERE ('SoftwareInstallation' IN labels(asset) OR 'ContainerImage' IN labels(asset))
		MATCH (asset)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE NOT coalesce(f.status, 'OPEN') IN ['RESOLVED', 'FIXED', 'PATCHED', 'CLOSED']
		  AND ($project_id IS NULL OR EXISTS { (:Project {id: $project_id})-[:HAS_ENDPOINT]->(e) })
		OPTIONAL MATCH (asset)-[:INSTANCE_OF]->(s:Software)
		OPTIONAL MATCH (c:Container)-[:HAS_INSTALLATION|USES_IMAGE]->(asset)
		OPTIONAL MATCH (f)-[:HAS_REMEDIATION]->(rem:Remediation)
		RETURN f.id                AS finding_id,
		       f.status            AS status,
		       v.cve_id            AS cve_id,
		       asset.id            AS installation_id,
		       coalesce(s.name, asset.name, asset.id) AS software_name,
		       coalesce(s.version, 'N/A') AS software_version,
		       rem.fixed_version   AS fixed_version,
		       si.id               AS installation_id,
		       s.name              AS software_name,
		       s.version           AS software_version,
		       coalesce(rem.fixed_version, v.fixed_version) AS fixed_version,
		       e.id                AS endpoint_id,
		       e.hostname          AS hostname,
		       e.environment       AS environment,
		       c IS NOT NULL       AS in_container,
		       c.name              AS container_name,
		       f.risk_score        AS risk_score,
		       f.asset_criticality AS asset_criticality,
		       f.urgency_boost     AS urgency_boost,
		       f.priority_score    AS priority_score,
		       EXISTS { (:Patch)-[:FIXES]->(v) } AS patch_available
		// coalesce porque en Cypher los NULL ordenan primero con DESC: sin él, los
		// findings a los que aún no se les ha calculado la prioridad encabezarían la cola.
		ORDER BY coalesce(priority_score, 0.0) DESC, coalesce(risk_score, 0.0) DESC, finding_id ASC
		LIMIT $limit
	`

	var projectParam any
	if projectID != nil {
		projectParam = *projectID
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{
			"project_id": projectParam,
			"limit":      int64(limit),
		})
		if err != nil {
			return nil, err
		}

		items := make([]domain.PatchQueueItem, 0)
		for result.Next(ctx) {
			props := result.Record().AsMap()
			items = append(items, domain.PatchQueueItem{
				Position:         len(items) + 1,
				FindingID:        getInt64(props, "finding_id"),
				CVEID:            getString(props, "cve_id"),
				Status:           getString(props, "status"),
				InstallationID:   getString(props, "installation_id"),
				SoftwareName:     getString(props, "software_name"),
				SoftwareVersion:  getString(props, "software_version"),
				FixedVersion:     getString(props, "fixed_version"),
				EndpointID:       getInt64(props, "endpoint_id"),
				Hostname:         getString(props, "hostname"),
				Environment:      getString(props, "environment"),
				InContainer:      getBool(props, "in_container"),
				ContainerName:    getString(props, "container_name"),
				RiskScore:        getFloat64(props, "risk_score"),
				AssetCriticality: getFloat64(props, "asset_criticality"),
				UrgencyBoost:     getFloat64(props, "urgency_boost"),
				PriorityScore:    getFloat64(props, "priority_score"),
				PatchAvailable:   getBool(props, "patch_available"),
			})
		}
		return items, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.PatchQueueItem{}, nil
	}
	return res.([]domain.PatchQueueItem), nil
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
