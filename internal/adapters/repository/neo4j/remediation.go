package neo4j

import (
	"context"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type remediationRepo struct {
	driver neo4j.DriverWithContext
}

func (r *remediationRepo) Save(ctx context.Context, rem *domain.Remediation) error {
	query := `MERGE (n:Remediation {id: $id}) ON CREATE SET n.fixed_version = $fv, n.status = $status`
	params := map[string]any{"id": rem.RemediationID, "fv": rem.FixedVersion, "status": rem.Status}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *remediationRepo) Update(ctx context.Context, rem *domain.Remediation) error {
	query := `MATCH (n:Remediation {id: $id}) SET n.fixed_version = $fv, n.status = $status`
	params := map[string]any{"id": rem.RemediationID, "fv": rem.FixedVersion, "status": rem.Status}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *remediationRepo) GetByID(ctx context.Context, id int64) (*domain.Remediation, error) {
	query := `MATCH (n:Remediation {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Remediation{
		RemediationID: getInt64(props, "id"),
		FixedVersion:  getString(props, "fixed_version"),
		Status:        getString(props, "status"),
	}, nil
}

func (r *remediationRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Remediation {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}

// GetFixedVersionByInstallationAndCVE devuelve la versión corregida registrada en la
// remediación, o cadena vacía si no consta.
func (r *remediationRepo) GetFixedVersionByInstallationAndCVE(ctx context.Context, installationID, cveID string) (string, error) {
	query := `
		MATCH (:SoftwareInstallation {id: $installation_id})-[:HAS_FINDING]->(f:Finding)
		      -[:OF_VULNERABILITY]->(:Vulnerability {cve_id: $cve_id})
		MATCH (f)-[:HAS_REMEDIATION]->(rem:Remediation)
		WHERE coalesce(rem.fixed_version, '') <> ''
		RETURN rem.fixed_version AS fixed_version
		LIMIT 1
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{
			"installation_id": installationID,
			"cve_id":          cveID,
		})
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			value, _ := result.Record().Get("fixed_version")
			return toStr(value), result.Err()
		}
		return "", result.Err()
	})

	if err != nil {
		return "", err
	}
	if res == nil {
		return "", nil
	}
	return res.(string), nil
}

// ApplyByInstallationAndCVE sincroniza estado y fecha en las remediaciones de los findings
// de una instalación para un CVE. appliedAt se desreferencia a any porque el driver no
// acepta punteros y al revertir hay que escribir null.
func (r *remediationRepo) ApplyByInstallationAndCVE(ctx context.Context, installationID, cveID, status string, appliedAt *time.Time) (int, error) {
	query := `
		MATCH (:SoftwareInstallation {id: $installation_id})-[:HAS_FINDING]->(f:Finding)
		      -[:OF_VULNERABILITY]->(:Vulnerability {cve_id: $cve_id})
		MATCH (f)-[:HAS_REMEDIATION]->(rem:Remediation)
		SET rem.status     = $status,
		    rem.applied_at = $applied_at
		RETURN count(rem) AS updated
	`

	var appliedAtParam any
	if appliedAt != nil {
		appliedAtParam = appliedAt.UTC()
	}

	params := map[string]any{
		"installation_id": installationID,
		"cve_id":          cveID,
		"status":          status,
		"applied_at":      appliedAtParam,
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	res, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			updated, _ := result.Record().Get("updated")
			return toInt64(updated), result.Err()
		}
		return int64(0), result.Err()
	})

	if err != nil {
		return 0, err
	}
	if res == nil {
		return 0, nil
	}
	return int(res.(int64)), nil
}

// UpdateFixedVersionByCVE fija la versión corregida en el nodo Vulnerability y,
// si existen, en todas las remediaciones asociadas a findings del CVE indicado.
// Algunos findings creados por el autoscan aún no tienen nodo Remediation, así
// que Vulnerability.fixed_version actúa como fallback para vistas como Patch Queue.
// Devuelve el número de remediaciones actualizadas.
func (r *remediationRepo) UpdateFixedVersionByCVE(ctx context.Context, cveID string, fixedVersion string) (int, error) {
	query := `
		MATCH (v:Vulnerability {cve_id: $cve_id})
		SET v.fixed_version = $fixed_version
		WITH v
		OPTIONAL MATCH (v)<-[:OF_VULNERABILITY]-(:Finding)-[:HAS_REMEDIATION]->(rem:Remediation)
		FOREACH (_ IN CASE WHEN rem IS NULL THEN [] ELSE [1] END |
			SET rem.fixed_version = $fixed_version
		)
		RETURN count(rem) AS updated
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	res, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{
			"cve_id":        cveID,
			"fixed_version": fixedVersion,
		})
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			updated, _ := result.Record().Get("updated")
			return toInt64(updated), result.Err()
		}
		return int64(0), result.Err()
	})

	if err != nil {
		return 0, err
	}
	if res == nil {
		return 0, nil
	}
	return int(res.(int64)), nil
}
