package neo4j

import (
	"context"

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

// UpdateFixedVersionByCVE fija la versión corregida en todas las remediaciones asociadas
// a findings del CVE indicado, recorriendo
// (Vulnerability)<-[:OF_VULNERABILITY]-(Finding)-[:HAS_REMEDIATION]->(Remediation).
// Devuelve el número de remediaciones actualizadas.
func (r *remediationRepo) UpdateFixedVersionByCVE(ctx context.Context, cveID string, fixedVersion string) (int, error) {
	query := `
		MATCH (:Vulnerability {cve_id: $cve_id})<-[:OF_VULNERABILITY]-(:Finding)-[:HAS_REMEDIATION]->(rem:Remediation)
		SET rem.fixed_version = $fixed_version
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
