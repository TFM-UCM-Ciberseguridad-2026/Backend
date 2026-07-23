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
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *remediationRepo) Update(ctx context.Context, rem *domain.Remediation) error {
	query := `MATCH (n:Remediation {id: $id}) SET n.fixed_version = $fv, n.status = $status`
	params := map[string]any{"id": rem.RemediationID, "fv": rem.FixedVersion, "status": rem.Status}
	return executeWriteHelper(ctx, r.driver, query, params)
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
