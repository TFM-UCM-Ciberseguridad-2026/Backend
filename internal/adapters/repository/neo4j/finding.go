package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type findingRepo struct {
	driver neo4j.DriverWithContext
}

func (r *findingRepo) Save(ctx context.Context, f *domain.Finding) error {
	query := `MERGE (n:Finding {id: $id}) SET n.risk_score = $risk, n.status = $status`
	params := map[string]any{"id": f.FindingID, "risk": f.RiskScore, "status": f.Status}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *findingRepo) GetByID(ctx context.Context, id int64) (*domain.Finding, error) {
	query := `MATCH (n:Finding {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Finding{
		FindingID: getInt64(props, "id"),
		RiskScore: getFloat64(props, "risk_score"),
		Status:    getString(props, "status"),
	}, nil
}

func (r *findingRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Finding {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}
