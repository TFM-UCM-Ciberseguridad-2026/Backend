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
	query := `
		MERGE (n:Finding {id: $id})
		SET n.status = $status,
		    n.first_seen = $first_seen,
		    n.last_seen = $last_seen,
		    n.resolved_at = $resolved_at,
		    n.impact_score = $impact_score,
		    n.likelihood = $likelihood,
		    n.remediation_factor = $remediation_factor,
		    n.risk_score = $risk_score,
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
		"remediation_factor": f.RemediationFactor,
		"risk_score":         f.RiskScore,
		"priority_score":     f.PriorityScore,
		"risk_computed_at":   riskComputedAt,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
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
		RemediationFactor: getFloat64(props, "remediation_factor"),
		RiskScore:         getFloat64(props, "risk_score"),
		PriorityScore:     getFloat64(props, "priority_score"),
		RiskComputedAt:    getTimePtr(props, "risk_computed_at"),
	}, nil
}

func (r *findingRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Finding {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}
