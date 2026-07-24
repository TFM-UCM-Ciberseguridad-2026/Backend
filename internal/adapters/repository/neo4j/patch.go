package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type patchRepo struct {
	driver neo4j.DriverWithContext
}

func (r *patchRepo) Save(ctx context.Context, p *domain.Patch) error {
	query := `MERGE (n:Patch {id: $id}) ON CREATE SET n.description = $desc, n.url = $url`
	params := map[string]any{
		"id":   p.PatchID,
		"desc": p.Description,
		"url":  p.URL,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *patchRepo) Update(ctx context.Context, p *domain.Patch) error {
	query := `MATCH (n:Patch {id: $id}) SET n.description = $desc, n.url = $url`
	params := map[string]any{
		"id":   p.PatchID,
		"desc": p.Description,
		"url":  p.URL,
	}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *patchRepo) GetByID(ctx context.Context, id int64) (*domain.Patch, error) {
	query := `MATCH (n:Patch {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Patch{
		PatchID:     getInt64(props, "id"),
		Description: getString(props, "description"),
		URL:         getString(props, "url"),
	}, nil
}

func (r *patchRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Patch {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}
