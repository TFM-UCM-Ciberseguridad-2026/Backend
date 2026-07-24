package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type projectRepo struct {
	driver neo4j.DriverWithContext
}

func (r *projectRepo) Save(ctx context.Context, p *domain.Project) error {
	query := `MERGE (n:Project {id: $id}) ON CREATE SET n.nombre = $name`
	params := map[string]any{
		"id":   p.ProjectID,
		"name": p.Nombre,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *projectRepo) Update(ctx context.Context, p *domain.Project) error {
	query := `MATCH (n:Project {id: $id}) SET n.nombre = $name`
	params := map[string]any{
		"id":   p.ProjectID,
		"name": p.Nombre,
	}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

func (r *projectRepo) GetByID(ctx context.Context, id int64) (*domain.Project, error) {
	query := `MATCH (n:Project {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Project{
		ProjectID: getInt64(props, "id"),
		Nombre:    getString(props, "nombre"),
	}, nil
}

func (r *projectRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Project {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}
