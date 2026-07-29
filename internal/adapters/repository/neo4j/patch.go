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
	query := `MERGE (n:Patch {id: $id}) ON CREATE SET n.description = $desc, n.url = $url, n.release_date = $release_date`

	var releaseDate any
	if p.ReleaseDate != nil {
		releaseDate = *p.ReleaseDate
	}

	params := map[string]any{
		"id":           p.PatchID,
		"desc":         p.Description,
		"url":          p.URL,
		"release_date": releaseDate,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *patchRepo) Update(ctx context.Context, p *domain.Patch) error {
	query := `MATCH (n:Patch {id: $id}) SET n.description = $desc, n.url = $url, n.release_date = $release_date`

	var releaseDate any
	if p.ReleaseDate != nil {
		releaseDate = *p.ReleaseDate
	}

	params := map[string]any{
		"id":           p.PatchID,
		"desc":         p.Description,
		"url":          p.URL,
		"release_date": releaseDate,
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
		ReleaseDate: getTimePtr(props, "release_date"),
	}, nil
}

func (r *patchRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Patch {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}

// GetByURL recupera un parche a partir de su URL, que identifica de forma única al
// parche publicado por el fabricante. Permite deduplicar antes de crear un nodo nuevo.
// Devuelve (nil, nil) si no existe.
func (r *patchRepo) GetByURL(ctx context.Context, url string) (*domain.Patch, error) {
	query := `MATCH (n:Patch {url: $url}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"url": url})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Patch{
		PatchID:     getInt64(props, "id"),
		Description: getString(props, "description"),
		URL:         getString(props, "url"),
		ReleaseDate: getTimePtr(props, "release_date"),
	}, nil
}

// GetByVulnerability recupera todos los parches que corrigen un CVE concreto,
// recorriendo la relación (Patch)-[:FIXES]->(Vulnerability).
func (r *patchRepo) GetByVulnerability(ctx context.Context, cveID string) ([]domain.Patch, error) {
	query := `
		MATCH (p:Patch)-[:FIXES]->(:Vulnerability {cve_id: $cve_id})
		RETURN p.id           AS id,
		       p.description  AS description,
		       p.url          AS url,
		       p.release_date AS release_date
		ORDER BY id
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"cve_id": cveID})
		if err != nil {
			return nil, err
		}

		patches := make([]domain.Patch, 0)
		for result.Next(ctx) {
			props := result.Record().AsMap()
			patches = append(patches, domain.Patch{
				PatchID:     getInt64(props, "id"),
				Description: getString(props, "description"),
				URL:         getString(props, "url"),
				ReleaseDate: getTimePtr(props, "release_date"),
			})
		}

		return patches, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.Patch{}, nil
	}
	return res.([]domain.Patch), nil
}
