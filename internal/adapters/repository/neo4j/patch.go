package neo4j

import (
	"context"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type patchRepo struct {
	driver neo4j.DriverWithContext
}

// SaveApplication declara que un parche se ha aplicado sobre una instalación.
//
// Usa MERGE sobre la relación para que volver a declarar el mismo parche en la misma
// instalación actualice la arista en lugar de duplicarla: una instalación tiene una
// única situación actual respecto a un parche dado.
func (r *patchRepo) SaveApplication(ctx context.Context, a *domain.AppliedPatch) error {
	query := `
		MATCH (p:Patch {id: $patch_id})
		MATCH (si:SoftwareInstallation {id: $installation_id})
		MERGE (p)-[rel:APPLIED_TO]->(si)
		SET rel.applied_at         = $applied_at,
		    rel.applied_by         = $applied_by,
		    rel.remediation_level  = $remediation_level,
		    rel.remediation_factor = $remediation_factor,
		    rel.cve_id             = $cve_id,
		    rel.notes              = $notes
	`
	// Sin RETURN: executeWriteUpdateHelper añade el suyo para detectar si el MATCH
	// encontró algo, y dos RETURN seguidos son un error de sintaxis en Cypher.

	params := map[string]any{
		"patch_id":           a.PatchID,
		"installation_id":    a.InstallationID,
		"applied_at":         a.AppliedAt,
		"applied_by":         a.AppliedBy,
		"remediation_level":  string(a.RemediationLevel),
		"remediation_factor": a.RemediationFactor,
		"cve_id":             a.CVEID,
		"notes":              a.Notes,
	}

	// executeWriteUpdateHelper falla si el MATCH no encuentra el parche o la
	// instalación, que es justo lo que queremos: declarar sobre algo inexistente
	// es un error, no una operación silenciosa.
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

// GetApplicationsByInstallation devuelve el histórico de parches aplicados sobre una
// instalación, del más reciente al más antiguo.
func (r *patchRepo) GetApplicationsByInstallation(ctx context.Context, installationID string) ([]domain.AppliedPatch, error) {
	query := `
		MATCH (p:Patch)-[rel:APPLIED_TO]->(:SoftwareInstallation {id: $installation_id})
		RETURN p.id                AS patch_id,
		       p.url               AS patch_url,
		       p.description       AS patch_description,
		       rel.applied_at         AS applied_at,
		       rel.applied_by         AS applied_by,
		       rel.remediation_level  AS remediation_level,
		       rel.remediation_factor AS remediation_factor,
		       rel.cve_id             AS cve_id,
		       rel.notes              AS notes
		ORDER BY applied_at DESC
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"installation_id": installationID})
		if err != nil {
			return nil, err
		}

		applications := make([]domain.AppliedPatch, 0)
		for result.Next(ctx) {
			props := result.Record().AsMap()

			appliedAt := time.Time{}
			if t, ok := props["applied_at"].(time.Time); ok {
				appliedAt = t
			}

			applications = append(applications, domain.AppliedPatch{
				PatchID:           getInt64(props, "patch_id"),
				InstallationID:    installationID,
				CVEID:             getString(props, "cve_id"),
				AppliedAt:         appliedAt,
				AppliedBy:         getString(props, "applied_by"),
				RemediationLevel:  domain.RemediationLevel(getString(props, "remediation_level")),
				RemediationFactor: getFloat64(props, "remediation_factor"),
				Notes:             getString(props, "notes"),
				PatchURL:          getString(props, "patch_url"),
				PatchDescription:  getString(props, "patch_description"),
			})
		}

		return applications, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.AppliedPatch{}, nil
	}
	return res.([]domain.AppliedPatch), nil
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
