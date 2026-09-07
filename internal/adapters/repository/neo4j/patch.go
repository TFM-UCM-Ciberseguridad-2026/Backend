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

// SaveApplication declara un parche como aplicado sobre una instalación. MERGE sobre la
// relación: una instalación tiene una única situación actual respecto a un parche, así que
// redeclarar actualiza la arista en vez de duplicarla.
func (r *patchRepo) SaveApplication(ctx context.Context, a *domain.AppliedPatch) error {
	query := `
		MATCH (p:Patch {id: $patch_id})
		MATCH (target)
		WHERE ($asset_type = 'CONTAINER' AND target:Container AND target.id = $container_id)
		   OR ($asset_type <> 'CONTAINER' AND target:SoftwareInstallation AND target.id = $installation_id)
		MERGE (p)-[rel:APPLIED_TO]->(target)
		SET rel.applied_at         = $applied_at,
		    rel.applied_by         = $applied_by,
		    rel.remediation_level  = $remediation_level,
		    rel.remediation_factor = $remediation_factor,
		    rel.cve_id             = $cve_id,
		    rel.notes              = $notes,
		    rel.verified           = $verified,
		    rel.verification_conclusive = $verification_conclusive,
		    rel.verification_reason     = $verification_reason,
		    rel.installed_version       = $installed_version,
		    rel.expected_version        = $expected_version,
		    rel.matched_package         = $matched_package,
		    rel.asset_type              = CASE WHEN $asset_type = '' THEN CASE WHEN target:Container THEN 'CONTAINER' ELSE 'SOFTWARE_INSTALLATION' END ELSE $asset_type END,
		    rel.asset_id                = CASE WHEN $asset_id = '' THEN target.id ELSE $asset_id END,
		    rel.container_id            = CASE WHEN $container_id = '' AND target:Container THEN target.id ELSE $container_id END,
		    rel.image_id                = CASE WHEN $image_id = '' AND target:Container THEN coalesce(target.image_id, '') ELSE $image_id END,
		    rel.finding_id              = $finding_id
	`
	// Sin RETURN propio: executeWriteUpdateHelper añade el suyo y dos seguidos son
	// error de sintaxis.

	params := map[string]any{
		"patch_id":                a.PatchID,
		"installation_id":         a.InstallationID,
		"asset_type":              a.AssetType,
		"asset_id":                a.AssetID,
		"container_id":            a.ContainerID,
		"image_id":                a.ImageID,
		"finding_id":              a.FindingID,
		"applied_at":              a.AppliedAt,
		"applied_by":              a.AppliedBy,
		"remediation_level":       string(a.RemediationLevel),
		"remediation_factor":      a.RemediationFactor,
		"cve_id":                  a.CVEID,
		"notes":                   a.Notes,
		"verified":                a.Verification.Verified,
		"verification_conclusive": a.Verification.Conclusive,
		"verification_reason":     a.Verification.Reason,
		"installed_version":       a.Verification.InstalledVersion,
		"expected_version":        a.Verification.ExpectedVersion,
		"matched_package":         a.Verification.MatchedPackage,
	}

	// El helper falla si el MATCH no encuentra parche o instalación, que es lo deseado:
	// declarar sobre algo inexistente no debe pasar en silencio.
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

// GetApplicationsByInstallation devuelve el histórico de una instalación, del más
// reciente al más antiguo.

// GetByProject devuelve, agrupados por CVE, los parches publicados para las
// vulnerabilidades del alcance de un proyecto.
//
// Es una sola consulta a propósito: quien lo consume es la ficha de una técnica ATT&CK,
// que puede reunir más de cien CVE, y resolverlas de una en una contra
// /api/vulnerabilities/{cve}/patches sería un N+1 desde el navegador.
//
// El alcance replica el de la matriz de TTPs: una CVE entra si el proyecto tiene un
// hallazgo suyo, o si cuelga de la imagen de un contenedor por HAS_VULNERABILITY, que es
// el camino por el que llegan las CVE de imagen todavía sin hallazgo. Con projectID 0 no
// se acota nada y se devuelve el grafo entero.
func (r *patchRepo) GetByProject(ctx context.Context, projectID int64) ([]domain.CVEPatches, error) {
	query := `
		MATCH (p:Patch)-[:FIXES]->(v:Vulnerability)
		WHERE $project_id = 0 OR toString($project_id) = "0"
		   OR EXISTS {
		        MATCH (proj:Project)-[:HAS_ENDPOINT]->(scoped)-[:HAS_INSTALLATION|HOSTS|USES_IMAGE*1..3]->(asset)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)
		        WHERE proj.id = $project_id OR toString(proj.id) = toString($project_id) OR proj.name = toString($project_id)
		      }
		   OR EXISTS {
		        MATCH (proj:Project)-[:HAS_ENDPOINT]->(scoped)-[:HAS_INSTALLATION|HOSTS|USES_IMAGE*1..3]->(img:ContainerImage)-[:HAS_VULNERABILITY]->(v)
		        WHERE proj.id = $project_id OR toString(proj.id) = toString($project_id) OR proj.name = toString($project_id)
		      }
		WITH v, p
		ORDER BY p.id
		RETURN coalesce(v.cve_id, '') AS cve_id,
		       collect(DISTINCT {
		         id:           p.id,
		         description:  p.description,
		         url:          p.url,
		         release_date: p.release_date
		       }) AS patches
		ORDER BY cve_id
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"project_id": projectID})
		if err != nil {
			return nil, err
		}

		agrupados := make([]domain.CVEPatches, 0)
		for result.Next(ctx) {
			rec := result.Record().AsMap()

			cveID := getString(rec, "cve_id")
			if cveID == "" {
				continue
			}

			lista, _ := rec["patches"].([]any)
			patches := make([]domain.Patch, 0, len(lista))
			for _, item := range lista {
				props, ok := item.(map[string]any)
				if !ok {
					continue
				}
				patches = append(patches, domain.Patch{
					PatchID:     getInt64(props, "id"),
					Description: getString(props, "description"),
					URL:         getString(props, "url"),
					ReleaseDate: getTimePtr(props, "release_date"),
				})
			}

			agrupados = append(agrupados, domain.CVEPatches{CVEID: cveID, Patches: patches})
		}

		return agrupados, result.Err()
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return []domain.CVEPatches{}, nil
	}
	return res.([]domain.CVEPatches), nil
}
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
		       rel.notes              AS notes,
		       rel.verified                AS verified,
		       rel.verification_conclusive AS verification_conclusive,
		       rel.verification_reason     AS verification_reason,
		       rel.installed_version       AS installed_version,
		       rel.expected_version        AS expected_version,
		       rel.matched_package         AS matched_package,
		       rel.asset_type              AS asset_type,
		       rel.asset_id                AS asset_id,
		       rel.container_id            AS container_id,
		       rel.image_id                AS image_id,
		       rel.finding_id              AS finding_id
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
				AssetType:         getString(props, "asset_type"),
				AssetID:           getString(props, "asset_id"),
				InstallationID:    installationID,
				ContainerID:       getString(props, "container_id"),
				ImageID:           getString(props, "image_id"),
				FindingID:         getInt64(props, "finding_id"),
				CVEID:             getString(props, "cve_id"),
				AppliedAt:         appliedAt,
				AppliedBy:         getString(props, "applied_by"),
				RemediationLevel:  domain.RemediationLevel(getString(props, "remediation_level")),
				RemediationFactor: getFloat64(props, "remediation_factor"),
				Notes:             getString(props, "notes"),
				Verification: domain.PatchVerification{
					Verified:         getBool(props, "verified"),
					Conclusive:       getBool(props, "verification_conclusive"),
					Reason:           getString(props, "verification_reason"),
					InstalledVersion: getString(props, "installed_version"),
					ExpectedVersion:  getString(props, "expected_version"),
					MatchedPackage:   getString(props, "matched_package"),
				},
				PatchURL:         getString(props, "patch_url"),
				PatchDescription: getString(props, "patch_description"),
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

func (r *patchRepo) GetApplicationsByContainer(ctx context.Context, containerID string) ([]domain.AppliedPatch, error) {
	query := `
		MATCH (p:Patch)-[rel:APPLIED_TO]->(c:Container {id: $container_id})
		RETURN p.id AS patch_id, p.url AS patch_url, p.description AS patch_description,
		       rel.asset_type AS asset_type, rel.asset_id AS asset_id,
		       rel.container_id AS container_id, rel.image_id AS image_id, rel.finding_id AS finding_id,
		       rel.applied_at AS applied_at, rel.applied_by AS applied_by,
		       rel.remediation_level AS remediation_level, rel.remediation_factor AS remediation_factor,
		       rel.cve_id AS cve_id, rel.notes AS notes,
		       rel.verified AS verified, rel.verification_conclusive AS verification_conclusive,
		       rel.verification_reason AS verification_reason, rel.installed_version AS installed_version,
		       rel.expected_version AS expected_version, rel.matched_package AS matched_package
		ORDER BY applied_at DESC
	`
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"container_id": containerID})
		if err != nil {
			return nil, err
		}
		applications := make([]domain.AppliedPatch, 0)
		for result.Next(ctx) {
			props := result.Record().AsMap()
			appliedAt := time.Time{}
			if value, ok := props["applied_at"].(time.Time); ok {
				appliedAt = value
			}
			applications = append(applications, domain.AppliedPatch{
				PatchID: getInt64(props, "patch_id"), AssetType: getString(props, "asset_type"), AssetID: getString(props, "asset_id"),
				ContainerID: containerID, ImageID: getString(props, "image_id"), FindingID: getInt64(props, "finding_id"), CVEID: getString(props, "cve_id"),
				AppliedAt: appliedAt, AppliedBy: getString(props, "applied_by"), RemediationLevel: domain.RemediationLevel(getString(props, "remediation_level")),
				RemediationFactor: getFloat64(props, "remediation_factor"), Notes: getString(props, "notes"),
				Verification: domain.PatchVerification{Verified: getBool(props, "verified"), Conclusive: getBool(props, "verification_conclusive"), Reason: getString(props, "verification_reason"), InstalledVersion: getString(props, "installed_version"), ExpectedVersion: getString(props, "expected_version"), MatchedPackage: getString(props, "matched_package")},
				PatchURL:     getString(props, "patch_url"), PatchDescription: getString(props, "patch_description"),
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
