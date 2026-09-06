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

// SaveApplication declara un parche como aplicado distinguiendo por cve_id para no sobrescribir relaciones.
func (r *patchRepo) SaveApplication(ctx context.Context, a *domain.AppliedPatch) error {
	query := `
		MATCH (p:Patch) WHERE p.id = $patch_id OR toInteger(p.id) = toInteger($patch_id) OR toString(p.id) = toString($patch_id)
		MATCH (target)
		WHERE ($asset_type = 'CONTAINER' AND target:Container AND (target.id = $container_id OR toString(target.id) = toString($container_id)))
		   OR ($asset_type <> 'CONTAINER' AND target:SoftwareInstallation AND (target.id = $installation_id OR toString(target.id) = toString($installation_id)))
		MERGE (p)-[rel:APPLIED_TO {cve_id: $cve_id}]->(target)
		SET rel.applied_at              = $applied_at,
		    rel.applied_by              = $applied_by,
		    rel.remediation_level       = $remediation_level,
		    rel.remediation_factor      = $remediation_factor,
		    rel.notes                   = $notes,
		    rel.verified                = $verified,
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

	return executeWriteUpdateHelper(ctx, r.driver, query, params)
}

// GetAppliedPatchHistoryByEndpoint recupera el histórico de parches y findings resueltos agrupado por software.
func (r *patchRepo) GetAppliedPatchHistoryByEndpoint(ctx context.Context, endpointID int64) (*domain.EndpointPatchHistory, error) {
	query := `
		MATCH (e:Endpoint)
		WHERE e.id = $endpoint_id OR toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)
		OPTIONAL MATCH (e)-[:HAS_INSTALLATION|HOSTS*1..2]->(si:SoftwareInstallation)
		OPTIONAL MATCH (si)-[:INSTANCE_OF]->(s:Software)
		OPTIONAL MATCH (p:Patch)-[rel:APPLIED_TO]->(si)
		OPTIONAL MATCH (si)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		WHERE (toUpper(coalesce(f.status, '')) IN ['PATCHED', 'RESOLVED', 'CLOSED', 'MITIGATED'] OR f.remediation_factor = 0.0)
		  AND (rel.cve_id = v.cve_id OR (p IS NOT NULL AND (p)-[:FIXES]->(v)) OR rel IS NOT NULL)
		
		WITH e, si, s,
		     collect(DISTINCT CASE WHEN p IS NOT NULL AND rel IS NOT NULL THEN {
		         patch_id: p.id,
		         patch_url: coalesce(p.url, ''),
		         patch_description: coalesce(p.description, ''),
		         cve_id: coalesce(rel.cve_id, ''),
		         applied_at: rel.applied_at,
		         applied_by: coalesce(rel.applied_by, ''),
		         remediation_level: coalesce(rel.remediation_level, 'OFFICIAL_FIX'),
		         remediation_factor: coalesce(rel.remediation_factor, 0.0),
		         notes: coalesce(rel.notes, ''),
		         verified: coalesce(rel.verified, false),
		         verification_conclusive: coalesce(rel.verification_conclusive, false),
		         verification_reason: coalesce(rel.verification_reason, ''),
		         installed_version: coalesce(rel.installed_version, ''),
		         expected_version: coalesce(rel.expected_version, '')
		     } ELSE null END) AS raw_patches,
		     collect(DISTINCT CASE WHEN f IS NOT NULL AND v IS NOT NULL THEN {
		         finding_id: f.id,
		         cve_id: v.cve_id,
		         status: coalesce(f.status, 'PATCHED'),
		         patch_id: coalesce(p.id, 0),
		         patch_description: coalesce(p.description, rel.notes, 'Parche oficial aplicado'),
		         patch_url: coalesce(p.url, ''),
		         remediation_level: coalesce(rel.remediation_level, 'OFFICIAL_FIX'),
		         applied_at: coalesce(rel.applied_at, f.resolved_at, f.last_seen),
		         applied_by: coalesce(rel.applied_by, 'operator'),
		         notes: coalesce(rel.notes, ''),
		         expected_version: coalesce(rel.expected_version, s.version, '')
		     } ELSE null END) AS raw_findings
		WHERE si IS NOT NULL
		RETURN e.id AS endpoint_id,
		       coalesce(e.hostname, '') AS hostname,
		       collect({
		           installation_id: si.id,
		           software_id: coalesce(s.id, 0),
		           software_name: coalesce(s.name, si.install_path, si.id),
		           current_version: coalesce(s.version, 'N/A'),
		           applied_patches: [p IN raw_patches WHERE p IS NOT NULL],
		           resolved_findings: [f IN raw_findings WHERE f IS NOT NULL]
		       }) AS software_groups
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{"endpoint_id": endpointID})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, nil
		}

		rec := result.Record()
		epID := getInt64Any(rec.Values[0])
		hostname := getStringAny(rec.Values[1])
		groupsRaw, _ := rec.Get("software_groups")

		var groups []domain.SoftwarePatchHistoryGroup
		if list, ok := groupsRaw.([]any); ok {
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}

				instID := getString(m, "installation_id")
				swID := getInt64(m, "software_id")
				swName := getString(m, "software_name")
				currVer := getString(m, "current_version")

				var patches []domain.AppliedPatch
				if pList, ok := m["applied_patches"].([]any); ok {
					for _, pItem := range pList {
						pMap, ok := pItem.(map[string]any)
						if !ok {
							continue
						}
						appliedAt := time.Time{}
						if t, ok := pMap["applied_at"].(time.Time); ok {
							appliedAt = t
						}
						patches = append(patches, domain.AppliedPatch{
							PatchID:           getInt64(pMap, "patch_id"),
							InstallationID:    instID,
							CVEID:             getString(pMap, "cve_id"),
							AppliedAt:         appliedAt,
							AppliedBy:         getString(pMap, "applied_by"),
							RemediationLevel:  domain.RemediationLevel(getString(pMap, "remediation_level")),
							RemediationFactor: getFloat64(pMap, "remediation_factor"),
							Notes:             getString(pMap, "notes"),
							PatchURL:          getString(pMap, "patch_url"),
							PatchDescription:  getString(pMap, "patch_description"),
							Verification: domain.PatchVerification{
								Verified:         getBool(pMap, "verified"),
								Conclusive:       getBool(pMap, "verification_conclusive"),
								Reason:           getString(pMap, "verification_reason"),
								InstalledVersion: getString(pMap, "installed_version"),
								ExpectedVersion:  getString(pMap, "expected_version"),
							},
						})
					}
				}

				var findings []domain.ResolvedFindingInfo
				if fList, ok := m["resolved_findings"].([]any); ok {
					for _, fItem := range fList {
						fMap, ok := fItem.(map[string]any)
						if !ok {
							continue
						}
						appliedAt := time.Time{}
						if t, ok := fMap["applied_at"].(time.Time); ok {
							appliedAt = t
						}
						findings = append(findings, domain.ResolvedFindingInfo{
							FindingID:          getInt64(fMap, "finding_id"),
							CVEID:              getString(fMap, "cve_id"),
							Status:             getString(fMap, "status"),
							PatchID:            getInt64(fMap, "patch_id"),
							PatchDescription:   getString(fMap, "patch_description"),
							PatchURL:           getString(fMap, "patch_url"),
							RemediationLevel:   getString(fMap, "remediation_level"),
							AppliedAt:          appliedAt,
							AppliedBy:          getString(fMap, "applied_by"),
							Notes:              getString(fMap, "notes"),
							ExpectedVersion:    getString(fMap, "expected_version"),
						})
					}
				}

				groups = append(groups, domain.SoftwarePatchHistoryGroup{
					InstallationID:   instID,
					SoftwareID:       swID,
					SoftwareName:     swName,
					CurrentVersion:   currVer,
					AppliedPatches:   patches,
					ResolvedFindings: findings,
				})
			}
		}

		return &domain.EndpointPatchHistory{
			EndpointID:     epID,
			Hostname:       hostname,
			SoftwareGroups: groups,
		}, nil
	})

	if err != nil {
		return nil, err
	}
	if res == nil {
		return &domain.EndpointPatchHistory{EndpointID: endpointID, SoftwareGroups: []domain.SoftwarePatchHistoryGroup{}}, nil
	}
	return res.(*domain.EndpointPatchHistory), nil
}

// GetApplicationsByInstallation devuelve el histórico de una instalación concreta.
func (r *patchRepo) GetApplicationsByInstallation(ctx context.Context, installationID string) ([]domain.AppliedPatch, error) {
	query := `
		MATCH (p:Patch)-[rel:APPLIED_TO]->(si:SoftwareInstallation)
		WHERE si.id = $installation_id OR toString(si.id) = toString($installation_id)
		RETURN p.id                        AS patch_id,
		       p.url                       AS patch_url,
		       p.description               AS patch_description,
		       rel.applied_at              AS applied_at,
		       rel.applied_by              AS applied_by,
		       rel.remediation_level       AS remediation_level,
		       rel.remediation_factor      AS remediation_factor,
		       rel.cve_id                  AS cve_id,
		       rel.notes                   AS notes,
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