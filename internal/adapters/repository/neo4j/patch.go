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

// SaveApplication declara un parche como aplicado. Permite que convivan TEMPORARY_FIX y OFFICIAL_FIX para el mismo CVE.
func (r *patchRepo) SaveApplication(ctx context.Context, a *domain.AppliedPatch) error {
	query := `
		MATCH (p:Patch) WHERE p.id = $patch_id OR toInteger(p.id) = toInteger($patch_id) OR toString(p.id) = toString($patch_id)
		MATCH (target)
		WHERE ($asset_type = 'CONTAINER' AND target:Container AND (target.id = $container_id OR toString(target.id) = toString($container_id)))
		   OR ($asset_type <> 'CONTAINER' AND target:SoftwareInstallation AND (target.id = $installation_id OR toString(target.id) = toString($installation_id)))
		MERGE (p)-[rel:APPLIED_TO {cve_id: $cve_id, remediation_level: $remediation_level}]->(target)
		SET rel.applied_at              = $applied_at,
		    rel.applied_by              = $applied_by,
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

// GetAppliedPatchHistoryByEndpoint recupera el histórico de parches y findings resueltos
// agrupado por software tradicional y por imágenes de contenedores alojadas en el endpoint.
func (r *patchRepo) GetAppliedPatchHistoryByEndpoint(ctx context.Context, endpointID int64) (*domain.EndpointPatchHistory, error) {
	query := `
		MATCH (e:Endpoint)
		WHERE e.id = $endpoint_id OR toInteger(e.id) = toInteger($endpoint_id) OR toString(e.id) = toString($endpoint_id) OR elementId(e) = toString($endpoint_id)

		// ── RAMA 1: Software nativo en el host o instalaciones en contenedor ──
		OPTIONAL MATCH (e)-[:HAS_INSTALLATION|HOSTS*1..2]->(si:SoftwareInstallation)
		OPTIONAL MATCH (si)-[:INSTANCE_OF]->(s:Software)
		
		// 1.1 Parches aplicados en la instalación
		OPTIONAL MATCH (p1:Patch)-[rel1:APPLIED_TO]->(si)
		WITH e, si, s,
		     collect(DISTINCT CASE WHEN p1 IS NOT NULL AND rel1 IS NOT NULL THEN {
		         patch_id: p1.id,
		         patch_url: coalesce(p1.url, ''),
		         patch_description: coalesce(p1.description, ''),
		         cve_id: coalesce(rel1.cve_id, ''),
		         applied_at: rel1.applied_at,
		         applied_by: coalesce(rel1.applied_by, ''),
		         remediation_level: coalesce(rel1.remediation_level, 'OFFICIAL_FIX'),
		         remediation_factor: coalesce(rel1.remediation_factor, 0.0),
		         notes: coalesce(rel1.notes, ''),
		         verified: coalesce(rel1.verified, false),
		         verification_conclusive: coalesce(rel1.verification_conclusive, false),
		         verification_reason: coalesce(rel1.verification_reason, ''),
		         installed_version: coalesce(rel1.installed_version, ''),
		         expected_version: coalesce(rel1.expected_version, rel1.installed_version, s.version, '')
		     } ELSE null END) AS si_raw_patches

		// 1.2 Findings resueltos emparejados EXACTAMENTE por su cve_id aplicado (sin relaciones cruzadas)
		OPTIONAL MATCH (si)-[:HAS_FINDING]->(f1:Finding)-[:OF_VULNERABILITY]->(v1:Vulnerability)
		WHERE (toUpper(coalesce(f1.status, '')) IN ['PATCHED', 'RESOLVED', 'CLOSED', 'MITIGATED', 'SUPERSEDED'] OR f1.remediation_factor = 0.0)
		OPTIONAL MATCH (p1_match:Patch)-[rel1_match:APPLIED_TO]->(si)
		WHERE rel1_match.cve_id = v1.cve_id

		WITH e, si, s, si_raw_patches,
		     collect(DISTINCT CASE WHEN f1 IS NOT NULL AND v1 IS NOT NULL THEN {
		         finding_id: f1.id,
		         cve_id: v1.cve_id,
		         status: coalesce(f1.status, 'PATCHED'),
		         patch_id: coalesce(p1_match.id, 0),
		         patch_description: coalesce(p1_match.description, rel1_match.notes, 'Parche oficial aplicado'),
		         patch_url: coalesce(p1_match.url, ''),
		         remediation_level: coalesce(rel1_match.remediation_level, 'OFFICIAL_FIX'),
		         applied_at: coalesce(rel1_match.applied_at, f1.resolved_at, f1.last_seen),
		         applied_by: coalesce(rel1_match.applied_by, 'operator'),
		         notes: coalesce(rel1_match.notes, ''),
		         expected_version: coalesce(rel1_match.expected_version, rel1_match.installed_version, s.version, '')
		     } ELSE null END) AS si_raw_findings

		WITH e,
		     collect(CASE WHEN si IS NOT NULL THEN {
		         installation_id: si.id,
		         software_id: coalesce(s.id, 0),
		         software_name: coalesce(s.name, si.install_path, si.id),
		         current_version: coalesce(s.version, 'N/A'),
		         applied_patches: [p IN si_raw_patches WHERE p IS NOT NULL],
		         resolved_findings: [f IN si_raw_findings WHERE f IS NOT NULL]
		     } ELSE null END) AS si_groups

		// ── RAMA 2: Contenedores e imágenes de contenedor alojadas en el endpoint ──
		OPTIONAL MATCH (e)-[:HOSTS]->(c:Container)
		OPTIONAL MATCH (c)-[:USES_IMAGE]->(ci:ContainerImage)
		
		// 2.1 Parches aplicados a contenedores
		OPTIONAL MATCH (p2:Patch)-[rel2:APPLIED_TO]->(target2)
		WHERE target2 = c OR target2 = ci
		WITH e, si_groups, c, ci,
		     collect(DISTINCT CASE WHEN p2 IS NOT NULL AND rel2 IS NOT NULL THEN {
		         patch_id: p2.id,
		         patch_url: coalesce(p2.url, ''),
		         patch_description: coalesce(p2.description, ''),
		         cve_id: coalesce(rel2.cve_id, ''),
		         applied_at: rel2.applied_at,
		         applied_by: coalesce(rel2.applied_by, ''),
		         remediation_level: coalesce(rel2.remediation_level, 'OFFICIAL_FIX'),
		         remediation_factor: coalesce(rel2.remediation_factor, 0.0),
		         notes: coalesce(rel2.notes, ''),
		         verified: coalesce(rel2.verified, false),
		         verification_conclusive: coalesce(rel2.verification_conclusive, false),
		         verification_reason: coalesce(rel2.verification_reason, ''),
		         installed_version: coalesce(rel2.installed_version, ci.tag, ''),
		         expected_version: coalesce(rel2.expected_version, rel2.installed_version, ci.tag, '')
		     } ELSE null END) AS c_raw_patches

		// 2.2 Findings resueltos de contenedores emparejados EXACTAMENTE por cve_id
		OPTIONAL MATCH (ci_or_c)-[:HAS_FINDING]->(f2:Finding)-[:OF_VULNERABILITY]->(v2:Vulnerability)
		WHERE (ci_or_c = ci OR ci_or_c = c)
		  AND (f2.container_id = c.id OR f2.container_id IS NULL OR f2.image_id = ci.id)
		  AND (toUpper(coalesce(f2.status, '')) IN ['PATCHED', 'RESOLVED', 'CLOSED', 'MITIGATED', 'SUPERSEDED'] OR f2.remediation_factor = 0.0)
		OPTIONAL MATCH (p2_match:Patch)-[rel2_match:APPLIED_TO]->(target2_match)
		WHERE (target2_match = c OR target2_match = ci) AND rel2_match.cve_id = v2.cve_id

		WITH e, si_groups, c, ci, c_raw_patches,
		     collect(DISTINCT CASE WHEN f2 IS NOT NULL AND v2 IS NOT NULL THEN {
		         finding_id: f2.id,
		         cve_id: v2.cve_id,
		         status: coalesce(f2.status, 'PATCHED'),
		         patch_id: coalesce(p2_match.id, 0),
		         patch_description: coalesce(p2_match.description, rel2_match.notes, 'Vulnerabilidad de contenedor resuelta'),
		         patch_url: coalesce(p2_match.url, ''),
		         remediation_level: coalesce(rel2_match.remediation_level, 'OFFICIAL_FIX'),
		         applied_at: coalesce(rel2_match.applied_at, f2.resolved_at, f2.last_seen),
		         applied_by: coalesce(rel2_match.applied_by, 'operator'),
		         notes: coalesce(rel2_match.notes, ''),
		         expected_version: coalesce(rel2_match.expected_version, rel2_match.installed_version, ci.tag, '')
		     } ELSE null END) AS c_raw_findings

		WITH e, si_groups,
		     collect(CASE WHEN c IS NOT NULL AND (size(c_raw_patches) > 0 OR size(c_raw_findings) > 0) THEN {
		         installation_id: c.id,
		         software_id: 0,
		         software_name: CASE
		             WHEN ci IS NOT NULL THEN 'Contenedor: ' + coalesce(c.name, c.id) + ' (' + coalesce(ci.name, ci.id) + ')'
		             ELSE 'Contenedor: ' + coalesce(c.name, c.id)
		         END,
		         current_version: coalesce(ci.tag, 'latest'),
		         applied_patches: [p IN c_raw_patches WHERE p IS NOT NULL],
		         resolved_findings: [f IN c_raw_findings WHERE f IS NOT NULL]
		     } ELSE null END) AS c_groups

		// ── UNIFICACIÓN ──
		RETURN e.id AS endpoint_id,
		       coalesce(e.hostname, '') AS hostname,
		       [g IN (si_groups + c_groups) WHERE g IS NOT NULL AND (g.software_id > 0 OR size(g.applied_patches) > 0 OR size(g.resolved_findings) > 0)] AS software_groups
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
	query := `MERGE (n:Patch {id: $id}) ON CREATE SET n.description = $desc, n.url = $url, n.release_date = $release_date, n.source = $source, n.reference_type = $reference_type, n.official = $official, n.fixed_version = $fixed_version`

	var releaseDate any
	if p.ReleaseDate != nil {
		releaseDate = *p.ReleaseDate
	}

	params := map[string]any{
		"id":           p.PatchID,
		"desc":         p.Description,
		"url":          p.URL,
		"release_date": releaseDate,
		"source":         p.Source,
		"reference_type": p.ReferenceType,
		"official":       p.Official,
		"fixed_version":  p.FixedVersion,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *patchRepo) Update(ctx context.Context, p *domain.Patch) error {
	query := `MATCH (n:Patch {id: $id}) SET n.description = $desc, n.url = $url, n.release_date = $release_date, n.source = $source, n.reference_type = $reference_type, n.official = $official, n.fixed_version = $fixed_version`

	var releaseDate any
	if p.ReleaseDate != nil {
		releaseDate = *p.ReleaseDate
	}

	params := map[string]any{
		"id":           p.PatchID,
		"desc":         p.Description,
		"url":          p.URL,
		"release_date": releaseDate,
		"source":         p.Source,
		"reference_type": p.ReferenceType,
		"official":       p.Official,
		"fixed_version":  p.FixedVersion,
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
		Source:        getString(props, "source"),
		ReferenceType: getString(props, "reference_type"),
		Official:      getBool(props, "official"),
		FixedVersion:  getString(props, "fixed_version"),
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
		Source:        getString(props, "source"),
		ReferenceType: getString(props, "reference_type"),
		Official:      getBool(props, "official"),
		FixedVersion:  getString(props, "fixed_version"),
	}, nil
}

// GetByVulnerability recupera todos los parches que corrigen un CVE concreto.
func (r *patchRepo) GetByVulnerability(ctx context.Context, cveID string) ([]domain.Patch, error) {
	query := `
			MATCH (p:Patch)-[:FIXES]->(:Vulnerability {cve_id: $cve_id})
			RETURN p.id AS id,
					p.description AS description,
					p.url AS url,
					p.release_date AS release_date,
					coalesce(p.source, '') AS source,
					coalesce(p.reference_type, '') AS reference_type,
					coalesce(p.official, false) AS official,
					coalesce(p.fixed_version, '') AS fixed_version
			ORDER BY id
	`

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{
			AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			result, err := tx.Run(ctx, query, map[string]any{
					"cve_id": cveID,
			})
			if err != nil {
					return nil, err
			}

			patches := make([]domain.Patch, 0)

			for result.Next(ctx) {
					props := result.Record().AsMap()

					patches = append(patches, domain.Patch{
							PatchID:       getInt64(props, "id"),
							Description:   getString(props, "description"),
							URL:           getString(props, "url"),
							ReleaseDate:   getTimePtr(props, "release_date"),
							Source:        getString(props, "source"),
							ReferenceType: getString(props, "reference_type"),
							Official:      getBool(props, "official"),
							FixedVersion:  getString(props, "fixed_version"),
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