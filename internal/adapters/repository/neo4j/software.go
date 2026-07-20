package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// ==========================================
// IMPLEMENTACIÓN DE SoftwarePort
// ==========================================

type softwareRepo struct {
	driver neo4j.DriverWithContext
}

func (r *softwareRepo) Save(ctx context.Context, s *domain.Software) error {
	query := `
		MERGE (n:Software {id: $id})
		SET n.name = $name, n.version = $version, n.type = $type, n.cpe = $cpe, n.purl = $purl, n.vendor = $vendor
	`
	params := map[string]any{
		"id":      s.SoftwareID,
		"name":    s.Name,
		"version": s.Version,
		"type":    s.Type,
		"cpe":     s.CPE,
		"purl":    s.PURL,
		"vendor":  s.Vendor,
	}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *softwareRepo) GetByID(ctx context.Context, id int64) (*domain.Software, error) {
	query := `MATCH (n:Software {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Software{
		SoftwareID: getInt64(props, "id"),
		Name:       getString(props, "name"),
		Version:    getString(props, "version"),
		Type:       getString(props, "type"),
		CPE:        getString(props, "cpe"),
		PURL:       getString(props, "purl"),
		Vendor:     getString(props, "vendor"),
	}, nil
}

func (r *softwareRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `MATCH (n:Software {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}

// ==========================================
// IMPLEMENTACIÓN DE SoftwareInstallationPort
// ==========================================

type softwareInstallationRepo struct {
	driver neo4j.DriverWithContext
}

func (r *softwareInstallationRepo) Save(ctx context.Context, si *domain.SoftwareInstallation) error {
	query := `
        MERGE (n:SoftwareInstallation {id: $id})
        SET n.first_seen = $first_seen,
            n.last_seen = $last_seen,
            n.status = $status,
            n.install_path = $install_path,
            n.detected_by = $detected_by,
            n.package_manager = $package_manager,
			n.risk_score = $risk_score,
			n.risk_tier = $risk_tier,
			n.risk_computed_at = $risk_computed_at,
			n.driver_finding_id = $driver_finding_id,
			n.driver_cve_id = $driver_cve_id,
			n.criticality_level = $criticality_level,
			n.criticality_multiplier = $criticality_multiplier,
			n.priority_score = $priority_score,
			n.priority_tier = $priority_tier,
			n.priority_computed_at = $priority_computed_at
    `

	var lastSeen any
	if si.LastSeen != nil {
		lastSeen = *si.LastSeen
	} else {
		lastSeen = nil
	}

	var riskComputedAt any
	if si.RiskComputedAt != nil {
		riskComputedAt = *si.RiskComputedAt
	}

	var priorityComputedAt any
	if si.PriorityComputedAt != nil {
		priorityComputedAt = *si.PriorityComputedAt
	}

	params := map[string]any{
		"id":                     si.InstallationID,
		"first_seen":             si.FirstSeen,
		"last_seen":              lastSeen,
		"status":                 si.Status,
		"install_path":           si.InstallPath,
		"detected_by":            si.DetectedBy,
		"package_manager":        si.PackageManager,
		"risk_score":             si.RiskScore,
		"risk_tier":              si.RiskTier,
		"risk_computed_at":       riskComputedAt,
		"driver_finding_id":      si.DriverFindingID,
		"driver_cve_id":          si.DriverCVEID,
		"criticality_level":      si.CriticalityLevel,
		"criticality_multiplier": si.CriticalityMultiplier,
		"priority_score":         si.PriorityScore,
		"priority_tier":          si.PriorityTier,
		"priority_computed_at":   priorityComputedAt,
	}

	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *softwareInstallationRepo) GetByID(ctx context.Context, id string) (*domain.SoftwareInstallation, error) {
	query := `MATCH (n:SoftwareInstallation {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}

	installation := &domain.SoftwareInstallation{
		InstallationID:        getString(props, "id"),
		Status:                getString(props, "status"),
		InstallPath:           getString(props, "install_path"),
		DetectedBy:            getString(props, "detected_by"),
		PackageManager:        getString(props, "package_manager"),
		FirstSeen:             getTime(props, "first_seen"),
		LastSeen:              getTimePtr(props, "last_seen"),
		RiskScore:             getFloat64(props, "risk_score"),
		RiskTier:              getString(props, "risk_tier"),
		RiskComputedAt:        getTimePtr(props, "risk_computed_at"),
		DriverFindingID:       getInt64(props, "driver_finding_id"),
		DriverCVEID:           getString(props, "driver_cve_id"),
		CriticalityLevel:      getString(props, "criticality_level"),
		CriticalityMultiplier: getFloat64(props, "criticality_multiplier"),
		PriorityScore:         getFloat64(props, "priority_score"),
		PriorityTier:          getString(props, "priority_tier"),
		PriorityComputedAt:    getTimePtr(props, "priority_computed_at"),
	}

	return installation, nil
}

func (r *softwareInstallationRepo) DeleteByID(ctx context.Context, id string) error {
	query := `MATCH (n:SoftwareInstallation {id: $id}) DETACH DELETE n`
	return executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})
}
