package domain

import (
	"strings"
	"time"
)

type RemediationLevel string

const (
	RemediationLevelOfficialFix  RemediationLevel = "OFFICIAL_FIX"  // Parche del fabricante
	RemediationLevelTemporaryFix RemediationLevel = "TEMPORARY_FIX" // Hotfix o backport
	RemediationLevelWorkaround   RemediationLevel = "WORKAROUND"    // Mitigación de configuración
	RemediationLevelUnavailable  RemediationLevel = "UNAVAILABLE"   // Sin remediación
)

func (r RemediationLevel) IsValid() bool {
	switch r {
	case RemediationLevelOfficialFix, RemediationLevelTemporaryFix,
		RemediationLevelWorkaround, RemediationLevelUnavailable:
		return true
	default:
		return false
	}
}

func (r RemediationLevel) FullyRemediates() bool {
	return r == RemediationLevelOfficialFix
}

const (
	RemediationStatusOpen    = "OPEN"
	RemediationStatusPartial = "PARTIAL"
	RemediationStatusApplied = "APPLIED"
)

func (r RemediationLevel) RemediationStatus() string {
	switch r {
	case RemediationLevelOfficialFix:
		return RemediationStatusApplied
	case RemediationLevelTemporaryFix, RemediationLevelWorkaround:
		return RemediationStatusPartial
	default:
		return RemediationStatusOpen
	}
}

type AppliedPatch struct {
	PatchID           int64             `json:"patch_id"`
	InstallationID    string            `json:"installation_id"`
	CVEID             string            `json:"cve_id"`
	AppliedAt         time.Time         `json:"applied_at"`
	AppliedBy         string            `json:"applied_by"`
	RemediationLevel  RemediationLevel  `json:"remediation_level"`
	RemediationFactor float64           `json:"remediation_factor"`
	Notes             string            `json:"notes"`
	Verification      PatchVerification `json:"verification"`
	PatchURL          string            `json:"patch_url,omitempty"`
	PatchDescription  string            `json:"patch_description,omitempty"`
}

// ResolvedFindingInfo modela el detalle de un hallazgo concreto resuelto por un parche.
type ResolvedFindingInfo struct {
	FindingID          int64     `json:"finding_id"`
	CVEID              string    `json:"cve_id"`
	Status             string    `json:"status"`
	PatchID            int64     `json:"patch_id"`
	PatchDescription   string    `json:"patch_description"`
	PatchURL           string    `json:"patch_url"`
	RemediationLevel   string    `json:"remediation_level"`
	AppliedAt          time.Time `json:"applied_at"`
	AppliedBy          string    `json:"applied_by"`
	Notes              string    `json:"notes,omitempty"`
	VerificationReason string    `json:"verification_reason,omitempty"`
	ExpectedVersion    string    `json:"expected_version,omitempty"`
}

// SoftwarePatchHistoryGroup agrupa los parches y findings resueltos de un software instalado en el endpoint.
type SoftwarePatchHistoryGroup struct {
	InstallationID   string                `json:"installation_id"`
	SoftwareID       int64                 `json:"software_id"`
	SoftwareName     string                `json:"software_name"`
	CurrentVersion   string                `json:"current_version"`
	ResolvedFindings []ResolvedFindingInfo `json:"resolved_findings"`
	AppliedPatches   []AppliedPatch        `json:"applied_patches"`
}

// EndpointPatchHistory representa el histórico del endpoint agrupado por software.
type EndpointPatchHistory struct {
	EndpointID     int64                       `json:"endpoint_id"`
	Hostname       string                      `json:"hostname"`
	SoftwareGroups []SoftwarePatchHistoryGroup `json:"software_groups"`
}

func ParseFixedVersions(raw string) []FixedVersion {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	versions := make([]FixedVersion, 0, len(parts))

	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}

		if idx := strings.LastIndex(entry, "@"); idx > 0 {
			versions = append(versions, FixedVersion{
				Package: strings.TrimSpace(entry[:idx]),
				Version: strings.TrimSpace(entry[idx+1:]),
			})
			continue
		}

		versions = append(versions, FixedVersion{Version: entry})
	}

	return versions
}