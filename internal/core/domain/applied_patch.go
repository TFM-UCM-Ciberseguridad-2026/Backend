package domain

import (
	"strings"
	"time"
)

// Declaración de un parche aplicado sobre una instalación concreta.
//
// (Patch)-[:FIXES]->(Vulnerability) dice que el parche existe para un CVE;
// (Patch)-[:APPLIED_TO]->(SoftwareInstallation) dice que además se ha aplicado aquí.

// RemediationLevel expresa hasta qué punto una declaración corrige la vulnerabilidad.
// Los nombres siguen la métrica Remediation Level de CVSS 3.1.
type RemediationLevel string

const (
	RemediationLevelOfficialFix  RemediationLevel = "OFFICIAL_FIX"  // parche del fabricante
	RemediationLevelTemporaryFix RemediationLevel = "TEMPORARY_FIX" // hotfix o backport
	RemediationLevelWorkaround   RemediationLevel = "WORKAROUND"    // mitigación de configuración
	RemediationLevelUnavailable  RemediationLevel = "UNAVAILABLE"   // sin remediación, revierte una previa
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

// FullyRemediates: solo el parche oficial elimina la vulnerabilidad; el resto son
// mitigaciones que dejan riesgo residual.
func (r RemediationLevel) FullyRemediates() bool {
	return r == RemediationLevelOfficialFix
}

// Estados del nodo Remediation.
const (
	RemediationStatusOpen    = "OPEN"
	RemediationStatusPartial = "PARTIAL"
	RemediationStatusApplied = "APPLIED"
)

// RemediationStatus traduce el nivel al estado del nodo Remediation. UNAVAILABLE vuelve
// a OPEN porque sirve para revertir una declaración previa.
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

// AppliedPatch es la relación (Patch)-[:APPLIED_TO]->(SoftwareInstallation) y sus
// propiedades. CVEID y RemediationFactor se guardan en la arista para reconstruir el
// histórico sin recorrer el grafo ni recalcular nada.
type AppliedPatch struct {
	PatchID        int64  `json:"patch_id"`
	AssetType      string `json:"asset_type,omitempty"`
	AssetID        string `json:"asset_id,omitempty"`
	InstallationID string `json:"installation_id,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ImageID        string `json:"image_id,omitempty"`
	FindingID      int64  `json:"finding_id,omitempty"`
	CVEID          string `json:"cve_id"`

	AppliedAt time.Time `json:"applied_at"`
	AppliedBy string    `json:"applied_by"` // texto libre: no hay modelo de usuarios

	RemediationLevel  RemediationLevel `json:"remediation_level"`
	RemediationFactor float64          `json:"remediation_factor"`
	Notes             string           `json:"notes"`

	Verification PatchVerification `json:"verification"`

	// Se rellenan al leer el histórico, para no consultar el nodo Patch aparte.
	PatchURL         string `json:"patch_url,omitempty"`
	PatchDescription string `json:"patch_description,omitempty"`
}

// ParseFixedVersions reconstruye las versiones corregidas desde la cadena
// "paquete@versión, ..." que persiste Remediation.fixed_version. Las entradas sin "@"
// se toman como versión suelta.
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
