package domain

import "time"

/*
Este archivo define la declaración de un parche aplicado sobre una instalación concreta.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Distinción disponible/aplicado: (Patch)-[:FIXES]->(Vulnerability) indica que un parche
   existe para un CVE; (Patch)-[:APPLIED_TO]->(SoftwareInstallation) indica que además se
   ha aplicado en un activo concreto. Son hechos distintos y el grafo los separa.
3. Base del histórico: cada declaración deja una arista con su fecha, de modo que una misma
   instalación puede acumular varias aplicaciones a lo largo del tiempo.
*/

// RemediationLevel expresa hasta qué punto una declaración corrige la vulnerabilidad.
// Los nombres siguen la métrica Remediation Level (RL) de CVSS 3.1 para no inventar
// vocabulario, aunque los factores son los del modelo de riesgo de este proyecto.
type RemediationLevel string

const (
	// RemediationLevelOfficialFix es el parche oficial del fabricante: elimina la
	// vulnerabilidad.
	RemediationLevelOfficialFix RemediationLevel = "OFFICIAL_FIX"

	// RemediationLevelTemporaryFix es una corrección provisional (hotfix, backport no
	// oficial): reduce mucho el riesgo pero la vulnerabilidad sigue presente.
	RemediationLevelTemporaryFix RemediationLevel = "TEMPORARY_FIX"

	// RemediationLevelWorkaround es una mitigación de configuración (deshabilitar un
	// módulo, filtrar en el firewall): reduce el riesgo sin tocar el software.
	RemediationLevelWorkaround RemediationLevel = "WORKAROUND"

	// RemediationLevelUnavailable indica que no hay remediación aplicable. Se admite
	// para poder revertir una declaración previa dejando constancia.
	RemediationLevelUnavailable RemediationLevel = "UNAVAILABLE"
)

// IsValid indica si el nivel es uno de los reconocidos.
func (r RemediationLevel) IsValid() bool {
	switch r {
	case RemediationLevelOfficialFix, RemediationLevelTemporaryFix,
		RemediationLevelWorkaround, RemediationLevelUnavailable:
		return true
	default:
		return false
	}
}

// FullyRemediates indica si el nivel elimina la vulnerabilidad por completo. Solo el
// parche oficial lo hace: el resto son mitigaciones que dejan riesgo residual.
func (r RemediationLevel) FullyRemediates() bool {
	return r == RemediationLevelOfficialFix
}

// Estados del nodo Remediation. Reflejan en qué situación está la solución planteada
// para un finding, y se sincronizan al declarar un parche aplicado.
const (
	// RemediationStatusOpen indica que la remediación está pendiente de aplicar.
	RemediationStatusOpen = "OPEN"

	// RemediationStatusPartial indica que se ha aplicado una mitigación que reduce el
	// riesgo pero no elimina la vulnerabilidad.
	RemediationStatusPartial = "PARTIAL"

	// RemediationStatusApplied indica que se ha aplicado el parche oficial.
	RemediationStatusApplied = "APPLIED"
)

// RemediationStatus traduce el nivel declarado al estado del nodo Remediation.
// UNAVAILABLE devuelve el estado abierto porque sirve para revertir una declaración
// previa y dejar la remediación de nuevo como pendiente.
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

// AppliedPatch representa la declaración de que un parche se ha aplicado sobre una
// instalación de software concreta. Se materializa como la relación
// (Patch)-[:APPLIED_TO]->(SoftwareInstallation) con sus propiedades.
type AppliedPatch struct {
	PatchID        int64  `json:"patch_id"`
	InstallationID string `json:"installation_id"`

	// CVEID es el CVE que el parche corrige. Se guarda en la arista para poder
	// reconstruir el histórico sin recorrer el grafo hacia la vulnerabilidad.
	CVEID string `json:"cve_id"`

	AppliedAt time.Time `json:"applied_at"`

	// AppliedBy identifica a quien declara la aplicación (operador, sistema de
	// despliegue...). Es texto libre: el proyecto no tiene modelo de usuarios.
	AppliedBy string `json:"applied_by"`

	RemediationLevel RemediationLevel `json:"remediation_level"`

	// RemediationFactor es el factor resultante que se propagó a los findings
	// afectados. Se persiste en la arista para dejar constancia de con qué criterio
	// se recalculó el riesgo en su momento.
	RemediationFactor float64 `json:"remediation_factor"`

	Notes string `json:"notes"`

	// PatchURL y PatchDescription se rellenan al leer el histórico, para no obligar a
	// consultar el nodo Patch por separado.
	PatchURL         string `json:"patch_url,omitempty"`
	PatchDescription string `json:"patch_description,omitempty"`
}
