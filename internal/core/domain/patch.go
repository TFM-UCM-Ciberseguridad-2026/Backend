package domain

import "time"

/*
Este archivo define la entidad de dominio para los Parches de seguridad (Patches).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Parche: Estructura la representación de una remediación aplicada o disponible para corregir vulnerabilidades específicas.
*/

// Patch representa la entidad de dominio de un parche de seguridad (nodo Patch en Neo4j).
type Patch struct {
	PatchID     int64      `json:"patch_id"`
	Description string     `json:"description"`
	ReleaseDate *time.Time `json:"release_date"`
	URL         string     `json:"url"`
	Source        string `json:"source"`
	ReferenceType string `json:"reference_type"`
	Official      bool   `json:"official"`
	FixedVersion  string `json:"fixed_version,omitempty"`
}

// CVEPatches agrupa los parches publicados para una CVE.
//
// Se sirve por proyecto y no por CVE porque quien lo consume —la ficha de una técnica
// ATT&CK— necesita los parches de todas sus CVE a la vez: pedirlos de uno en uno serían
// más de cien peticiones al abrir una sola técnica.
type CVEPatches struct {
	CVEID   string  `json:"cve_id"`
	Patches []Patch `json:"patches"`
}
