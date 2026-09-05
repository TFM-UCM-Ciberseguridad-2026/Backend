package domain

/*
Este archivo define la entidad de dominio para TTPs (Tactics, Techniques, and Procedures).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain` en el núcleo de lógica pura.
2. Mapeo de Técnicas MITRE ATT&CK: Representa de manera agnóstica la técnica de ataque explotada o usada.
*/

type TTP struct {
	TTPID       string `json:"ttp_id"`      // e.g. "T1059"
	Name        string `json:"name"`        // e.g. "Command and Scripting Interpreter"
	Tactic      string `json:"tactic"`      // e.g. "Execution"
	Description string `json:"description"` // e.g. "Adversaries may abuse..."
}

// TTPMapping represents the inference mapping details from a Vulnerability to a TTP.
type TTPMapping struct {
	Confidence string `json:"confidence"` // "high" or "low"
	Source     string `json:"source"`     // "cwe_mapping" or "cve_description_fallback"
}

// TTPMatrixItem represents a TTP mapped to multiple CVEs, ready for frontend rendering.

type TTPMatrixCVE struct {
	ID   string `json:"id"`
	CVSS any    `json:"cvss"`
	Desc string `json:"desc"`
}

type TTPMatrixItem struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Tactic string         `json:"tactic"`
	Desc   string         `json:"desc"`
	CVEs   []TTPMatrixCVE `json:"cves"`
}

// TTPTopItem representa una TTP con su frecuencia de aparición, para el top-10 del dashboard.
type TTPTopItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	Count  int    `json:"count"`
}

// TTPStats agrupa las métricas de inteligencia de amenazas para el dashboard.
// Nota MVP: duration_avg_capec_ms / duration_avg_llm_ms se omiten porque la relación
// :MAPS_TO no persiste duración de procesamiento (solo confidence, source, updated_at).
//
// MappedCVEs cuenta únicamente las CVE para las que el pipeline ha escrito una
// arista de mapeo. CapecPendingCVEs cuenta las que NO están mapeadas pero cuyo CWE
// sí tiene cobertura en el catálogo CAPEC: son resolubles de forma determinista,
// sin inferencia del LLM, y miden el trabajo que queda por delante. Son conceptos
// distintos y se publican por separado; mezclarlos daba una cobertura del 100%
// con el trabajo sin hacer.
type TTPStats struct {
	TotalCVEs        int          `json:"total_cves"`
	MappedCVEs       int          `json:"mapped_cves"`
	UnmappedCVEs     int          `json:"unmapped_cves"`
	CapecPendingCVEs int          `json:"capec_pending_cves"`
	HighConfidence   int          `json:"high_confidence"`
	MediumConfidence int          `json:"medium_confidence"`
	CapecStatic      int          `json:"capec_static"`
	LlmEnriched      int          `json:"llm_enriched"`
	TopTTPs          []TTPTopItem `json:"top_ttps"`
}
