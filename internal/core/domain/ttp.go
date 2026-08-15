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
