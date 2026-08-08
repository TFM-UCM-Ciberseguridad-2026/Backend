package domain

/*
Este archivo define la entidad de dominio para CAPEC (Common Attack Pattern Enumeration and Classification).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain` en el núcleo de lógica pura.
2. Mapeo de Patrones de Ataque MITRE CAPEC: Representa los patrones de ataque catalogados y sus relaciones directas con debilidades CWE.
*/

type CAPEC struct {
	CAPECID     string   `json:"capec_id"`    // Ej: "CAPEC-100"
	Name        string   `json:"name"`        // Ej: "Overflow Buffers"
	Description string   `json:"description"` // Descripción STIX del patrón de ataque
	CWEs        []string `json:"cwes"`        // Lista de CWE IDs asociados (Ej: ["CWE-120", "CWE-119"])
	TTPs        []string `json:"ttps"`        // Lista de TTP IDs de MITRE ATT&CK asociados (Ej: ["T1190", "T1059"])
}
