package domain

/*
Este archivo define la entidad de dominio para los Parches de seguridad (Patches).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Parche: Estructura la representación de una remediación aplicada o disponible para corregir vulnerabilidades específicas.
*/

// Patch representa la entidad de dominio de un parche de seguridad (nodo Patch en Neo4j).
type Patch struct {
	PatchID int    `json:"patch_id"`
	Name    string `json:"name"`
}
