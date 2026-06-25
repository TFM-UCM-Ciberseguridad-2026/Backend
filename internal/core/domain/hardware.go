package domain

/*
Este archivo define la entidad de dominio para el Hardware.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Hardware: Modela los componentes físicos o dispositivos de red.
*/

// Hardware representa la entidad de dominio de un componente físico (nodo Hardware en Neo4j).
type Hardware struct {
	HardwareID string `json:"hardware_id"`
	Modelo     string `json:"modelo"`
	Tipo       string `json:"tipo"`
}
