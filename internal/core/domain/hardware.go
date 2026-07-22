package domain

/*
Este archivo define la entidad de dominio para el Hardware.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Hardware: Modela los componentes físicos o dispositivos de red.
*/

// Hardware representa la entidad de dominio de un componente físico (nodo Hardware en Neo4j).
type Hardware struct {
	HardwareID   int64  `json:"hardware_id"`
	Model        string `json:"modelo"`
	Type         string `json:"tipo"`
	Manufacturer string `json:"manufacturer"`
	SerialNumber string `json:"serial_number"`
	CPU          string `json:"cpu"`
	RAMGB        int    `json:"ram_gb"`
	StorageGB    int    `json:"storage_gb"`
}