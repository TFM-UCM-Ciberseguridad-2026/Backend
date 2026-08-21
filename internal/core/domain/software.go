package domain

import "time"

/*
Este archivo define la entidad de dominio de Software y la especificación CPE.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain`, en el corazón de la lógica de negocio pura.
2. Representación de CPE (Common Platform Enumeration): Estructura el formato estándar industrial de nomenclatura de sistemas operativos, aplicaciones y hardware (CPE v2.3), que es el estándar utilizado por las bases de datos de vulnerabilidades (NIST NVD) para asociar fallas de seguridad a componentes específicos.
3. Entidad del Inventario: Permite catalogar el software detectado en los sistemas locales para realizar auditorías automáticas de seguridad mediante análisis de CPEs y cruce con base de datos de CVEs.
*/

// Constantes de estado de resolución CPE
const (
	CPEStatusVerifiedAuto        = "VERIFIED_AUTO"        // Coincidencia exacta o alias confirmado en base de datos
	CPEStatusVerifiedManual      = "VERIFIED_MANUAL"      // Confirmado manualmente por el usuario
	CPEStatusPendingConfirmation = "PENDING_CONFIRMATION" // Coincidencia difusa encontrada, pendiente de validación por el usuario
	CPEStatusNotInNVD            = "NOT_IN_NVD"            // Software interno/propietario no catalogado en NIST NVD
)

// Software representa la entidad de dominio de una aplicación, sistema operativo o componente catalogado (nodo Software en Neo4j).
type Software struct {
	SoftwareID  int64      `json:"software_id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Type        string     `json:"type"` // Tipo de recurso según la convención CPE 2.3: 'a' (aplicación/servicio), 'o' (sistema operativo), 'h' (hardware/firmware)
	CPE         string     `json:"cpe"`
	PURL        string     `json:"purl"`
	ReleaseDate *time.Time `json:"release_date"`
	Vendor      string     `json:"vendor"`
	CPEStatus   string     `json:"cpe_status"`
}


