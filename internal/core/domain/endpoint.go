package domain

import "time"

/*
Este archivo define las entidades de dominio para Endpoints.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain`, definiendo las estructuras de datos esenciales para el modelado de la red y equipos sin acoplamiento tecnológico.
2. Inventario de Infraestructura: Representa lógicamente los activos auditados en la red (endpoints como servidores, workstations o contenedores).
3. Relacion/*
es de Red: Define la pertenencia y ubicación de los endpoints en subredes específicas (direccionamiento CIDR, VLANs, Gateways).
4. Contextualización de la Superficie de Ataque: Proporciona el mapeo lógico de la infraestructura de red para evaluar el impacto lateral y la severidad contextual de las vulnerabilidades descubiertas en el software instalado en cada host.
*/

// Endpoint representa la entidad de dominio de un equipo en la red (nodo Endpoint en Neo4j).

// Tipos normalizados de equipos (Endpoint roles)
const (
	EndpointTypeServer           = "Server"
	EndpointTypeWorkstation      = "Workstation"
	EndpointTypeDomainController = "Domain Controller"
	EndpointTypeFirewall         = "Firewall"
	EndpointTypeRouter           = "Router"
)

// IsValidEndpointType comprueba si una cadena corresponde a un tipo válido de equipo.
func IsValidEndpointType(t string) bool {
	switch t {
	case EndpointTypeServer, EndpointTypeWorkstation, EndpointTypeDomainController, EndpointTypeFirewall, EndpointTypeRouter:
		return true
	default:
		return false
	}
}

// TODO: Faltan campos respecto al nist, ademas se pueden subdividir en structs mas pequeñas para que sea mas legible
type Endpoint struct {
	EndpointID      int64  `json:"endpoint_id"`
	Hostname        string `json:"hostname"`
	Type            string `json:"tipo"` // Tipo/Rol del equipo en la red ('Server', 'Workstation', 'Domain Controller', 'Firewall', 'Router')
	Status          string `json:"status"`
	InternetExposed bool   `json:"internet_exposed"`
	Environment     string `json:"environment"`

	// Security requirements CIA del endpoint (Low/Medium/High), usados como CR/IR/AR
	// en el cálculo del CVSS environmental de cada finding asociado.
	ConfidentialityReq string `json:"confidentiality_req"`
	IntegrityReq       string `json:"integrity_req"`
	AvailabilityReq    string `json:"availability_req"`

	// Riesgo agregado del endpoint, cacheado a partir de los findings asociados
	// (no se setea a mano, lo recalcula el servicio de riesgo).
	RiskScore      float64    `json:"risk_score"`
	RiskTier       string     `json:"risk_tier"` //Se puede quitar si no se considera necesario
	RiskComputedAt *time.Time `json:"risk_computed_at"`

	PriorityScore      float64    `json:"priority_score"`
	PriorityTier       string     `json:"priority_tier"`
	PriorityComputedAt *time.Time `json:"priority_computed_at"`

	TechnicalDriverInstallationID string  `json:"technical_driver_installation_id"`
	TechnicalDriverSoftwareName   string  `json:"technical_driver_software_name"`
	TechnicalDriverRiskScore      float64 `json:"technical_driver_risk_score"`
	TechnicalDriverCVEID          string  `json:"technical_driver_cve_id"`

	PriorityDriverInstallationID string  `json:"priority_driver_installation_id"`
	PriorityDriverSoftwareName   string  `json:"priority_driver_software_name"`
	PriorityDriverPriorityScore  float64 `json:"priority_driver_priority_score"`
	PriorityDriverCVEID          string  `json:"priority_driver_cve_id"`

	RiskySoftwareCount int `json:"risky_software_count"`
}
