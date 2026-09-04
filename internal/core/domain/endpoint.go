package domain

import (
	"strings"
	"time"
)

/*
Este archivo define las entidades de dominio para Endpoints.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain`, definiendo las estructuras de datos esenciales para el modelado de la red y equipos sin acoplamiento tecnológico.
2. Inventario de Infraestructura: Representa lógicamente los activos auditados en la red (endpoints como servidores, workstations o contenedores).
3. Relaciones de Red: Define la pertenencia y ubicación de los endpoints en subredes específicas (direccionamiento CIDR, VLANs, Gateways).
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

// NormalizeEndpointType convierte cadenas libres/legacy (como 'Linux', 'Windows') a un tipo de equipo válido.
func NormalizeEndpointType(t string) string {
	if IsValidEndpointType(t) {
		return t
	}
	lower := strings.ToLower(strings.TrimSpace(t))
	switch {
	case strings.Contains(lower, "workstation") || strings.Contains(lower, "puesto") || strings.Contains(lower, "pc") || strings.Contains(lower, "laptop"):
		return EndpointTypeWorkstation
	case strings.Contains(lower, "domain") || strings.Contains(lower, "dc") || strings.Contains(lower, "ad"):
		return EndpointTypeDomainController
	case strings.Contains(lower, "firewall") || strings.Contains(lower, "fw"):
		return EndpointTypeFirewall
	case strings.Contains(lower, "router") || strings.Contains(lower, "switch"):
		return EndpointTypeRouter
	default:
		return EndpointTypeServer
	}
}

// TODO: Faltan campos respecto al nist, ademas se pueden subdividir en structs mas pequeñas para que sea mas legible
type Endpoint struct {
	EndpointID      int64        `json:"endpoint_id"`
	Hostname        string       `json:"hostname"`
	Type            string       `json:"tipo"` // Tipo/Rol del equipo en la red ('Server', 'Workstation', 'Domain Controller', 'Firewall', 'Router')
	Status          string       `json:"status"`
	InternetExposed bool         `json:"internet_exposed"`
	Environment     string       `json:"environment"`
	IPs             []EndpointIP `json:"ips,omitempty"`

	// Category es el bucket de negocio ('Workstation' o 'Server') con el que se gobierna el
	// parcheo de este activo. No se rellena a mano: la congela ApplyCategory a partir de Type
	// al crear y al actualizar el endpoint. Ver endpoint_category.go.
	Category string `json:"category"`

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

type EndpointIP struct {
	IP     string `json:"ip"`
	VLANID int64  `json:"vlan_id"`
}
