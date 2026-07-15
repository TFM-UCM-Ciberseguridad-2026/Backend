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

// TODO: Faltan campos respecto al nist, ademas se pueden subdividir en structs mas pequeñas para que sea mas legible
type Endpoint struct {
	EndpointID      int64  `json:"endpoint_id"`
	Hostname        string `json:"hostname"`
	Type            string `json:"tipo"` // Tipo de activo/endpoint siguiendo la nomenclatura CPE: 'a' (aplicación/servicio), 'o' (sistema operativo) o 'h' (hardware/dispositivo)
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
}
