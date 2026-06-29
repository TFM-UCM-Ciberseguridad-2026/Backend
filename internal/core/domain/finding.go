package domain

import "time"

/*
Este archivo define las entidades de dominio para Finding.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain`, definiendo las estructuras de datos esenciales para el modelado de la red y equipos sin acoplamiento tecnológico.
2. Inventario de Infraestructura: Representa lógicamente los activos auditados en la red (endpoints como servidores, workstations o contenedores).
3. Relaciones de Red: Define la pertenencia y ubicación de los endpoints en subredes específicas (direccionamiento CIDR, VLANs, Gateways).
4. Contextualización de la Superficie de Ataque: Proporciona el mapeo lógico de la infraestructura de red para evaluar el impacto lateral y la severidad contextual de las vulnerabilidades descubiertas en el software instalado en cada host.
*/

// Finding representa la entidad de dominio de un problema de seguridad especifico encontradio en el entrono. Una vulnerabildiad es una debilidad en el software pero el finding es la evidencia de que esa vulnerabilidad existe en un endpoint especifico. (nodo Finding en Neo4j).
type Finding struct {
	FindingID  int64      `json:"finding_id"`
	RiskScore  float64    `json:"risk_score"`
	Status     string     `json:"status"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   *time.Time `json:"last_seen"`
	ResolvedAt *time.Time `json:"resolved_at"`
}
