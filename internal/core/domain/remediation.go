package domain

import "time"

/*
Este archivo define las entidades de dominio para Remediation.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain`, definiendo las estructuras de datos esenciales para el modelado de la red y equipos sin acoplamiento tecnológico.
2. Inventario de Infraestructura: Representa lógicamente los activos auditados en la red (endpoints como servidores, workstations o contenedores).
3. Relaciones de Red: Define la pertenencia y ubicación de los endpoints en subredes específicas (direccionamiento CIDR, VLANs, Gateways).
4. Contextualización de la Superficie de Ataque: Proporciona el mapeo lógico de la infraestructura de red para evaluar el impacto lateral y la severidad contextual de las vulnerabilidades descubiertas en el software instalado en cada host.
*/

// Remediation representa la entidad de dominio de una solución de seguridad implementada para corregir una vulnerabilidad específica. (nodo Remediation en Neo4j).
type Remediation struct {
	RemediationID  	int64  `json:"remediation_id"`
	FixedVersion   	string `json:"fixed_version"`
	Status 			string `json:"status"`
	AppliedAt 		*time.Time `json:"applied_at"`
}


