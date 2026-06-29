package domain

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
type Endpoint struct {
	EndpointID      int64  `json:"endpoint_id"`
	Hostname        string `json:"hostname"`
	Type            string `json:"tipo"`
	Status		  	string `json:"status"`
	Criticality	  	string `json:"criticality"`
	InternetExposed bool   `json:"internet_exposed"`
	Environment     string `json:"environment"`	
}


