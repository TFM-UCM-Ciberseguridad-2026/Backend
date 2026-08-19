package domain

/*
Este archivo define la entidad de dominio para las Redes (Networks).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Relaciones de Red: Define la pertenencia y ubicación de los endpoints en subredes específicas (direccionamiento CIDR, VLANs, Gateways).
*/

// Network representa la entidad de dominio de una subred (nodo Network en Neo4j).
type Network struct {
	NetworkID   int64  `json:"network_id"`
	Nombre      string `json:"nombre"`
	CIDR        string `json:"cidr"`
	Gateway     string `json:"gateway"`
	VLANID      int64  `json:"vlan_id"`
	Descripcion string `json:"descripcion"`
}
