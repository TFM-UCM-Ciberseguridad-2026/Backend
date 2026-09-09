package domain

import (
	"fmt"
	"net"
	"strings"
)

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

// NormalizeCIDR valida un CIDR y lo devuelve en su forma canónica de red.
// Ejemplo: "10.0.1.37/24" -> "10.0.1.0/24". Sirve para que dos redes escritas
// de forma distinta pero equivalentes se detecten como duplicadas.
func NormalizeCIDR(cidr string) (string, error) {
	trimmed := strings.TrimSpace(cidr)
	if trimmed == "" {
		return "", fmt.Errorf("%w: el CIDR es obligatorio", ErrInvalidNetwork)
	}
	_, ipNet, err := net.ParseCIDR(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: el CIDR '%s' no es válido (formato esperado: 10.0.1.0/24)", ErrInvalidNetwork, trimmed)
	}
	return ipNet.String(), nil
}

// ValidateAndNormalizeNetwork comprueba los campos obligatorios de una red, normaliza
// su CIDR a la forma canónica y verifica que el gateway sea una IP contenida en el rango.
// Modifica la red in-place con los valores ya normalizados.
func ValidateAndNormalizeNetwork(nw *Network) error {
	if nw == nil {
		return fmt.Errorf("%w: red no informada", ErrInvalidNetwork)
	}

	nw.Nombre = strings.TrimSpace(nw.Nombre)
	if nw.Nombre == "" {
		return fmt.Errorf("%w: el nombre de la red es obligatorio", ErrInvalidNetwork)
	}

	normalized, err := NormalizeCIDR(nw.CIDR)
	if err != nil {
		return err
	}
	nw.CIDR = normalized

	nw.Gateway = strings.TrimSpace(nw.Gateway)
	if nw.Gateway == "" {
		return fmt.Errorf("%w: el gateway es obligatorio", ErrInvalidNetwork)
	}
	gatewayIP := net.ParseIP(nw.Gateway)
	if gatewayIP == nil {
		return fmt.Errorf("%w: el gateway '%s' no es una dirección IP válida", ErrInvalidNetwork, nw.Gateway)
	}
	_, ipNet, _ := net.ParseCIDR(nw.CIDR)
	if ipNet != nil {
		if !ipNet.Contains(gatewayIP) {
			return fmt.Errorf("%w: el gateway %s está fuera del rango %s", ErrInvalidNetwork, nw.Gateway, nw.CIDR)
		}
		if err := checkGatewayIsUsableHost(gatewayIP, ipNet, nw.Gateway, nw.CIDR); err != nil {
			return err
		}
	}

	if nw.VLANID < 0 {
		return fmt.Errorf("%w: el VLAN ID no puede ser negativo", ErrInvalidNetwork)
	}
	if nw.VLANID > 4094 {
		return fmt.Errorf("%w: el VLAN ID %d está fuera del rango válido (0-4094)", ErrInvalidNetwork, nw.VLANID)
	}

	nw.Descripcion = strings.TrimSpace(nw.Descripcion)
	return nil
}

// checkGatewayIsUsableHost rechaza que el gateway sea la dirección de red o la de broadcast
// del rango: ninguna de las dos es asignable a un host, así que un gateway ahí es un error
// de tipeo (10.0.1.0/24 con gateway 10.0.1.0 en vez de 10.0.1.1).
//
// Solo aplica a IPv4. En /31 (RFC 3021, enlaces punto a punto) y /32 (host único) las dos
// direcciones sí son utilizables, por lo que se dejan pasar. IPv6 no tiene broadcast.
func checkGatewayIsUsableHost(gatewayIP net.IP, ipNet *net.IPNet, gatewayRaw, cidr string) error {
	v4 := gatewayIP.To4()
	if v4 == nil || ipNet.IP.To4() == nil {
		return nil
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return nil
	}

	if v4.Equal(ipNet.IP.To4()) {
		return fmt.Errorf("%w: el gateway %s es la dirección de red de %s, no una IP asignable a un host", ErrInvalidNetwork, gatewayRaw, cidr)
	}

	if v4.Equal(broadcastIPv4(ipNet)) {
		return fmt.Errorf("%w: el gateway %s es la dirección de broadcast de %s, no una IP asignable a un host", ErrInvalidNetwork, gatewayRaw, cidr)
	}

	return nil
}

// broadcastIPv4 calcula la última dirección de un rango IPv4 (red | complemento de máscara).
func broadcastIPv4(ipNet *net.IPNet) net.IP {
	base := ipNet.IP.To4()
	mask := net.IP(ipNet.Mask).To4()
	if base == nil || mask == nil {
		return nil
	}

	out := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		out[i] = base[i] | ^mask[i]
	}
	return out
}

/*
=== Emparejamiento activo↔red por subred más específica ===

Las redes de un proyecto no son un conjunto plano de rangos disjuntos: se puede declarar
un supernet 10.0.0.0/16 y, dentro, una subred 10.0.1.0/24. Una IP como 10.0.1.5 cae en
los dos rangos, y hay que decidir cuál manda en lugar de engancharla a ambos.

La jerarquía NO se almacena: es una función pura de los CIDR, así que se calcula al vuelo
comparando rangos. Eso evita un segundo origen de verdad que se desincronice al editar un
CIDR, y hace desaparecer el caso "subred fuera del rango de su supuesto padre": si un rango
no contiene la IP, sencillamente no es candidato, no hay nada que validar.
*/

// CIDRSpecificity devuelve el número de bits de host del rango: cuantos menos, más
// específico es (un /24 IPv4 devuelve 8; un /16, 16).
//
// Se cuentan los bits de host y no los de red porque el prefijo por sí solo no es
// comparable entre familias: un /24 IPv6 abarca 2^104 direcciones y un /24 IPv4 solo 2^8.
// Los bits de host expresan directamente "el rango más pequeño", que es la regla de
// desempate, y ordenan bien tanto dentro de una familia como entre las dos.
func CIDRSpecificity(cidr string) (int, error) {
	trimmed := strings.TrimSpace(cidr)
	_, ipNet, err := net.ParseCIDR(trimmed)
	if err != nil {
		return 0, fmt.Errorf("%w: el CIDR '%s' no es válido", ErrInvalidNetwork, trimmed)
	}
	ones, bits := ipNet.Mask.Size()
	return bits - ones, nil
}

// CIDRContainsIP indica si la dirección cae dentro del rango. Tolera CIDR no canónicos
// (10.0.0.1/24 se comporta igual que 10.0.0.0/24) porque en la base hay redes anteriores
// a NormalizeCIDR, y devuelve false ante cualquier entrada que no se pueda interpretar:
// un CIDR mal formado no empareja con nada.
func CIDRContainsIP(cidr, ip string) bool {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return ipNet.Contains(parsed)
}
