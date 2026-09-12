package domain

/*
Reglas de dominio sobre las direcciones IP de los activos (Endpoints y Contenedores).

Una IP identifica a un activo dentro de su dominio de red: dos activos del mismo proyecto
no pueden compartirla. Este archivo cubre lo que se puede comprobar sin base de datos
(formato y repeticiones dentro del propio activo); el cruce contra el resto de activos del
proyecto lo resuelve el repositorio vía FindIPConflicts.
*/

import (
	"fmt"
	"net"
	"strings"
)

// IPConflict describe una IP que ya está ocupada por otro activo del mismo proyecto.
type IPConflict struct {
	IP        string `json:"ip"`
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name"`
	AssetKind string `json:"asset_kind"` // "Endpoint" o "Container"
}

// NormalizeAssetIPs valida las IPs declaradas por un activo y las devuelve normalizadas.
//
// Comprueba que cada dirección sea válida y que no se repita dentro de la propia lista
// (poner dos veces la misma IP en el mismo formulario). Las entradas vacías se descartan
// en silencio: el formulario permite añadir filas de IP y dejarlas sin rellenar.
func NormalizeAssetIPs(ips []EndpointIP) ([]EndpointIP, error) {
	normalized := make([]EndpointIP, 0, len(ips))
	seen := make(map[string]bool, len(ips))

	for _, entry := range ips {
		raw := strings.TrimSpace(entry.IP)
		if raw == "" {
			continue
		}

		parsed := net.ParseIP(raw)
		if parsed == nil {
			return nil, fmt.Errorf("%w: '%s' no es una dirección IP válida", ErrInvalidIP, raw)
		}

		// Comparamos por la forma canónica para que 10.0.1.1 y 010.0.1.1 no cuelen como
		// dos IPs distintas del mismo activo.
		key := parsed.String()
		if seen[key] {
			return nil, fmt.Errorf("%w: la dirección %s está repetida en este activo", ErrInvalidIP, key)
		}
		seen[key] = true

		if entry.VLANID < 0 || entry.VLANID > 4094 {
			return nil, fmt.Errorf("%w: el VLAN ID %d de la IP %s está fuera del rango válido (0-4094)", ErrInvalidIP, entry.VLANID, key)
		}

		normalized = append(normalized, EndpointIP{IP: key, VLANID: entry.VLANID})
	}

	return normalized, nil
}

// FormatIPConflicts construye el mensaje de error que se devuelve al cliente cuando una o
// varias IPs ya están ocupadas por otros activos del proyecto.
func FormatIPConflicts(conflicts []IPConflict) error {
	if len(conflicts) == 0 {
		return nil
	}

	parts := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		name := c.AssetName
		if name == "" {
			name = c.AssetID
		}
		parts = append(parts, fmt.Sprintf("%s (ya asignada a '%s')", c.IP, name))
	}

	return fmt.Errorf("%w: %s. Dos activos del mismo proyecto no pueden compartir dirección IP", ErrDuplicateIP, strings.Join(parts, ", "))
}
