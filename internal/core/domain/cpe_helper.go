package domain

import (
	"fmt"
	"strings"
)

/*
MapTypeToCPEPart se encarga de normalizar el tipo de activo a los formatos válidos de CPE v2.3:
- 'a' (Applications/Aplicaciones o servicios).
- 'o' (Operating Systems/Sistemas Operativos).
- 'h' (Hardware/Dispositivos físicos).
Mapea cadenas largas comunes (ej. "operating system", "os", "device") a estas letras simplificadas.
*/
func MapTypeToCPEPart(typeStr string) string {
	switch strings.ToLower(strings.TrimSpace(typeStr)) {
	case "o", "os", "operating-system", "operating_system", "sistema-operativo", "sistema_operativo", "operating system":
		return "o"
	case "h", "hardware", "device", "dispositivo":
		return "h"
	default:
		return "a" // Default a aplicación/servicio
	}
}

/*
GenerateCPE23 construye un identificador CPE v2.3 formateado y normalizado para consultas de vulnerabilidades.
Recibe:
- part: tipo de recurso (aplicación, SO, hardware).
- vendor: proveedor del software.
- product: nombre del producto.
- version: versión del software.
Limpia cada token (convierte a minúsculas, elimina espacios y cambia espacios por guiones bajos) para
asegurar compatibilidad con el estándar NIST NVD.
*/
func GenerateCPE23(part, vendor, product, version string) string {
	cpePart := MapTypeToCPEPart(part)
	cleanVendor := cleanCPEToken(vendor)
	cleanProduct := cleanCPEToken(product)
	cleanVersion := cleanCPEToken(version)

	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*", cpePart, cleanVendor, cleanProduct, cleanVersion)
}

func cleanCPEToken(token string) string {
	t := strings.TrimSpace(token)
	t = strings.ToLower(t)
	t = strings.ReplaceAll(t, " ", "_")
	if t == "" {
		return "*"
	}
	return t
}
