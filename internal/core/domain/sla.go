package domain

/*
Este archivo define los plazos de parcheo por defecto del módulo de gobierno.

Propósito arquitectónico y teórico:
 1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain` como lógica
    pura, sin dependencias de persistencia ni de transporte.
 2. El SLA depende de dos ejes, no de uno: la severidad CVSS del hallazgo y la categoría del
    activo donde está. Un mismo CVE no admite el mismo plazo en un servidor de producción
    que en el puesto de un usuario, porque no comparten ni exposición ni ventana de
    mantenimiento. Ver EndpointCategory en endpoint_category.go.
 3. Valores por defecto, no fijos: la configuración real de cada proyecto se persiste como
    nodos :SLAConfig y la edita el usuario desde la pestaña de Gobierno. Esto es solo el
    punto de partida de un proyecto nuevo y el relleno de los huecos que falten.
*/

// SLAPolicy es la matriz (categoría de activo × severidad) → días de plazo.
type SLAPolicy map[EndpointCategory]map[string]int

// defaultSLAPolicy son los plazos de arranque, en días naturales desde la detección.
//
//	                CRITICAL   HIGH   MEDIUM   LOW
//	Servidores          7        30      90     180
//	Puestos            30        60      90     180
//	Contenedores        3        15      30      90
//
// Los servidores son más exigentes en los dos niveles altos porque concentran la exposición
// y el impacto; a partir de MEDIUM el plazo converge, ya que ahí manda la ventana de
// mantenimiento y no la urgencia.
//
// Los contenedores tienen el plazo más corto en todas las severidades. No es que sean más
// críticos, es que remediarlos es más barato: la imagen se reconstruye sobre una base
// actualizada y se redespliega desde el pipeline, sin ventana de mantenimiento ni reinicio de
// un host compartido (NIST SP 800-190).
var defaultSLAPolicy = SLAPolicy{
	CategoryServer: {
		"Critical": 7,
		"High":     30,
		"Medium":   90,
		"Low":      180,
	},
	CategoryWorkstation: {
		"Critical": 30,
		"High":     60,
		"Medium":   90,
		"Low":      180,
	},
	CategoryContainer: {
		"Critical": 3,
		"High":     15,
		"Medium":   30,
		"Low":      90,
	},
}

// severityOrder fija el orden de presentación de las severidades, de más grave a menos.
// Los mapas de Go no conservan orden y la configuración se pinta como una fila de tarjetas:
// sin esto, los cuatro plazos bailarían de posición entre recargas.
var severityOrder = []string{"Critical", "High", "Medium", "Low"}

// slaCategoryLabels da el nombre con el que cada grupo se presenta al usuario.
var slaCategoryLabels = map[EndpointCategory]string{
	CategoryServer:      "Servidores",
	CategoryWorkstation: "Puestos de trabajo",
	CategoryContainer:   "Contenedores",
}

// SLADaysFor devuelve el plazo por defecto para una categoría y una severidad.
// El segundo valor es false cuando la combinación no está cubierta.
func SLADaysFor(category EndpointCategory, severity string) (int, bool) {
	bySeverity, ok := defaultSLAPolicy[category]
	if !ok {
		return 0, false
	}
	days, ok := bySeverity[severity]
	return days, ok
}

// DefaultSLAConfigs expresa la política por defecto en la forma que persiste el módulo de
// gobierno: una fila por par (categoría, severidad), en orden de presentación.
//
// Es la única fuente de los plazos de arranque. El repositorio la usa para completar los
// pares que el usuario todavía no haya configurado, de modo que la respuesta siempre trae la
// matriz entera y la pantalla nunca tiene que inventar valores.
func DefaultSLAConfigs() []SLAConfig {
	categories := SLACategories()
	configs := make([]SLAConfig, 0, len(categories)*len(severityOrder))

	for _, category := range categories {
		for _, severity := range severityOrder {
			days, ok := SLADaysFor(category, severity)
			if !ok {
				continue
			}
			configs = append(configs, SLAConfig{
				Category: category,
				Severity: severity,
				Days:     days,
			})
		}
	}
	return configs
}

// SLASeverities devuelve las severidades en orden de presentación.
func SLASeverities() []string {
	out := make([]string, len(severityOrder))
	copy(out, severityOrder)
	return out
}

// SLACategories devuelve las categorías de activo que tienen SLA propio, en orden de
// presentación: primero los dos grupos de endpoint y después los contenedores.
func SLACategories() []EndpointCategory {
	return []EndpointCategory{CategoryServer, CategoryWorkstation, CategoryContainer}
}

// IsSLACategory indica si la categoría tiene un acuerdo propio que se pueda configurar.
func IsSLACategory(category EndpointCategory) bool {
	for _, c := range SLACategories() {
		if c == category {
			return true
		}
	}
	return false
}

// SLACategoryLabel devuelve el nombre de la categoría para mostrar al usuario.
func SLACategoryLabel(category EndpointCategory) string {
	if label, ok := slaCategoryLabels[category]; ok {
		return label
	}
	return string(category)
}
