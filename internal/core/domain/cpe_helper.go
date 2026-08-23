package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CPEFinalItem representa el objeto final de respuesta expuesto al frontend en la Fase 5.
type CPEFinalItem struct {
	Title        string    `json:"title"`
	CPE          string    `json:"cpe"`
	ID           string    `json:"id"`
	LastModified time.Time `json:"last_modified"`
	URL          string    `json:"url,omitempty"`
}

// NVDProductItem representa un elemento extraído de la API v2.0 de NVD.
type NVDProductItem struct {
	CPEName      string    `json:"cpe_name"`
	CPENameID    string    `json:"cpe_name_id"`
	Title        string    `json:"title"`
	Deprecated   bool      `json:"deprecated"`
	LastModified time.Time `json:"last_modified"`
	URL          string    `json:"url,omitempty"`
}


// CPESuggestion representa una opción candidata de CPE oficial devuelta para autocompletar o sugerir al usuario.
type CPESuggestion struct {
	CPE                      string `json:"cpe"`
	Vendor                   string `json:"vendor"`
	Product                  string `json:"product"`
	Title                    string `json:"title"`
	MatchType                string `json:"match_type"` // EXACT_MATCH, FUZZY_SUGGESTION, CUSTOM_INTERNAL
	RequiresUserConfirmation bool   `json:"requires_user_confirmation"`
	URL                      string `json:"url,omitempty"`
}


// CPEMatchResult es el resultado producido por la canalización de resolución de CPEs en el dominio.
type CPEMatchResult struct {
	CPE              string          `json:"cpe"`
	CPEStatus        string          `json:"cpe_status"`
	CanonicalVendor  string          `json:"canonical_vendor"`
	CanonicalProduct string          `json:"canonical_product"`
	SuggestedCPE     string          `json:"suggested_cpe,omitempty"`
	Suggestions      []CPESuggestion `json:"suggestions,omitempty"`
}


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

/*
cleanCPEToken limpia y sanea cada componente del CPE:
- Convierte a minúsculas y elimina espacios iniciales/finales.
- Reemplaza dos puntos (:) por guiones bajos para no alterar la estructura de 13 campos delimitados por ':' del estándar CPE 2.3.
- Reemplaza espacios, barras (/) y barras invertidas (\) por guiones bajos.
- Elimina caracteres de control o consulta HTTP (?, #, &, ", ').
- Si la cadena queda vacía, asigna el comodín '*'.
*/
func cleanCPEToken(token string) string {
	t := strings.TrimSpace(token)
	t = strings.ToLower(t)
	t = strings.ReplaceAll(t, ":", "_")
	t = strings.ReplaceAll(t, " ", "_")
	t = strings.ReplaceAll(t, "/", "_")
	t = strings.ReplaceAll(t, "\\", "_")
	t = strings.ReplaceAll(t, "?", "")
	t = strings.ReplaceAll(t, "#", "")
	t = strings.ReplaceAll(t, "&", "")
	t = strings.ReplaceAll(t, "\"", "")
	t = strings.ReplaceAll(t, "'", "")

	if t == "" {
		return "*"
	}
	return t
}

/*
CleanVersionString normaliza cadenas de versión (ej: "v1.2.3", "v.9.0.37-RELEASE") a un formato limpio para CPEs.
- Elimina prefijos comunes como 'v', 'v.', 'version', 'ver'.
- Trimea espacios y reemplaza espacios internos por guiones o puntos.
*/
func CleanVersionString(versionStr string) string {
	v := strings.TrimSpace(versionStr)
	vLower := strings.ToLower(v)

	// Eliminar prefijos comunes
	if strings.HasPrefix(vLower, "v.") {
		v = v[2:]
	} else if strings.HasPrefix(vLower, "v") && len(v) > 1 && (v[1] >= '0' && v[1] <= '9') {
		v = v[1:]
	} else if strings.HasPrefix(vLower, "version ") {
		v = v[8:]
	} else if strings.HasPrefix(vLower, "ver ") {
		v = v[4:]
	}

	v = strings.TrimSpace(v)
	if v == "" {
		return "*"
	}
	return cleanCPEToken(v)
}

/*
CalculateStringSimilarity calcula un coeficiente de similitud entre 0.0 y 1.0 usando la distancia Levenshtein normalizada.
- 1.0 indica cadenas idénticas (ignorando mayúsculas/minúsculas y espacios trimeados).
- 0.0 indica cero coincidencia.
*/
func CalculateStringSimilarity(s1, s2 string) float64 {
	str1 := strings.ToLower(strings.TrimSpace(s1))
	str2 := strings.ToLower(strings.TrimSpace(s2))

	if str1 == str2 {
		return 1.0
	}
	if len(str1) == 0 || len(str2) == 0 {
		return 0.0
	}

	dist := levenshteinDistance(str1, str2)
	maxLen := len(str1)
	if len(str2) > maxLen {
		maxLen = len(str2)
	}

	similarity := 1.0 - (float64(dist) / float64(maxLen))
	if similarity < 0.0 {
		return 0.0
	}
	return similarity
}

func levenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n1, n2 := len(r1), len(r2)

	column := make([]int, n1+1)
	for i := 0; i <= n1; i++ {
		column[i] = i
	}

	for j := 1; j <= n2; j++ {
		column[0] = j
		lastDiagonal := j - 1
		for i := 1; i <= n1; i++ {
			oldColumn := column[i]
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			column[i] = minInt(column[i]+1, column[i-1]+1, lastDiagonal+cost)
			lastDiagonal = oldColumn
		}
	}
	return column[n1]
}

func minInt(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= a && b <= c {
		return b
	}
	return c
}

var (

	// Regex para detectar y extraer versiones numéricas (ej. v6.0, 1.24.0, 2.0)
	versionRegex = regexp.MustCompile(`(?i)\bv?([0-9]+(?:\.[0-9]+)+)\b`)
	// Regex para limpiar caracteres no alfanuméricos
	nonAlphaNumericRegex = regexp.MustCompile(`[^a-z0-9]+`)
	// Stopwords irrelevantes para la búsqueda de CPEs
	cpeStopwords = map[string]bool{
		"the":      true,
		"for":      true,
		"server":   true,
		"software": true,
		"inc":      true,
		"corp":     true,
		"ltd":      true,
		"v":        true,
	}
)

// SanitizeAndTokenizeInput ejecuta la Fase 1 del pipeline: convierte a minúsculas,
// extrae versión si existe, limpia caracteres no alfanuméricos y tokeniza palabras clave.
func SanitizeAndTokenizeInput(rawInput string) ([]string, string) {
	lowered := strings.ToLower(strings.TrimSpace(rawInput))
	if lowered == "" {
		return []string{}, ""
	}

	// 1. Extraer versión si existe
	extractedVersion := ""
	if match := versionRegex.FindString(lowered); match != "" {
		extractedVersion = strings.TrimPrefix(strings.ToLower(match), "v")
		// Eliminar el bloque de versión del texto para tokenizar solo fabricante y producto
		lowered = strings.Replace(lowered, match, " ", 1)
	}

	// 2. Reemplazar puntuación no alfanumérica por espacios
	cleaned := nonAlphaNumericRegex.ReplaceAllString(lowered, " ")

	// 3. Tokenizar y filtrar palabras vacías
	rawTokens := strings.Fields(cleaned)
	tokens := []string{}
	seen := make(map[string]bool)

	for _, tok := range rawTokens {
		tok = strings.TrimSpace(tok)
		if tok == "" || cpeStopwords[tok] {
			continue
		}
		if !seen[tok] {
			seen[tok] = true
			tokens = append(tokens, tok)
		}
	}

	return tokens, extractedVersion
}



