package domain

import (
	"regexp"
	"strings"
)

/*
Este archivo define la entidad de dominio para TTPs (Tactics, Techniques, and Procedures).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain` en el núcleo de lógica pura.
2. Mapeo de Técnicas MITRE ATT&CK: Representa de manera agnóstica la técnica de ataque explotada o usada.
*/

type TTP struct {
	TTPID       string `json:"ttp_id"`      // e.g. "T1059"
	Name        string `json:"name"`        // e.g. "Command and Scripting Interpreter"
	Tactic      string `json:"tactic"`      // e.g. "Execution"
	Description string `json:"description"` // e.g. "Adversaries may abuse..."
}

// ATTACKCatalog agrupa todo lo que se extrae de un bundle STIX de MITRE ATT&CK,
// incluida la versión del catálogo.
//
// La versión importa fuera de la ingesta: la capa que se exporta al ATT&CK
// Navigator declara contra qué versión se interpretan sus técnicas. Estaba fijada
// a mano en el frontend y se quedó en la 14 mientras el catálogo cargado iba por
// la 19.2, así que el Navigator interpretaba los datos con un mapa de cinco
// versiones de antigüedad.
type ATTACKCatalog struct {
	Version     string // x_mitre_version de la colección, p. ej. "19.2"
	SpecVersion string // x_mitre_attack_spec_version, p. ej. "3.3.0"
	TTPs        []TTP
	Actors      []ThreatActor
	Relations   []ThreatActorTTPRelation
}

// ATTACKCatalogInfo describe la versión del catálogo efectivamente cargada en el
// grafo. Es lo que se publica por la API para que nadie tenga que suponerla.
type ATTACKCatalogInfo struct {
	Version     string `json:"version"`      // "19.2"
	SpecVersion string `json:"spec_version"` // "3.3.0"
	TotalTTPs   int    `json:"total_ttps"`
	UpdatedAt   int64  `json:"updated_at"`
}

// VersionMayor devuelve el componente mayor de la versión ("19.2" → "19"), que es
// la granularidad que espera el campo versions.attack de una capa del Navigator.
func (i ATTACKCatalogInfo) VersionMayor() string {
	if i.Version == "" {
		return ""
	}
	if punto := strings.Index(i.Version, "."); punto > 0 {
		return i.Version[:punto]
	}
	return i.Version
}

// TTPMappingRequest es lo que se le pide al mapeador para una vulnerabilidad.
//
// Candidatas es la lista cerrada de técnicas entre las que puede elegir. Si viene
// vacía, el modelo responde de memoria, que es el comportamiento anterior y el
// que producía identificadores fuera del catálogo.
type TTPMappingRequest struct {
	CWE         string
	Description string
	CVSSVector  string
	Candidatas  []TTP
}

// TTPMapping represents the inference mapping details from a Vulnerability to a TTP.
type TTPMapping struct {
	Confidence string `json:"confidence"` // "high" or "low"
	Source     string `json:"source"`     // "cwe_mapping" or "cve_description_fallback"
}

// Procedencias de un mapeo CVE→TTP. Determinan DÓNDE se persiste la arista, no
// solo cómo se etiqueta:
//
//   - FuenteCAPECStatic es una deducción de catálogo (CWE→CAPEC→ATT&CK). Es
//     genérica del CWE por construcción, así que se persiste una sola vez en
//     (CWE)-[:MAPS_TO]->(TTP) y todas las CVE de ese CWE la comparten con
//     propiedad.
//
//   - FuenteLLMEnriched es una inferencia sobre UNA CVE concreta: el prompt
//     incluye su descripción y su vector CVSS. Persistirla a nivel de CWE hacía
//     que todas las CVE de ese CWE heredaran técnicas inferidas a partir del
//     texto de otra, acumulándolas sin límite. Va en (CVE)-[:MAPS_TO]->(TTP).
const (
	FuenteCAPECStatic = "capec_static"
	FuenteLLMEnriched = "llm_enriched"
)

// reIdentificadorTTP valida un identificador de técnica COMPLETO. El anclaje es
// deliberado: una expresión sin anclar recorta los identificadores demasiado
// largos en vez de rechazarlos, y convierte una alucinación como "T11905" en
// "T1190", que sí existe. Validar sobre el identificador entero es lo único que
// distingue un error de formato de una técnica real.
var reIdentificadorTTP = regexp.MustCompile(`^T\d{4}(?:\.\d{3})?$`)

// NormalizarTTPID pasa un identificador a su forma canónica y dice si es válido.
//
// La normalización precede a la validación a propósito: los modelos responden a
// veces en minúsculas, y validar antes de normalizar rechazaba respuestas
// correctas.
//
// Acepta también la forma "T1190 Exploit Public-Facing Application" o
// "T1498: Network Denial of Service", quedándose con el identificador. Cuando al
// modelo se le ofrece una lista de candidatas como "T1190 Exploit Public-Facing
// Application", tiende a devolver la línea entera; medido en producción, eso
// hacía fallar el 5,6% de las segundas fases. La intención es inequívoca —el
// identificador encabeza la cadena— así que rechazarla era perder información
// por un detalle de formato.
//
// Solo se mira el PRIMER token: así se interpreta lo que el modelo afirma sin
// convertir esto en un barrido de texto, que fue justo el defecto original del
// parser.
//
// Que sea válido significa solo que está bien formado. NO significa que la
// técnica exista en el catálogo cargado: eso solo puede decirlo el grafo.
func NormalizarTTPID(bruto string) (string, bool) {
	id := strings.ToUpper(strings.TrimSpace(bruto))
	if reIdentificadorTTP.MatchString(id) {
		return id, true
	}

	primero := strings.TrimRight(primerToken(id), ".:,;-")
	if reIdentificadorTTP.MatchString(primero) {
		return primero, true
	}
	return id, false
}

// primerToken devuelve el texto hasta el primer separador.
func primerToken(s string) string {
	corte := strings.IndexAny(s, " \t\n:;,|—–-")
	if corte < 0 {
		return s
	}
	return s[:corte]
}

// Motivos por los que una técnica propuesta no llega a persistirse. Se emiten en
// los registros [TTP-DESCARTE] para poder medir la tasa de descarte entre
// modelos o versiones del catálogo.
const (
	// MotivoFormatoInvalido: el identificador no está bien formado.
	MotivoFormatoInvalido = "formato_invalido"

	// MotivoNoEnCatalogo: está bien formado pero no hay técnica con ese ID en el
	// catálogo cargado. Agrupa dos casos que el grafo no distingue, porque las
	// técnicas revocadas por MITRE no se ingieren: identificador inexistente y
	// técnica retirada en una versión posterior de ATT&CK.
	MotivoNoEnCatalogo = "no_en_catalogo_vigente"

	// MotivoFueraDeLista: al modelo se le dio una lista cerrada de candidatas y
	// respondió con una técnica que no estaba en ella.
	MotivoFueraDeLista = "fuera_de_lista_ofrecida"

	// MotivoIncoherenteCVSS: la técnica exige interacción del usuario y el vector
	// CVSS de la vulnerabilidad declara UI:N.
	MotivoIncoherenteCVSS = "incoherente_con_vector_cvss"
)

// TTPMatrixItem represents a TTP mapped to multiple CVEs, ready for frontend rendering.

type TTPMatrixCVE struct {
	ID   string `json:"id"`
	CVSS any    `json:"cvss"`
	Desc string `json:"desc"`
}

type TTPMatrixItem struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Tactic string         `json:"tactic"`
	Desc   string         `json:"desc"`
	CVEs   []TTPMatrixCVE `json:"cves"`
}

// TTPTopItem representa una TTP con su frecuencia de aparición, para el top-10 del dashboard.
type TTPTopItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	Count  int    `json:"count"`
}

// TTPStats agrupa las métricas de inteligencia de amenazas para el dashboard.
// Nota MVP: duration_avg_capec_ms / duration_avg_llm_ms se omiten porque la relación
// :MAPS_TO no persiste duración de procesamiento (solo confidence, source, updated_at).
//
// MappedCVEs cuenta únicamente las CVE para las que el pipeline ha escrito una
// arista de mapeo. CapecPendingCVEs cuenta las que NO están mapeadas pero cuyo CWE
// sí tiene cobertura en el catálogo CAPEC: son resolubles de forma determinista,
// sin inferencia del LLM, y miden el trabajo que queda por delante. Son conceptos
// distintos y se publican por separado; mezclarlos daba una cobertura del 100%
// con el trabajo sin hacer.
type TTPStats struct {
	TotalCVEs        int          `json:"total_cves"`
	MappedCVEs       int          `json:"mapped_cves"`
	UnmappedCVEs     int          `json:"unmapped_cves"`
	CapecPendingCVEs int          `json:"capec_pending_cves"`
	HighConfidence   int          `json:"high_confidence"`
	MediumConfidence int          `json:"medium_confidence"`

	// HighConfidenceCVEs / MediumConfidenceCVEs cuentan VULNERABILIDADES, no
	// mapeos, y se publican junto a los anteriores porque las dos lecturas
	// divergen mucho.
	//
	// Medido: 58% de los mapeos son de confianza alta, pero solo el 30% de las
	// CVE tienen alguna técnica de confianza alta. La diferencia es densidad, no
	// fiabilidad: la vía CAPEC aporta 6,35 técnicas por CVE frente a 2,04 del
	// LLM, así que con el 30% de las CVE produce el 58% de las aristas.
	//
	// Publicar solo la cifra por mapeo sugiere una fiabilidad que el sistema no
	// tiene a nivel de vulnerabilidad, que es la unidad con la que trabaja quien
	// analiza.
	HighConfidenceCVEs   int `json:"high_confidence_cves"`
	MediumConfidenceCVEs int `json:"medium_confidence_cves"`
	CapecStatic      int          `json:"capec_static"`
	LlmEnriched      int          `json:"llm_enriched"`
	TopTTPs          []TTPTopItem `json:"top_ttps"`
}
