package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

// OllamaClient implementa el puerto TTPMapper.
type OllamaClient struct {
	host       string
	model      string
	httpClient *http.Client
	cache      *TTPCache
	sem        chan struct{} // semáforo para limitar concurrencia
}

// Ensure OllamaClient implements ports.TTPMapper
var _ ports.TTPMapper = (*OllamaClient)(nil)

const (
	ollamaCallTimeout = 120 * time.Second // Timeout por llamada individual a Ollama
	maxRetries        = 2                 // Máximo de reintentos en caso de timeout/cancelación
	maxConcurrent     = 2                 // Máximo de llamadas simultáneas a Ollama
)

// NewOllamaClient crea un nuevo cliente para Ollama.
func NewOllamaClient(host, model string) *OllamaClient {
	if model == "" {
		model = "gemma4:e4b"
	}
	if host == "" {
		host = "http://localhost:11434"
	}
	return &OllamaClient{
		host:       host,
		model:      model,
		httpClient: &http.Client{Timeout: ollamaCallTimeout},
		cache:      NewTTPCache(),
		sem:        make(chan struct{}, maxConcurrent),
	}
}

type generateOptions struct {
	Temperature float64 `json:"temperature"`
}

type generateRequest struct {
	Model   string          `json:"model"`
	Prompt  string          `json:"prompt"`
	Stream  bool            `json:"stream"`
	Format  string          `json:"format"`
	Options generateOptions `json:"options"`
}

type generateResponse struct {
	Response string `json:"response"`
}

// acquireSem adquiere un slot del semáforo (bloquea si todos están ocupados).
func (c *OllamaClient) acquireSem() {
	c.sem <- struct{}{}
}

// releaseSem libera un slot del semáforo.
func (c *OllamaClient) releaseSem() {
	<-c.sem
}

func (c *OllamaClient) generateTTPs(parentCtx context.Context, prompt string) ([]string, string, error) {
	c.acquireSem()
	defer c.releaseSem()

	startTime := time.Now()
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Backoff exponencial: 5s, 10s
			backoff := time.Duration(5*(1<<(attempt-1))) * time.Second
			log.Printf("[Ollama] Reintento %d/%d tras %v...", attempt, maxRetries, backoff)
			time.Sleep(backoff)
		}

		// Crear un contexto con timeout propio para cada llamada,
		// desvinculado del contexto HTTP padre para evitar cancelaciones prematuras.
		callCtx, cancel := context.WithTimeout(context.Background(), ollamaCallTimeout)

		result, raw, err := c.doGenerate(callCtx, prompt)
		cancel()

		if err != nil {
			lastErr = err
			// Solo reintentar en errores de timeout/cancelación/red
			if strings.Contains(err.Error(), "context canceled") ||
				strings.Contains(err.Error(), "context deadline exceeded") ||
				strings.Contains(err.Error(), "connection refused") {
				continue
			}
			// Error no retriable
			return nil, "", err
		}

		elapsed := time.Since(startTime).Round(time.Millisecond)
		log.Printf("[Ollama] Tarea completada (%s) en %v -> %d TTPs mapeadas: %v", c.model, elapsed, len(result), result)
		return result, raw, nil
	}

	return nil, "", fmt.Errorf("agotados %d reintentos para Ollama: %w", maxRetries, lastErr)
}

// respuestaTTPs es la forma que el prompt exige al modelo.
type respuestaTTPs struct {
	TTPs []string `json:"ttps"`
}

// extraerTTPs obtiene los identificadores de técnica de la respuesta del modelo.
//
// La lectura es estructurada: se parsea el JSON y se atiende ÚNICAMENTE al array
// "ttps". Antes se barría el texto completo con una expresión regular, así que
// cualquier identificador mencionado en otro campo —una lista de descartes, un
// razonamiento, o el propio ejemplo del prompt— se persistía como si el modelo
// lo hubiera afirmado.
//
// Solo si la respuesta no es JSON válido se recurre al texto plano, y aun
// entonces cada candidato se valida entero con domain.NormalizarTTPID.
func extraerTTPs(respuesta string) []string {
	var estructurada respuestaTTPs
	if err := json.Unmarshal([]byte(respuesta), &estructurada); err == nil {
		// La respuesta es JSON bien formado: es la fuente autorizada, aunque
		// "ttps" venga vacío o ausente. Devolver 0 aquí es correcto y significa
		// que el modelo no afirmó ninguna técnica.
		return normalizarIdentificadores(estructurada.TTPs)
	}
	return normalizarIdentificadores(candidatosDesdeTexto(respuesta))
}

// candidatosDesdeTexto trocea una respuesta en prosa en posibles identificadores.
// No extrae subcadenas: parte por separadores y devuelve tokens completos, que
// normalizarIdentificadores validará enteros.
func candidatosDesdeTexto(texto string) []string {
	campos := strings.FieldsFunc(texto, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.'
	})

	candidatos := make([]string, 0, len(campos))
	for _, campo := range campos {
		// Los puntos de puntuación al final ("...usa T1190.") no forman parte del
		// identificador; los interiores sí (T1059.001), por eso solo se recortan
		// los de los extremos.
		if limpio := strings.Trim(campo, "."); limpio != "" {
			candidatos = append(candidatos, limpio)
		}
	}
	return candidatos
}

// normalizarIdentificadores normaliza, valida y deduplica conservando el orden
// de llegada.
//
// La validación es la del dominio (domain.NormalizarTTPID), compartida con el
// repositorio: el mismo criterio decide qué es un identificador bien formado en
// la frontera del LLM y en la de escritura al grafo.
func normalizarIdentificadores(brutos []string) []string {
	vistos := make(map[string]bool, len(brutos))
	ttps := make([]string, 0, len(brutos))

	for _, bruto := range brutos {
		id, valido := domain.NormalizarTTPID(bruto)
		if !valido {
			continue
		}
		if !vistos[id] {
			vistos[id] = true
			ttps = append(ttps, id)
		}
	}
	return ttps
}

func (c *OllamaClient) doGenerate(ctx context.Context, prompt string) ([]string, string, error) {
	reqBody := generateRequest{
		Model:  c.model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
		Options: generateOptions{
			Temperature: 0.2,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("error marshaling request: %w", err)
	}

	url := fmt.Sprintf("%s/api/generate", strings.TrimRight(c.host, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, "", fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("error calling ollama API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("ollama API returned status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %w", err)
	}

	var genResp generateResponse
	if err := json.Unmarshal(bodyBytes, &genResp); err != nil {
		return nil, "", fmt.Errorf("error unmarshaling ollama response: %w", err)
	}

	ttps := extraerTTPs(genResp.Response)

	if len(ttps) == 0 {
		log.Printf("[Ollama] failed to find any TTPs in response: %s", genResp.Response)
		return nil, "", fmt.Errorf("no TTPs found in response")
	}

	return ttps, genResp.Response, nil
}

// MapCWEToTTP mapea un CWE a TTPs, con caché.
func (c *OllamaClient) MapCWEToTTP(ctx context.Context, cwe string) ([]string, error) {
	ttps, _, err := c.MapEnrichedToTTPRaw(ctx, domain.TTPMappingRequest{CWE: cwe})
	if err != nil {
		log.Printf("[Ollama] MapCWEToTTP error for CWE %s: %v", cwe, err)
		return nil, err
	}
	return ttps, nil
}

func (c *OllamaClient) buildEnrichedPrompt(req domain.TTPMappingRequest) string {
	var sb strings.Builder
	sb.WriteString("You are a cybersecurity expert mapping vulnerabilities to MITRE ATT&CK.\n\n")
	sb.WriteString("Given the following vulnerability details, identify the MITRE ATT&CK TTP IDs (Techniques) ")
	sb.WriteString("that an attacker would use to exploit this specific weakness. Consider the attack vector, ")
	sb.WriteString("the affected component, and the exploitation conditions described.\n\n")

	if req.CWE != "" {
		sb.WriteString(fmt.Sprintf("CWE: %s\n", req.CWE))
	}
	if req.CVSSVector != "" {
		sb.WriteString(fmt.Sprintf("CVSS Vector: %s\n", req.CVSSVector))
	}
	if req.Description != "" {
		sb.WriteString(fmt.Sprintf("Vulnerability Description: %s\n", req.Description))
	}

	if len(req.Candidatas) > 0 {
		// Lista cerrada. Se ofrecen identificador y nombre: sin el nombre el modelo
		// no puede elegir con criterio, y sin la lista responde de memoria, que es
		// de donde salían las técnicas retiradas y los identificadores inventados.
		sb.WriteString("\nYou MUST choose ONLY from the following MITRE ATT&CK techniques. ")
		sb.WriteString("These are the techniques present in the currently loaded ATT&CK catalog ")
		sb.WriteString("that are compatible with this vulnerability's CVSS vector. ")
		sb.WriteString("Any ID not in this list will be rejected.\n\n")
		sb.WriteString("AVAILABLE TECHNIQUES:\n")
		for _, t := range req.Candidatas {
			sb.WriteString(t.TTPID)
			if t.Name != "" {
				sb.WriteString(" ")
				sb.WriteString(t.Name)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\nSelect the 1 to 4 techniques from the list above that best describe how an ")
		sb.WriteString("attacker would exploit this specific vulnerability. Prefer precision over quantity.\n")
	}

	sb.WriteString("\nYou MUST return ONLY a JSON object with a single key \"ttps\" containing an array of TTP ID strings.\n")
	if len(req.Candidatas) > 0 {
		// Al ver la lista como "T1190 Exploit Public-Facing Application", el modelo
		// tiende a devolver la línea entera en lugar del identificador. Se le pide
		// explícitamente lo contrario; el parser además tolera esa forma.
		sb.WriteString("Return ONLY the identifier of each technique, never its name. ")
		sb.WriteString("Write \"T1190\", not \"T1190 Exploit Public-Facing Application\".\n")
	}
	// El ejemplo se da con marcadores en lugar de identificadores reales: usar
	// T1190 y T1059.001 como muestra los convertía en las dos técnicas más
	// propuestas del sistema, con T1190 en el 31% de las respuestas.
	sb.WriteString("Format: {\"ttps\": [\"Txxxx\", \"Txxxx.yyy\"]}")

	return sb.String()
}

func (c *OllamaClient) MapEnrichedToTTPRaw(ctx context.Context, req domain.TTPMappingRequest) ([]string, string, error) {
	// Estrategia de Caché Híbrida:
	// Solo cacheamos si es una consulta simple (CWE sin descripción ni CVSS, ej. tests).
	// Si tiene contexto enriquecido de producción, evitamos el cacheo para garantizar máxima precisión.
	isSimpleQuery := req.Description == "" && req.CVSSVector == "" && len(req.Candidatas) == 0
	if isSimpleQuery && req.CWE != "" {
		if ttps, found := c.cache.Get(req.CWE); found {
			return ttps, "[CACHE HIT - NO RAW RESPONSE]", nil
		}
	}

	ttps, raw, err := c.elegirEntreCandidatas(ctx, req)
	if err != nil {
		return nil, raw, err
	}

	if isSimpleQuery && req.CWE != "" {
		c.cache.Set(req.CWE, ttps)
	}

	return ttps, raw, nil
}

// elegirEntreCandidatas resuelve el mapeo respetando la lista ofrecida.
//
// Cuando la lista incluye subtécnicas se hace en DOS FASES. Ofrecer el catálogo
// entero de una vez (464 técnicas tras filtrar por vector) resultó
// contraproducente al medirlo: el modelo dejaba de razonar y elegía por posición
// en la lista, con las respuestas agrupadas en rangos contiguos de identificador
// y la concordancia cayendo a cero.
//
// La alternativa de ofrecer solo técnicas padre daba buenos números pero dejaba
// 387 subtécnicas —el 55% del catálogo— fuera de alcance de forma permanente.
// Dos fases conserva el alcance completo sin que ninguna lista pase de unas
// pocas decenas de opciones.
func (c *OllamaClient) elegirEntreCandidatas(ctx context.Context, req domain.TTPMappingRequest) ([]string, string, error) {
	if len(req.Candidatas) == 0 {
		// Sin lista: el modelo responde de memoria. Es el modo de reserva para
		// cuando el catálogo no está disponible.
		return c.generateTTPs(ctx, c.buildEnrichedPrompt(req))
	}

	padres := domain.SoloTecnicasPadre(req.Candidatas)
	hayCandidatasSinDesplegar := len(padres) < len(req.Candidatas)

	// Fase 1: elegir entre técnicas padre.
	peticionPadres := req
	if hayCandidatasSinDesplegar {
		peticionPadres.Candidatas = padres
	}
	elegidas, raw, err := c.generateTTPs(ctx, c.buildEnrichedPrompt(peticionPadres))
	if err != nil {
		return nil, raw, err
	}
	elegidas = filtrarPorCandidatas(elegidas, peticionPadres.Candidatas)
	if len(elegidas) == 0 {
		return nil, raw, fmt.Errorf("ninguna técnica propuesta pertenece a la lista ofrecida")
	}

	if !hayCandidatasSinDesplegar {
		return elegidas, raw, nil
	}

	// Fase 2: afinar dentro de las ramas elegidas. Si falla, se conserva el
	// resultado de la fase 1: una técnica padre correcta es mejor que nada.
	rama := domain.RamaDeTecnicas(req.Candidatas, elegidas)
	peticionRama := req
	peticionRama.Candidatas = rama

	afinadas, rawFase2, err := c.generateTTPs(ctx, c.buildEnrichedPrompt(peticionRama))
	if err != nil {
		log.Printf("[Ollama] fase 2 fallida (%v): se conserva el mapeo a técnicas padre %v", err, elegidas)
		return elegidas, raw, nil
	}
	afinadas = filtrarPorCandidatas(afinadas, rama)
	if len(afinadas) == 0 {
		log.Printf("[Ollama] fase 2 sin resultados dentro de las ramas %v: se conserva el mapeo padre", elegidas)
		return elegidas, raw, nil
	}

	return afinadas, rawFase2, nil
}

// filtrarPorCandidatas conserva solo las técnicas ofrecidas, registrando las que
// el modelo se inventó pese a tener la lista delante.
func filtrarPorCandidatas(ttps []string, candidatas []domain.TTP) []string {
	permitida := make(map[string]bool, len(candidatas))
	for _, c := range candidatas {
		permitida[c.TTPID] = true
	}

	conservadas := make([]string, 0, len(ttps))
	for _, t := range ttps {
		if permitida[t] {
			conservadas = append(conservadas, t)
			continue
		}
		log.Printf("[TTP-DESCARTE] ttp=%s motivo=%s (el modelo ignoró la lista de %d candidatas)",
			t, domain.MotivoFueraDeLista, len(candidatas))
	}
	return conservadas
}

// InvalidateCache limpia la caché para un CWE específico (útil para pruebas).
func (c *OllamaClient) InvalidateCache(cwe string) {
	c.cache.Invalidate(cwe)
}

// FlushCache limpia por completo la caché de TTPs.
func (c *OllamaClient) FlushCache() {
	c.cache.FlushAll()
}

// Ensure sync import is used (for future use if needed)
var _ = sync.Mutex{}
