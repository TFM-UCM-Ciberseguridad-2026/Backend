package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

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

	// Use regex to extract all TTP IDs from the response string
	re := regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)
	matches := re.FindAllString(genResp.Response, -1)

	// Deduplicate matches
	ttpMap := make(map[string]bool)
	var ttps []string
	for _, m := range matches {
		if !ttpMap[m] {
			ttpMap[m] = true
			ttps = append(ttps, m)
		}
	}

	if len(ttps) == 0 {
		log.Printf("[Ollama] failed to find any TTPs in response: %s", genResp.Response)
		return nil, "", fmt.Errorf("no TTPs found in response")
	}

	return ttps, genResp.Response, nil
}

// MapCWEToTTP mapea un CWE a TTPs, con caché.
func (c *OllamaClient) MapCWEToTTP(ctx context.Context, cwe string) ([]string, error) {
	ttps, _, err := c.MapEnrichedToTTPRaw(ctx, cwe, "", "")
	if err != nil {
		log.Printf("[Ollama] MapCWEToTTP error for CWE %s: %v", cwe, err)
		return nil, err
	}
	return ttps, nil
}

func (c *OllamaClient) buildEnrichedPrompt(cwe, description, cvssVector string) string {
	var sb strings.Builder
	sb.WriteString("You are a cybersecurity expert mapping vulnerabilities to MITRE ATT&CK.\n\n")
	sb.WriteString("Given the following vulnerability details, identify the MITRE ATT&CK TTP IDs (Techniques) ")
	sb.WriteString("that an attacker would use to exploit this specific weakness. Consider the attack vector, ")
	sb.WriteString("the affected component, and the exploitation conditions described.\n\n")

	if cwe != "" {
		sb.WriteString(fmt.Sprintf("CWE: %s\n", cwe))
	}
	if cvssVector != "" {
		sb.WriteString(fmt.Sprintf("CVSS Vector: %s\n", cvssVector))
	}
	if description != "" {
		sb.WriteString(fmt.Sprintf("Vulnerability Description: %s\n", description))
	}

	sb.WriteString("\nYou MUST return ONLY a JSON object with a single key \"ttps\" containing an array of TTP ID strings.\n")
	sb.WriteString("Example: {\"ttps\": [\"T1190\", \"T1059.001\"]}")

	return sb.String()
}

func (c *OllamaClient) MapEnrichedToTTPRaw(ctx context.Context, cwe, description, cvssVector string) ([]string, string, error) {
	// Estrategia de Caché Híbrida:
	// Solo cacheamos si es una consulta simple (CWE sin descripción ni CVSS, ej. tests).
	// Si tiene contexto enriquecido de producción, evitamos el cacheo para garantizar máxima precisión.
	isSimpleQuery := description == "" && cvssVector == ""
	if isSimpleQuery && cwe != "" {
		if ttps, found := c.cache.Get(cwe); found {
			return ttps, "[CACHE HIT - NO RAW RESPONSE]", nil
		}
	}

	prompt := c.buildEnrichedPrompt(cwe, description, cvssVector)
	ttps, raw, err := c.generateTTPs(ctx, prompt)
	if err != nil {
		return nil, "", err
	}

	if isSimpleQuery && cwe != "" {
		c.cache.Set(cwe, ttps)
	}

	return ttps, raw, nil
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
