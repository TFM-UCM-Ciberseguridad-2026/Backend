package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

/*
cpe_guesser.go implementa el adaptador de infraestructura para consultar el servicio
CIRCL CPE Guesser (https://cpe-guesser.cve-search.org/search).

Fase 2 del Pipeline de Resolución de CPEs:
- Realiza búsquedas difusas y de lenguaje natural basadas en tokens de palabras clave.
- Devuelve las tuplas [score, cpe_base] ordenadas por relevancia.
*/

type CPEGuesserAdapter struct {
	baseURL    string
	httpClient *http.Client
}

func NewCPEGuesserAdapter(baseURL string, httpClient *http.Client) *CPEGuesserAdapter {
	if baseURL == "" {
		baseURL = "https://cpe-guesser.cve-search.org/search"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &CPEGuesserAdapter{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

type guesserRequest struct {
	Query []string `json:"query"`
}

// SearchBaseCPEs realiza la Fase 2 del pipeline: consulta CPE-Guesser y devuelve los primeros topK CPEs base.
func (a *CPEGuesserAdapter) SearchBaseCPEs(ctx context.Context, tokens []string, topK int) ([]string, error) {
	if len(tokens) == 0 {
		return []string{}, nil
	}
	if topK <= 0 {
		topK = 3
	}

	reqBody, err := json.Marshal(guesserRequest{Query: tokens})
	if err != nil {
		return nil, fmt.Errorf("error serializando petición a cpe-guesser: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("error creando petición HTTP a cpe-guesser: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando consulta a cpe-guesser: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cpe-guesser devolvió un código HTTP %d", resp.StatusCode)
	}

	// La respuesta de cpe-guesser es un array de tuplas: [[score (float), cpe (string)], ...]
	var rawResults [][]any
	if err := json.NewDecoder(resp.Body).Decode(&rawResults); err != nil {
		return nil, fmt.Errorf("error decodificando respuesta JSON de cpe-guesser: %w", err)
	}

	baseCPEs := []string{}
	seen := make(map[string]bool)

	for _, item := range rawResults {
		if len(item) < 2 {
			continue
		}
		cpeStr, ok := item[1].(string)
		if !ok || cpeStr == "" {
			continue
		}

		if !seen[cpeStr] {
			seen[cpeStr] = true
			baseCPEs = append(baseCPEs, cpeStr)
			if len(baseCPEs) >= topK {
				break
			}
		}
	}

	return baseCPEs, nil
}
