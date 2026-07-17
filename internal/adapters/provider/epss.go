package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const epssBaseURL = "https://api.first.org/data/v1/epss"

//usamos 100 CVEs por petición como margen seguro.
const epssBatchSize = 100

type epssItem struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

type epssResponseDTO struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Total      int        `json:"total"`
	Data       []epssItem `json:"data"`
}

// EPSSAdapter implementa ports.EPSSProvider consumiendo la API pública de FIRST.org.
type EPSSAdapter struct {
	baseURL    string
	httpClient *http.Client
}

func NewEPSSAdapter() *EPSSAdapter {
	return &EPSSAdapter{
		baseURL: epssBaseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Devuelve un mapa cveID → epssScore (0.0–1.0).
// CVEs sin registro EPSS aún (lag de 1-2 días) no aparecen en el mapa:
// el caller debe aplicar un valor conservador (0.1) para esos casos.
func (a *EPSSAdapter) FetchEPSS(ctx context.Context, cveIDs []string) (map[string]float64, error) {
	results := make(map[string]float64, len(cveIDs))

	for i := 0; i < len(cveIDs); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}

		partial, err := a.fetchBatch(ctx, cveIDs[i:end])
		if err != nil {
			return nil, err
		}
		for cve, score := range partial {
			results[cve] = score
		}
	}

	return results, nil
}

func (a *EPSSAdapter) fetchBatch(ctx context.Context, cveIDs []string) (map[string]float64, error) {
	reqURL := fmt.Sprintf("%s?cve=%s", a.baseURL, strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando request EPSS: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error llamando API EPSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api EPSS devolvió status %d", resp.StatusCode)
	}

	var dto epssResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		return nil, fmt.Errorf("error decodificando respuesta EPSS: %w", err)
	}

	results := make(map[string]float64, len(dto.Data))
	for _, item := range dto.Data {
		score, err := strconv.ParseFloat(item.EPSS, 64)
		if err != nil {
			continue // dato malformado: lo ignoramos, el caller aplica default
		}
		results[item.CVE] = score
	}

	return results, nil
}
