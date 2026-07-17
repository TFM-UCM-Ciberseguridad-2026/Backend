package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevVulnDTO struct {
	CVEID         string `json:"cveID"`
	VendorProject string `json:"vendorProject"`
	Product       string `json:"product"`
	DateAdded     string `json:"dateAdded"`
}

type kevResponseDTO struct {
	Title          string       `json:"title"`
	CatalogVersion string       `json:"catalogVersion"`
	DateReleased   string       `json:"dateReleased"`
	Count          int          `json:"count"`
	Vulnerabilities []kevVulnDTO `json:"vulnerabilities"`
}

// KEVAdapter implementa ports.KEVProvider descargando el catálogo JSON de CISA KEV.
// El catálogo completo se descarga una vez al día vía cron.
type KEVAdapter struct {
	url        string
	httpClient *http.Client
}

func NewKEVAdapter() *KEVAdapter {
	return &KEVAdapter{
		url: kevURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// FetchKEV descarga el catálogo CISA KEV y devuelve un set de CVE IDs.
// El mapa resultante contiene true para cada CVE con explotación activa confirmada.
func (a *KEVAdapter) FetchKEV(ctx context.Context) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando request KEV: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error descargando catálogo KEV CISA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catálogo KEV devolvió status %d", resp.StatusCode)
	}

	var dto kevResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		return nil, fmt.Errorf("error decodificando catálogo KEV: %w", err)
	}

	catalog := make(map[string]bool, dto.Count)
	for _, v := range dto.Vulnerabilities {
		catalog[v.CVEID] = true
	}

	return catalog, nil
}
