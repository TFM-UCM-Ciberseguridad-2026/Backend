package service_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func TestExecuteCPEPipeline_NginxVersionMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Saltando test de integración con APIs externas (NVD / CIRCL) en modo corto")
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	guesserAdapter := provider.NewCPEGuesserAdapter("https://cpe-guesser.cve-search.org/search", httpClient)
	nvdAdapter := provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cpes/2.0", "", 10)

	cpeService := service.NewCPEService(nvdAdapter).WithCPEGuesser(guesserAdapter)

	tests := []struct {
		name            string
		query           string
		expectedVersion string
	}{
		{
			name:            "Nombre: nginx, Versión: 1.10.0",
			query:           "nginx 1.10.0",
			expectedVersion: "1.10.0",
		},
		{
			name:            "Nombre: nginx, Versión: 1.10",
			query:           "nginx 1.10",
			expectedVersion: "1.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()


			results, err := cpeService.ExecuteCPEPipeline(ctx, tt.query)
			if err != nil {
				t.Fatalf("Error inesperado ejecutando CPE pipeline para %q: %v", tt.query, err)
			}

			if len(results) == 0 {
				t.Fatalf("Se esperaban resultados de sugerencias CPE para %q, pero se obtuvo una lista vacía", tt.query)
			}

			t.Logf("Se obtuvieron %d resultados para %q:", len(results), tt.query)
			for i, item := range results {
				if i < 5 {
					t.Logf(" [%d] Title: %s | CPE: %s", i+1, item.Title, item.CPE)
				}
			}

			first := results[0]
			if first.CPE == "" {
				t.Errorf("El primer CPE no debería estar vacío")
			}

			if !containsSubstring(first.CPE, tt.expectedVersion) && !containsSubstring(first.Title, tt.expectedVersion) {
				t.Errorf("Se esperaba que la primera recomendación contuviera la versión %s, pero se obtuvo: Title=%q, CPE=%q", tt.expectedVersion, first.Title, first.CPE)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && searchSubstr(s, substr))
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
