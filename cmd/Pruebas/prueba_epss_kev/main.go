package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
)
//Prueba creada por el Claude. Funcioona correctamente. Se puede ejecutar con go run main.go
// CVEs de prueba: mezcla de CVEs conocidos en KEV + uno reciente sin exploits
var testCVEs = []string{
	"CVE-2021-44228", // Log4Shell — debería estar en KEV, EPSS ~0.97
	"CVE-2017-0144",  // EternalBlue (WannaCry) — en KEV
	"CVE-2023-44487", // HTTP/2 Rapid Reset — en KEV
	"CVE-2024-3400",  // PAN-OS 0-day — en KEV
	"CVE-2023-12345", // CVE ficticio — no debería existir
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testEPSS(ctx)
	fmt.Println()
	testKEV(ctx, testCVEs)
}

func testEPSS(ctx context.Context) {
	fmt.Println("=== PRUEBA EPSS (api.first.org) ===")

	adapter := provider.NewEPSSAdapter()

	scores, err := adapter.FetchEPSS(ctx, testCVEs)
	if err != nil {
		log.Fatalf("❌ Error EPSS: %v", err)
	}

	fmt.Printf("CVEs solicitados: %d | CVEs con score EPSS: %d\n", len(testCVEs), len(scores))
	fmt.Println("--------------------------------------------------------------------------------")

	for _, cve := range testCVEs {
		score, found := scores[cve]
		if found {
			fmt.Printf("  %-20s EPSS: %.4f  (%.1f%% percentil aprox.)\n", cve, score, score*100)
		} else {
			fmt.Printf("  %-20s EPSS: sin datos (CVE nuevo o ficticio — aplicar default 0.10)\n", cve)
		}
	}
	fmt.Println("================================================================================")
}

func testKEV(ctx context.Context, cves []string) {
	fmt.Println("=== PRUEBA KEV (CISA Known Exploited Vulnerabilities) ===")

	adapter := provider.NewKEVAdapter()

	catalog, err := adapter.FetchKEV(ctx)
	if err != nil {
		log.Fatalf("❌ Error KEV: %v", err)
	}

	fmt.Printf("Total CVEs en el catálogo CISA KEV: %d\n", len(catalog))
	fmt.Println("--------------------------------------------------------------------------------")

	inKEV := 0
	for _, cve := range cves {
		if catalog[cve] {
			fmt.Printf("  %-20s ✓ EN KEV  → likelihood = 1.0\n", cve)
			inKEV++
		} else {
			fmt.Printf("  %-20s - no está en KEV\n", cve)
		}
	}
	fmt.Printf("--------------------------------------------------------------------------------\n")
	fmt.Printf("Resultado: %d/%d CVEs de prueba están en KEV\n", inKEV, len(cves))
	fmt.Println("================================================================================")
}
