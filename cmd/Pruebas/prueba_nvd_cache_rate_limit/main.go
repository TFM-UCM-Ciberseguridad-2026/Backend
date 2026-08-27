package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

func main() {
	fmt.Println("=== PRUEBA NVD CACHE + RATE LIMIT ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	adapter := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)
	cpe := "cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*"

	fmt.Println("[1/3] Primera consulta NVD por CPE...")
	startFirst := time.Now()
	first, err := adapter.FetchByCPE(ctx, cpe)
	if err != nil {
		log.Fatalf("Primera consulta falló: %v", err)
	}
	firstDuration := time.Since(startFirst)
	fmt.Printf("    CVEs: %d | duración: %s\n", len(first.Vulnerabilities), firstDuration.Round(time.Millisecond))

	if len(first.Vulnerabilities) == 0 {
		log.Fatalf("ASSERT FAIL: Tomcat 9.0.37 debería devolver CVEs")
	}

	fmt.Println("[2/3] Segunda consulta al mismo CPE, debe usar cache...")
	startSecond := time.Now()
	second, err := adapter.FetchByCPE(ctx, cpe)
	if err != nil {
		log.Fatalf("Segunda consulta falló: %v", err)
	}
	secondDuration := time.Since(startSecond)
	fmt.Printf("    CVEs: %d | duración: %s\n", len(second.Vulnerabilities), secondDuration.Round(time.Millisecond))

	if len(second.Vulnerabilities) != len(first.Vulnerabilities) {
		log.Fatalf("ASSERT FAIL: resultados distintos entre primera y segunda consulta: %d != %d", len(first.Vulnerabilities), len(second.Vulnerabilities))
	}

	if secondDuration >= firstDuration {
		log.Fatalf("ASSERT FAIL: segunda consulta no parece cacheada: primera=%s segunda=%s", firstDuration, secondDuration)
	}

	fmt.Println("[3/3] Resultado")
	fmt.Println("    ✓ Segunda consulta reutiliza cache en memoria")
	fmt.Println("    ✓ Resultados consistentes")
	fmt.Println("\n✓ PRUEBA COMPLETADA")
}
