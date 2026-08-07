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
	// Carga de configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error inicializando la configuración: %v", err)
	}

	log.Printf("Configuración cargada correctamente.")

	// Inicializamos el adaptador
	nistScanner := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)

	// Definimos un contexto
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Vamos a buscar las vulnerabilidades de las últimas 24 horas
	endDate := time.Now().UTC()
	startDate := endDate.Add(-24 * time.Hour)

	log.Printf("Conectando a la API de NIST en: %s", cfg.NVD.BaseURL)
	log.Printf("Buscando desde %s hasta %s", startDate.Format(time.RFC3339), endDate.Format(time.RFC3339))

	vulnerabilities, err := nistScanner.FetchByDate(ctx, startDate, endDate)
	if err != nil {
		log.Fatalf("Error ejecutando el scanner de NIST por fecha: %v", err)
	}

	fmt.Printf("\nmostrando %d vulnerabilidades de la respuesta de NIST:\n", len(vulnerabilities))
	fmt.Println("================================================================================")

	for _, vuln := range vulnerabilities {
		fmt.Printf("[ID CVE]:      %s\n", vuln.CVEID)
		fmt.Printf("    Score CVSS:  %.1f\n", vuln.BaseScore)
		fmt.Printf("    CWE:         %v\n", vuln.CWE)
		fmt.Printf("    Primer CPE:  %s\n", vuln.CPE)
		
		if len(vuln.Patches) > 0 {
			fmt.Printf("Parches Encontrados: %d\n", len(vuln.Patches))
			for i, p := range vuln.Patches {
				fmt.Printf("      - %d: %s\n", i+1, p.URL)
			}
		} else {
			fmt.Printf("No se detectaron parches oficiales.\n")
		}
		
		fmt.Println("--------------------------------------------------------------------------------")
	}

	fmt.Println("================================================================================")
}
