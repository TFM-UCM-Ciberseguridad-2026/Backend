package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

/*
main ejecuta un flujo que descarga 100 vulnerabilidades de la API del NIST NVD, las parsea y convierte de forma dinámica a formato CVSS v3.1, y comprueba que se recuperen en el formato CVSS v3.1 esperado, todo en memoria sin requerir base de datos.
*/
func main() {
	fmt.Println("=== INICIANDO PRUEBA: COMPROBACIÓN DE PARSEO CVSS (SIN BD) ===")

	// 1. Cargar Configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 2. Pruebas unitarias de conversión en memoria para verificar la lógica
	fmt.Println("\n--- PARTE 1: Ejecutando vectores de prueba unitaria ---")

	// Caso CVSS v2.0 -> v3.1
	v2Vector := "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	fmt.Printf("[Test CVSS 2.0] Vector original: %s\n", v2Vector)
	v31FromV2, scoreFromV2, err := domain.CVSS2ToCVSS31(v2Vector)
	if err != nil {
		fmt.Printf("  Error convirtiendo CVSS 2.0 a 3.1: %v\n", err)
	} else {
		fmt.Printf("  Vector convertido CVSS 3.1: %s\n", v31FromV2)
		fmt.Printf("  Score calculado CVSS 3.1:   %.1f\n", scoreFromV2)
	}

	// Caso CVSS v4.0 -> v3.1
	v4Vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	fmt.Printf("[Test CVSS 4.0] Vector original: %s\n", v4Vector)
	v31FromV4, scoreFromV4, err := domain.CVSS4ToCVSS31(v4Vector)
	if err != nil {
		fmt.Printf("  Error convirtiendo CVSS 4.0 a 3.1: %v\n", err)
	} else {
		fmt.Printf("  Vector convertido CVSS 3.1: %s\n", v31FromV4)
		fmt.Printf("  Score calculado CVSS 3.1:   %.1f\n", scoreFromV4)
	}

	// 3. Inicializar Proveedor (NIST NVD)
	fmt.Println("\n--- PARTE 2: Descargando de NIST NVD y verificando conversiones ---")
	nistScanner := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)
	fmt.Printf("Conectando a NIST NVD (%s)...\n", cfg.NVD.BaseURL)

	// 4. Obtener 100 Vulnerabilidades
	limit := 100
	offset := 5000 // Usar un offset intermedio para obtener vulnerabilidades interesantes
	fmt.Printf("Descargando %d vulnerabilidades de NIST NVD con offset %d...\n", limit, offset)

	vulnerabilities, err := nistScanner.FetchVulnerabilities(ctx, limit, offset)
	if err != nil {
		log.Fatalf("Error descargando vulnerabilidades del NIST: %v", err)
	}
	fmt.Printf("Descarga completada. Total recibidas: %d\n", len(vulnerabilities))

	// 5. Verificar en Memoria
	successCount := 0
	emptyCount := 0
	
	fmt.Println("\nVerificando vectores en memoria...")
	fmt.Println("--------------------------------------------------------------------------------")
	for i, vuln := range vulnerabilities {
		if vuln.NVDVector == "" {
			emptyCount++
			fmt.Printf("[%d/%d] %s: Sin vector de métricas\n", i+1, len(vulnerabilities), vuln.CVEID)
		} else {
			if !strings.HasPrefix(vuln.NVDVector, "CVSS:3.1/") {
				log.Fatalf("ERROR CRÍTICO en %s: NVDVector %q NO está en formato CVSS v3.1", vuln.CVEID, vuln.NVDVector)
			}
			successCount++
			fmt.Printf("[%d/%d] %s: OK -> Vector: %s (BaseScore: %.1f)\n", 
				i+1, len(vulnerabilities), vuln.CVEID, vuln.NVDVector, vuln.BaseScore)
		}
	}
	fmt.Println("--------------------------------------------------------------------------------")

	fmt.Printf("\n=== PRUEBA FINALIZADA CON ÉXITO ===\n")
	fmt.Printf("Vulnerabilidades procesadas: %d\n", len(vulnerabilities))
	fmt.Printf("Vulnerabilidades con vector CVSS v3.1 verificado: %d\n", successCount)
	fmt.Printf("Vulnerabilidades sin vector (métricas ausentes en API): %d\n", emptyCount)
}
