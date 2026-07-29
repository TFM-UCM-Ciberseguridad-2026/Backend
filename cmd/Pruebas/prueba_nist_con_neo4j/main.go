package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

func main() {
	fmt.Println("Iniciando Motor TFM - Prueba de Integración NIST <-> Neo4j")

	// 1. Cargar Configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 2. Inicializar Persistencia (Neo4j)
	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)
	
	// Obtenemos todos los repositorios, pero solo usaremos vulnRepo y dbHelper
	_, vulnRepo, _, _, _, _, _, _, _, _, _, dbHelper, _, _ := neo4j.NewRepository(driver)

	fmt.Println("Conexión a Neo4j establecida.")
	
	// Limpiar DB para que se vea claro el resultado
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)
	fmt.Println("Base de datos limpiada para la prueba.")

	// 3. Inicializar Proveedor (NIST NVD)
	nistScanner := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, 30)
	fmt.Printf("Conectando a NIST NVD (%s, 30)...\n", cfg.NVD.BaseURL)

	// 4. Fetch de Vulnerabilidades
	limit := 5
	offset := 100000 // Offset de prueba de Lucas
	vulnerabilities, err := nistScanner.FetchVulnerabilities(ctx, limit, offset)
	if err != nil {
		log.Fatalf("Error descargando vulnerabilidades del NIST: %v", err)
	}

	fmt.Printf("\nDescargadas %d vulnerabilidades. Procediendo a inyectarlas en Neo4j...\n", len(vulnerabilities))
	fmt.Println("================================================================================")

	// 5. Guardar en Neo4j
	for i, vuln := range vulnerabilities {
		// Pasamos un puntero a la funcion Save
		err := vulnRepo.Save(ctx, &vuln)
		if err != nil {
			log.Printf("Error guardando %s: %v", vuln.CVEID, err)
			continue
		}
		fmt.Printf("Guardado [%d/%d]: %s (Score: %.1f)\n", i+1, len(vulnerabilities), vuln.CVEID, vuln.BaseScore)
	}

	fmt.Println("================================================================================")
	
	// 6. Prueba de Recuperación: Leer la primera de Neo4j
	if len(vulnerabilities) > 0 {
		firstCVE := vulnerabilities[0].CVEID
		fmt.Printf("\nRecuperando %s desde Neo4j para verificar...\n", firstCVE)
		
		dbVuln, err := vulnRepo.GetByID(ctx, firstCVE)
		if err != nil {
			log.Fatalf("Error leyendo de Neo4j: %v", err)
		}
		if dbVuln != nil {
			fmt.Printf("Recuperado con éxito de la Base de Datos:\n")
			fmt.Printf("    ID:          %s\n", dbVuln.CVEID)
			fmt.Printf("    Score:       %.1f\n", dbVuln.BaseScore)
			fmt.Printf("    Descripción: %s\n", dbVuln.Description)
		} else {
			fmt.Println("No se encontró la vulnerabilidad en Neo4j.")
		}
	}

	fmt.Println("\n¡PRUEBA NIST <-> NEO4J SUPERADA! Pulsa Ctrl+C para salir.")
}
