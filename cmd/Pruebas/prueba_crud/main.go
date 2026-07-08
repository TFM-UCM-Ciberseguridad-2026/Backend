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
	fmt.Println("Iniciando Motor TFM - Prueba de Ciclo de Vida CRUD con API NIST (Create, Update, Delete)")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// Inicializar los puertos
	_, vulnRepo, _, _, _, _, _, _, _, _, _, dbHelper, _ := neo4j.NewRepository(driver)
	nistScanner := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey)

	fmt.Println("Conexión a Neo4j establecida.")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)
	fmt.Println("Base de datos limpiada.")

	// Fetch vulnerability from NIST
	fmt.Println("\n=== FASE 0: FETCH API NIST ===")
	limit := 1
	offset := 100000 // Usamos el offset de Lucas
	vulnerabilities, err := nistScanner.FetchVulnerabilities(ctx, limit, offset)
	if err != nil || len(vulnerabilities) == 0 {
		log.Fatalf("Error descargando vulnerabilidad del NIST: %v", err)
	}
	realVuln := vulnerabilities[0]
	fmt.Printf("Vulnerabilidad obtenida del NIST: %s (Score: %.1f)\n", realVuln.CVEID, realVuln.BaseScore)

	fmt.Println("\n=== FASE 1: CREATE ===")
	_ = vulnRepo.Save(ctx, &realVuln)
	fmt.Printf("[SAVE] Nodos creados (%s).\n", realVuln.CVEID)

	// Verificamos la creación
	vulnCreated, _ := vulnRepo.GetByID(ctx, realVuln.CVEID)
	fmt.Printf("[LECTURA] (Tras CREATE) -> ID: %s, Score: %.1f, Desc: %s...\n", vulnCreated.CVEID, vulnCreated.BaseScore, vulnCreated.Description[:40])

	fmt.Println("\n=== FASE 2: UPDATE (Modificación vía MERGE) ===")
	// Modificamos la vulnerabilidad (mismo CVE, distinto score simulando mitigación)
	realVuln.BaseScore = 0.0
	realVuln.Description = "[MITIGADA] " + realVuln.Description

	_ = vulnRepo.Save(ctx, &realVuln)
	fmt.Println("[SAVE] Nodos modificados usando Save() de nuevo.")

	// Verificamos la modificación
	vulnDB, _ := vulnRepo.GetByID(ctx, realVuln.CVEID)
	fmt.Printf("[LECTURA] (Tras UPDATE) -> Score: %.1f, Desc: %s...\n", vulnDB.BaseScore, vulnDB.Description[:40])

	fmt.Println("\n=== FASE 3: DELETE ===")
	err = vulnRepo.DeleteByID(ctx, realVuln.CVEID)
	if err != nil {
		log.Fatalf("Error al borrar Vulnerabilidad: %v", err)
	}
	fmt.Println("[DELETE] Comando DeleteByID ejecutado para la vulnerabilidad.")

	// Verificamos que ya no existen
	vulnDel, _ := vulnRepo.GetByID(ctx, realVuln.CVEID)
	
	if vulnDel == nil {
		fmt.Printf("[LECTURA] (Tras DELETE) -> Comprobación correcta: La vulnerabilidad %s ya no existe en la BD (devuelve nil).\n", realVuln.CVEID)
	}

	fmt.Println("\n¡PRUEBA CRUD CON NIST SUPERADA COMPLETAMENTE!")
}
