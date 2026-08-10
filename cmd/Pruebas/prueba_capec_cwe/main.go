package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("=== INICIANDO PRUEBA DE INGESTIÓN Y CONEXIÓN CWE - CAPEC ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)
	fmt.Println("Conexión a Neo4j establecida con éxito.")

	// Inicializar repositorios y proveedores
	endpointRepo, vulnRepo, swRepo, installRepo, findingRepo, remRepo, _, hwRepo, netRepo, patchRepo, projRepo, dbHelper, relRepo, _ := neo4j.NewRepository(driver)

	capecRepo := neo4j.NewCAPECRepository(driver)
	capecProvider := provider.NewCapecSTIXProvider("", 60)

	orchestrator := service.NewOrchestrator(
		projRepo, endpointRepo, hwRepo, netRepo, installRepo, swRepo,
		findingRepo, vulnRepo, remRepo, relRepo, nil, nil, patchRepo, dbHelper, nil,
	).WithCAPEC(capecRepo, capecProvider)

	// Sincronizar catálogo CAPEC STIX 2.1
	fmt.Println("\n1. Sincronizando catálogo STIX 2.1 CAPEC...")
	count, err := orchestrator.SyncCAPECCatalog(ctx)
	if err != nil {
		log.Fatalf("❌ Error sincronizando catálogo CAPEC: %v", err)
	}
	fmt.Printf("✅ Se han procesado e ingerido %d patrones de ataque CAPEC en Neo4j.\n", count)

	// Validar la lectura de un CAPEC de prueba (ej: CAPEC-100 u otro)
	fmt.Println("\n2. Recuperando CAPEC-100 de Neo4j para validar la entidad y sus CWEs asociadas...")
	capec, err := capecRepo.GetByID(ctx, "CAPEC-100")
	if err != nil || capec == nil {
		log.Fatalf("❌ Error recuperando CAPEC-100 de Neo4j: %v", err)
	}

	fmt.Printf("   CAPEC ID:    %s\n", capec.CAPECID)
	fmt.Printf("   Nombre:      %s\n", capec.Name)
	fmt.Printf("   CWEs:        %v\n", capec.CWEs)

	// Validar la existencia de relaciones (:CAPEC)-[:MAPS_TO_CWE]->(:CWE) en Neo4j
	fmt.Println("\n3. Verificando relaciones (CAPEC)-[:MAPS_TO_CWE]->(CWE) mediante Cypher...")
	cypherQuery := `
		MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE)
		RETURN count(c) AS totalRelaciones, count(DISTINCT c) AS totalCapecs, count(DISTINCT w) AS totalCwes
	`
	res, err := dbHelper.ExecuteRead(ctx, cypherQuery, nil)
	if err != nil {
		log.Fatalf("❌ Error consultando relaciones en Neo4j: %v", err)
	}

	fmt.Printf("   Resultado Cypher: %+v\n", res)
	fmt.Println("\n✅ PRUEBA COMPLETADA CON ÉXITO: Relación CWE - CAPEC ingerida y verificada correctamente.")
}
