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
	fmt.Println("Iniciando prueba manual del ETL de MITRE CTI...")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// Inicializar los puertos para el ETL
	mitreCTIProvider := provider.NewMitreCTIProvider()
	mitreCatalogRepo := neo4j.NewMitreCatalogRepository(driver)

	// Inicializar un orquestador mínimo
	orchestrator := service.NewOrchestrator(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	).WithMitreCatalog(mitreCTIProvider, mitreCatalogRepo)

	fmt.Println("Descargando e insertando STIX 2.1 (CAPEC y ATT&CK). Esto puede tomar unos minutos...")
	
	if err := orchestrator.SyncMitreCatalogDaily(ctx); err != nil {
		log.Fatalf("Error ejecutando SyncMitreCatalogDaily: %v", err)
	}

	fmt.Println("¡Catálogo MITRE sincronizado con éxito!")
}

