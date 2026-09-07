package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider/ollama"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

/*
Este comando ejecuta exclusivamente la función RunDailyPipeline de forma directa y única.
Permite verificar la ingesta de vulnerabilidades, escaneo de Docker Scout y recálculo de
riesgo en tiempo real contra la base de datos de producción/desarrollo sin arrancar el servidor web.
*/

func main() {
	fmt.Println("=== Ejecución Manual de Prueba: RunDailyPipeline ===")

	// 1. Configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 2. Conexión a la base de datos Neo4j
	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer func() {
		fmt.Println("Cerrando conexión a Neo4j...")
		driver.Close(context.Background())
	}()

	// 3. Inicialización de Repositorios
	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)
	capecRepo := neo4j.NewCAPECRepository(driver)

	// 4. Inicialización del Servicio/Orquestador (Core)
	nistAPIAdapter := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)
	nistAPIAdapter.SetCacheTTL(time.Duration(cfg.NVD.CacheTTLHours) * time.Hour)
	epssAdapter := provider.NewEPSSAdapter()
	kevAdapter := provider.NewKEVAdapter()
	scoutAdapter := provider.NewScoutAdapter()
	osvAdapter := provider.NewOSVAdapter()
	ollamaClient := ollama.NewOllamaClient(cfg.Ollama.Host, cfg.Ollama.Model)

	capecProvider := provider.NewCapecSTIXProvider("", 120)
	cpeGuesserAdapter := provider.NewCPEGuesserAdapter("", nil)

	orchestrator := service.NewOrchestrator(
		projectRepo,
		endpointRepo,
		hardwareRepo,
		networkRepo,
		softwareInstRepo,
		softwareRepo,
		findingRepo,
		vulnRepo,
		remediationRepo,
		relRepo,
		infraRepo,
		containerRepo,
		patchRepo,
		dbHelper,
		nistAPIAdapter,
	).WithRisk(riskRepo, epssAdapter, kevAdapter).
		WithScout(scoutAdapter).
		WithPatchProvider(osvAdapter).
		WithTTPMapper(ollamaClient).
		WithCPEResolution(nistAPIAdapter).
		WithCPEGuesser(cpeGuesserAdapter)

	orchestrator.WithCAPEC(capecRepo, capecProvider)

	// 5. Ejecución exclusiva y directa de RunDailyPipeline
	fmt.Println("Iniciando ejecución directa de RunDailyPipeline()...")
	pipelineCtx, cancelPipeline := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancelPipeline()

	startTime := time.Now()
	err = orchestrator.RunDailyPipeline(pipelineCtx)
	elapsed := time.Since(startTime)

	if err != nil {
		log.Fatalf("❌ Error durante la ejecución de RunDailyPipeline: %v (Tiempo transcurrido: %v)", err, elapsed)
	}

	fmt.Printf("✅ RunDailyPipeline ejecutada con éxito en %v.\n", elapsed)
}
