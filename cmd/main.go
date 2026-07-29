package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/handler"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/handler/middleware"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
	"github.com/go-co-op/gocron"
)

/*
Este archivo implementa el Compositor Principal (Composition Root) del sistema.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en la raíz de comandos (`cmd/main.go`), sirviendo como el punto de inicio donde se configuran y cablean todos los adaptadores y puertos (Inyección de Dependencias).
2. Punto de Entrada Único (main): Actúa como el punto de inicio del hilo ejecutable principal del sistema operativo.
3. Inyección de Dependencias Manual: Instancia de manera secuencial los componentes de configuración, bases de datos (adaptadores de persistencia), proveedores de API externa (adaptadores de salida), servicios lógicos (núcleo/casos de uso) y controladores HTTP (adaptadores de entrada).
4. Orquestador de Bootstrap: Asocia los adaptadores específicos a sus correspondientes puertos (interfaces) y los inyecta en el constructor de los servicios de aplicación, iniciando posteriormente el servidor web.
*/

func main() {
	fmt.Println("=== Iniciando Backend TFM (API HTTP) ===")

	// 1. Configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 2. Conexión a la base de datos Neo4j (Adaptador Outbound)
	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer func() {
		fmt.Println("Cerrando conexión a Neo4j...")
		driver.Close(context.Background())
	}()

	// 3. Inicialización de Repositorios (Adaptadores Outbound)
	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	// 4. Inicialización del Servicio/Orquestador (Core)
	nistAPIAdapter := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)
	epssAdapter := provider.NewEPSSAdapter()
	kevAdapter := provider.NewKEVAdapter()
	scoutAdapter := provider.NewScoutAdapter()
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
	).WithRisk(riskRepo, epssAdapter, kevAdapter).WithScout(scoutAdapter)

	// 5. Inicialización de los Controladores HTTP (Adaptadores Inbound)
	h := handler.NewOrchestratorHandler(orchestrator)
	router := handler.NewRouter(h)

	// Middleware CORS para evitar bloqueos del navegador en desarrollo
	corsHandler := middleware.CORS(router)

	// Iniciar planificador Cron para la tarea diaria del NIST
	s := gocron.NewScheduler(time.UTC)
	s.Every(1).Day().At("02:00").Do(func() {
		fmt.Println("Ejecutando tarea diaria: Sincronización con NIST...")
		cronCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute) // Damos tiempo porque la API del NIST puede ser lenta
		defer cancel()
		if err := orchestrator.SyncNistDaily(cronCtx); err != nil {
			log.Printf("Error en sincronización diaria NIST: %v", err)
		} else {
			log.Println("Sincronización diaria NIST completada con éxito.")
		}
	})
	
	// Añadimos el escaneo de contenedores diario
	s.Every(1).Day().At("03:00").Do(func() {
		fmt.Println("Ejecutando tarea diaria: Escaneo de imágenes con Docker Scout...")
		cronCtx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		if err := orchestrator.SyncScoutDaily(cronCtx); err != nil {
			log.Printf("Error en escaneo diario Docker Scout: %v", err)
		} else {
			log.Println("Escaneo diario Docker Scout completado con éxito.")
		}
	})
	
	s.StartAsync()

	// 6. Levantar Servidor Web (con Graceful Shutdown)
	port := ":8080"
	server := handler.NewServer(port, corsHandler)
	server.Start()
}
