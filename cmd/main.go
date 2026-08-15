package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/handler"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/handler/middleware"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider/ollama"
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
	ttpRepo := neo4j.NewTTPRepository(driver)
	actorRepo := neo4j.NewThreatActorRepository(driver)

	// 4. Inicialización del Servicio/Orquestador (Core)
	nistAPIAdapter := provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds)
	epssAdapter := provider.NewEPSSAdapter()
	kevAdapter := provider.NewKEVAdapter()
	scoutAdapter := provider.NewScoutAdapter()
	osvAdapter := provider.NewOSVAdapter()
	ollamaClient := ollama.NewOllamaClient(cfg.Ollama.Host, cfg.Ollama.Model)
	mitreAttackProvider := provider.NewMitreAttackSTIXProvider("", 120)

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
	).WithRisk(riskRepo, epssAdapter, kevAdapter).WithScout(scoutAdapter).WithPatchProvider(osvAdapter).WithTTPMapper(ollamaClient)

	// Inyectar el repositorio y proveedor para el catálogo de MITRE ATT&CK
	orchestrator.WithMitreATTACK(ttpRepo, mitreAttackProvider, actorRepo)

	// Iniciar sincronización inicial del catálogo de MITRE ATT&CK en segundo plano si está vacío o incompleto.
	go func() {
		time.Sleep(5 * time.Second) // dar un pequeño margen para que el backend esté listo
		initCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		count, err := orchestrator.GetTotalMitreTTPs(initCtx)
		if err != nil {
			log.Printf("[MITRE Sync] Error comprobando catálogo de TTPs: %v", err)
			return
		}

		var taCount int64
		res, err := dbHelper.ExecuteRead(initCtx, "MATCH (n:ThreatActor) RETURN count(n) AS total", nil)
		if err == nil && res != nil {
			if m, ok := res.(map[string]any); ok {
				if total, ok := m["total"].(int64); ok {
					taCount = total
				}
			}
		}

		if count == 0 || taCount == 0 {
			log.Printf("[MITRE Sync] Catálogo incompleto (TTPs: %d, Threat Actors: %d). Iniciando descarga e importación automática de MITRE ATT&CK Enterprise...", count, taCount)
			num, err := orchestrator.SyncATTACKCatalog(initCtx)
			if err != nil {
				log.Printf("[MITRE Sync] Error importando catálogo MITRE: %v", err)
			} else {
				log.Printf("[MITRE Sync] Importación de MITRE ATT&CK completada con éxito. %d TTPs importadas.", num)
			}
		} else {
			log.Printf("[MITRE Sync] Catálogo de MITRE ya inicializado con %d TTPs y %d Threat Actors.", count, taCount)
		}
	}()

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
