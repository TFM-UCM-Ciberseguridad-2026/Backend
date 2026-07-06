package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
	http_handler "github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/handler/http"
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
	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, _, projectRepo, _, relRepo := neo4j.NewRepository(driver)

	// 4. Inicialización del Servicio/Orquestador (Core)
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
	)

	// 5. Inicialización de los Controladores HTTP (Adaptadores Inbound)
	handler := http_handler.NewOrchestratorHandler(orchestrator)
	router := http_handler.NewRouter(handler)

	// 6. Levantar Servidor Web
	port := ":8080"
	fmt.Printf("Servidor HTTP levantado en el puerto %s\n", port)
	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Error crítico en el servidor HTTP: %v", err)
	}
}
