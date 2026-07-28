package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("=== Iniciando Prueba de Escaneo Automático de Vulnerabilidades ===")

	// 1. Cargar Configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 2. Conectar a Neo4j
	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// 3. Inicializar repositorios
	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo , _ := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)

	// Limpiar base de datos
	fmt.Println("Limpiando base de datos...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)
	fmt.Println("[OK] Base de datos limpia.")

	// 4. Inicializar NIST Adapter y Orchestrator
	nistAPIAdapter := provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cves/2.0", cfg.NVD.APIKey, 30)
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
		nil, // containerRepo
		patchRepo,
		dbHelper,
		nistAPIAdapter,
	)

	// 5. Inyectar datos de prueba
	now := time.Now().UTC()
	project := &domain.Project{ProjectID: 1, Nombre: "Proyecto de Prueba de Vulnerabilidades"}
	if err := orchestrator.CreateProject(ctx, project); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	ep := &domain.Endpoint{
		EndpointID:         100,
		Hostname:           "srv-tomcat-target",
		Type:               "Linux",
		InternetExposed:    true,
		ConfidentialityReq: "High",
		IntegrityReq:       "High",
		AvailabilityReq:    "Medium",
	}
	if err := orchestrator.AddEndpointToProject(ctx, 1, ep); err != nil {
		log.Fatalf("Error asociando endpoint: %v", err)
	}

	// Caso 1: Tomcat 9.0.37 (tipo aplicación -> 'a')
	swApp := &domain.Software{
		SoftwareID: 200,
		Name:       "Tomcat",
		Version:    "9.0.37",
		Vendor:     "Apache",
		Type:       "application", // Debería mapear a 'a'
	}
	instApp := &domain.SoftwareInstallation{
		InstallationID: "inst-tomcat-target",
		FirstSeen:      now,
		Status:         "INSTALLED",
		InstallPath:    "/opt/tomcat",
	}
	if err := orchestrator.RegisterSoftwareInstallation(ctx, 100, swApp, instApp); err != nil {
		log.Fatalf("Error registrando instalación de Tomcat: %v", err)
	}

	// Caso 2: Ubuntu 20.04 (tipo sistema operativo -> 'o')
	swOS := &domain.Software{
		SoftwareID: 201,
		Name:       "ubuntu_linux",
		Version:    "20.04",
		Vendor:     "canonical",
		Type:       "operating system", // Debería mapear a 'o'
	}
	instOS := &domain.SoftwareInstallation{
		InstallationID: "inst-ubuntu-target",
		FirstSeen:      now,
		Status:         "INSTALLED",
		InstallPath:    "/",
	}
	if err := orchestrator.RegisterSoftwareInstallation(ctx, 100, swOS, instOS); err != nil {
		log.Fatalf("Error registrando instalación de Ubuntu: %v", err)
	}

	fmt.Println("Datos de prueba registrados (Tomcat y Ubuntu en srv-tomcat-target).")

	// 6. Ejecutar el escaneo automático
	fmt.Println("\nEjecutando escaneo automático por CPE/versión...")
	if err := orchestrator.AutoScanAndRegisterVulnerabilities(ctx, "inst-tomcat-target", 200); err != nil {
		log.Fatalf("Error durante el escaneo automático de Tomcat: %v", err)
	}
	if err := orchestrator.AutoScanAndRegisterVulnerabilities(ctx, "inst-ubuntu-target", 201); err != nil {
		log.Fatalf("Error durante el escaneo automático de Ubuntu: %v", err)
	}
	fmt.Println("Escaneo automático finalizado.")

	// 7. Verificar resultados en Neo4j mediante consultas Cypher
	fmt.Println("\nVerificando resultados en Neo4j...")

	// Verificar si los CPEs se generaron correctamente
	dbSwApp, err := softwareRepo.GetByID(ctx, 200)
	if err != nil {
		log.Fatalf("Error recuperando Tomcat: %v", err)
	}
	fmt.Printf("CPE Tomcat: %s (Esperado: cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*)\n", dbSwApp.CPE)

	dbSwOS, err := softwareRepo.GetByID(ctx, 201)
	if err != nil {
		log.Fatalf("Error recuperando Ubuntu: %v", err)
	}
	fmt.Printf("CPE Ubuntu: %s (Esperado: cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*)\n", dbSwOS.CPE)

	// Contar vulnerabilidades encontradas y enlazadas para Tomcat
	resApp, err := dbHelper.ExecuteRead(ctx, `
		MATCH (si:SoftwareInstallation {id: "inst-tomcat-target"})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		RETURN count(v) as vuln_count
	`, nil)
	if err != nil {
		log.Fatalf("Error contando vulnerabilidades de Tomcat: %v", err)
	}
	fmt.Printf("Vulnerabilidades enlazadas a Tomcat en DB: %+v\n", resApp)

	// Contar vulnerabilidades encontradas y enlazadas para Ubuntu
	resOS, err := dbHelper.ExecuteRead(ctx, `
		MATCH (si:SoftwareInstallation {id: "inst-ubuntu-target"})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
		RETURN count(v) as vuln_count
	`, nil)
	if err != nil {
		log.Fatalf("Error contando vulnerabilidades de Ubuntu: %v", err)
	}
	fmt.Printf("Vulnerabilidades enlazadas a Ubuntu en DB: %+v\n", resOS)

	fmt.Println("\n¡PRUEBA COMPLETADA CON ÉXITO!")
}
