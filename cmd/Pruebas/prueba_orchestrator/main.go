package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("=== Iniciando Prueba de Integración del Orquestador ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// 1. Instanciamos los repositorios
	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, exploitRepo, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo := neo4j.NewRepository(driver)

	// Limpiamos base de datos
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)
	fmt.Println("[OK] Base de datos limpiada.")

	// 2. Instanciamos el Orquestador Inyectando los Puertos
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

	fmt.Println("[OK] Orquestador instanciado correctamente con Inyección de Dependencias.")

	// =========================================================================
	// Ejecución de Casos de Uso
	// =========================================================================

	now := time.Now().UTC()

	fmt.Println("\n--- Ejecutando Casos de Uso ---")

	// CU 1: Crear proyecto
	proj := &domain.Project{ProjectID: 100, Nombre: "Proyecto Orquestador"}
	if err := orchestrator.CreateProject(ctx, proj); err != nil {
		log.Fatalf("Error CreateProject: %v", err)
	}
	fmt.Println("CreateProject ejecutado.")

	// CU 2: Añadir endpoint al proyecto
	ep := &domain.Endpoint{
		EndpointID:         555, 
		Hostname:           "srv-orchestrator", 
		Type:               "Windows", 
		InternetExposed:    true,
		ConfidentialityReq: "High",
		IntegrityReq:       "High",
		AvailabilityReq:    "High",
	}
	if err := orchestrator.AddEndpointToProject(ctx, 100, ep); err != nil {
		log.Fatalf("Error AddEndpointToProject: %v", err)
	}
	fmt.Println("AddEndpointToProject ejecutado.")

	// CU 3: Asociar hardware
	hw := &domain.Hardware{HardwareID: 777, Model: "ThinkServer", Manufacturer: "Lenovo", RAMGB: 64}
	if err := orchestrator.AssociateHardwareToEndpoint(ctx, 555, hw); err != nil {
		log.Fatalf("Error AssociateHardwareToEndpoint: %v", err)
	}
	fmt.Println("AssociateHardwareToEndpoint ejecutado.")

	// CU 4: Asociar red
	net := &domain.Network{NetworkID: 999, Nombre: "DMZ", CIDR: "192.168.1.0/24", Gateway: "192.168.1.1"}
	if err := orchestrator.AssociateNetworkToEndpoint(ctx, 555, net); err != nil {
		log.Fatalf("Error AssociateNetworkToEndpoint: %v", err)
	}
	fmt.Println("AssociateNetworkToEndpoint ejecutado.")

	// CU 5: Registrar instalación de software
	sw := &domain.Software{SoftwareID: 404, Name: "Apache Tomcat", Version: "9.0.41", Vendor: "Apache Software Foundation"}
	inst := &domain.SoftwareInstallation{InstallationID: "inst-tomcat-555", FirstSeen: now, Status: "INSTALLED", InstallPath: "/opt/tomcat"}
	if err := orchestrator.RegisterSoftwareInstallation(ctx, 555, sw, inst); err != nil {
		log.Fatalf("Error RegisterSoftwareInstallation: %v", err)
	}
	fmt.Println("RegisterSoftwareInstallation ejecutado.")

	// CU 6: Generar Finding
	find := &domain.Finding{
		FindingID:         808, 
		Status:            "OPEN",
		ImpactScore:       6.5,
		Likelihood:        0.8,
		RemediationFactor: 1.0,
		PriorityScore:     7.2,
		RiskScore:         9.8,
	}
	if err := orchestrator.GenerateFinding(ctx, "inst-tomcat-555", find); err != nil {
		log.Fatalf("Error GenerateFinding: %v", err)
	}
	fmt.Println("GenerateFinding ejecutado.")

	// CU 7: Asociar vulnerabilidades y remediaciones al finding
	vuln := &domain.Vulnerability{
		CVEID:       "CVE-2026-TEST", 
		Description: "Vulnerabilidad inventada de prueba", 
		BaseScore:   9.8,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		KEV:         true,
		EPSSScore:   0.95,
	}
	rem := &domain.Remediation{RemediationID: 303, FixedVersion: "9.0.43", Status: "PENDING"}
	if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, 808, vuln, rem); err != nil {
		log.Fatalf("Error AssociateVulnerabilitiesAndRemediations: %v", err)
	}
	fmt.Println("AssociateVulnerabilitiesAndRemediations ejecutado.")

	// (Añadido para evitar error unused vars, parche y exploit no están cubiertos explícitamente en el orquestador por ahora)
	_ = patchRepo
	_ = exploitRepo

	fmt.Println("\n¡PRUEBA DEL ORQUESTADOR SUPERADA! Revisa Neo4j Desktop para ver el grafo resultante.")
}
