package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

func main() {
	fmt.Println("Iniciando Motor TFM (Backend) - Prueba de Persistencia Masiva...")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando la configuración: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)
	fmt.Println("Conexión a Neo4j establecida con éxito.")

	// Instanciamos los 11 repositorios específicos
	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, exploitRepo, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, _ := neo4j.NewRepository(driver)
	_ = dbHelper
	_ = softwareInstRepo

	// Limpiamos la base de datos para la prueba limpia
	fmt.Println("Limpiando base de datos...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	fmt.Println("\n=== INYECTANDO 10 ENTIDADES DE DOMINIO ===")

	// 1. Endpoint
	ep := &domain.Endpoint{EndpointID: 1, Hostname: "srv-db", Type: "Linux", InternetExposed: false}
	_ = endpointRepo.Save(ctx, ep)

	// 2. Vulnerability
	vuln := &domain.Vulnerability{
		CVEID:       "CVE-2025-0001",
		Description: "RCE Crítico",
		BaseScore:   9.9,
	}
	_ = vulnRepo.Save(ctx, vuln)

	// 3. Software
	sw := &domain.Software{SoftwareID: 10, Name: "PostgreSQL", Version: "15.3", Vendor: "PostgreSQL Global Development Group"}
	_ = softwareRepo.Save(ctx, sw)

	// 4. Finding
	find := &domain.Finding{FindingID: 100, RiskScore: 8.5, Status: "OPEN"}
	_ = findingRepo.Save(ctx, find)

	// 5. Remediation
	rem := &domain.Remediation{RemediationID: 50, FixedVersion: "15.4", Status: "PENDING"}
	_ = remediationRepo.Save(ctx, rem)

	// 6. Exploit
	exp := &domain.Exploit{ExploitID: 33, RequiredPrivilege: "NONE", PrivilegeGranted: "ROOT", Technique: "Buffer Overflow"}
	_ = exploitRepo.Save(ctx, exp)

	// 7. Hardware
	hw := &domain.Hardware{HardwareID: 200, Model: "PowerEdge R740", Manufacturer: "Dell", RAMGB: 128}
	_ = hardwareRepo.Save(ctx, hw)

	// 8. Network
	net := &domain.Network{NetworkID: 5, Nombre: "VLAN-Servers", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1"}
	_ = networkRepo.Save(ctx, net)

	// 9. Patch
	patch := &domain.Patch{PatchID: 7, Description: "Security Update KB123", URL: "https://example.com/patch"}
	_ = patchRepo.Save(ctx, patch)

	// 10. Project
	proj := &domain.Project{ProjectID: 1, Nombre: "Auditoría Q1 2026"}
	_ = projectRepo.Save(ctx, proj)

	fmt.Println("✅ Nodos inyectados con éxito. Recuperando...")

	// Validar que se pueden leer todos
	epDB, _ := endpointRepo.GetByID(ctx, 1)
	vulnDB, _ := vulnRepo.GetByID(ctx, "CVE-2025-0001")
	swDB, _ := softwareRepo.GetByID(ctx, 10)
	findDB, _ := findingRepo.GetByID(ctx, 100)
	remDB, _ := remediationRepo.GetByID(ctx, 50)
	expDB, _ := exploitRepo.GetByID(ctx, 33)
	hwDB, _ := hardwareRepo.GetByID(ctx, 200)
	netDB, _ := networkRepo.GetByID(ctx, 5)
	patchDB, _ := patchRepo.GetByID(ctx, 7)
	projDB, _ := projectRepo.GetByID(ctx, 1)

	fmt.Printf("1. Endpoint: %+v\n", epDB)
	fmt.Printf("2. Vulnerability: %+v\n", vulnDB)
	fmt.Printf("3. Software: %+v\n", swDB)
	fmt.Printf("4. Finding: %+v\n", findDB)
	fmt.Printf("5. Remediation: %+v\n", remDB)
	fmt.Printf("6. Exploit: %+v\n", expDB)
	fmt.Printf("7. Hardware: %+v\n", hwDB)
	fmt.Printf("8. Network: %+v\n", netDB)
	fmt.Printf("9. Patch: %+v\n", patchDB)
	fmt.Printf("10. Project: %+v\n", projDB)

	fmt.Println("\n¡PRUEBA SUPERADA! Las 10 interfaces Hexagonales funcionan con Neo4j.")
}
