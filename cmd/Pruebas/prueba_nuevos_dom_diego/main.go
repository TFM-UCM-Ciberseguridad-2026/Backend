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

// Prueba de humo para validar que los campos nuevos de dominio (CIA por endpoint,
// vector CVSS + EPSS/KEV en Vulnerability, desglose de riesgo en Finding) se
// persisten y se leen correctamente desde Neo4j, junto con lo que ya existía.
func main() {
	fmt.Println("Iniciando prueba de nuevos campos de dominio (riesgo/CIA)...")

	now := time.Now().UTC()

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

	endpointRepo, vulnRepo, softwareRepo, installationRepo, findingRepo, remediationRepo, exploitRepo, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo , _ := neo4j.NewRepository(driver)

	fmt.Println("Limpiando base de datos...")
	if err := dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		log.Fatalf("Error limpiando la base de datos: %v", err)
	}

	fmt.Println("\n=== CREANDO GRAFO BÁSICO (campos nuevos + existentes) ===")

	// 1. Project
	proj := &domain.Project{ProjectID: 1, Nombre: "Prueba Nuevos Dominios"}
	if err := projectRepo.Save(ctx, proj); err != nil {
		log.Fatalf("Error guardando Project: %v", err)
	}

	// 2. Endpoint: réplica de BBDD, crítica en Confidencialidad y Disponibilidad,
	// con el riesgo agregado ya cacheado (como si el job diario lo hubiera calculado).
	ep := &domain.Endpoint{
		EndpointID:         1,
		Hostname:           "srv-db-replica",
		Type:               "Linux Server",
		Status:             "ACTIVE",
		Environment:        "production",
		InternetExposed:    false,
		ConfidentialityReq: "H",
		IntegrityReq:       "M",
		AvailabilityReq:    "H",
		RiskScore:          0.82,
		RiskTier:           "CRITICAL",
		RiskComputedAt:     &now,
	}
	if err := endpointRepo.Save(ctx, ep); err != nil {
		log.Fatalf("Error guardando Endpoint: %v", err)
	}

	// 3. Hardware
	hw := &domain.Hardware{HardwareID: 200, Model: "PowerEdge R740", Manufacturer: "Dell", RAMGB: 128}
	if err := hardwareRepo.Save(ctx, hw); err != nil {
		log.Fatalf("Error guardando Hardware: %v", err)
	}

	// 4. Network
	net := &domain.Network{NetworkID: 5, Nombre: "VLAN-Servers", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1"}
	if err := networkRepo.Save(ctx, net); err != nil {
		log.Fatalf("Error guardando Network: %v", err)
	}

	// 5. Software
	sw := &domain.Software{SoftwareID: 3001, Name: "Polkit", Version: "0.105", Vendor: "freedesktop.org"}
	if err := softwareRepo.Save(ctx, sw); err != nil {
		log.Fatalf("Error guardando Software: %v", err)
	}

	// 6. SoftwareInstallation
	install := &domain.SoftwareInstallation{
		InstallationID: "inst-polkit-srv-db-replica",
		FirstSeen:      now,
		LastSeen:       &now,
		Status:         "INSTALLED",
		InstallPath:    "/usr/bin/pkexec",
		DetectedBy:     "NMAP",
		PackageManager: "APT",
	}
	if err := installationRepo.Save(ctx, install); err != nil {
		log.Fatalf("Error guardando SoftwareInstallation: %v", err)
	}

	// 7. Vulnerability: PwnKit, con vector CVSS completo + EPSS/KEV poblados.
	vuln := &domain.Vulnerability{
		CVEID:       "CVE-2021-4034",
		Description: "PwnKit - Local Privilege Escalation en Polkit",
		BaseScore:   7.8,
		CVSSVector:  "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CWE:         "CWE-78",
		CPE:         "cpe:2.3:a:freedesktop:polkit:0.105",
		TTPRelated:  "T1068",
		Exploit:     true,
		KEV:         true,
		EPSSScore:   0.94,
	}
	if err := vulnRepo.Save(ctx, vuln); err != nil {
		log.Fatalf("Error guardando Vulnerability: %v", err)
	}

	// 8. Finding: desglose completo de riesgo (KEV -> likelihood=1.0, sin mitigar -> R=1.0)
	find := &domain.Finding{
		FindingID:         100,
		Status:            "OPEN",
		FirstSeen:         now,
		LastSeen:          &now,
		ResolvedAt:        nil,
		ImpactScore:       0.78,
		Likelihood:        1.0,
		RemediationFactor: 1.0,
		RiskScore:         0.78, // Likelihood * RemediationFactor * ImpactScore
		PriorityScore:     1.56, // riesgo x2.0 por estar en KEV
		RiskComputedAt:    &now,
	}
	if err := findingRepo.Save(ctx, find); err != nil {
		log.Fatalf("Error guardando Finding: %v", err)
	}

	// 9. Exploit
	exp := &domain.Exploit{ExploitID: 33, RequiredPrivilege: "USER", PrivilegeGranted: "ROOT", Technique: "T1068"}
	if err := exploitRepo.Save(ctx, exp); err != nil {
		log.Fatalf("Error guardando Exploit: %v", err)
	}

	// 10. Remediation (pendiente, todavía no mitigada)
	rem := &domain.Remediation{RemediationID: 50, FixedVersion: "0.105-31", Status: "PENDING"}
	if err := remediationRepo.Save(ctx, rem); err != nil {
		log.Fatalf("Error guardando Remediation: %v", err)
	}

	// 11. Patch
	patch := &domain.Patch{PatchID: 7, Description: "Security Update Polkit", ReleaseDate: &now, URL: "https://example.com/patch-polkit"}
	if err := patchRepo.Save(ctx, patch); err != nil {
		log.Fatalf("Error guardando Patch: %v", err)
	}

	fmt.Println("\n=== CREANDO RELACIONES DEL GRAFO ===")

	rels := []struct {
		name string
		fn   func() error
	}{
		{"HAS_ENDPOINT", func() error { return relRepo.LinkProjectToEndpoint(ctx, 1, 1) }},
		{"HAS_HARDWARE", func() error { return relRepo.LinkEndpointToHardware(ctx, 1, 200) }},
		{"CONNECTED_TO", func() error { return relRepo.LinkEndpointToNetwork(ctx, 1, 5) }},
		{"HAS_INSTALLATION", func() error { return relRepo.LinkEndpointToInstallation(ctx, 1, "inst-polkit-srv-db-replica") }},
		{"INSTANCE_OF", func() error { return relRepo.LinkInstallationToSoftware(ctx, "inst-polkit-srv-db-replica", 3001) }},
		{"HAS_FINDING", func() error { return relRepo.LinkInstallationToFinding(ctx, "inst-polkit-srv-db-replica", 100) }},
		{"OF_VULNERABILITY", func() error { return relRepo.LinkFindingToVulnerability(ctx, 100, "CVE-2021-4034") }},
		{"HAS_EXPLOIT", func() error { return relRepo.LinkFindingToExploit(ctx, 100, 33) }},
		{"HAS_REMEDIATION", func() error { return relRepo.LinkFindingToRemediation(ctx, 100, 50) }},
		{"USES_PATCH", func() error { return relRepo.LinkRemediationToPatch(ctx, 50, 7) }},
		{"FIXES", func() error { return relRepo.LinkPatchToVulnerability(ctx, 7, "CVE-2021-4034") }},
	}

	for _, rel := range rels {
		if err := rel.fn(); err != nil {
			log.Fatalf("Error creando relación %s: %v", rel.name, err)
		}
	}

	fmt.Println("✅ Nodos y relaciones creados con éxito. Recuperando de Neo4j para validar round-trip...")

	epDB, err := endpointRepo.GetByID(ctx, 1)
	if err != nil {
		log.Fatalf("Error leyendo Endpoint: %v", err)
	}
	vulnDB, err := vulnRepo.GetByID(ctx, "CVE-2021-4034")
	if err != nil {
		log.Fatalf("Error leyendo Vulnerability: %v", err)
	}
	findDB, err := findingRepo.GetByID(ctx, 100)
	if err != nil {
		log.Fatalf("Error leyendo Finding: %v", err)
	}

	fmt.Println("\n=== RESULTADO ===")
	fmt.Printf("Endpoint:      %+v\n", epDB)
	fmt.Printf("Vulnerability: %+v\n", vulnDB)
	fmt.Printf("Finding:       %+v\n", findDB)

	// Verificación explícita de que los campos nuevos han hecho el viaje de ida y vuelta.
	ok := epDB.ConfidentialityReq == "H" && epDB.IntegrityReq == "M" && epDB.AvailabilityReq == "H" &&
		epDB.RiskTier == "CRITICAL" && epDB.RiskComputedAt != nil &&
		vulnDB.CVSSVector == vuln.CVSSVector && vulnDB.KEV && vulnDB.EPSSScore == 0.94 &&
		findDB.ImpactScore == 0.78 && findDB.Likelihood == 1.0 && findDB.PriorityScore == 1.56 && findDB.RiskComputedAt != nil

	if ok {
		fmt.Println("\n✅ PRUEBA SUPERADA: los campos nuevos (CIA, CVSS vector, EPSS/KEV, desglose de riesgo) se persisten y se leen bien.")
	} else {
		log.Fatal("\n❌ PRUEBA FALLIDA: alguno de los campos nuevos no volvió con el valor esperado tras el round-trip.")
	}
}
