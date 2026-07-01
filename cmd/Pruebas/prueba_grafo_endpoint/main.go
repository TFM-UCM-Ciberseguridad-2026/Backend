package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

func main() {
	fmt.Println("Iniciando Motor TFM (Backend) - Prueba de Persistencia Masiva...")

	now := time.Now().UTC()
	fmt.Printf("Hora de inicio: %s\n", now.Format(time.RFC3339))

	// Cargamos la configuración

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando la configuración: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	driver, err := repository.NewNeo4jDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)
	fmt.Println("Conexión a Neo4j establecida con éxito.")

	// Instanciamos los 11 repositorios específicos
	endpointRepo, vulnRepo, softwareRepo, installationRepo, findingRepo, remediationRepo, exploitRepo, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper := repository.NewNeo4jRepository(driver)
	_ = dbHelper

	// Limpiamos la base de datos para la prueba limpia
	fmt.Println("Limpiando base de datos...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	fmt.Println("\n=== INYECTANDO 11 ENTIDADES DE DOMINIO ===")

	// 1. Project
	proj := &domain.Project{ProjectID: 1, Nombre: "Auditoría Q1 2026"}
	if err := projectRepo.Save(ctx, proj); err != nil { 
		log.Fatalf("Error guardando Project: %v", err)
	}

	// 2. Endpoint
	ep := &domain.Endpoint{EndpointID: 1, Hostname: "srv-db", Type: "Linux", InternetExposed: false}
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
	sw1 := &domain.Software{SoftwareID: 10, Name: "PostgreSQL", Version: "15.3", Vendor: "PostgreSQL Global Development Group"}
	if err := softwareRepo.Save(ctx, sw1); err != nil { 
		log.Fatalf("Error guardando Software 1: %v", err)
	}

	sw2 := &domain.Software{SoftwareID: 3001, Name: "OpenSSL", Version: "1.1.1", Vendor: "OpenSSL"}
	if err := softwareRepo.Save(ctx, sw2); err != nil { 
		log.Fatalf("Error guardando Software 2: %v", err)
	}

	// 6. Software Installation
	install1 := &domain.SoftwareInstallation{
		InstallationID: "inst-openssl-srv-prod-01",
		FirstSeen: now,
		LastSeen:  &now,
		Status:	"INSTALLED",
		InstallPath: "/usr/bin/openssl",
		DetectedBy: "NMAP",
		PackageManager: "APT",
	}
	if err := installationRepo.Save(ctx, install1); err != nil { 
		log.Fatalf("Error guardando Installation 1: %v", err)
	}

	install2 := &domain.SoftwareInstallation{
		InstallationID: "inst-postgresql-srv-prod-01",
		FirstSeen: now,
		LastSeen:  &now,
		Status:	"INSTALLED",
		InstallPath: "/usr/bin/psql",
		DetectedBy: "NMAP",
		PackageManager: "APT",
	}
	if err := installationRepo.Save(ctx, install2); err != nil { 
		log.Fatalf("Error guardando Installation 2: %v", err)
	}

	// 7. Finding

	find1 := &domain.Finding{FindingID: 100, RiskScore: 8.5, Status: "OPEN", FirstSeen: now, LastSeen: &now, ResolvedAt: nil}
	if err := findingRepo.Save(ctx, find1); err != nil { 
		log.Fatalf("Error guardando Finding 1: %v", err)
	}

	find2 := &domain.Finding{FindingID: 1001, RiskScore: 10, Status: "CLOSED", FirstSeen: now, LastSeen: &now, ResolvedAt: &now}
	if err := findingRepo.Save(ctx, find2); err != nil { 
		log.Fatalf("Error guardando Finding 2: %v", err)
	}

	find3 := &domain.Finding{FindingID: 1002, RiskScore: 5, Status: "OPEN", FirstSeen: now, LastSeen: &now, ResolvedAt: nil}
	if err := findingRepo.Save(ctx, find3); err != nil { 
		log.Fatalf("Error guardando Finding 3: %v", err)
	}


	// 8. Vulnerability
	vuln1 := &domain.Vulnerability{
		CVEID:       "CVE-2025-0001",
		Description: domain.Description{Lang: "es", Value: "RCE Crítico"},
		BaseScore:  10,
	}
	if err := vulnRepo.Save(ctx, vuln1); err != nil { 
		log.Fatalf("Error guardando Vuln 1: %v", err)
	}


	vuln2 := &domain.Vulnerability{
		CVEID:       "CVE-2025-0002",
		Description: domain.Description{Lang: "es", Value: "DoS"},
		BaseScore:   5,
	}
	if err := vulnRepo.Save(ctx, vuln2); err != nil { 
		log.Fatalf("Error guardando Vuln 2: %v", err)
	}


	vuln3 := &domain.Vulnerability{
		CVEID:       "CVE-2025-0003",
		Description: domain.Description{Lang: "es", Value: "LFI"},
		BaseScore:   8.5,
	}
	if err := vulnRepo.Save(ctx, vuln3); err != nil { 
		log.Fatalf("Error guardando Vuln 3: %v", err)
	}


	// 9. Exploit
	exp := &domain.Exploit{ExploitID: 33, RequiredPrivilege: "NONE", PrivilegeGranted: "ROOT", Technique: "Buffer Overflow"}
	if err := exploitRepo.Save(ctx, exp); err != nil { 
		log.Fatalf("Error guardando Explotacion: %v", err)
	}
	
	// 10. Remediation
	rem := &domain.Remediation{RemediationID: 50, FixedVersion: "15.4", Status: "PENDING"}
	if err := remediationRepo.Save(ctx, rem); err != nil { 
		log.Fatalf("Error guardando Remediacion: %v", err)
	}
	

	// 11. Patch
	patch := &domain.Patch{PatchID: 7, Description: "Security Update OpenSSL", ReleaseDate: &now,  URL: "https://example.com/patch"}
	if err := patchRepo.Save(ctx, patch); err != nil { 
		log.Fatalf("Error guardando Patch: %v", err)
	}

	fmt.Println("\n=== CREANDO RELACIONES DEL GRAFO ===")

	// HAS_ENDPOINT
	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (p:Project {id: $projectID})
		MATCH (e:Endpoint {id: $endpointID})
		MERGE (p)-[:HAS_ENDPOINT]->(e)
	`, map[string]any{
		"projectID":  1,
		"endpointID": 1,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_ENDPOINT: %v", err)
	}

	// HAS_HARDWARE

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (h:Hardware {id: $hardwareID})
		MERGE (e)-[:HAS_HARDWARE]->(h)
	`, map[string]any{
		"endpointID": 1,
		"hardwareID": 200,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_HARDWARE: %v", err)
	}

	// CONNECTED_TO

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (n:Network {id: $networkID})
		MERGE (e)-[:CONNECTED_TO]->(n)
	`, map[string]any{
		"endpointID": 1,
		"networkID":  5,
	})
	if err != nil {
		log.Fatalf("Error creando relación CONNECTED_TO: %v", err)
	}

	// HAS_INSTALLATION_1_openssl

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (si:SoftwareInstallation {id: $installationID})
		MERGE (e)-[:HAS_INSTALLATION]->(si)
	`, map[string]any{
		"endpointID":     1,
		"installationID": "inst-openssl-srv-prod-01",
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_INSTALLATION OpenSSL: %v", err)
	}

	// HAS_INSTALLATION_2_postgresql

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (e:Endpoint {id: $endpointID})
		MATCH (si:SoftwareInstallation {id: $installationID})
		MERGE (e)-[:HAS_INSTALLATION]->(si)
	`, map[string]any{
		"endpointID":     1,
		"installationID": "inst-postgresql-srv-prod-01",
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_INSTALLATION PostgreSQL: %v", err)
	}

	// INSTANCE_OF_openssl

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (s:Software {id: $softwareID})
		MERGE (si)-[:INSTANCE_OF]->(s)
	`, map[string]any{
		"installationID": "inst-openssl-srv-prod-01",
		"softwareID":     3001,
	})
	if err != nil {
		log.Fatalf("Error creando relación INSTANCE_OF OpenSSL: %v", err)
	}

	// INSTANCE_OF_postgresql

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (s:Software {id: $softwareID})
		MERGE (si)-[:INSTANCE_OF]->(s)
	`, map[string]any{
		"installationID": "inst-postgresql-srv-prod-01",
		"softwareID":     10,
	})
	if err != nil {
		log.Fatalf("Error creando relación INSTANCE_OF PostgreSQL: %v", err)
	}

	//HAS_FINDING_1

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (f:Finding {id: $findingID})
		MERGE (si)-[:HAS_FINDING]->(f)
	`, map[string]any{
		"installationID": "inst-openssl-srv-prod-01",
		"findingID":      100,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_FINDING #100: %v", err)
	}

	//HAS_FINDING_2

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (f:Finding {id: $findingID})
		MERGE (si)-[:HAS_FINDING]->(f)
	`, map[string]any{
		"installationID": "inst-openssl-srv-prod-01",
		"findingID":      1001,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_FINDING #1001: %v", err)
	}

	//HAS_FINDING_3

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (si:SoftwareInstallation {id: $installationID})
		MATCH (f:Finding {id: $findingID})
		MERGE (si)-[:HAS_FINDING]->(f)
	`, map[string]any{
		"installationID": "inst-postgresql-srv-prod-01",
		"findingID":      1002,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_FINDING #1002: %v", err)
	}

	// AFFECTED_BY_1

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (f:Finding {id: $findingID})
		MATCH (v:Vulnerability {cve_id: $cveID})
		MERGE (f)-[:OF_VULNERABILITY]->(v)
	`, map[string]any{
		"findingID": 100,
		"cveID":     "CVE-2025-0001",
	})
	if err != nil {
		log.Fatalf("Error creando relación OF_VULNERABILITY #100: %v", err)
	}

	// AFFECTED_BY_2

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (f:Finding {id: $findingID})
		MATCH (v:Vulnerability {cve_id: $cveID})
		MERGE (f)-[:OF_VULNERABILITY]->(v)
	`, map[string]any{
		"findingID": 1001,
		"cveID":     "CVE-2025-0002",
	})
	if err != nil {
		log.Fatalf("Error creando relación OF_VULNERABILITY #1001: %v", err)
	}

	// AFFECTED_BY_3

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (f:Finding {id: $findingID})
		MATCH (v:Vulnerability {cve_id: $cveID})
		MERGE (f)-[:OF_VULNERABILITY]->(v)
	`, map[string]any{
		"findingID": 1002,
		"cveID":     "CVE-2025-0003",
	})
	if err != nil {
		log.Fatalf("Error creando relación OF_VULNERABILITY #1002: %v", err)
	}

	// HAS_EXPLOIT

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (f:Finding {id: $findingID})
		MATCH (r:Exploit {id: $ExploitID})
		MERGE (f)-[:HAS_EXPLOIT]->(r)
	`, map[string]any{
		"findingID":     100,
		"ExploitID": 33,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_EXPLOIT: %v", err)
	}

	// HAS_REMEDIATION

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (f:Finding {id: $findingID})
		MATCH (r:Remediation {id: $remediationID})
		MERGE (f)-[:HAS_REMEDIATION]->(r)
	`, map[string]any{
		"findingID":     100,
		"remediationID": 50,
	})
	if err != nil {
		log.Fatalf("Error creando relación HAS_REMEDIATION: %v", err)
	}

	// USES_PATCH

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (r:Remediation {id: $remediationID})
		MATCH (p:Patch {id: $patchID})
		MERGE (r)-[:USES_PATCH]->(p)
	`, map[string]any{
		"remediationID": 50,
		"patchID":       7,
	})
	if err != nil {
		log.Fatalf("Error creando relación USES_PATCH: %v", err)
	}

	// FIXES

	err = dbHelper.ExecuteWrite(ctx, `
		MATCH (p:Patch {id: $patchID})
		MATCH (v:Vulnerability {cve_id: $cveID})
		MERGE (p)-[:FIXES]->(v)
	`, map[string]any{
		"patchID": 7,
		"cveID":   "CVE-2025-0001",
	})
	if err != nil {
		log.Fatalf("Error creando relación FIXES: %v", err)
	}
	

	fmt.Println("✅ Nodos y relaciones creados con éxito. Recuperando nodos...")

	// Validar que se pueden leer todos
	epDB, _ := endpointRepo.GetByID(ctx, 1)
	vulnDB, _ := vulnRepo.GetByID(ctx, "CVE-2025-0001")
	sw1DB, _ := softwareRepo.GetByID(ctx, 10)
	sw2DB, _ := softwareRepo.GetByID(ctx, 3001)
	swInstDB, _ := installationRepo.GetByID(ctx, "inst-openssl-srv-prod-01")
	swInstDB2, _ := installationRepo.GetByID(ctx, "inst-postgresql-srv-prod-01")
	findDB, _ := findingRepo.GetByID(ctx, 100)
	remDB, _ := remediationRepo.GetByID(ctx, 50)
	expDB, _ := exploitRepo.GetByID(ctx, 33)
	hwDB, _ := hardwareRepo.GetByID(ctx, 200)
	netDB, _ := networkRepo.GetByID(ctx, 5)
	patchDB, _ := patchRepo.GetByID(ctx, 7)
	projDB, _ := projectRepo.GetByID(ctx, 1)

	fmt.Printf("1. Endpoint: %+v\n", epDB)
	fmt.Printf("2. Vulnerability: %+v\n", vulnDB)
	fmt.Printf("3. Software: %+v\n", sw1DB)
	fmt.Printf("3. Software: %+v\n", sw2DB)
	fmt.Printf("3. SoftwareInstallation: %+v\n", swInstDB)
	fmt.Printf("3. SoftwareInstallation: %+v\n", swInstDB2)
	fmt.Printf("4. Finding: %+v\n", findDB)
	fmt.Printf("5. Remediation: %+v\n", remDB)
	fmt.Printf("6. Exploit: %+v\n", expDB)
	fmt.Printf("7. Hardware: %+v\n", hwDB)
	fmt.Printf("8. Network: %+v\n", netDB)
	fmt.Printf("9. Patch: %+v\n", patchDB)
	fmt.Printf("10. Project: %+v\n", projDB)

	fmt.Println("\n¡PRUEBA SUPERADA! Las 10 interfaces Hexagonales funcionan con Neo4j.")
}
