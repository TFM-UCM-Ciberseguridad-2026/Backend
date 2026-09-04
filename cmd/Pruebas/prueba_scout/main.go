package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("==================================================================")
	fmt.Println("=== PRUEBA DE INTEGRACIÓN: DOCKER SCOUT -> NEO4J ATTACK PATHS ===")
	fmt.Println("==================================================================")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}
	ctx := context.Background()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	// Inicializar Orquestador normal
	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo, softwareInstRepo, softwareRepo, findingRepo, vulnRepo, remediationRepo, relRepo, infraRepo, containerRepo, patchRepo, dbHelper, nil,
	).WithRisk(riskRepo, nil, nil)

	// Inicializar adaptador Scout
	scoutAdapter := provider.NewScoutAdapter()

	// Inyectar JSON falso de Docker Scout para el test
	mockScoutJSON := `[
		{
			"cve": "CVE-2023-38545",
			"description": "curl: heap based buffer overflow in the SOCKS5 proxy handshake",
			"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"package": "curl",
			"version": "8.3.0"
		}
	]`
	scoutAdapter.SetMockData([]byte(mockScoutJSON))

	// Inyectar el adaptador en el orquestador
	orchestrator.WithScout(scoutAdapter)

	fmt.Println("\n[*] Limpiando BD...")
	dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	fmt.Println("[*] Preparando topología base...")
	setupCypher := `
		CREATE (net:Network {id: 1, nombre: "Test-Net"})
		CREATE (e1:Endpoint {id: 9999, hostname: "Public-Server", internet_exposed: true})
		CREATE (e1)-[:CONNECTED_TO]->(net)
		
		CREATE (e2:Endpoint {id: 8888, hostname: "Internal-Server", internet_exposed: false})
		CREATE (e2)-[:CONNECTED_TO]->(net)
		
		CREATE (ci:ContainerImage {id: "IMG-ALPINE-CURL", name: "alpine:with-curl"})
		CREATE (c1:Container {id: "CONT-VULN", name: "vulnerable-container", state: "running"})
		CREATE (e1)-[:HOSTS]->(c1)
		CREATE (c1)-[:USES_IMAGE]->(ci)
		
		// Añadir vulnerabilidad a e2 para completar el path (no container, regular)
		CREATE (si2:SoftwareInstallation {id: "inst-internal"})
		CREATE (f2:Finding {id: 100, risk_score: 5.0})
		CREATE (v2:Vulnerability {cve_id: "CVE-INTERNAL", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"})
		CREATE (e2)-[:HAS_INSTALLATION]->(si2)-[:HAS_FINDING]->(f2)-[:OF_VULNERABILITY]->(v2)
	`
	err = dbHelper.ExecuteWrite(ctx, setupCypher, nil)
	if err != nil {
		log.Fatalf("Error preparando BD: %v", err)
	}

	// Ejecutar la integración de Scout (simula: docker scout cves alpine:with-curl)
	fmt.Println("\n[*] Ejecutando escaneo con Docker Scout...")
	_, err = orchestrator.ScanAndSaveContainerImage(ctx, "alpine:with-curl", "IMG-ALPINE-CURL", domain.VulnerabilityScanOptions{ForceRefresh: true})
	if err != nil {
		log.Fatalf("Error en el escaneo de Docker Scout: %v", err)
	}
	fmt.Println("[+] Escaneo completado. CVEs mapeados en Neo4j a la ContainerImage.")

	// Debug query
	fmt.Println("\n[*] Verificando enlaces...")
	dbHelper.ExecuteWrite(ctx, `
		MATCH (ep:Endpoint)-[:HOSTS]->(c:Container)-[:USES_IMAGE]->(ci:ContainerImage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		RETURN ep.hostname, c.name, ci.name, v.cve_id, v.cvss_vector
	`, nil)

	// Verificar si el Path Engine es capaz de encontrar la vulnerabilidad inyectada por Scout
	fmt.Println("\n[*] Ejecutando algoritmo de Path de Explotación (GetExploitationPaths)...")
	paths, err := infraRepo.GetExploitationPaths(ctx, 0)
	if err != nil {
		log.Fatalf("Error calculando paths: %v", err)
	}

	if len(paths) == 0 {
		fmt.Println("[-] No se encontraron rutas de explotación.")
	} else {
		fmt.Printf("[+] ¡Éxito! Se detectó %d ruta de explotación explotando el CVE descubierto por Scout:\n", len(paths))
		for i, path := range paths {
			fmt.Printf("--- RUTA %d (Destino Final: %s) ---\n", i+1, path.Steps[len(path.Steps)-1].TargetEndpoint)
			for j, step := range path.Steps {
				targetName := step.TargetEndpoint
				if step.IsContainer {
					targetName = fmt.Sprintf("%s (Contenedor: %s)", step.TargetEndpoint, step.ContainerName)
				}
				fmt.Printf("  Salto %d: %s | Vuln (de Scout): %s | Consigue Root: %v\n", j+1, targetName, step.Vulnerability, step.RootObtained)
			}
			fmt.Println("\n[INFO] Detalle del Path en JSON:")
			pathJSON, _ := json.MarshalIndent(path, "", "  ")
			fmt.Println(string(pathJSON))
		}
	}
}
