package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

func main() {
	fmt.Println("==================================================================")
	fmt.Println("=== PRUEBA: VULNERABILIDADES DE SOFTWARE DENTRO DE CONTENEDORES ===")
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

	_, _, _, _, _, _, _, _, _, _, _, dbHelper, relRepo, _ := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)

	fmt.Println("\n[*] Limpiando BD...")
	dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	fmt.Println("[*] Preparando topología base...")
	setupCypher := `
		CREATE (net:Network {id: 1, nombre: "Test-Net"})
		CREATE (e1:Endpoint {id: 111, hostname: "Public-Server", internet_exposed: true})
		CREATE (e1)-[:CONNECTED_TO]->(net)
		
		CREATE (e2:Endpoint {id: 222, hostname: "Internal-Server", internet_exposed: false})
		CREATE (e2)-[:CONNECTED_TO]->(net)
		
		CREATE (c1:Container {id: "CONT-VULN-SOFT", name: "tomcat-container", state: "running"})
		CREATE (e1)-[:HOSTS]->(c1)

		// Instalación de software DENTRO del contenedor
		CREATE (si_cont:SoftwareInstallation {id: "inst-tomcat-cont"})
		CREATE (f_cont:Finding {id: 555, risk_score: 9.8})
		// Vuln de red (RCE) para entrar
		CREATE (v_cont_rce:Vulnerability {cve_id: "CVE-TOMCAT-RCE", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
		
		CREATE (c1)-[:HAS_INSTALLATION]->(si_cont)
		CREATE (si_cont)-[:HAS_FINDING]->(f_cont)-[:OF_VULNERABILITY]->(v_cont_rce)

		// Añadir vulnerabilidad al destino interno para completar el path (no container, regular)
		CREATE (si_int:SoftwareInstallation {id: "inst-internal"})
		CREATE (f_int:Finding {id: 777, risk_score: 5.0})
		CREATE (v_int:Vulnerability {cve_id: "CVE-INTERNAL", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"})
		CREATE (e2)-[:HAS_INSTALLATION]->(si_int)-[:HAS_FINDING]->(f_int)-[:OF_VULNERABILITY]->(v_int)
	`
	err = dbHelper.ExecuteWrite(ctx, setupCypher, nil)
	if err != nil {
		log.Fatalf("Error preparando BD: %v", err)
	}

	// Como validación, vamos a crear manualmente el enlace con el repositorio por si la macro Cypher fallara
	// aunque la macro cypher lo hace todo, verificamos que el repo no de error si lo usamos
	err = relRepo.LinkContainerToInstallation(ctx, "CONT-VULN-SOFT", "inst-tomcat-cont")
	if err != nil {
		log.Fatalf("Error LinkContainerToInstallation: %v", err)
	}

	// Ejecutar GetExploitationPaths
	fmt.Println("\n[*] Ejecutando algoritmo de Path de Explotación (GetExploitationPaths)...")
	paths, err := infraRepo.GetExploitationPaths(ctx, 0)
	if err != nil {
		log.Fatalf("Error calculando paths: %v", err)
	}

	if len(paths) == 0 {
		fmt.Println("[-] CORRECTO: No se encontraron rutas de explotación en Fase 1.")
		fmt.Println("    (El atacante tiene RCE en el contenedor, pero carece de LPE para escapar al Host y enrutar hacia Internal-Server).")
	} else {
		fmt.Printf("[+] ADVERTENCIA: Se detectó %d ruta de ataque a través del software del contenedor:\n", len(paths))
		for i, path := range paths {
			fmt.Printf("--- RUTA %d (Destino Final: %s) ---\n", i+1, path.Steps[len(path.Steps)-1].TargetEndpoint)
			for j, step := range path.Steps {
				targetName := step.TargetEndpoint
				if step.IsContainer {
					targetName = fmt.Sprintf("%s (Contenedor: %s)", step.TargetEndpoint, step.ContainerName)
				}
				fmt.Printf("  Salto %d: %s | Vuln: %s | Consigue Root (Escape): %v\n", j+1, targetName, step.Vulnerability, step.RootObtained)
			}
			fmt.Println("\n[INFO] Detalle del Path en JSON:")
			pathJSON, _ := json.MarshalIndent(path, "", "  ")
			fmt.Println(string(pathJSON))
		}
	}

	fmt.Println("\n[*] FASE 2: Simulando descubrimiento de vulnerabilidad de Escape de Contenedor (LPE) en Tomcat...")
	lpeCypher := `
		MATCH (si_cont:SoftwareInstallation {id: "inst-tomcat-cont"})
		CREATE (f_cont_lpe:Finding {id: 666, risk_score: 7.8})
		CREATE (v_cont_lpe:Vulnerability {cve_id: "CVE-TOMCAT-ESCAPE", cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", description: "Container escape vulnerability"})
		CREATE (si_cont)-[:HAS_FINDING]->(f_cont_lpe)-[:OF_VULNERABILITY]->(v_cont_lpe)
	`
	err = dbHelper.ExecuteWrite(ctx, lpeCypher, nil)
	if err != nil {
		log.Fatalf("Error inyectando LPE: %v", err)
	}

	fmt.Println("[*] Recalculando paths de explotación tras el escape de contenedor...")
	paths, err = infraRepo.GetExploitationPaths(ctx, 0)
	if err != nil {
		log.Fatalf("Error calculando paths (Fase 2): %v", err)
	}

	if len(paths) == 0 {
		fmt.Println("[-] No se encontraron rutas de explotación en Fase 2.")
	} else {
		fmt.Printf("[+] ¡Éxito! Se detectó %d ruta de ataque a través del software del contenedor:\n", len(paths))
		for i, path := range paths {
			fmt.Printf("--- RUTA %d (Destino Final: %s) ---\n", i+1, path.Steps[len(path.Steps)-1].TargetEndpoint)
			for j, step := range path.Steps {
				targetName := step.TargetEndpoint
				if step.IsContainer {
					targetName = fmt.Sprintf("%s (Contenedor: %s)", step.TargetEndpoint, step.ContainerName)
				}
				fmt.Printf("  Salto %d: %s | Vuln: %s | Consigue Root (Escape): %v\n", j+1, targetName, step.Vulnerability, step.RootObtained)
			}
		}
	}
}
