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
	fmt.Println("=== PRUEBA DE RUTAS DE EXPLOTACIÓN AVANZADA CON CONTENEDORES ===")
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

	_, _, _, _, _, _, _, _, _, _, _, dbHelper, _, _ := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)

	fmt.Println("\n[*] Limpiando BD...")
	dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	setupCypher := `
		// --- REDES ---
		CREATE (net1:Network {id: 1, nombre: "DMZ-Net"})
		CREATE (net2:Network {id: 2, nombre: "Internal-Net"})

		// --- 1. DMZ-Server (Host) y Contenedor Frontend ---
		CREATE (e1:Endpoint {id: 1000, hostname: "DMZ-Server", internet_exposed: true})
		CREATE (e1)-[:CONNECTED_TO]->(net1)
		
		CREATE (c1:Container {id: "CONT-FRONT", name: "web-frontend-container", state: "running"})
		CREATE (e1)-[:HOSTS]->(c1)

		CREATE (si1:SoftwareInstallation {id: "inst-front"})
		CREATE (f1:Finding {id: 10, risk_score: 9.8})
		CREATE (v1:Vulnerability {cve_id: "CVE-FRONT-RCE", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", description: "RCE en Frontend Web"})
		
		CREATE (c1)-[:HAS_INSTALLATION]->(si1)
		CREATE (si1)-[:HAS_FINDING]->(f1)
		CREATE (f1)-[:OF_VULNERABILITY]->(v1)

		// --- 2. Internal-App-Server (Host) y Contenedor Backend ---
		CREATE (e2:Endpoint {id: 2000, hostname: "Internal-App-Server", internet_exposed: false})
		CREATE (e2)-[:CONNECTED_TO]->(net1)
		CREATE (e2)-[:CONNECTED_TO]->(net2)

		CREATE (c2:Container {id: "CONT-BACK", name: "backend-api-container", state: "running"})
		CREATE (e2)-[:HOSTS]->(c2)

		CREATE (si2:SoftwareInstallation {id: "inst-back"})
		CREATE (f2:Finding {id: 20, risk_score: 7.5})
		CREATE (v2:Vulnerability {cve_id: "CVE-BACK-PIVOT", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", description: "Vulnerabilidad de red en API interna"})
		
		CREATE (c2)-[:HAS_INSTALLATION]->(si2)
		CREATE (si2)-[:HAS_FINDING]->(f2)
		CREATE (f2)-[:OF_VULNERABILITY]->(v2)

		// --- 3. Internal-DB-Server (Host SIN contenedor) ---
		CREATE (e3:Endpoint {id: 3000, hostname: "Internal-DB-Server", internet_exposed: false})
		CREATE (e3)-[:CONNECTED_TO]->(net2)

		CREATE (si3:SoftwareInstallation {id: "inst-db"})
		CREATE (f3:Finding {id: 30, risk_score: 6.0})
		CREATE (v3:Vulnerability {cve_id: "CVE-DB-LEAK", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", description: "Fuga de información en DB"})
		
		CREATE (e3)-[:HAS_INSTALLATION]->(si3)
		CREATE (si3)-[:HAS_FINDING]->(f3)
		CREATE (f3)-[:OF_VULNERABILITY]->(v3)

		// --- 4. Secure-Vault (Seguro, sin Paths) ---
		CREATE (e4:Endpoint {id: 4000, hostname: "Secure-Vault", internet_exposed: false})
		CREATE (e4)-[:CONNECTED_TO]->(net2)
	`
	err = dbHelper.ExecuteWrite(ctx, setupCypher, nil)
	if err != nil {
		log.Fatalf("Error insertando datos de prueba: %v", err)
	}
	fmt.Println("[+] Entorno de red y contenedores instanciado correctamente.")

	fmt.Println("\n[INFO] -----------------------------------------------------------")
	fmt.Println("[INFO] ESCENARIO DE PRUEBA CREADO:")
	fmt.Println("[INFO] 1. 'DMZ-Server' (Expuesto a Internet).")
	fmt.Println("[INFO]    - Aloja el contenedor: 'web-frontend-container'.")
	fmt.Println("[INFO]    - Contenedor vulnerable a RCE remoto (CVE-FRONT-RCE).")
	fmt.Println("[INFO]    - El atacante compromete el contenedor pero no tiene acceso Root al host (no hay escape).")
	fmt.Println("[INFO]")
	fmt.Println("[INFO] 2. 'Internal-App-Server' (En DMZ-Net y Internal-Net).")
	fmt.Println("[INFO]    - Aloja el contenedor: 'backend-api-container'.")
	fmt.Println("[INFO]    - Contenedor vulnerable a CVE-BACK-PIVOT por red.")
	fmt.Println("[INFO]    - El atacante salta aquí desde la DMZ.")
	fmt.Println("[INFO]")
	fmt.Println("[INFO] 3. 'Internal-DB-Server' (En Internal-Net).")
	fmt.Println("[INFO]    - Base de datos corriendo nativamente en el host (sin contenedor).")
	fmt.Println("[INFO]    - Vulnerable a fuga de datos por red (CVE-DB-LEAK).")
	fmt.Println("[INFO]    - Último salto del atacante.")
	fmt.Println("[INFO]")
	fmt.Println("[INFO] 4. 'Secure-Vault' (Aislado y seguro, no debe aparecer).")
	fmt.Println("[INFO] -----------------------------------------------------------\n")

	fmt.Println("[*] ==============================================================")
	fmt.Println("[*] FASE 1: Calculando Paths Iniciales (Sin Container Escapes)")
	fmt.Println("[*] ==============================================================")
	paths, err := infraRepo.GetExploitationPaths(ctx)
	if err != nil {
		log.Fatalf("Error calculando paths: %v", err)
	}

	for i, path := range paths {
		fmt.Printf("--- RUTA %d (Destino Final: %s) ---\n", i+1, path.Steps[len(path.Steps)-1].TargetEndpoint)
		for j, step := range path.Steps {
			targetName := step.TargetEndpoint
			if step.IsContainer {
				targetName = fmt.Sprintf("%s (Contenedor: %s)", step.TargetEndpoint, step.ContainerName)
			}
			fmt.Printf("  Salto %d: %s | Vuln: %s | Consigue Root en Host: %v\n", j+1, targetName, step.Vulnerability, step.RootObtained)
		}
	}

	fmt.Println("\n[*] ==============================================================")
	fmt.Println("[*] FASE 2: Descubierto Container Escape (chroot breakout) en App-Server")
	fmt.Println("[*] ==============================================================")
	
	escapeCypher := `
		MATCH (c2:Container {id: "CONT-BACK"})
		CREATE (siEscape:SoftwareInstallation {id: "inst-back-escape"})
		CREATE (fEscape:Finding {id: 25, risk_score: 8.8})
		CREATE (vEscape:Vulnerability {cve_id: "CVE-ESCAPE-0DAY", cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", description: "Container Escape a nivel de kernel"})
		
		CREATE (c2)-[:HAS_INSTALLATION]->(siEscape)
		CREATE (siEscape)-[:HAS_FINDING]->(fEscape)
		CREATE (fEscape)-[:OF_VULNERABILITY]->(vEscape)
	`
	dbHelper.ExecuteWrite(ctx, escapeCypher, nil)
	
	fmt.Println("[INFO] Se ha reportado una nueva vulnerabilidad local (CVE-ESCAPE-0DAY) en 'backend-api-container'.")
	fmt.Println("[INFO] Esta vulnerabilidad tiene impacto Crítico localmente (C:H, I:H, A:H) permitiendo escapar al host.")
	fmt.Println("[INFO] Recalculando Attack Paths...\n")

	paths2, err := infraRepo.GetExploitationPaths(ctx)
	if err != nil {
		log.Fatalf("Error calculando paths: %v", err)
	}

	for i, path := range paths2 {
		fmt.Printf("--- RUTA %d (Destino Final: %s) ---\n", i+1, path.Steps[len(path.Steps)-1].TargetEndpoint)
		for j, step := range path.Steps {
			targetName := step.TargetEndpoint
			if step.IsContainer {
				targetName = fmt.Sprintf("%s (Contenedor: %s)", step.TargetEndpoint, step.ContainerName)
			}
			rootLabel := step.RootObtained
			
			if rootLabel {
				fmt.Printf("  Salto %d: %s | Vuln: %s | Consigue Root en Host: >> TRUE << (ESCAPE!)\n", j+1, targetName, step.Vulnerability)
			} else {
				fmt.Printf("  Salto %d: %s | Vuln: %s | Consigue Root en Host: %v\n", j+1, targetName, step.Vulnerability, rootLabel)
			}
		}
	}

	fmt.Println("\n[INFO] Detalle en formato JSON de la ruta principal (con Container Escape):")
	if len(paths2) > 0 {
		pathJSON, _ := json.MarshalIndent(paths2[0], "", "  ")
		fmt.Println(string(pathJSON))
	}
}
