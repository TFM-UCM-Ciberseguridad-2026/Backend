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

const (
	testProjectID   = int64(7700)
	testHostID      = int64(7701)
	testContainerID = "container-bug-test-1"
	testImageID     = "nginx:1.25-alpine"
	testCVE         = "CVE-2024-9999"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║     PRUEBA VERIFICACIÓN DE BUGS (1, 2, 3 Y 4) DE CONTENEDOR  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo,
		_, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	orch := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo, containerRepo, patchRepo, dbHelper,
		provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds),
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter()).
		WithPatchProvider(provider.NewOSVAdapter())

	// ── 1. Limpieza ────────────────────────────────────────────────────────
	fmt.Println("\n[1/5] Limpiando datos de prueba previa...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) WHERE n.id IN [$pid, $hid] DETACH DELETE n", map[string]any{
		"pid": testProjectID, "hid": testHostID,
	})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (c:Container {id: $cid}) DETACH DELETE c", map[string]any{"cid": testContainerID})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (ci:ContainerImage {id: $img}) DETACH DELETE ci", map[string]any{"img": testImageID})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (v:Vulnerability {cve_id: $cve}) DETACH DELETE v", map[string]any{"cve": testCVE})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (f:Finding) WHERE f.finding_key STARTS WITH $prefix DETACH DELETE f", map[string]any{"prefix": testContainerID})
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Crear Infraestructura de Contenedor ─────────────────────────────
	fmt.Println("\n[2/5] Creando Proyecto, Host, Imagen y Contenedor...")
	if err := orch.CreateProject(ctx, &domain.Project{ProjectID: testProjectID, Name: "Proyecto Bugs Contenedor"}); err != nil {
		log.Fatalf("error creando proyecto: %v", err)
	}

	host := &domain.Endpoint{
		EndpointID: testHostID, Hostname: "docker-host-01", Type: "Linux", Status: "ACTIVE",
		InternetExposed: true, Environment: "prod",
		ConfidentialityReq: "High", IntegrityReq: "High", AvailabilityReq: "High",
	}
	if err := orch.AddEndpointToProject(ctx, testProjectID, host); err != nil {
		log.Fatalf("error agregando host: %v", err)
	}

	img := &domain.ContainerImage{ImageID: testImageID, Name: "nginx", Tag: "1.25-alpine"}
	if err := orch.SaveContainerImage(ctx, img); err != nil {
		log.Fatalf("error guardando imagen: %v", err)
	}

	container := &domain.Container{
		ContainerID: testContainerID, Name: "web-nginx-prod", State: "running",
		ImageID: testImageID, HostID: testHostID, InternetExposed: true,
	}
	if err := orch.SaveContainer(ctx, container); err != nil {
		log.Fatalf("error guardando contenedor: %v", err)
	}

	vuln := &domain.Vulnerability{
		VulnerabilityID: testCVE, CVEID: testCVE, BaseScore: 9.8,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := vulnRepo.Save(ctx, vuln); err != nil {
		log.Fatalf("error guardando vulnerabilidad: %v", err)
	}
	_ = containerRepo.LinkVulnerabilityToImage(ctx, testImageID, testCVE)
	fmt.Println("    ✓ Infraestructura creada correctamente.")

	// ── 3. Verificar Bug #4 (Asignación Atómica de IDs sin Fragmentación) ─
	fmt.Println("\n[3/5] Verificando Bug #4 (Sincronización atómica de IDs en contenedores)...")

	// Primera sincronización (Creación)
	if err := orch.SaveContainer(ctx, container); err != nil {
		log.Fatalf("error resincronizando contenedor: %v", err)
	}
	// Ejecutar syncContainerFindingsForImage
	_ = orch.SaveContainerImage(ctx, img)

	// Consultar el finding creado
	f1, _, err := findingRepo.EnsureForContainerImageContextAndCVE(ctx, testContainerID, testImageID, testCVE, &domain.Finding{
		FindingID: 0, Status: "OPEN", ImpactScore: 9.8, RiskScore: 4.9, PriorityScore: 0.95,
	})
	if err != nil || f1 == nil || f1.FindingID == 0 {
		log.Fatalf("ASSERT FAIL (Bug 4): El finding creado no tiene un FindingID válido asignado (> 0): %v, id=%d", err, f1.FindingID)
	}
	idOriginal := f1.FindingID
	fmt.Printf("    ✓ Finding creado con ID atómico: %d\n", idOriginal)

	// Segunda sincronización (Re-sync cuando ya existe)
	f2, created, err := findingRepo.EnsureForContainerImageContextAndCVE(ctx, testContainerID, testImageID, testCVE, &domain.Finding{
		FindingID: 0, Status: "OPEN", ImpactScore: 9.8, RiskScore: 4.9, PriorityScore: 0.95,
	})
	if err != nil || created || f2.FindingID != idOriginal {
		log.Fatalf("ASSERT FAIL (Bug 4): Re-sync creó un nodo duplicado o alteró el ID original (%d vs %d, created=%v)", idOriginal, f2.FindingID, created)
	}
	fmt.Println("    ✓ Re-sincronizar reutiliza el Finding idéntico sin fragmentar secuencias de IDs.")

	// Fijo scores de prioridad en el finding para probar GetPatchQueue
	_ = riskRepo.UpdateFindingScores(ctx, idOriginal, 9.8, 0.5, 1.0, 1.0, 4.9, 1.75, 1.8, 0.95, service.ClassifyRiskTier(4.9), service.ClassifyRiskTier(0.95))

	// ── 4. Verificar Bug #1 y Bug #2 (Inclusión de Contenedor y Deduplicación en Cola) ──
	fmt.Println("\n[4/5] Verificando Bug #1 (Inclusión) y Bug #2 (Deduplicación) en GetPatchQueue...")
	pid := testProjectID
	pqResp, err := orch.GetPatchQueue(ctx, domain.PatchQueueQuery{ProjectID: &pid, Page: 1, Limit: 20})
	if err != nil {
		log.Fatalf("error consultando cola de parcheo: %v", err)
	}

	if pqResp.Total != 1 || len(pqResp.Queue) != 1 {
		log.Fatalf("ASSERT FAIL (Bug 1/2): Se esperaba exactamente 1 item en la cola de parcheo, obtenidos Total=%d, len=%d", pqResp.Total, len(pqResp.Queue))
	}
	item := pqResp.Queue[0]
	if item.FindingID != idOriginal || !item.InContainer || item.ContainerName != "web-nginx-prod" {
		log.Fatalf("ASSERT FAIL (Bug 1): El item devuelto no refleja los datos del contenedor correctamente: %+v", item)
	}
	fmt.Printf("    ✓ Bug #1 corregido: Contenedor '%s' (Finding #%d) devuelto en la Cola de Parches (in_container=%v)\n",
		item.ContainerName, item.FindingID, item.InContainer)

	// Simular múltiples rutas agregando relaciones adicionales en el grafo
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (e:Endpoint {id: $hid}), (c:Container {id: $cid}) MERGE (e)-[:USES_IMAGE]->(c)", map[string]any{
		"hid": testHostID, "cid": testContainerID,
	})
	pqRespDupCheck, err := orch.GetPatchQueue(ctx, domain.PatchQueueQuery{ProjectID: &pid, Page: 1, Limit: 20})
	if err != nil || pqRespDupCheck.Total != 1 || len(pqRespDupCheck.Queue) != 1 {
		log.Fatalf("ASSERT FAIL (Bug 2): Rutas múltiples provocaron duplicados en la cola de parcheo: Total=%d, len=%d", pqRespDupCheck.Total, len(pqRespDupCheck.Queue))
	}
	fmt.Println("    ✓ Bug #2 corregido: Consulta deduplicada con DISTINCT, devuelta exactamente 1 entrada sin duplicados.")

	// ── 5. Verificar Bug #3 (Helper getInt con float64 en Container) ────────
	fmt.Println("\n[5/5] Verificando Bug #3 (Deserialización getInt con float64)...")
	// Forzar propiedades numéricas en el nodo Container como float64 en Neo4j
	_ = dbHelper.ExecuteWrite(ctx, `
		MATCH (c:Container {id: $cid})
		SET c.technical_driver_finding_id = toFloat($fid),
		    c.priority_driver_finding_id = toFloat($fid),
		    c.risky_asset_count = 5.0
	`, map[string]any{"cid": testContainerID, "fid": idOriginal})

	cDomain, err := containerRepo.GetContainer(ctx, testContainerID)
	if err != nil {
		log.Fatalf("error obteniendo contenedor: %v", err)
	}
	if cDomain.TechnicalDriverFindingID != idOriginal || cDomain.PriorityDriverFindingID != idOriginal || cDomain.RiskyAssetCount != 5 {
		log.Fatalf("ASSERT FAIL (Bug 3): getInt falló al convertir float64 a int64. Obtenidos Tech=%d, Prio=%d, Count=%d (esperado %d)",
			cDomain.TechnicalDriverFindingID, cDomain.PriorityDriverFindingID, cDomain.RiskyAssetCount, idOriginal)
	}
	fmt.Printf("    ✓ Bug #3 corregido: getInt convirtió exitosamente float64(%.1f) -> int64(%d) para los drivers de riesgo.\n",
		float64(idOriginal), cDomain.TechnicalDriverFindingID)

	// ── Limpieza final de datos de prueba ────────────────────────────────
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) WHERE n.id IN [$pid, $hid] DETACH DELETE n", map[string]any{
		"pid": testProjectID, "hid": testHostID,
	})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (c:Container {id: $cid}) DETACH DELETE c", map[string]any{"cid": testContainerID})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (ci:ContainerImage {id: $img}) DETACH DELETE ci", map[string]any{"img": testImageID})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (v:Vulnerability {cve_id: $cve}) DETACH DELETE v", map[string]any{"cve": testCVE})
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (f:Finding {id: $fid}) DETACH DELETE f", map[string]any{"fid": idOriginal})

	fmt.Println("\n✓ ¡TODAS LAS PRUEBAS DE VERIFICACIÓN DE BUGS (1, 2, 3 Y 4) PASARON CON ÉXITO!")
}
