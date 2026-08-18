package main

// Prueba de regresión: el riesgo del software instalado dentro de un contenedor debe
// puntuar igual que el mismo software instalado directamente en el host.
//
// El motor recorre dos caminos hasta la instalación:
//   (Endpoint)-[:HAS_INSTALLATION]->(SoftwareInstallation)
//   (Endpoint)-[:HOSTS]->(Container)-[:HAS_INSTALLATION]->(SoftwareInstallation)
//
// Se ha roto dos veces: basta con que una consulta de risk.go meta el endpoint en el
// patrón principal con -[:HAS_INSTALLATION]-> para que el segundo camino desaparezca y
// las vulnerabilidades del contenedor dejen de puntuar en silencio.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_riesgo_contenedores

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
	projectID = int64(9950)

	// Escenario A: software directamente en el endpoint
	epHostID   = int64(9951)
	swHostID   = int64(9960)
	findHostID = int64(9970)
	remHostID  = int64(9980)
	instHost   = "inst-cont-reg-host"

	// Escenario B: mismo software dentro de un contenedor
	epContID   = int64(9952)
	swContID   = int64(9961)
	findContID = int64(9971)
	remContID  = int64(9981)
	instCont   = "inst-cont-reg-cont"
	containerD = "CONT-REG-TEST"
	imageD     = "IMG-REG-TEST"

	// Escenario C: endpoint decomisado, para comprobar que ese filtro sigue vivo
	epBajaID   = int64(9953)
	swBajaID   = int64(9962)
	findBajaID = int64(9972)
	remBajaID  = int64(9982)
	instBaja   = "inst-cont-reg-baja"

	cveID   = "CVE-2021-44228"
	cvssVec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  REGRESIÓN – RIESGO DEL SOFTWARE DENTRO DE CONTENEDORES       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
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
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter())

	// ── 1. Limpieza ────────────────────────────────────────────────────────
	fmt.Println("\n[1/5] Limpiando datos previos...")
	for _, id := range []int64{projectID, epHostID, epContID, epBajaID,
		swHostID, swContID, swBajaID, findHostID, findContID, findBajaID,
		remHostID, remContID, remBajaID} {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	for _, id := range []string{instHost, instCont, instBaja, containerD, imageD} {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (v:Vulnerability {cve_id: $c}) DETACH DELETE v`, map[string]any{"c": cveID})
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Escenario ───────────────────────────────────────────────────────
	fmt.Println("\n[2/5] Creando el mismo CVE en tres ubicaciones distintas...")
	now := time.Now().UTC()

	if err := orch.CreateProject(ctx, &domain.Project{ProjectID: projectID, Nombre: "Regresión contenedores"}); err != nil {
		log.Fatalf("proyecto: %v", err)
	}

	crearEndpoint(ctx, orch, epHostID, "host-directo", "ACTIVE")
	crearEndpoint(ctx, orch, epContID, "host-con-contenedor", "ACTIVE")
	crearEndpoint(ctx, orch, epBajaID, "host-decomisado", "DECOMISADO")

	// A: instalación colgada del endpoint
	if err := orch.RegisterSoftwareInstallation(ctx, epHostID,
		software(swHostID), instalacion(instHost, now)); err != nil {
		log.Fatalf("instalación host: %v", err)
	}
	crearFinding(ctx, orch, instHost, findHostID, remHostID)

	// B: instalación colgada de un contenedor del endpoint
	if err := orch.SaveContainerImage(ctx, &domain.ContainerImage{
		ImageID: imageD, Name: "app", Tag: "1.0", Digest: "sha256:regresion",
	}); err != nil {
		log.Fatalf("imagen: %v", err)
	}
	if err := orch.SaveContainer(ctx, &domain.Container{
		ContainerID: containerD, Name: "app-regresion", State: "running",
		ImageID: imageD, HostID: epContID,
	}); err != nil {
		log.Fatalf("contenedor: %v", err)
	}
	if err := softwareRepo.Save(ctx, software(swContID)); err != nil {
		log.Fatalf("sw contenedor: %v", err)
	}
	if err := softwareInstRepo.Save(ctx, instalacion(instCont, now)); err != nil {
		log.Fatalf("inst contenedor: %v", err)
	}
	if err := relRepo.LinkContainerToInstallation(ctx, containerD, instCont); err != nil {
		log.Fatalf("link contenedor-instalación: %v", err)
	}
	_ = relRepo.LinkInstallationToSoftware(ctx, instCont, swContID)
	crearFinding(ctx, orch, instCont, findContID, remContID)

	// C: instalación en un endpoint dado de baja
	if err := orch.RegisterSoftwareInstallation(ctx, epBajaID,
		software(swBajaID), instalacion(instBaja, now)); err != nil {
		log.Fatalf("instalación baja: %v", err)
	}
	crearFinding(ctx, orch, instBaja, findBajaID, remBajaID)

	fmt.Println("    · host-directo         → Endpoint -[:HAS_INSTALLATION]-> sw")
	fmt.Println("    · host-con-contenedor  → Endpoint -[:HOSTS]-> Container -[:HAS_INSTALLATION]-> sw")
	fmt.Println("    · host-decomisado      → como el primero, pero el endpoint está de baja")

	// ── 3. Calcular ────────────────────────────────────────────────────────
	fmt.Println("\n[3/5] Calculando el riesgo de los tres endpoints...")
	for _, id := range []int64{epHostID, epContID, epBajaID} {
		if err := orch.ComputeEndpointRisk(ctx, id); err != nil {
			log.Fatalf("ComputeEndpointRisk(%d): %v", id, err)
		}
	}
	fmt.Println("    ✓ Cálculo completado.")

	// ── 4. Resultados ──────────────────────────────────────────────────────
	fmt.Println("\n[4/5] Resultados:")
	riesgoHost, tierHost := leerEndpoint(ctx, dbHelper, epHostID)
	riesgoCont, tierCont := leerEndpoint(ctx, dbHelper, epContID)
	riesgoBaja, _ := leerEndpoint(ctx, dbHelper, epBajaID)
	instalHost := leerInstalacion(ctx, dbHelper, instHost)
	instalCont := leerInstalacion(ctx, dbHelper, instCont)

	fmt.Println("┌──────────────────────┬────────────┬──────────┬────────────────┐")
	fmt.Printf("│ %-20s │ %-10s │ %-8s │ %-14s │\n", "Endpoint", "Riesgo", "Tier", "Riesgo instal.")
	fmt.Println("├──────────────────────┼────────────┼──────────┼────────────────┤")
	fmt.Printf("│ %-20s │ %10.4f │ %-8s │ %14.4f │\n", "host-directo", riesgoHost, tierHost, instalHost)
	fmt.Printf("│ %-20s │ %10.4f │ %-8s │ %14.4f │\n", "con contenedor", riesgoCont, tierCont, instalCont)
	fmt.Println("└──────────────────────┴────────────┴──────────┴────────────────┘")

	// ── 5. Aserciones ──────────────────────────────────────────────────────
	fmt.Println("\n[5/5] Validando...")

	if riesgoHost <= 0 {
		log.Fatalf("ASSERT FAIL: el caso de referencia (host) no puntúa: %.4f", riesgoHost)
	}
	fmt.Printf("    ✓ El caso de referencia puntúa (%.4f)\n", riesgoHost)

	if riesgoCont == 0 {
		log.Fatalf("ASSERT FAIL: el riesgo del contenedor es 0. Alguna consulta de risk.go " +
			"ha perdido el recorrido HAS_INSTALLATION|HOSTS")
	}
	if riesgoHost != riesgoCont {
		log.Fatalf("ASSERT FAIL: mismo CVE debería dar el mismo riesgo: host=%.4f contenedor=%.4f",
			riesgoHost, riesgoCont)
	}
	fmt.Println("    ✓ El endpoint con contenedor puntúa igual que el host")

	if instalCont == 0 || instalHost != instalCont {
		log.Fatalf("ASSERT FAIL: riesgo de instalación distinto: host=%.4f contenedor=%.4f",
			instalHost, instalCont)
	}
	fmt.Println("    ✓ El riesgo de la instalación también coincide")

	// El endpoint dado de baja no debe puntuar: confirma que el filtro sigue vivo.
	if riesgoBaja != 0 {
		log.Fatalf("ASSERT FAIL: un endpoint decomisado no debería puntuar, da %.4f", riesgoBaja)
	}
	fmt.Println("    ✓ El endpoint decomisado sigue quedando fuera del cálculo")

	// La instalación del contenedor debe aparecer entre las del endpoint.
	instalaciones, err := riskRepo.GetInstallationIDsByEndpoint(ctx, epContID)
	if err != nil {
		log.Fatalf("GetInstallationIDsByEndpoint: %v", err)
	}
	if !contiene(instalaciones, instCont) {
		log.Fatalf("ASSERT FAIL: %s no aparece entre las instalaciones del endpoint: %v", instCont, instalaciones)
	}
	fmt.Println("    ✓ GetInstallationIDsByEndpoint incluye la instalación del contenedor")

	// Y en el resumen de software del endpoint.
	resumen, err := riskRepo.GetSoftwareRiskSummariesByEndpoint(ctx, epContID)
	if err != nil {
		log.Fatalf("GetSoftwareRiskSummariesByEndpoint: %v", err)
	}
	encontrado := false
	for _, s := range resumen {
		if s.InstallationID == instCont {
			encontrado = true
			if s.RiskScore == 0 {
				log.Fatalf("ASSERT FAIL: el resumen devuelve riesgo 0 para %s", instCont)
			}
		}
	}
	if !encontrado {
		log.Fatalf("ASSERT FAIL: %s no aparece en el resumen de software del endpoint", instCont)
	}
	fmt.Println("    ✓ GetSoftwareRiskSummariesByEndpoint incluye la instalación del contenedor")

	// Y los findings de esa instalación se leen sin pasar por el endpoint.
	scores, err := riskRepo.GetFindingScoresByInstallation(ctx, instCont)
	if err != nil {
		log.Fatalf("GetFindingScoresByInstallation: %v", err)
	}
	if len(scores) != 1 {
		log.Fatalf("ASSERT FAIL: se esperaba 1 finding en %s, hay %d (¿filas duplicadas?)", instCont, len(scores))
	}
	fmt.Println("    ✓ GetFindingScoresByInstallation devuelve el finding, sin duplicar filas")

	// La instalación del endpoint decomisado no debe aportar scores.
	scoresBaja, err := riskRepo.GetFindingScoresByInstallation(ctx, instBaja)
	if err != nil {
		log.Fatalf("GetFindingScoresByInstallation(baja): %v", err)
	}
	if len(scoresBaja) != 0 {
		log.Fatalf("ASSERT FAIL: la instalación de un endpoint decomisado no debe aportar scores, aporta %d", len(scoresBaja))
	}
	fmt.Println("    ✓ La instalación del endpoint decomisado no aporta scores")

	fmt.Println("\n✓ PRUEBA DE REGRESIÓN COMPLETADA")
}

func software(id int64) *domain.Software {
	return &domain.Software{
		SoftwareID: id, Name: "log4j-core", Version: "2.14.1",
		Vendor: "apache", Type: "application",
	}
}

func instalacion(id string, now time.Time) *domain.SoftwareInstallation {
	return &domain.SoftwareInstallation{InstallationID: id, FirstSeen: now, Status: "INSTALLED"}
}

func crearEndpoint(ctx context.Context, orch *service.Orchestrator, id int64, hostname, estado string) {
	ep := &domain.Endpoint{
		EndpointID: id, Hostname: hostname, Type: "Linux", Status: estado,
		InternetExposed: true, Environment: "prod",
		ConfidentialityReq: "High", IntegrityReq: "High", AvailabilityReq: "High",
	}
	if err := orch.AddEndpointToProject(ctx, projectID, ep); err != nil {
		log.Fatalf("endpoint %s: %v", hostname, err)
	}
}

func crearFinding(ctx context.Context, orch *service.Orchestrator, instID string, findingID, remID int64) {
	now := time.Now().UTC()
	f := &domain.Finding{FindingID: findingID, Status: "OPEN", FirstSeen: now, RemediationFactor: 1.0}
	if err := orch.GenerateFinding(ctx, instID, f); err != nil {
		log.Fatalf("finding %d: %v", findingID, err)
	}
	v := &domain.Vulnerability{VulnerabilityID: cveID, CVEID: cveID, CVSSVector: cvssVec, BaseScore: 10.0}
	rem := &domain.Remediation{RemediationID: remID, Status: "OPEN"}
	if err := orch.AssociateVulnerabilitiesAndRemediations(ctx, findingID, v, rem); err != nil {
		log.Fatalf("vulnerabilidad de %d: %v", findingID, err)
	}
}

func leerEndpoint(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}, endpointID int64) (float64, string) {
	res, err := db.ExecuteRead(ctx,
		`MATCH (e:Endpoint {id: $id}) RETURN e.risk_score AS s, e.risk_tier AS t`,
		map[string]any{"id": endpointID})
	if err != nil {
		log.Fatalf("lectura endpoint: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		s, _ := m["s"].(float64)
		t, _ := m["t"].(string)
		return s, t
	}
	return 0, ""
}

func leerInstalacion(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}, installationID string) float64 {
	res, err := db.ExecuteRead(ctx,
		`MATCH (si:SoftwareInstallation {id: $id}) RETURN si.risk_score AS s`,
		map[string]any{"id": installationID})
	if err != nil {
		log.Fatalf("lectura instalación: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		s, _ := m["s"].(float64)
		return s
	}
	return 0
}

func contiene(lista []string, valor string) bool {
	for _, v := range lista {
		if v == valor {
			return true
		}
	}
	return false
}
