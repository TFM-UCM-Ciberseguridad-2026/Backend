package main

// Prueba E2E de la issue #3: cálculo de riesgo tras aplicar un parche.
//
// Comprueba que declarar un parche recalcula el riesgo del endpoint sin intervención,
// que la verificación por versión avisa sin bloquear, y que todo funciona igual cuando
// la instalación cuelga de un contenedor.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_riesgo_tras_parche

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
	projectID = int64(9701)

	// Escenario A: software directamente en el endpoint
	epHostID   = int64(9702)
	swHostID   = int64(9710)
	findHostID = int64(9720)
	remHostID  = int64(9730)
	instHost   = "inst-riesgo-host"

	// Escenario B: software dentro de un contenedor
	epContID   = int64(9703)
	swContID   = int64(9711)
	findContID = int64(9721)
	remContID  = int64(9731)
	instCont   = "inst-riesgo-contenedor"
	containerD = "CONT-RIESGO-TEST"
	imageD     = "IMG-RIESGO-TEST"

	cveID    = "CVE-2021-44228"
	patchURL = "https://logging.apache.org/log4j/2.x/security.html#riesgo-test"

	vulnerableVersion = "2.14.1"
	fixedVersion      = "org.apache.logging.log4j:log4j-core@2.15.0"
	patchedVersion    = "2.17.1"
)

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  PRUEBA ISSUE #3 – CÁLCULO DE RIESGO TRAS APLICAR UN PARCHE    ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")

	// ── 0. Comparación de versiones (lógica pura, sin BBDD) ────────────────
	fmt.Println("\n[1/6] Comprobando la comparación de versiones...")
	comprobarComparacionVersiones()

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
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter()).
		WithPatchProvider(provider.NewOSVAdapter())

	// ── 2. Limpieza ────────────────────────────────────────────────────────
	fmt.Println("\n[2/6] Limpiando datos previos...")
	for _, id := range []int64{projectID, epHostID, epContID, swHostID, swContID,
		findHostID, findContID, remHostID, remContID} {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	for _, id := range []string{instHost, instCont, containerD, imageD} {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (p:Patch {url: $u}) DETACH DELETE p`, map[string]any{"u": patchURL})
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (v:Vulnerability {cve_id: $c}) DETACH DELETE v`, map[string]any{"c": cveID})
	fmt.Println("    ✓ Limpieza completada.")

	// ── 3. Escenario A: software en el host ────────────────────────────────
	fmt.Println("\n[3/6] Escenario A — software instalado en el propio endpoint...")
	now := time.Now().UTC()

	if err := orch.CreateProject(ctx, &domain.Project{ProjectID: projectID, Nombre: "Riesgo tras parche"}); err != nil {
		log.Fatalf("proyecto: %v", err)
	}
	crearEndpoint(ctx, orch, epHostID, "srv-riesgo-host")

	swHost := &domain.Software{SoftwareID: swHostID, Name: "log4j-core", Version: vulnerableVersion, Vendor: "apache", Type: "application"}
	instalacionHost := &domain.SoftwareInstallation{InstallationID: instHost, FirstSeen: now, Status: "INSTALLED"}
	if err := orch.RegisterSoftwareInstallation(ctx, epHostID, swHost, instalacionHost); err != nil {
		log.Fatalf("instalación host: %v", err)
	}
	crearFindingConCVE(ctx, orch, instHost, findHostID, remHostID)

	// La versión corregida la deja el enriquecimiento desde OSV; aquí la fijamos
	// directamente para no depender de la red en esta prueba.
	if _, err := remediationRepo.UpdateFixedVersionByCVE(ctx, cveID, fixedVersion); err != nil {
		log.Fatalf("fixed_version: %v", err)
	}

	if err := orch.RegisterPatchesForVulnerability(ctx, cveID, []domain.Patch{
		{Description: "Log4j 2.15.0", URL: patchURL},
	}); err != nil {
		log.Fatalf("parche: %v", err)
	}
	parches, err := orch.GetPatchesForVulnerability(ctx, cveID)
	if err != nil || len(parches) == 0 {
		log.Fatalf("no se registró el parche: %v", err)
	}
	patchID := parches[0].PatchID

	if err := orch.ComputeEndpointRisk(ctx, epHostID); err != nil {
		log.Fatalf("riesgo inicial host: %v", err)
	}
	riesgoInicialHost, _ := leerRiesgo(ctx, dbHelper, epHostID)
	fmt.Printf("    Riesgo de partida: %.4f  (versión instalada %s)\n", riesgoInicialHost, vulnerableVersion)
	if riesgoInicialHost == 0 {
		log.Fatalf("ASSERT FAIL: el riesgo de partida debería ser > 0")
	}

	// ── 4. Declarar el parche SIN actualizar la versión ────────────────────
	fmt.Println("\n[4/6] Declarando OFFICIAL_FIX con la versión aún vulnerable...")
	app, _, err := orch.DeclarePatchApplied(ctx, instHost, cveID, patchID,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", "Declarado sin actualizar", "")
	if err != nil {
		log.Fatalf("declaración: %v", err)
	}

	fmt.Printf("    Verificada        : %v\n", app.Verification.Verified)
	fmt.Printf("    Concluyente       : %v\n", app.Verification.Conclusive)
	fmt.Printf("    Motivo            : %s\n", app.Verification.Reason)
	fmt.Printf("    Instalada/esperada: %s / %s\n", app.Verification.InstalledVersion, app.Verification.ExpectedVersion)
	fmt.Printf("    Paquete detectado : %s\n", app.Verification.MatchedPackage)

	if app.Verification.Verified {
		log.Fatalf("ASSERT FAIL: no debería verificarse con la versión %s por debajo de 2.15.0", vulnerableVersion)
	}
	if !app.Verification.Conclusive {
		log.Fatalf("ASSERT FAIL: la comparación 2.14.1 vs 2.15.0 sí es concluyente")
	}
	if app.Verification.Reason != domain.VerificationVersionBelowFix {
		log.Fatalf("ASSERT FAIL: motivo = %q", app.Verification.Reason)
	}
	fmt.Println("    ✓ Detecta que la versión no alcanza la corregida, pero registra igual")

	// El riesgo debe haberse recalculado solo, sin llamar a ComputeEndpointRisk
	riesgoTrasDeclarar, tierTrasDeclarar := leerRiesgo(ctx, dbHelper, epHostID)
	fmt.Printf("    Riesgo tras declarar (sin recalcular a mano): %.4f (%s)\n", riesgoTrasDeclarar, tierTrasDeclarar)
	if riesgoTrasDeclarar != 0.0 {
		log.Fatalf("ASSERT FAIL: el riesgo debería haberse recalculado a 0, es %.4f", riesgoTrasDeclarar)
	}
	fmt.Println("    ✓ El riesgo se recalcula automáticamente al declarar")

	// ── 5. Actualizar la versión y volver a declarar ───────────────────────
	fmt.Println("\n[5/6] Actualizando la versión instalada a", patchedVersion, "y redeclarando...")
	swHost.Version = patchedVersion
	if err := softwareRepo.Update(ctx, swHost); err != nil {
		log.Fatalf("update software: %v", err)
	}

	appOK, _, err := orch.DeclarePatchApplied(ctx, instHost, cveID, patchID,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", "Actualizado de verdad", patchedVersion)
	if err != nil {
		log.Fatalf("redeclaración: %v", err)
	}
	fmt.Printf("    Verificada: %v  |  %s\n", appOK.Verification.Verified, appOK.Verification.Reason)
	fmt.Printf("    Instalada/esperada: %s / %s\n", appOK.Verification.InstalledVersion, appOK.Verification.ExpectedVersion)

	if !appOK.Verification.Verified {
		log.Fatalf("ASSERT FAIL: 2.17.1 supera a 2.15.0, debería verificarse")
	}
	if appOK.Verification.Reason != domain.VerificationVersionAtOrAboveFix {
		log.Fatalf("ASSERT FAIL: motivo = %q", appOK.Verification.Reason)
	}
	fmt.Println("    ✓ Con la versión actualizada, la declaración queda verificada")

	// El histórico debe conservar la verificación
	historico, err := orch.GetAppliedPatchHistory(ctx, instHost)
	if err != nil || len(historico) == 0 {
		log.Fatalf("histórico: %v", err)
	}
	if !historico[0].Verification.Verified || historico[0].Verification.ExpectedVersion == "" {
		log.Fatalf("ASSERT FAIL: el histórico no conserva la verificación: %+v", historico[0].Verification)
	}
	fmt.Println("    ✓ El histórico conserva la evidencia de la verificación")

	// ── 6. Escenario B: software dentro de un contenedor ───────────────────
	fmt.Println("\n[6/6] Escenario B — mismo CVE dentro de un contenedor...")
	crearEndpoint(ctx, orch, epContID, "srv-riesgo-contenedor")

	if err := orch.SaveContainerImage(ctx, &domain.ContainerImage{
		ImageID: imageD, Name: "app", Tag: "1.0", Digest: "sha256:riesgo",
	}); err != nil {
		log.Fatalf("imagen: %v", err)
	}
	if err := orch.SaveContainer(ctx, &domain.Container{
		ContainerID: containerD, Name: "app-riesgo", State: "running",
		ImageID: imageD, HostID: epContID,
	}); err != nil {
		log.Fatalf("contenedor: %v", err)
	}

	swCont := &domain.Software{SoftwareID: swContID, Name: "log4j-core", Version: vulnerableVersion, Vendor: "apache", Type: "application"}
	if err := softwareRepo.Save(ctx, swCont); err != nil {
		log.Fatalf("sw contenedor: %v", err)
	}
	if err := softwareInstRepo.Save(ctx, &domain.SoftwareInstallation{
		InstallationID: instCont, FirstSeen: now, Status: "INSTALLED",
	}); err != nil {
		log.Fatalf("inst contenedor: %v", err)
	}
	if err := relRepo.LinkContainerToInstallation(ctx, containerD, instCont); err != nil {
		log.Fatalf("link contenedor-instalación: %v", err)
	}
	_ = relRepo.LinkInstallationToSoftware(ctx, instCont, swContID)
	crearFindingConCVE(ctx, orch, instCont, findContID, remContID)

	if err := orch.ComputeEndpointRisk(ctx, epContID); err != nil {
		log.Fatalf("riesgo inicial contenedor: %v", err)
	}
	riesgoContInicial, tierCont := leerRiesgo(ctx, dbHelper, epContID)
	fmt.Printf("    Riesgo de partida del endpoint con contenedor: %.4f (%s)\n", riesgoContInicial, tierCont)
	if riesgoContInicial == 0 {
		log.Fatalf("ASSERT FAIL: el motor de riesgo sigue sin ver las vulns de contenedor")
	}
	fmt.Println("    ✓ El motor de riesgo ya cuenta las vulnerabilidades de contenedor")

	if _, _, err := orch.DeclarePatchApplied(ctx, instCont, cveID, patchID,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", "Imagen reconstruida", patchedVersion); err != nil {
		log.Fatalf("declaración contenedor: %v", err)
	}

	riesgoContFinal, _ := leerRiesgo(ctx, dbHelper, epContID)
	fmt.Printf("    Riesgo tras declarar: %.4f\n", riesgoContFinal)
	if riesgoContFinal != 0.0 {
		log.Fatalf("ASSERT FAIL: el recálculo no alcanzó al endpoint del contenedor (%.4f)", riesgoContFinal)
	}
	fmt.Println("    ✓ El recálculo automático alcanza al endpoint que aloja el contenedor")

	fmt.Println("\n✓ PRUEBA ISSUE #3 COMPLETADA")
}

// comprobarComparacionVersiones ejercita la lógica pura de comparación.
func comprobarComparacionVersiones() {
	casos := []struct {
		a, b       string
		esperado   int
		concluyente bool
		etiqueta   string
	}{
		{"2.14.1", "2.15.0", -1, true, "menor por segmento intermedio"},
		{"2.17.1", "2.15.0", 1, true, "mayor"},
		{"2.15.0", "2.15.0", 0, true, "iguales"},
		{"2.15", "2.15.0", 0, true, "cola implícita a cero"},
		{"2.15", "2.15.1", -1, true, "cola más corta es menor"},
		{"2.9", "2.10", -1, true, "numérico, no alfabético"},
		{"5.2.20.RELEASE", "5.3.18", -1, true, "decide antes del sufijo"},
		{"0.105-31", "0.105-32", -1, true, "revisión de distribución"},
		{"2.15.0-beta", "2.15.0-rc1", 0, false, "sufijos no comparables"},
		{"", "2.15.0", 0, false, "versión vacía"},
	}

	for _, c := range casos {
		got, ok := domain.CompareVersions(c.a, c.b)
		estado := "✓"
		if ok != c.concluyente || (ok && got != c.esperado) {
			estado = "✗"
		}
		fmt.Printf("    %s %-16s vs %-12s → %2d (concluyente=%v)  %s\n", estado, c.a, c.b, got, ok, c.etiqueta)
		if ok != c.concluyente {
			log.Fatalf("ASSERT FAIL: %q vs %q concluyente=%v, esperado %v", c.a, c.b, ok, c.concluyente)
		}
		if ok && got != c.esperado {
			log.Fatalf("ASSERT FAIL: %q vs %q = %d, esperado %d", c.a, c.b, got, c.esperado)
		}
	}
	fmt.Println("    ✓ Los 10 casos de comparación se comportan como se espera")
}

func crearEndpoint(ctx context.Context, orch *service.Orchestrator, id int64, hostname string) {
	ep := &domain.Endpoint{
		EndpointID: id, Hostname: hostname, Type: "Linux", Status: "ACTIVE",
		InternetExposed: true, Environment: "prod",
		ConfidentialityReq: "High", IntegrityReq: "High", AvailabilityReq: "High",
	}
	if err := orch.AddEndpointToProject(ctx, projectID, ep); err != nil {
		log.Fatalf("endpoint %s: %v", hostname, err)
	}
}

func crearFindingConCVE(ctx context.Context, orch *service.Orchestrator, instID string, findingID, remID int64) {
	now := time.Now().UTC()
	finding := &domain.Finding{FindingID: findingID, Status: "OPEN", FirstSeen: now, RemediationFactor: 1.0}
	if err := orch.GenerateFinding(ctx, instID, finding); err != nil {
		log.Fatalf("finding %d: %v", findingID, err)
	}

	vuln := &domain.Vulnerability{
		VulnerabilityID: cveID, CVEID: cveID,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", BaseScore: 10.0,
	}
	rem := &domain.Remediation{RemediationID: remID, Status: "OPEN"}
	if err := orch.AssociateVulnerabilitiesAndRemediations(ctx, findingID, vuln, rem); err != nil {
		log.Fatalf("vulnerabilidad de %d: %v", findingID, err)
	}
}

func leerRiesgo(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}, endpointID int64) (float64, string) {
	res, err := db.ExecuteRead(ctx,
		`MATCH (e:Endpoint {id: $id}) RETURN e.risk_score AS s, e.risk_tier AS t`,
		map[string]any{"id": endpointID})
	if err != nil {
		log.Fatalf("lectura riesgo: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		s, _ := m["s"].(float64)
		t, _ := m["t"].(string)
		return s, t
	}
	return 0, ""
}
