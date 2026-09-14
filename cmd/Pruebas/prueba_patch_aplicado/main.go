package main

// Prueba de integración end-to-end para la issue #2: declaración de un parche aplicado.
//
// Valida:
//   1. Declarar un parche crea (Patch)-[:APPLIED_TO]->(SoftwareInstallation) con fecha,
//      autor, nivel y factor de remediación
//   2. Un WORKAROUND baja el factor a 0.50 y deja el finding abierto: el riesgo se
//      reduce a la mitad pero la vulnerabilidad sigue contando
//   3. Un OFFICIAL_FIX pone el factor a 0, marca el finding como PATCHED y lo saca de
//      la agregación: el riesgo del endpoint cae a cero
//   4. Redeclarar sobre la misma instalación actualiza la arista, no la duplica
//   5. El histórico devuelve las declaraciones de la instalación
//   6. Declarar sobre una instalación o un parche inexistente falla en vez de pasar
//      desapercibido
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_patch_aplicado

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
	projectID      = int64(9601)
	endpointID     = int64(9602)
	softwareID     = int64(9610)
	findingID      = int64(9620)
	remediationID  = int64(9630)
	installationID = "inst-patch-aplicado-test"

	cveID     = "CVE-2021-44228"
	patchURL  = "https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228"
	fakeInstD = "inst-que-no-existe"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  PRUEBA ISSUE #2 – DECLARACIÓN DE UN PARCHE APLICADO     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
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
	fmt.Println("\n[1/8] Limpiando datos previos...")
	for _, id := range []int64{projectID, endpointID, softwareID, findingID, remediationID} {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (n {id: $id}) DETACH DELETE n`, map[string]any{"id": installationID})
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (p:Patch {url: $url}) DETACH DELETE p`, map[string]any{"url": patchURL})
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (v:Vulnerability {cve_id: $c}) DETACH DELETE v`, map[string]any{"c": cveID})
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Infraestructura ─────────────────────────────────────────────────
	fmt.Println("\n[2/8] Creando endpoint, instalación, finding y parche...")
	now := time.Now().UTC()

	if err := orch.CreateProject(ctx, &domain.Project{ProjectID: projectID, Name: "Patch Applied Test"}); err != nil {
		log.Fatalf("proyecto: %v", err)
	}

	endpoint := &domain.Endpoint{
		EndpointID: endpointID, Hostname: "srv-patch-aplicado", Type: "Linux", Status: "ACTIVE",
		InternetExposed: true, Environment: "prod",
		ConfidentialityReq: "High", IntegrityReq: "High", AvailabilityReq: "High",
	}
	if err := orch.AddEndpointToProject(ctx, projectID, endpoint); err != nil {
		log.Fatalf("endpoint: %v", err)
	}

	software := &domain.Software{SoftwareID: softwareID, Name: "log4j-core", Version: "2.14.1", Vendor: "apache", Type: "application"}
	installation := &domain.SoftwareInstallation{InstallationID: installationID, FirstSeen: now, Status: "INSTALLED"}
	if err := orch.RegisterSoftwareInstallation(ctx, endpointID, software, installation); err != nil {
		log.Fatalf("instalación: %v", err)
	}

	finding := &domain.Finding{FindingID: findingID, Status: "OPEN", FirstSeen: now, RemediationFactor: 1.0}
	if err := orch.GenerateFinding(ctx, installationID, finding); err != nil {
		log.Fatalf("finding: %v", err)
	}

	vulnerability := &domain.Vulnerability{
		VulnerabilityID: cveID, CVEID: cveID,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", BaseScore: 10.0,
	}
	remediation := &domain.Remediation{RemediationID: remediationID, Status: "OPEN"}
	if err := orch.AssociateVulnerabilitiesAndRemediations(ctx, findingID, vulnerability, remediation); err != nil {
		log.Fatalf("vulnerabilidad: %v", err)
	}

	if err := orch.RegisterPatchesForVulnerability(ctx, cveID, []domain.Patch{
		{Description: "Apache Log4j 2.15.0", URL: patchURL},
	}); err != nil {
		log.Fatalf("parche: %v", err)
	}
	patches, err := orch.GetPatchesForVulnerability(ctx, cveID)
	if err != nil || len(patches) == 0 {
		log.Fatalf("no se registró el parche: %v", err)
	}
	patchID := patches[0].PatchID
	fmt.Printf("    ✓ Escenario listo (patch #%d sobre %s).\n", patchID, installationID)

	// ── 3. Riesgo de partida ───────────────────────────────────────────────
	fmt.Println("\n[3/8] Riesgo antes de declarar ningún parche...")
	if err := orch.ComputeEndpointRisk(ctx, endpointID); err != nil {
		log.Fatalf("riesgo inicial: %v", err)
	}
	riskInicial, tierInicial := leerRiesgoEndpoint(ctx, dbHelper)
	rfInicial, statusInicial := leerFinding(ctx, dbHelper)
	fmt.Printf("    Endpoint : %.4f (%s)\n", riskInicial, tierInicial)
	fmt.Printf("    Finding  : RF=%.2f  status=%s\n", rfInicial, statusInicial)

	if riskInicial == 0 {
		log.Fatalf("ASSERT FAIL: el riesgo de partida debería ser > 0")
	}

	// ── 4. Declarar un WORKAROUND ──────────────────────────────────────────
	fmt.Println("\n[4/8] Declarando un WORKAROUND (mitigación parcial)...")
	appliedAt := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	app, affected, err := orch.DeclarePatchApplied(ctx, installationID, cveID, patchID,
		domain.RemediationLevelWorkaround, appliedAt, "diego", "Deshabilitado JNDI lookup por configuración", "")
	if err != nil {
		log.Fatalf("declaración workaround: %v", err)
	}
	fmt.Printf("    ✓ Nivel %s → factor %.2f, findings afectados: %v\n", app.RemediationLevel, app.RemediationFactor, affected)

	if err := orch.ComputeEndpointRisk(ctx, endpointID); err != nil {
		log.Fatalf("recálculo: %v", err)
	}
	riskWorkaround, tierWorkaround := leerRiesgoEndpoint(ctx, dbHelper)
	rfWorkaround, statusWorkaround := leerFinding(ctx, dbHelper)
	fmt.Printf("    Endpoint : %.4f (%s)\n", riskWorkaround, tierWorkaround)
	fmt.Printf("    Finding  : RF=%.2f  status=%s\n", rfWorkaround, statusWorkaround)

	remStatusWA, remAppliedWA := leerRemediation(ctx, dbHelper)
	fmt.Printf("    Remediation: status=%s  applied_at=%s\n", remStatusWA, remAppliedWA)

	if rfWorkaround != 0.50 {
		log.Fatalf("ASSERT FAIL: RF tras workaround = %.2f, esperado 0.50", rfWorkaround)
	}
	if statusWorkaround != "OPEN" {
		log.Fatalf("ASSERT FAIL: un workaround no debe cerrar el finding, status=%s", statusWorkaround)
	}
	if remStatusWA != domain.RemediationStatusPartial {
		log.Fatalf("ASSERT FAIL: Remediation.status = %s, esperado %s", remStatusWA, domain.RemediationStatusPartial)
	}
	if remAppliedWA == "" {
		log.Fatalf("ASSERT FAIL: Remediation.applied_at no se sincronizó")
	}
	if riskWorkaround >= riskInicial {
		log.Fatalf("ASSERT FAIL: el riesgo debería bajar (%.4f → %.4f)", riskInicial, riskWorkaround)
	}
	if riskWorkaround == 0 {
		log.Fatalf("ASSERT FAIL: un workaround no debe anular el riesgo")
	}
	fmt.Println("    ✓ El riesgo baja pero el finding sigue contando")

	// ── 5. Declarar el parche OFICIAL ──────────────────────────────────────
	fmt.Println("\n[5/8] Declarando el parche OFICIAL sobre la misma instalación...")
	appOficial, affectedOficial, err := orch.DeclarePatchApplied(ctx, installationID, cveID, patchID,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", "Actualizado a 2.17.1", "2.17.1")
	if err != nil {
		log.Fatalf("declaración oficial: %v", err)
	}
	fmt.Printf("    ✓ Nivel %s → factor %.2f, findings afectados: %v\n",
		appOficial.RemediationLevel, appOficial.RemediationFactor, affectedOficial)

	if err := orch.ComputeEndpointRisk(ctx, endpointID); err != nil {
		log.Fatalf("recálculo: %v", err)
	}
	riskFinal, tierFinal := leerRiesgoEndpoint(ctx, dbHelper)
	rfFinal, statusFinal := leerFinding(ctx, dbHelper)
	fmt.Printf("    Endpoint : %.4f (%s)\n", riskFinal, tierFinal)
	fmt.Printf("    Finding  : RF=%.2f  status=%s\n", rfFinal, statusFinal)

	remStatusFinal, remAppliedFinal := leerRemediation(ctx, dbHelper)
	fmt.Printf("    Remediation: status=%s  applied_at=%s\n", remStatusFinal, remAppliedFinal)

	if rfFinal != 0.0 {
		log.Fatalf("ASSERT FAIL: RF tras parche oficial = %.2f, esperado 0.00", rfFinal)
	}
	if statusFinal != "PATCHED" {
		log.Fatalf("ASSERT FAIL: el parche oficial debe marcar PATCHED, status=%s", statusFinal)
	}
	if remStatusFinal != domain.RemediationStatusApplied {
		log.Fatalf("ASSERT FAIL: Remediation.status = %s, esperado %s", remStatusFinal, domain.RemediationStatusApplied)
	}
	if remAppliedFinal == "" {
		log.Fatalf("ASSERT FAIL: Remediation.applied_at vacío tras el parche oficial")
	}
	fmt.Println("    ✓ Remediation sincronizada (status APPLIED + applied_at)")
	if riskFinal != 0.0 {
		log.Fatalf("ASSERT FAIL: el riesgo del endpoint debería ser 0, es %.4f", riskFinal)
	}
	fmt.Println("    ✓ El parche oficial cierra el finding y anula el riesgo")

	// Comprobar que no queda puntuación obsoleta en el finding
	scoreFinding := leerRiskScoreFinding(ctx, dbHelper)
	if scoreFinding != 0.0 {
		log.Fatalf("ASSERT FAIL: el finding conserva risk_score=%.4f obsoleto", scoreFinding)
	}
	fmt.Println("    ✓ El finding no conserva puntuación obsoleta")

	// ── 6. La redeclaración no duplica la arista ───────────────────────────
	fmt.Println("\n[6/8] Comprobando que no se duplican las aristas APPLIED_TO...")
	nAristas := contarAristas(ctx, dbHelper)
	fmt.Printf("    Aristas APPLIED_TO: %d (se declaró 2 veces)\n", nAristas)
	if nAristas != 1 {
		log.Fatalf("ASSERT FAIL: se esperaba 1 arista, hay %d", nAristas)
	}
	fmt.Println("    ✓ La segunda declaración actualiza la arista existente")

	// ── 7. Histórico ───────────────────────────────────────────────────────
	fmt.Println("\n[7/8] Consultando el histórico de la instalación...")
	historico, err := orch.GetAppliedPatchHistory(ctx, installationID)
	if err != nil {
		log.Fatalf("histórico: %v", err)
	}
	for _, h := range historico {
		fmt.Printf("    ┌─ Patch #%d (%s)\n", h.PatchID, h.CVEID)
		fmt.Printf("    │  Nivel    : %s (factor %.2f)\n", h.RemediationLevel, h.RemediationFactor)
		fmt.Printf("    │  Aplicado : %s por %q\n", h.AppliedAt.Format("2006-01-02 15:04"), h.AppliedBy)
		fmt.Printf("    │  Notas    : %s\n", h.Notes)
		fmt.Printf("    └─ URL      : %s\n", h.PatchURL)
	}
	if len(historico) != 1 {
		log.Fatalf("ASSERT FAIL: el histórico debería tener 1 entrada, tiene %d", len(historico))
	}
	if historico[0].RemediationLevel != domain.RemediationLevelOfficialFix {
		log.Fatalf("ASSERT FAIL: el histórico debe reflejar la última declaración, tiene %s", historico[0].RemediationLevel)
	}
	if historico[0].AppliedBy != "diego" || historico[0].PatchURL == "" {
		log.Fatalf("ASSERT FAIL: el histórico no conserva autor o URL del parche")
	}
	fmt.Println("    ✓ El histórico refleja la última declaración con todos sus datos")

	// ── 8. Revertir la declaración ─────────────────────────────────────────
	fmt.Println("\n[8/9] Revirtiendo la declaración (UNAVAILABLE)...")
	if _, _, err := orch.DeclarePatchApplied(ctx, installationID, cveID, patchID,
		domain.RemediationLevelUnavailable, time.Time{}, "diego", "Rollback: el parche rompía la app", ""); err != nil {
		log.Fatalf("reversión: %v", err)
	}

	if err := orch.ComputeEndpointRisk(ctx, endpointID); err != nil {
		log.Fatalf("recálculo tras reversión: %v", err)
	}
	riskRevert, tierRevert := leerRiesgoEndpoint(ctx, dbHelper)
	rfRevert, statusRevert := leerFinding(ctx, dbHelper)
	remStatusRevert, remAppliedRevert := leerRemediation(ctx, dbHelper)
	fmt.Printf("    Endpoint   : %.4f (%s)\n", riskRevert, tierRevert)
	fmt.Printf("    Finding    : RF=%.2f  status=%s\n", rfRevert, statusRevert)
	fmt.Printf("    Remediation: status=%s  applied_at=%q\n", remStatusRevert, remAppliedRevert)

	if rfRevert != 1.0 {
		log.Fatalf("ASSERT FAIL: RF tras revertir = %.2f, esperado 1.00", rfRevert)
	}
	if statusRevert != "OPEN" {
		log.Fatalf("ASSERT FAIL: revertir debe reabrir el finding, status=%s", statusRevert)
	}
	if remStatusRevert != domain.RemediationStatusOpen {
		log.Fatalf("ASSERT FAIL: Remediation.status tras revertir = %s, esperado %s", remStatusRevert, domain.RemediationStatusOpen)
	}
	if remAppliedRevert != "" {
		log.Fatalf("ASSERT FAIL: revertir debe limpiar applied_at, quedó %q", remAppliedRevert)
	}
	if riskRevert <= 0 {
		log.Fatalf("ASSERT FAIL: al revertir, el riesgo debe volver a contar (es %.4f)", riskRevert)
	}
	fmt.Println("    ✓ La reversión reabre el finding, limpia applied_at y restaura el riesgo")

	// ── 9. Errores esperados ───────────────────────────────────────────────
	fmt.Println("\n[9/9] Comprobando que los datos inválidos fallan...")

	if _, _, err := orch.DeclarePatchApplied(ctx, fakeInstD, cveID, patchID,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", "", ""); err == nil {
		log.Fatalf("ASSERT FAIL: declarar sobre una instalación inexistente debería fallar")
	}
	fmt.Println("    ✓ Instalación inexistente → error")

	if _, _, err := orch.DeclarePatchApplied(ctx, installationID, cveID, 999999,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", "", ""); err == nil {
		log.Fatalf("ASSERT FAIL: declarar un parche inexistente debería fallar")
	}
	fmt.Println("    ✓ Parche inexistente → error")

	if _, _, err := orch.DeclarePatchApplied(ctx, installationID, cveID, patchID,
		domain.RemediationLevel("NIVEL_INVENTADO"), time.Time{}, "diego", "", ""); err == nil {
		log.Fatalf("ASSERT FAIL: un nivel no reconocido debería fallar")
	}
	fmt.Println("    ✓ Nivel de remediación inválido → error")

	fmt.Println("\n✓ PRUEBA ISSUE #2 COMPLETADA")
}

func leerRiesgoEndpoint(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}) (float64, string) {
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

func leerFinding(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}) (float64, string) {
	res, err := db.ExecuteRead(ctx,
		`MATCH (f:Finding {id: $id}) RETURN f.remediation_factor AS rf, f.status AS st`,
		map[string]any{"id": findingID})
	if err != nil {
		log.Fatalf("lectura finding: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		rf, _ := m["rf"].(float64)
		st, _ := m["st"].(string)
		return rf, st
	}
	return 0, ""
}

// leerRemediation devuelve el estado y la fecha de aplicación de la remediación.
// La fecha se devuelve como cadena vacía cuando es nula, para poder comprobar que
// revertir la limpia.
func leerRemediation(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}) (string, string) {
	res, err := db.ExecuteRead(ctx,
		`MATCH (rem:Remediation {id: $id}) RETURN rem.status AS st, rem.applied_at AS ap`,
		map[string]any{"id": remediationID})
	if err != nil {
		log.Fatalf("lectura remediation: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		st, _ := m["st"].(string)
		applied := ""
		if t, ok := m["ap"].(time.Time); ok {
			applied = t.Format("2006-01-02 15:04")
		}
		return st, applied
	}
	return "", ""
}

func leerRiskScoreFinding(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}) float64 {
	res, err := db.ExecuteRead(ctx,
		`MATCH (f:Finding {id: $id}) RETURN f.risk_score AS s`,
		map[string]any{"id": findingID})
	if err != nil {
		log.Fatalf("lectura risk_score: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		s, _ := m["s"].(float64)
		return s
	}
	return 0
}

func contarAristas(ctx context.Context, db interface {
	ExecuteRead(context.Context, string, map[string]any) (any, error)
}) int64 {
	res, err := db.ExecuteRead(ctx,
		`MATCH (:Patch)-[rel:APPLIED_TO]->(:SoftwareInstallation {id: $id}) RETURN count(rel) AS n`,
		map[string]any{"id": installationID})
	if err != nil {
		log.Fatalf("conteo aristas: %v", err)
	}
	if m, ok := res.(map[string]any); ok {
		n, _ := m["n"].(int64)
		return n
	}
	return 0
}
