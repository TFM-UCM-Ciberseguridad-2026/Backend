package main

// Prueba E2E de la issue #4: prioridad de parcheo según la criticidad del activo.
//
// Tres endpoints con el MISMO CVE (Log4Shell) y distinta criticidad. Como el riesgo
// técnico es parecido, lo que debe ordenar la cola es el activo: producción con CIA
// alta y expuesto a Internet por delante del puesto de trabajo aislado.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_cola_parcheo

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
	projectID = int64(9801)
	cveID     = "CVE-2021-44228"
	cvssVec   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
)

// Tres activos de criticidad decreciente con el mismo CVE.
var activos = []struct {
	endpointID  int64
	hostname    string
	etiqueta    string
	tipo        string    // rol técnico: de él se deriva la categoría que fija el SLA
	cia         [3]string // CR, IR, AR
	internet    bool
	environment string
	softwareID  int64
	instID      string
	findingID   int64
	remID       int64
}{
	{9802, "db-prod", "BBDD producción, expuesta", domain.EndpointTypeServer,
		[3]string{"High", "High", "High"}, true, "prod",
		9810, "inst-cola-prod", 9820, 9830},
	{9803, "app-staging", "App staging, interna", domain.EndpointTypeServer,
		[3]string{"Medium", "Medium", "Medium"}, false, "staging",
		9811, "inst-cola-staging", 9821, 9831},
	{9804, "workstation", "Puesto de trabajo", domain.EndpointTypeWorkstation,
		[3]string{"Low", "Low", "Low"}, false, "dev",
		9812, "inst-cola-work", 9822, 9832},
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  PRUEBA ISSUE #4 – COLA DE PARCHEO POR CRITICIDAD DE ACTIVO  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

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

	// ── 1. Limpieza ────────────────────────────────────────────────────────
	fmt.Println("\n[1/5] Limpiando datos previos...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": projectID})
	for _, a := range activos {
		for _, id := range []int64{a.endpointID, a.softwareID, a.findingID, a.remID} {
			_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
		}
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": a.instID})
	}
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (v:Vulnerability {cve_id: $c}) DETACH DELETE v`, map[string]any{"c": cveID})
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Escenario ───────────────────────────────────────────────────────
	fmt.Println("\n[2/5] Creando 3 activos con el mismo CVE y distinta criticidad...")
	now := time.Now().UTC()

	if err := orch.CreateProject(ctx, &domain.Project{ProjectID: projectID, Nombre: "Cola de parcheo"}); err != nil {
		log.Fatalf("proyecto: %v", err)
	}

	for _, a := range activos {
		ep := &domain.Endpoint{
			EndpointID: a.endpointID, Hostname: a.hostname, Type: a.tipo, Status: "ACTIVE",
			InternetExposed: a.internet, Environment: a.environment,
			ConfidentialityReq: a.cia[0], IntegrityReq: a.cia[1], AvailabilityReq: a.cia[2],
		}
		if err := orch.AddEndpointToProject(ctx, projectID, ep); err != nil {
			log.Fatalf("endpoint %s: %v", a.hostname, err)
		}

		sw := &domain.Software{SoftwareID: a.softwareID, Name: "log4j-core", Version: "2.14.1", Vendor: "apache", Type: "application"}
		inst := &domain.SoftwareInstallation{InstallationID: a.instID, FirstSeen: now, Status: "INSTALLED"}
		if err := orch.RegisterSoftwareInstallation(ctx, a.endpointID, sw, inst); err != nil {
			log.Fatalf("instalación %s: %v", a.instID, err)
		}

		f := &domain.Finding{FindingID: a.findingID, Status: "OPEN", FirstSeen: now, RemediationFactor: 1.0}
		if err := orch.GenerateFinding(ctx, a.instID, f); err != nil {
			log.Fatalf("finding %d: %v", a.findingID, err)
		}

		v := &domain.Vulnerability{VulnerabilityID: cveID, CVEID: cveID, CVSSVector: cvssVec, BaseScore: 10.0}
		rem := &domain.Remediation{RemediationID: a.remID, Status: "OPEN"}
		if err := orch.AssociateVulnerabilitiesAndRemediations(ctx, a.findingID, v, rem); err != nil {
			log.Fatalf("vuln de %d: %v", a.findingID, err)
		}

		fmt.Printf("    · %-12s %s\n", a.hostname, a.etiqueta)
	}

	// ── 3. Calcular ────────────────────────────────────────────────────────
	fmt.Println("\n[3/5] Calculando el riesgo de los tres endpoints...")
	for _, a := range activos {
		if err := orch.ComputeEndpointRisk(ctx, a.endpointID); err != nil {
			log.Fatalf("riesgo %s: %v", a.hostname, err)
		}
	}
	fmt.Println("    ✓ Cálculo completado.")

	// ── 4. Cola de parcheo ─────────────────────────────────────────────────
	fmt.Println("\n[4/5] Consultando la cola de parcheo del proyecto...")
	pid := projectID
	cola, err := orch.GetPatchQueue(ctx, &pid, 20)
	if err != nil {
		log.Fatalf("cola: %v", err)
	}

	fmt.Println()
	fmt.Println("  #  Host          Entorno   Riesgo   Crit.   Urg.   Prioridad  Tier      Parche")
	fmt.Println("  ─  ────────────  ────────  ──────  ──────  ─────  ─────────  ────────  ──────")
	for _, it := range cola {
		parche := "no"
		if it.PatchAvailable {
			parche = "sí"
		}
		fmt.Printf("  %d  %-12s  %-8s  %.4f  %.2f    %.2f   %.4f     %-8s  %s\n",
			it.Position, it.Hostname, it.Environment, it.RiskScore,
			it.AssetCriticality, it.UrgencyBoost, it.PriorityScore, it.PriorityTier, parche)
	}

	// ── 5. Aserciones ──────────────────────────────────────────────────────
	fmt.Println("\n[5/5] Validando...")

	if len(cola) != 3 {
		log.Fatalf("ASSERT FAIL: se esperaban 3 entradas, hay %d", len(cola))
	}
	fmt.Println("    ✓ La cola devuelve los 3 findings pendientes")

	// El orden lo debe marcar la criticidad del activo, no el riesgo técnico.
	esperado := []string{"db-prod", "app-staging", "workstation"}
	for i, host := range esperado {
		if cola[i].Hostname != host {
			log.Fatalf("ASSERT FAIL: posición %d = %s, esperado %s", i+1, cola[i].Hostname, host)
		}
	}
	fmt.Println("    ✓ Ordena por criticidad del activo: db-prod > app-staging > workstation")

	// Lo importante de la issue: las prioridades tienen que ser distinguibles.
	if cola[0].PriorityScore == cola[1].PriorityScore || cola[1].PriorityScore == cola[2].PriorityScore {
		log.Fatalf("ASSERT FAIL: prioridades empatadas (%.4f, %.4f, %.4f): la cola no ordena",
			cola[0].PriorityScore, cola[1].PriorityScore, cola[2].PriorityScore)
	}
	fmt.Println("    ✓ Las tres prioridades son distintas (sin saturación en 1.0)")

	for _, it := range cola {
		if it.PriorityScore <= 0 || it.PriorityScore > 1 {
			log.Fatalf("ASSERT FAIL: prioridad fuera de [0,1]: %.4f", it.PriorityScore)
		}
		if it.PriorityTier == "" {
			log.Fatalf("ASSERT FAIL: %s sin priority_tier", it.Hostname)
		}
		if it.CVEID != cveID || it.SoftwareName == "" || it.EndpointID == 0 {
			log.Fatalf("ASSERT FAIL: entrada incompleta: %+v", it)
		}
	}
	fmt.Println("    ✓ Todas las entradas están acotadas en [0,1] y completas")

	// La criticidad debe reflejar el perfil del activo
	if cola[0].AssetCriticality <= cola[2].AssetCriticality {
		log.Fatalf("ASSERT FAIL: criticidad prod %.2f no supera a la del puesto %.2f",
			cola[0].AssetCriticality, cola[2].AssetCriticality)
	}
	fmt.Printf("    ✓ Criticidad del activo: %.2f (prod) frente a %.2f (puesto)\n",
		cola[0].AssetCriticality, cola[2].AssetCriticality)

	// Sin filtro de proyecto debe devolver al menos lo mismo
	global, err := orch.GetPatchQueue(ctx, nil, 100)
	if err != nil {
		log.Fatalf("cola global: %v", err)
	}
	if len(global) < len(cola) {
		log.Fatalf("ASSERT FAIL: la cola global (%d) no puede tener menos que la del proyecto (%d)", len(global), len(cola))
	}
	fmt.Printf("    ✓ Sin filtro devuelve toda la infraestructura (%d entradas)\n", len(global))

	// El límite se respeta
	limitada, err := orch.GetPatchQueue(ctx, &pid, 2)
	if err != nil {
		log.Fatalf("cola limitada: %v", err)
	}
	if len(limitada) != 2 {
		log.Fatalf("ASSERT FAIL: limit=2 devolvió %d entradas", len(limitada))
	}
	fmt.Println("    ✓ El límite se respeta")

	// Un finding parcheado sale de la cola
	if err := orch.RegisterPatchesForVulnerability(ctx, cveID, []domain.Patch{
		{Description: "Log4j 2.17.1", URL: "https://logging.apache.org/log4j/2.x/security.html#cola-test"},
	}); err != nil {
		log.Fatalf("parche: %v", err)
	}
	parches, _ := orch.GetPatchesForVulnerability(ctx, cveID)
	if _, _, err := orch.DeclarePatchApplied(ctx, activos[0].instID, cveID, parches[0].PatchID,
		domain.RemediationLevelOfficialFix, time.Time{}, "diego", ""); err != nil {
		log.Fatalf("declaración: %v", err)
	}

	trasParche, err := orch.GetPatchQueue(ctx, &pid, 20)
	if err != nil {
		log.Fatalf("cola tras parche: %v", err)
	}
	if len(trasParche) != 2 {
		log.Fatalf("ASSERT FAIL: tras parchear db-prod la cola debería tener 2, tiene %d", len(trasParche))
	}
	if trasParche[0].Hostname != "app-staging" {
		log.Fatalf("ASSERT FAIL: tras parchear, el primero debería ser app-staging, es %s", trasParche[0].Hostname)
	}
	fmt.Println("    ✓ Al declarar el parche, db-prod sale de la cola y sube app-staging")

	fmt.Println("\n✓ PRUEBA ISSUE #4 COMPLETADA")
}
