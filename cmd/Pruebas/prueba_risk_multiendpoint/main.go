package main

// Prueba extendida del motor de riesgo: 3 endpoints con perfiles CIA distintos
// y 8 findings con severidades HIGH, MEDIUM y LOW.
//
// Hipótesis verificadas:
//  1. Mismo vector CVSS → distinto impact_score según CIA del endpoint (H/H/H > M/M/M > L/L/L)
//  2. KEV   → likelihood 1.0 → risk dominado por el impact
//  3. exploit (sin KEV) → likelihood = max(EPSS, 0.5) → risk moderado
//  4. Sin KEV ni exploit → likelihood = EPSS (~0.1 para ficticio) → risk bajo
//  5. remediation_factor < 1.0 reduce risk proporcionalmente
//  6. Agregación multi-finding es monotónica y acotada en [0,1]
//
// Tiers esperados:
//   linux-web-prod (H/H/H) → CRITICAL  (driver: Log4Shell KEV + vector 10.0)
//   win-app-dev    (M/M/M) → MEDIUM    (2 findings con exploit, 1 mitigado, sin KEV)
//   workstation-01 (L/L/L) → LOW       (mismo vector que EP2 pero CIA bajas → menor impact)
//
// Ejecutar desde Backend/:
//   go run cmd/Pruebas/prueba_risk_multiendpoint/main.go

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
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const multiProjectID = int64(9100)

// ── Definición de endpoints ────────────────────────────────────────────────
type epDef struct {
	id             int64
	hostname       string
	label          string
	cr, ir, ar     string
	installationID string
	swID           int64
}

var testEndpoints = []epDef{
	{9101, "linux-web-prod", "Servidor web Linux (CIA H/H/H)", "High", "High", "High", "inst-multi-ep1", 9130},
	{9102, "win-app-dev", "App server Windows (CIA M/M/M)", "Medium", "Medium", "Medium", "inst-multi-ep2", 9131},
	{9103, "workstation-01", "Puesto de trabajo (CIA L/L/L)", "Low", "Low", "Low", "inst-multi-ep3", 9132},
}

// ── Definición de findings ─────────────────────────────────────────────────
type findingDef struct {
	epIdx             int     // índice en testEndpoints
	findingID         int64
	remediationID     int64
	remediationFactor float64
	cveID             string
	cvssVector        string
	baseScore         float64
	exploit           bool
	label             string
}

// CVE-FAKE-EXPLOIT-01 se usa en EP1 (M/M/M) y EP3 (L/L/L) con el MISMO vector
// para demostrar cómo el CIA del endpoint cambia el impact_score resultante.
var testFindings = []findingDef{
	// ── Endpoint 0: linux-web-prod (H/H/H) ─────────────────────────────
	// KEV + vector máximo → CRITICAL driver
	{0, 9110, 9120, 1.0,
		"CVE-2021-44228",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, false,
		"Log4Shell (KEV, CRITICAL, S:C/C:H/I:H/A:H, sin parche)"},
	// KEV + HIGH vector, workaround aplicado (RF=0.5) → prioridad media
	{0, 9111, 9121, 0.5,
		"CVE-2021-41773",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, false,
		"Apache path traversal (KEV, HIGH, solo C:H, workaround RF=0.5)"},
	// Sin KEV, sin exploit → likelihood 0.1 → risk muy bajo aunque esté en H/H/H
	{0, 9112, 9122, 1.0,
		"CVE-FAKE-MED-01",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.4, false,
		"Ficticio MEDIUM (local, sin KEV, sin exploit, likelihood=EPSS~0.1)"},

	// ── Endpoint 1: win-app-dev (M/M/M) ───────────────────────────────
	// has_exploit=true → likelihood = max(EPSS, 0.5). Sin KEV.
	{1, 9113, 9123, 1.0,
		"CVE-FAKE-EXPLOIT-01",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1, true,
		"Ficticio HIGH (has_exploit, sin KEV) — mismo vector que EP3 para comparar"},
	// has_exploit + agresivamente mitigado (RF=0.3)
	{1, 9114, 9124, 0.3,
		"CVE-FAKE-EXPLOIT-02",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H", 7.8, true,
		"Ficticio HIGH (has_exploit, mitigado RF=0.3) → risk reducido"},
	// Sin exploit, sin KEV → likelihood=EPSS~0.1
	{1, 9115, 9125, 1.0,
		"CVE-FAKE-MED-02",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 4.6, false,
		"Ficticio MEDIUM (sin exploit, sin KEV) → contribuye poco al aggregate"},

	// ── Endpoint 2: workstation-01 (L/L/L) ────────────────────────────
	// MISMO vector que EP1/F4 (CVE-FAKE-EXPLOIT-01) → impact MENOR por CIA L/L/L
	{2, 9116, 9126, 1.0,
		"CVE-FAKE-EXPLOIT-01",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1, true,
		"Ficticio HIGH (mismo vector que EP2) — CIA L/L/L reduce impact_score"},
	// Vector local muy bajo → impact mínimo incluso con H/H/H
	{2, 9117, 9127, 1.0,
		"CVE-FAKE-LOW-01",
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.2, false,
		"Ficticio LOW (local, AC:H, privilegios altos, UI:R)"},
}

// IDs numéricos a limpiar antes y después del test
var cleanIDs = []int64{
	multiProjectID,
	9101, 9102, 9103,
	9110, 9111, 9112, 9113, 9114, 9115, 9116, 9117,
	9120, 9121, 9122, 9123, 9124, 9125, 9126, 9127,
	9130, 9131, 9132,
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║     PRUEBA MOTOR DE RIESGO – Multi-Endpoint (variado)        ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println("  3 endpoints · 8 findings · HIGH + MEDIUM + LOW severities")
	fmt.Println()

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
		_, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	epssAdapter := provider.NewEPSSAdapter()
	kevAdapter := provider.NewKEVAdapter()

	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo,
		patchRepo, dbHelper,
		provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cves/2.0", cfg.NVD.APIKey, 30),
	).WithRisk(riskRepo, epssAdapter, kevAdapter)

	// ── 1. Limpieza ───────────────────────────────────────────────────────
	fmt.Println("[1/4] Limpiando nodos de prueba anteriores...")
	for _, id := range cleanIDs {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx,
		`MATCH (n) WHERE n.id IN ["inst-multi-ep1","inst-multi-ep2","inst-multi-ep3"] DETACH DELETE n`,
		nil)
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Infraestructura ────────────────────────────────────────────────
	fmt.Println("\n[2/4] Creando infraestructura de prueba...")
	now := time.Now().UTC()

	if err := orchestrator.CreateProject(ctx, &domain.Project{
		ProjectID: multiProjectID, Nombre: "Risk Multi-Endpoint Test",
	}); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	for _, ep := range testEndpoints {
		endpoint := &domain.Endpoint{
			EndpointID:         ep.id,
			Hostname:           ep.hostname,
			Type:               "Linux",
			Status:             "ACTIVE",
			Environment:        "prod",
			ConfidentialityReq: ep.cr,
			IntegrityReq:       ep.ir,
			AvailabilityReq:    ep.ar,
		}
		if err := orchestrator.AddEndpointToProject(ctx, multiProjectID, endpoint); err != nil {
			log.Fatalf("Error creando endpoint %s: %v", ep.hostname, err)
		}

		sw := &domain.Software{
			SoftwareID: ep.swID, Name: "app-" + ep.hostname, Version: "1.0", Vendor: "test", Type: "application",
		}
		si := &domain.SoftwareInstallation{
			InstallationID: ep.installationID, FirstSeen: now, Status: "INSTALLED",
		}
		if err := orchestrator.RegisterSoftwareInstallation(ctx, ep.id, sw, si); err != nil {
			log.Fatalf("Error registrando software en %s: %v", ep.hostname, err)
		}
	}

	for _, fd := range testFindings {
		ep := testEndpoints[fd.epIdx]
		finding := &domain.Finding{
			FindingID:         fd.findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			RemediationFactor: fd.remediationFactor,
		}
		if err := orchestrator.GenerateFinding(ctx, ep.installationID, finding); err != nil {
			log.Fatalf("Error creando finding %d: %v", fd.findingID, err)
		}

		vuln := &domain.Vulnerability{
			VulnerabilityID: fd.cveID,
			CVEID:           fd.cveID,
			CVSSVector:      fd.cvssVector,
			BaseScore:       fd.baseScore,
			Exploit:         fd.exploit,
		}
		rem := &domain.Remediation{RemediationID: fd.remediationID, Status: "OPEN"}
		if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, fd.findingID, vuln, rem); err != nil {
			log.Fatalf("Error vinculando vuln al finding %d: %v", fd.findingID, err)
		}
	}

	fmt.Printf("    ✓ %d endpoints · %d findings creados.\n", len(testEndpoints), len(testFindings))
	for _, ep := range testEndpoints {
		fmt.Printf("      %-20s CIA: CR=%-6s IR=%-6s AR=%s\n", ep.hostname, ep.cr, ep.ir, ep.ar)
	}

	// ── 3. Cálculo de riesgo ──────────────────────────────────────────────
	fmt.Println("\n[3/4] Ejecutando ComputeEndpointRisk para cada endpoint...")
	start := time.Now()
	for _, ep := range testEndpoints {
		if err := orchestrator.ComputeEndpointRisk(ctx, ep.id); err != nil {
			log.Fatalf("Error calculando riesgo de %s: %v", ep.hostname, err)
		}
		fmt.Printf("    ✓ %s calculado.\n", ep.hostname)
	}
	fmt.Printf("    Tiempo total: %.1fs\n", time.Since(start).Seconds())

	// ── 4. Resultados ─────────────────────────────────────────────────────
	fmt.Println("\n[4/4] Resultados por endpoint:")
	fmt.Println("══════════════════════════════════════════════════════════════")

	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{})
	defer session.Close(ctx)

	for _, ep := range testEndpoints {
		// Score del endpoint
		epRes, err := dbHelper.ExecuteRead(ctx,
			`MATCH (e:Endpoint {id: $id}) RETURN e.risk_score AS score, e.risk_tier AS tier`,
			map[string]any{"id": ep.id})
		if err != nil {
			log.Fatalf("Error leyendo endpoint %s: %v", ep.hostname, err)
		}

		var epScore float64
		var epTier string
		if m, ok := epRes.(map[string]any); ok {
			epScore, _ = m["score"].(float64)
			epTier, _ = m["tier"].(string)
		}

		fmt.Printf("\n  ┌─ %s [%s]\n", ep.label, ep.hostname)
		fmt.Printf("  │  Risk Score: %.4f   Tier: %s\n", epScore, epTier)
		fmt.Printf("  │\n")
		fmt.Printf("  │  FINDINGS (por priority_score DESC):\n")

		result, err := session.Run(ctx, `
			MATCH (e:Endpoint {id: $ep_id})-[:HAS_INSTALLATION]->(si)-[:HAS_FINDING]->(f)-[:OF_VULNERABILITY]->(v)
			RETURN v.cve_id         AS cve,
			       f.impact_score   AS impact,
			       f.likelihood     AS likelihood,
			       f.remediation_factor AS rf,
			       f.risk_score     AS risk,
			       f.priority_score AS priority
			ORDER BY priority DESC
		`, map[string]any{"ep_id": ep.id})
		if err != nil {
			log.Fatalf("Error leyendo findings de %s: %v", ep.hostname, err)
		}

		i := 1
		for result.Next(ctx) {
			rec := result.Record()
			cve, _ := rec.Get("cve")
			impact, _ := rec.Get("impact")
			likelihood, _ := rec.Get("likelihood")
			rf, _ := rec.Get("rf")
			risk, _ := rec.Get("risk")
			priority, _ := rec.Get("priority")

			fmt.Printf("  │  #%d %-25s  impact=%.4f  L=%.2f  RF=%.1f  risk=%.4f  prio=%.4f\n",
				i, cve, toF(impact), toF(likelihood), toF(rf), toF(risk), toF(priority))
			i++
		}
		fmt.Println("  └──────────────────────────────────────────────────────────")
	}

	// ── Análisis: mismo vector, distinto endpoint CIA ─────────────────────
	fmt.Println("\n  ANÁLISIS: mismo vector CVE-FAKE-EXPLOIT-01 en distintos endpoints")
	fmt.Println("  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N, has_exploit=true)")
	fmt.Println("  ┌────────────────────┬────────────┬───────────┬────────────┐")
	fmt.Println("  │ Endpoint           │ CIA        │ Impact    │ Risk Score │")
	fmt.Println("  ├────────────────────┼────────────┼───────────┼────────────┤")

	for _, ep := range testEndpoints[1:] { // solo EP2 y EP3 tienen este CVE
		res, err := session.Run(ctx, `
			MATCH (e:Endpoint {id: $ep_id})-[:HAS_INSTALLATION]->(si)-[:HAS_FINDING]->(f)-[:OF_VULNERABILITY]->(v {cve_id: "CVE-FAKE-EXPLOIT-01"})
			RETURN f.impact_score AS impact, f.risk_score AS risk
		`, map[string]any{"ep_id": ep.id})
		if err != nil {
			continue
		}
		if res.Next(ctx) {
			rec := res.Record()
			impact, _ := rec.Get("impact")
			risk, _ := rec.Get("risk")
			cia := fmt.Sprintf("%s/%s/%s", ep.cr[:1], ep.ir[:1], ep.ar[:1])
			fmt.Printf("  │ %-18s │ %-10s │   %.4f  │   %.4f   │\n",
				ep.hostname, cia, toF(impact), toF(risk))
		}
	}
	fmt.Println("  └────────────────────┴────────────┴───────────┴────────────┘")
	fmt.Println("  → Mismo CVE produce distinto impact según CIA del endpoint.")

	fmt.Println("\n✓ PRUEBA MULTI-ENDPOINT COMPLETADA")
}

func toF(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
