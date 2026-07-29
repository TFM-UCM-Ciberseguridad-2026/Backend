package main

// Prueba E2E con CVEs REALES — vectores CVSS del NVD, EPSS de api.first.org, KEV de CISA.
// No hay CVEs ficticios: todo el pipeline calcula con datos reales de las APIs públicas.
//
// CVEs seleccionados (6 CVEs con distintas severidades):
//   CVE-2021-44228  Log4Shell             base=10.0  CRITICAL  (esperar KEV=true,  EPSS≈0.97)
//   CVE-2021-34527  PrintNightmare        base= 8.8  HIGH      (esperar KEV=true,  EPSS≈0.96)
//   CVE-2022-30190  Follina/MSDT          base= 7.8  HIGH      (esperar KEV=true,  EPSS≈0.68)
//   CVE-2021-41773  Apache path traversal base= 7.5  HIGH      (esperar KEV=true,  EPSS≈0.97)
//   CVE-2022-0778   OpenSSL infinite loop base= 7.5  HIGH      (esperar KEV=false, EPSS bajo)
//   CVE-2022-21449  Java ECDSA bypass     base= 7.5  HIGH      (esperar KEV=false, EPSS bajo)
//
// 3 endpoints con perfiles CIA distintos:
//   db-prod-real     (CIA H/H/H) — BBDD crítica de producción
//   web-staging-real (CIA M/H/M) — servidor web staging
//   workstation-real (CIA L/L/L) — puesto de trabajo
//
// CVE-2021-44228 y CVE-2022-30190 aparecen en EP1 y EP3 → comparación CIA.
//
// Ejecutar desde Backend/:
//   go run cmd/Pruebas/prueba_risk_real_cves/main.go

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const realProjectID = int64(9200)

// ── CVEs reales con vectores CVSS 3.1 oficiales del NVD ────────────────────
// Los vectores se obtienen de https://nvd.nist.gov/vuln/detail/<CVE-ID>
type cveInfo struct {
	id         string
	name       string
	cvssVector string
	baseScore  float64
}

var realCVEs = map[string]cveInfo{
	"CVE-2021-44228": {
		"CVE-2021-44228", "Log4Shell (Apache Log4j2 RCE)",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0,
	},
	"CVE-2021-34527": {
		"CVE-2021-34527", "PrintNightmare (Windows Print Spooler RCE)",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8,
	},
	"CVE-2022-30190": {
		"CVE-2022-30190", "Follina (MSDT RCE via Office)",
		"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8,
	},
	"CVE-2021-41773": {
		"CVE-2021-41773", "Apache HTTP Server path traversal/RCE",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5,
	},
	"CVE-2022-0778": {
		"CVE-2022-0778", "OpenSSL infinite loop (DoS en BN_mod_sqrt)",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5,
	},
	"CVE-2022-21449": {
		"CVE-2022-21449", "Psychic Signatures (Java ECDSA bypass)",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.5,
	},
}

// ── Definición de endpoints ────────────────────────────────────────────────
type epDef struct {
	id             int64
	hostname       string
	label          string
	cr, ir, ar     string
	installationID string
	swID           int64
}

var endpoints = []epDef{
	{9201, "db-prod-real", "BBDD producción (CIA H/H/H)", "High", "High", "High", "inst-real-ep1", 9210},
	{9202, "web-staging-real", "Servidor web staging (CIA M/H/M)", "Medium", "High", "Medium", "inst-real-ep2", 9211},
	{9203, "workstation-real", "Puesto de trabajo (CIA L/L/L)", "Low", "Low", "Low", "inst-real-ep3", 9212},
}

// ── Definición de findings (CVEs reales, RF distintos) ─────────────────────
type findingDef struct {
	epIdx             int
	findingID         int64
	remediationID     int64
	remediationFactor float64
	cveID             string
	label             string // nota sobre el escenario
}

var findings = []findingDef{
	// Endpoint 0: db-prod-real (H/H/H) — servidor crítico sin mantenimiento al día
	{0, 9220, 9230, 1.0, "CVE-2021-44228", "Log4Shell sin parche"},
	{0, 9221, 9231, 0.6, "CVE-2021-34527", "PrintNightmare con workaround parcial (RF=0.6)"},
	{0, 9222, 9232, 1.0, "CVE-2022-30190", "Follina sin parche"},

	// Endpoint 1: web-staging-real (M/H/M) — staging, parcheo moderado
	{1, 9223, 9233, 1.0, "CVE-2021-41773", "Apache path traversal sin parche"},
	{1, 9224, 9234, 0.3, "CVE-2022-21449", "Java ECDSA bypass casi parchado (RF=0.3)"},
	{1, 9225, 9235, 1.0, "CVE-2022-0778", "OpenSSL DoS sin parche"},

	// Endpoint 2: workstation-real (L/L/L) — mismo CVE-2021-44228 y CVE-2022-30190 que EP1
	// Permite comparar: mismo CVE, distinto CIA → distinto impact_score
	{2, 9226, 9236, 1.0, "CVE-2021-44228", "Log4Shell en workstation (CIA L/L/L vs H/H/H)"},
	{2, 9227, 9237, 1.0, "CVE-2022-30190", "Follina en workstation (CIA L/L/L vs H/H/H)"},
}

var cleanIDs = []int64{
	realProjectID,
	9201, 9202, 9203,
	9210, 9211, 9212,
	9220, 9221, 9222, 9223, 9224, 9225, 9226, 9227,
	9230, 9231, 9232, 9233, 9234, 9235, 9236, 9237,
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║         PRUEBA MOTOR DE RIESGO – CVEs REALES (E2E)              ║")
	fmt.Println("║  NVD vectors · EPSS api.first.org · CISA KEV catalog            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	// Timeout generoso: EPSS + KEV + Neo4j
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo,
		_, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo , _ := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	epssAdapter := provider.NewEPSSAdapter()
	kevAdapter := provider.NewKEVAdapter()

	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo,
		nil, // containerRepo
		patchRepo, dbHelper,
		provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cves/2.0", cfg.NVD.APIKey, 30),
	).WithRisk(riskRepo, epssAdapter, kevAdapter)

	// ── 1. Limpieza ───────────────────────────────────────────────────────
	fmt.Println("\n[1/5] Limpiando nodos de prueba anteriores...")
	for _, id := range cleanIDs {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx,
		`MATCH (n) WHERE n.id IN ["inst-real-ep1","inst-real-ep2","inst-real-ep3"] DETACH DELETE n`,
		nil)
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Datos de inteligencia: EPSS + KEV ─────────────────────────────
	fmt.Println("\n[2/5] Obteniendo datos reales de EPSS (api.first.org) y KEV (CISA)...")
	allCVEIDs := make([]string, 0, len(realCVEs))
	for id := range realCVEs {
		allCVEIDs = append(allCVEIDs, id)
	}
	sort.Strings(allCVEIDs) // orden determinista en output

	epssStart := time.Now()
	epssScores, err := epssAdapter.FetchEPSS(ctx, allCVEIDs)
	if err != nil {
		log.Fatalf("Error obteniendo EPSS: %v", err)
	}
	fmt.Printf("    ✓ EPSS obtenido en %.1fs\n", time.Since(epssStart).Seconds())

	kevStart := time.Now()
	kevCatalog, err := kevAdapter.FetchKEV(ctx)
	if err != nil {
		log.Fatalf("Error obteniendo KEV: %v", err)
	}
	fmt.Printf("    ✓ KEV obtenido en %.1fs (%d vulnerabilidades en catálogo)\n",
		time.Since(kevStart).Seconds(), len(kevCatalog))

	fmt.Println()
	fmt.Println("    ┌─────────────────────┬────────────┬──────────┬──────────────────────────────────────┐")
	fmt.Println("    │ CVE                 │ Base Score │   EPSS   │ Nombre                               │")
	fmt.Println("    ├─────────────────────┼────────────┼──────────┼──────────────────────────────────────┤")
	for _, id := range allCVEIDs {
		cve := realCVEs[id]
		epss := epssScores[id]
		kev := kevCatalog[id]
		kevStr := "       "
		if kev {
			kevStr = "KEV ✓  "
		}
		fmt.Printf("    │ %-19s │  %4.1f %s │  %.4f  │ %-36s │\n",
			id, cve.baseScore, kevStr, epss, truncate(cve.name, 36))
	}
	fmt.Println("    └─────────────────────┴────────────┴──────────┴──────────────────────────────────────┘")

	// ── 3. Crear infraestructura de prueba ────────────────────────────────
	fmt.Println("\n[3/5] Creando infraestructura de prueba en Neo4j...")
	now := time.Now().UTC()

	if err := orchestrator.CreateProject(ctx, &domain.Project{
		ProjectID: realProjectID, Nombre: "Risk Real CVEs Test",
	}); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	for _, ep := range endpoints {
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
		if err := orchestrator.AddEndpointToProject(ctx, realProjectID, endpoint); err != nil {
			log.Fatalf("Error creando endpoint %s: %v", ep.hostname, err)
		}
		sw := &domain.Software{
			SoftwareID: ep.swID, Name: "sw-" + ep.hostname, Version: "1.0",
			Vendor: "test", Type: "application",
		}
		si := &domain.SoftwareInstallation{
			InstallationID: ep.installationID, FirstSeen: now, Status: "INSTALLED",
		}
		if err := orchestrator.RegisterSoftwareInstallation(ctx, ep.id, sw, si); err != nil {
			log.Fatalf("Error registrando software en %s: %v", ep.hostname, err)
		}
	}

	for _, fd := range findings {
		ep := endpoints[fd.epIdx]
		cve := realCVEs[fd.cveID]

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
			VulnerabilityID: cve.id,
			CVEID:           cve.id,
			CVSSVector:      cve.cvssVector,
			BaseScore:       cve.baseScore,
		}
		rem := &domain.Remediation{RemediationID: fd.remediationID, Status: "OPEN"}
		if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, fd.findingID, vuln, rem); err != nil {
			log.Fatalf("Error vinculando CVE %s al finding %d: %v", fd.cveID, fd.findingID, err)
		}
	}

	fmt.Printf("    ✓ %d endpoints · %d findings registrados en Neo4j.\n",
		len(endpoints), len(findings))

	// ── 4. Motor de riesgo ────────────────────────────────────────────────
	fmt.Println("\n[4/5] Ejecutando ComputeEndpointRisk (EPSS+KEV+cálculo+persistencia)...")
	calcStart := time.Now()
	for _, ep := range endpoints {
		if err := orchestrator.ComputeEndpointRisk(ctx, ep.id); err != nil {
			log.Fatalf("Error calculando riesgo de %s: %v", ep.hostname, err)
		}
		fmt.Printf("    ✓ %s calculado.\n", ep.hostname)
	}
	fmt.Printf("    Tiempo total cálculo: %.1fs\n", time.Since(calcStart).Seconds())

	// ── 5. Resultados ─────────────────────────────────────────────────────
	fmt.Println("\n[5/5] Resultados:")
	fmt.Println("══════════════════════════════════════════════════════════════════")

	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{})
	defer session.Close(ctx)

	for _, ep := range endpoints {
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

		cia := fmt.Sprintf("CR=%s/IR=%s/AR=%s", ep.cr, ep.ir, ep.ar)
		fmt.Printf("\n  ┌─ %s\n", ep.label)
		fmt.Printf("  │  Endpoint : %s  |  %s\n", ep.hostname, cia)
		fmt.Printf("  │  Risk Score: %.4f   →  Tier: %s\n", epScore, epTier)
		fmt.Printf("  │\n")

		result, err := session.Run(ctx, `
			MATCH (e:Endpoint {id: $ep_id})-[:HAS_INSTALLATION]->(si)-[:HAS_FINDING]->(f)-[:OF_VULNERABILITY]->(v)
			RETURN v.cve_id           AS cve,
			       v.base_score       AS base,
			       f.impact_score     AS env_impact,
			       f.likelihood       AS likelihood,
			       f.remediation_factor AS rf,
			       f.risk_score       AS risk,
			       f.priority_score   AS priority
			ORDER BY priority DESC
		`, map[string]any{"ep_id": ep.id})
		if err != nil {
			log.Fatalf("Error leyendo findings de %s: %v", ep.hostname, err)
		}

		fmt.Printf("  │  %-19s  %6s  %10s  %6s  %5s  %8s  %8s\n",
			"CVE", "Base", "Env.Impact", "Likeli.", "RF", "Risk", "Priority")
		fmt.Printf("  │  %-19s  %6s  %10s  %6s  %5s  %8s  %8s\n",
			"───────────────────", "──────", "──────────", "───────", "─────", "────────", "────────")
		for result.Next(ctx) {
			rec := result.Record()
			cve, _ := rec.Get("cve")
			base, _ := rec.Get("base")
			envImpact, _ := rec.Get("env_impact")
			likelihood, _ := rec.Get("likelihood")
			rf, _ := rec.Get("rf")
			risk, _ := rec.Get("risk")
			priority, _ := rec.Get("priority")

			// Marcar si es KEV
			kevMark := "    "
			if id, ok := cve.(string); ok && kevCatalog[id] {
				kevMark = "KEV!"
			}
			fmt.Printf("  │  %-19s  %4.1f    %8.4f  %6.4f  %4.2f  %8.4f  %8.4f  %s\n",
				cve, toF(base), toF(envImpact), toF(likelihood), toF(rf), toF(risk), toF(priority), kevMark)
		}
		fmt.Println("  └──────────────────────────────────────────────────────────────────")
	}

	// ── Comparación CIA: mismo CVE en distinto endpoint ──────────────────
	fmt.Println("\n  COMPARACIÓN: mismo CVE en distintos endpoints (CIA cambia el impact)")
	compareCVEs := []string{"CVE-2021-44228", "CVE-2022-30190"}
	compareEPs := []struct{ id int64; label string }{
		{9201, "db-prod (H/H/H)"},
		{9203, "workstation (L/L/L)"},
	}

	for _, cveID := range compareCVEs {
		cve := realCVEs[cveID]
		fmt.Printf("\n  %s — %s (base=%.1f)\n", cveID, cve.name, cve.baseScore)
		fmt.Printf("  ┌────────────────────────┬──────────┬──────────┬──────────┬──────────┐\n")
		fmt.Printf("  │ Endpoint               │ CIA      │ Env.Imp. │ Likelih. │   Risk   │\n")
		fmt.Printf("  ├────────────────────────┼──────────┼──────────┼──────────┼──────────┤\n")
		for _, ep := range compareEPs {
			res, err := session.Run(ctx, `
				MATCH (e:Endpoint {id: $ep_id})-[:HAS_INSTALLATION]->(si)
				      -[:HAS_FINDING]->(f)-[:OF_VULNERABILITY]->(v {cve_id: $cve})
				MATCH (e2:Endpoint {id: $ep_id})
				RETURN f.impact_score AS impact, f.likelihood AS l, f.risk_score AS risk,
				       e2.confidentiality_req AS cr, e2.integrity_req AS ir, e2.availability_req AS ar
			`, map[string]any{"ep_id": ep.id, "cve": cveID})
			if err != nil || !res.Next(ctx) {
				continue
			}
			rec := res.Record()
			impact, _ := rec.Get("impact")
			l, _ := rec.Get("l")
			risk, _ := rec.Get("risk")
			cr, _ := rec.Get("cr")
			ir, _ := rec.Get("ir")
			ar, _ := rec.Get("ar")
			cia := fmt.Sprintf("%s/%s/%s", firstChar(cr), firstChar(ir), firstChar(ar))
			fmt.Printf("  │ %-22s │ %-8s │  %.4f  │  %.4f  │  %.4f  │\n",
				ep.label, cia, toF(impact), toF(l), toF(risk))
		}
		fmt.Printf("  └────────────────────────┴──────────┴──────────┴──────────┴──────────┘\n")
	}

	fmt.Println("\n✓ PRUEBA COMPLETADA — flujo E2E con CVEs reales verificado.")
}

func toF(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func firstChar(v any) string {
	if s, ok := v.(string); ok && len(s) > 0 {
		return string(s[0])
	}
	return "?"
}
