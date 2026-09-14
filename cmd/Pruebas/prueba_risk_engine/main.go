package main

// Prueba de integración end-to-end del motor de riesgo.
// Inyecta findings con CVEs conocidos (Log4Shell, EternalBlue + uno ficticio),
// ejecuta ComputeEndpointRisk y muestra los scores calculados.
//
// Ejecutar desde Backend/:
//   go run cmd/Pruebas/prueba_risk_engine/main.go

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

const (
	projectID  = int64(9001)
	endpointID = int64(9002)
)

// Findings de prueba: mezcla de CVEs en KEV, con workaround, y ficticio
var testFindings = []struct {
	findingID         int64
	remediationID     int64
	installationID    string
	remediationFactor float64
	cveID             string
	cvssVector        string
	baseScore         float64
	label             string
}{
	{
		findingID: 9010, remediationID: 9020, installationID: "inst-log4j-risk-test",
		remediationFactor: 1.0, // sin parche aplicado
		cveID:             "CVE-2021-44228",
		cvssVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		baseScore:         10.0,
		label:             "Log4Shell (KEV, EPSS≈1.0, sin parche)",
	},
	{
		findingID: 9011, remediationID: 9021, installationID: "inst-log4j-risk-test",
		remediationFactor: 0.4, // workaround parcial aplicado
		cveID:             "CVE-2017-0144",
		cvssVector:        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
		baseScore:         8.1,
		label:             "EternalBlue (KEV, EPSS≈0.99, workaround 0.4)",
	},
	{
		findingID: 9012, remediationID: 9022, installationID: "inst-misc-risk-test",
		remediationFactor: 1.0,              // sin parche
		cveID:             "CVE-2023-12345", // ficticio: no está en KEV ni EPSS → default 0.1
		cvssVector:        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L",
		baseScore:         1.8,
		label:             "CVE ficticio (sin KEV, EPSS default 0.1)",
	},
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║        PRUEBA MOTOR DE RIESGO – End-to-End           ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	// Timeout generoso: NVD no se usa, pero EPSS+KEV necesitan ~5-10s
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo , _ := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	epssAdapter := provider.NewEPSSAdapter()
	kevAdapter := provider.NewKEVAdapter()

	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo, nil, patchRepo, dbHelper,
		provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cves/2.0", cfg.NVD.APIKey, 30),
	).WithRisk(riskRepo, epssAdapter, kevAdapter)

	// ── 1. Limpiar nodos de prueba anteriores ──────────────────────────────────
	fmt.Println("\n[1/4] Limpiando nodos de prueba anteriores...")
	cleanIDs := []int64{projectID, endpointID, 9010, 9011, 9012, 9020, 9021, 9022, 8001, 8002}
	for _, id := range cleanIDs {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx,
		`MATCH (n) WHERE n.id IN ["inst-log4j-risk-test","inst-misc-risk-test"] DETACH DELETE n`,
		nil)
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Crear infraestructura de prueba ─────────────────────────────────────
	fmt.Println("\n[2/4] Creando infraestructura de prueba...")

	now := time.Now().UTC()

	if err := orchestrator.CreateProject(ctx, &domain.Project{ProjectID: projectID, Name: "Risk Engine Test"}); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	// Endpoint: servidor de BBDD con requisitos CIA altos
	ep := &domain.Endpoint{
		EndpointID:         endpointID,
		Hostname:           "db-server-risk-test",
		Type:               "Linux",
		Status:             "ACTIVE",
		InternetExposed:    false,
		Environment:        "prod",
		ConfidentialityReq: "High",
		IntegrityReq:       "Medium",
		AvailabilityReq:    "High",
	}
	if err := orchestrator.AddEndpointToProject(ctx, projectID, ep); err != nil {
		log.Fatalf("Error creando endpoint: %v", err)
	}

	// Dos instalaciones de software en el endpoint
	installations := []struct {
		swID   int64
		instID string
		name   string
	}{
		{8001, "inst-log4j-risk-test", "log4j-core"},
		{8002, "inst-misc-risk-test", "custom-app"},
	}
	for _, inst := range installations {
		sw := &domain.Software{SoftwareID: inst.swID, Name: inst.name, Version: "2.14.1", Vendor: "apache", Type: "application"}
		si := &domain.SoftwareInstallation{InstallationID: inst.instID, FirstSeen: now, Status: "INSTALLED"}
		if err := orchestrator.RegisterSoftwareInstallation(ctx, endpointID, sw, si); err != nil {
			log.Fatalf("Error registrando %s: %v", inst.name, err)
		}
	}

	// Crear findings y vincular vulnerabilidades
	for _, tf := range testFindings {
		finding := &domain.Finding{
			FindingID:         tf.findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			RemediationFactor: tf.remediationFactor,
		}
		if err := orchestrator.GenerateFinding(ctx, tf.installationID, finding); err != nil {
			log.Fatalf("Error creando finding %d: %v", tf.findingID, err)
		}

		vuln := &domain.Vulnerability{
			VulnerabilityID: tf.cveID,
			CVEID:           tf.cveID,
			CVSSVector:      tf.cvssVector,
			BaseScore:       tf.baseScore,
		}
		rem := &domain.Remediation{
			RemediationID: tf.remediationID,
			Status:        "OPEN",
		}
		if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, tf.findingID, vuln, rem); err != nil {
			log.Fatalf("Error vinculando vuln al finding %d: %v", tf.findingID, err)
		}
	}

	fmt.Printf("    ✓ Endpoint [%s] con %d findings creados.\n", ep.Hostname, len(testFindings))
	fmt.Printf("      CIA: CR=%s / IR=%s / AR=%s\n", ep.ConfidentialityReq, ep.IntegrityReq, ep.AvailabilityReq)

	// ── 3. Ejecutar el motor de riesgo ────────────────────────────────────────
	fmt.Println("\n[3/4] Ejecutando ComputeEndpointRisk (llama a EPSS + KEV + cálculo)...")
	start := time.Now()
	if err := orchestrator.ComputeEndpointRisk(ctx, endpointID); err != nil {
		log.Fatalf("Error calculando riesgo: %v", err)
	}
	fmt.Printf("    ✓ Cálculo completado en %.1fs.\n", time.Since(start).Seconds())

	// ── 4. Mostrar resultados ──────────────────────────────────────────────────
	fmt.Println("\n[4/4] Resultados:")
	fmt.Println("════════════════════════════════════════════════════════")

	// Score del endpoint
	epRes, err := dbHelper.ExecuteRead(ctx,
		`MATCH (e:Endpoint {id: $id}) RETURN e.risk_score AS score, e.risk_tier AS tier`,
		map[string]any{"id": endpointID})
	if err != nil {
		log.Fatalf("Error leyendo endpoint: %v", err)
	}
	if m, ok := epRes.(map[string]any); ok {
		score, _ := m["score"].(float64)
		tier, _ := m["tier"].(string)
		fmt.Printf("  ENDPOINT [%s]\n", ep.Hostname)
		fmt.Printf("  ├─ Risk Score : %.4f\n", score)
		fmt.Printf("  └─ Risk Tier  : %s\n", tier)
	}

	fmt.Println("\n  FINDINGS (ordenados por prioridad de parcheo):")
	fmt.Println("  ┌──────────────────────────────────────────────────────────────")

	// Findings con sus scores, ordenados por priority_score DESC
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.Run(ctx, `
		MATCH (e:Endpoint {id: $ep_id})-[:HAS_INSTALLATION]->(si)-[:HAS_FINDING]->(f)-[:OF_VULNERABILITY]->(v)
		RETURN v.cve_id         AS cve,
		       f.impact_score   AS impact,
		       f.likelihood     AS likelihood,
			   f.exposure_factor AS exposure,
		       f.remediation_factor AS rem_factor,
		       f.risk_score     AS risk,
			   f.asset_criticality AS asset_crit,
			   f.urgency_boost AS urgency,
		       f.priority_score AS priority
		ORDER BY priority DESC
	`, map[string]any{"ep_id": endpointID})
	if err != nil {
		log.Fatalf("Error leyendo findings: %v", err)
	}

	i := 1
	for result.Next(ctx) {
		rec := result.Record()
		cve, _ := rec.Get("cve")
		impact, _ := rec.Get("impact")
		likelihood, _ := rec.Get("likelihood")
		exposure, _ := rec.Get("exposure")
		remFactor, _ := rec.Get("rem_factor")
		risk, _ := rec.Get("risk")
		assetCrit, _ := rec.Get("asset_crit")
		urgency, _ := rec.Get("urgency")
		priority, _ := rec.Get("priority")

		fmt.Printf("  │ #%d %-22s\n", i, cve)
		fmt.Printf("  │    Impact (env)    : %.4f\n", toF(impact))
		fmt.Printf("  │    Likelihood      : %.4f\n", toF(likelihood))
		fmt.Printf("  │    Exposure Factor : %.4f\n", toF(exposure))
		fmt.Printf("  │    Remediation (R) : %.2f\n", toF(remFactor))
		fmt.Printf("  │    Risk Score      : %.4f\n", toF(risk))
		fmt.Printf("  │    Asset Criticality: %.4f\n", toF(assetCrit))
		fmt.Printf("  │    Urgency Boost   : %.4f\n", toF(urgency))
		fmt.Printf("  │    Priority Score  : %.4f\n", toF(priority))
		if i < len(testFindings) {
			fmt.Println("  ├──────────────────────────────────────────────────────────────")
		}
		i++
	}
	fmt.Println("  └──────────────────────────────────────────────────────────────")
	fmt.Println("\n✓ PRUEBA COMPLETADA")
}

func toF(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
