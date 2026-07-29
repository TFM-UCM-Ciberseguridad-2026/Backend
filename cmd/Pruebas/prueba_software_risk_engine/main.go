package main

// Prueba de integración end-to-end para Phase 2.
//
// Valida:
//   Finding risk -> SoftwareInstallation risk -> Endpoint risk
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_software_risk_engine

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
	projectID  = int64(9101)
	endpointID = int64(9102)
)

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
		findingID:         9110,
		remediationID:     9120,
		installationID:    "inst-log4j-risk-test",
		remediationFactor: 1.0,
		cveID:             "CVE-2021-44228",
		cvssVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		baseScore:         10.0,
		label:             "Log4Shell",
	},
	{
		findingID:         9111,
		remediationID:     9121,
		installationID:    "inst-log4j-risk-test",
		remediationFactor: 0.4,
		cveID:             "CVE-2017-0144",
		cvssVector:        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
		baseScore:         8.1,
		label:             "EternalBlue",
	},
	{
		findingID:         9112,
		remediationID:     9122,
		installationID:    "inst-misc-risk-test",
		remediationFactor: 1.0,
		cveID:             "CVE-2023-12345",
		cvssVector:        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L",
		baseScore:         1.8,
		label:             "CVE ficticio sin EPSS/KEV",
	},
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║   PRUEBA PHASE 2 – SOFTWARE INSTALLATION RISK        ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

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

	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo, nil, patchRepo, dbHelper,
		provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cves/2.0", cfg.NVD.APIKey, 30),
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter())

	fmt.Println("\n[1/5] Limpiando datos previos de prueba...")
	cleanIDs := []int64{projectID, endpointID, 9110, 9111, 9112, 9120, 9121, 9122, 8101, 8102}
	for _, id := range cleanIDs {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (n) WHERE n.id IN ["inst-log4j-risk-test", "inst-misc-risk-test"] DETACH DELETE n`, nil)
	fmt.Println("    ✓ Limpieza completada.")

	fmt.Println("\n[2/5] Creando endpoint, software installations y findings...")
	now := time.Now().UTC()

	project := &domain.Project{ProjectID: projectID, Nombre: "Phase 2 Software Risk Test"}
	if err := orchestrator.CreateProject(ctx, project); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}
	createdProjectID := project.ProjectID

	endpoint := &domain.Endpoint{
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
	if err := orchestrator.AddEndpointToProject(ctx, createdProjectID, endpoint); err != nil {
		log.Fatalf("Error creando endpoint: %v", err)
	}
	createdEndpointID := endpoint.EndpointID

	installations := []struct {
		softwareID     int64
		installationID string
		name           string
		version        string
		vendor         string
	}{
		{8101, "inst-log4j-risk-test", "log4j-core", "2.14.1", "apache"},
		{8102, "inst-misc-risk-test", "custom-app", "1.0.0", "internal"},
	}

	createdInstallationIDs := make(map[string]string, len(installations))
	for _, inst := range installations {
		software := &domain.Software{
			SoftwareID: inst.softwareID,
			Name:       inst.name,
			Version:    inst.version,
			Vendor:     inst.vendor,
			Type:       "application",
		}
		softwareInstallation := &domain.SoftwareInstallation{
			InstallationID: inst.installationID,
			FirstSeen:      now,
			Status:         "INSTALLED",
		}

		if err := orchestrator.RegisterSoftwareInstallation(ctx, createdEndpointID, software, softwareInstallation); err != nil {
			log.Fatalf("Error registrando instalación %s: %v", inst.installationID, err)
		}
		createdInstallationIDs[inst.installationID] = softwareInstallation.InstallationID
	}

	for _, tf := range testFindings {
		createdInstallationID := createdInstallationIDs[tf.installationID]
		if createdInstallationID == "" {
			log.Fatalf("No existe instalación creada para %s", tf.installationID)
		}

		finding := &domain.Finding{
			FindingID:         tf.findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			RemediationFactor: tf.remediationFactor,
		}
		if err := orchestrator.GenerateFinding(ctx, createdInstallationID, finding); err != nil {
			log.Fatalf("Error creando finding %d: %v", tf.findingID, err)
		}

		vulnerability := &domain.Vulnerability{
			VulnerabilityID: tf.cveID,
			CVEID:           tf.cveID,
			CVSSVector:      tf.cvssVector,
			BaseScore:       tf.baseScore,
		}
		remediation := &domain.Remediation{
			RemediationID: tf.remediationID,
			Status:        "OPEN",
		}

		if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, tf.findingID, vulnerability, remediation); err != nil {
			log.Fatalf("Error vinculando vulnerabilidad al finding %d: %v", tf.findingID, err)
		}
	}

	fmt.Println("    ✓ Infraestructura de prueba creada.")
	fmt.Println("      Endpoint: db-server-risk-test")
	fmt.Println("      Installation A: inst-log4j-risk-test con CVE-2021-44228 y CVE-2017-0144")
	fmt.Println("      Installation B: inst-misc-risk-test con CVE-2023-12345")

	fmt.Println("\n[3/5] Ejecutando ComputeEndpointRisk...")
	start := time.Now()
	if err := orchestrator.ComputeEndpointRisk(ctx, createdEndpointID); err != nil {
		log.Fatalf("Error calculando riesgo del endpoint: %v", err)
	}
	fmt.Printf("    ✓ Cálculo completado en %.1fs.\n", time.Since(start).Seconds())

	fmt.Println("\n[4/5] Leyendo resultados persistidos...")
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{})
	defer session.Close(ctx)

	softwareRows, err := readSoftwareRisks(ctx, session, createdEndpointID)
	if err != nil {
		log.Fatalf("Error leyendo riesgos de software: %v", err)
	}

	endpointScore, endpointTier, err := readEndpointRisk(ctx, session, createdEndpointID)
	if err != nil {
		log.Fatalf("Error leyendo riesgo de endpoint: %v", err)
	}

	printResults(softwareRows, endpointScore, endpointTier)

	fmt.Println("\n[5/5] Validando aserciones Phase 2...")
	assertPhase2(softwareRows, endpointScore, endpointTier)

	fmt.Println("\n✓ PRUEBA PHASE 2 COMPLETADA")
}

type softwareRiskRow struct {
	InstallationID  string
	RiskScore       float64
	RiskTier        string
	DriverFindingID int64
	DriverCVEID     string
	RiskComputedAt  any
}

func readSoftwareRisks(ctx context.Context, session neo4jdriver.SessionWithContext, endpointID int64) ([]softwareRiskRow, error) {
	result, err := session.Run(ctx, `
		MATCH (:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)
		RETURN si.id AS installation_id,
		       si.risk_score AS risk_score,
		       si.risk_tier AS risk_tier,
		       si.driver_finding_id AS driver_finding_id,
		       si.driver_cve_id AS driver_cve_id,
		       si.risk_computed_at AS risk_computed_at
		ORDER BY installation_id
	`, map[string]any{"endpoint_id": endpointID})
	if err != nil {
		return nil, err
	}

	var rows []softwareRiskRow
	for result.Next(ctx) {
		rec := result.Record()
		installationID, _ := rec.Get("installation_id")
		riskScore, _ := rec.Get("risk_score")
		riskTier, _ := rec.Get("risk_tier")
		driverFindingID, _ := rec.Get("driver_finding_id")
		driverCVEID, _ := rec.Get("driver_cve_id")
		riskComputedAt, _ := rec.Get("risk_computed_at")

		rows = append(rows, softwareRiskRow{
			InstallationID:  toS(installationID),
			RiskScore:       toF(riskScore),
			RiskTier:        toS(riskTier),
			DriverFindingID: toI(driverFindingID),
			DriverCVEID:     toS(driverCVEID),
			RiskComputedAt:  riskComputedAt,
		})
	}

	return rows, result.Err()
}

func readEndpointRisk(ctx context.Context, session neo4jdriver.SessionWithContext, endpointID int64) (float64, string, error) {
	result, err := session.Run(ctx,
		`MATCH (e:Endpoint {id: $id}) RETURN e.risk_score AS score, e.risk_tier AS tier`,
		map[string]any{"id": endpointID},
	)
	if err != nil {
		return 0, "", err
	}
	if !result.Next(ctx) {
		return 0, "", fmt.Errorf("endpoint %d no encontrado", endpointID)
	}

	rec := result.Record()
	score, _ := rec.Get("score")
	tier, _ := rec.Get("tier")

	return toF(score), toS(tier), result.Err()
}

func printResults(rows []softwareRiskRow, endpointScore float64, endpointTier string) {
	fmt.Println("\nSOFTWARE INSTALLATIONS")
	for _, row := range rows {
		fmt.Printf("%s\n", row.InstallationID)
		fmt.Printf("  Risk Score      : %.4f\n", row.RiskScore)
		fmt.Printf("  Risk Tier       : %s\n", row.RiskTier)
		fmt.Printf("  Driver Finding  : %d\n", row.DriverFindingID)
		fmt.Printf("  Driver CVE      : %s\n", row.DriverCVEID)
		fmt.Printf("  Risk Computed At: %v\n", row.RiskComputedAt)
	}

	fmt.Println("\nENDPOINT")
	fmt.Printf("  Risk Score: %.4f\n", endpointScore)
	fmt.Printf("  Risk Tier : %s\n", endpointTier)
}

func assertPhase2(rows []softwareRiskRow, endpointScore float64, endpointTier string) {
	if len(rows) != 2 {
		log.Fatalf("ASSERT FAIL: se esperaban 2 SoftwareInstallation, recibidas %d", len(rows))
	}

	byID := make(map[string]softwareRiskRow, len(rows))
	for _, row := range rows {
		byID[row.InstallationID] = row

		if row.RiskComputedAt == nil {
			log.Fatalf("ASSERT FAIL: %s no tiene risk_computed_at", row.InstallationID)
		}
		if row.RiskTier == "" {
			log.Fatalf("ASSERT FAIL: %s no tiene risk_tier", row.InstallationID)
		}
		if row.DriverFindingID == 0 {
			log.Fatalf("ASSERT FAIL: %s no tiene driver_finding_id", row.InstallationID)
		}
		if row.DriverCVEID == "" {
			log.Fatalf("ASSERT FAIL: %s no tiene driver_cve_id", row.InstallationID)
		}
	}

	log4j := byID["inst-log4j-risk-test"]
	misc := byID["inst-misc-risk-test"]

	if log4j.DriverCVEID != "CVE-2021-44228" {
		log.Fatalf("ASSERT FAIL: inst-log4j-risk-test driver_cve_id = %s, esperado CVE-2021-44228", log4j.DriverCVEID)
	}
	if log4j.RiskScore <= misc.RiskScore {
		log.Fatalf("ASSERT FAIL: log4j risk %.4f debe ser mayor que misc risk %.4f", log4j.RiskScore, misc.RiskScore)
	}
	if endpointScore < log4j.RiskScore {
		log.Fatalf("ASSERT FAIL: endpoint risk %.4f debe ser >= log4j risk %.4f", endpointScore, log4j.RiskScore)
	}
	if endpointTier == "" {
		log.Fatalf("ASSERT FAIL: endpoint_tier está vacío")
	}

	fmt.Println("    ✓ inst-log4j-risk-test.driver_cve_id == CVE-2021-44228")
	fmt.Println("    ✓ inst-log4j-risk-test.risk_score > inst-misc-risk-test.risk_score")
	fmt.Println("    ✓ endpoint.risk_score >= inst-log4j-risk-test.risk_score")
	fmt.Println("    ✓ endpoint.risk_tier no está vacío")
	fmt.Println("    ✓ risk_computed_at, driver_finding_id y driver_cve_id persistidos")
}

func toF(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func toS(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toI(v any) int64 {
	if i, ok := v.(int64); ok {
		return i
	}
	return 0
}
