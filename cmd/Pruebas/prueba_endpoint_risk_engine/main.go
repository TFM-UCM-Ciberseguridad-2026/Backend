package main

// Prueba de integración end-to-end para Phase 3.
//
// Valida:
//   Finding risk -> SoftwareInstallation risk/priority -> Endpoint risk/priority
//
// Objetivo principal:
//   demostrar que el technical_driver y el priority_driver pueden ser distintos.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_endpoint_risk_engine

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
	projectID  = int64(9201)
	endpointID = int64(9202)
)

var installations = []struct {
	softwareID       int64
	installationID   string
	name             string
	version          string
	vendor           string
	criticalityLevel string
}{
	{
		softwareID:       8201,
		installationID:   "inst-devtool-risk-test",
		name:             "dev-utility",
		version:          "1.0.0",
		vendor:           "internal",
		criticalityLevel: "LOW",
	},
	{
		softwareID:       8202,
		installationID:   "inst-db-risk-test",
		name:             "postgresql",
		version:          "14.0",
		vendor:           "postgresql",
		criticalityLevel: "CRITICAL",
	},
}

var findings = []struct {
	findingID         int64
	remediationID     int64
	installationID    string
	remediationFactor float64
	cveID             string
	cvssVector        string
	baseScore         float64
	exploit           bool
	label             string
}{
	{
		findingID:         9210,
		remediationID:     9220,
		installationID:    "inst-devtool-risk-test",
		remediationFactor: 1.0,
		cveID:             "CVE-2023-12345",
		cvssVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		baseScore:         10.0,
		exploit:           true,
		label:             "High technical risk on low-criticality software",
	},
	{
		findingID:         9211,
		remediationID:     9221,
		installationID:    "inst-db-risk-test",
		remediationFactor: 1.0,
		cveID:             "CVE-2023-12346",
		cvssVector:        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
		baseScore:         7.6,
		exploit:           true,
		label:             "Lower technical risk on critical software",
	},
}

type softwareSummary struct {
	InstallationID        string
	SoftwareName          string
	RiskScore             float64
	RiskTier              string
	CriticalityLevel      string
	CriticalityMultiplier float64
	PriorityScore         float64
	PriorityTier          string
	DriverCVEID           string
}

type endpointSummary struct {
	RiskScore                     float64
	RiskTier                      string
	PriorityScore                 float64
	PriorityTier                  string
	TechnicalDriverInstallationID string
	TechnicalDriverSoftwareName   string
	TechnicalDriverRiskScore      float64
	TechnicalDriverCVEID          string
	PriorityDriverInstallationID  string
	PriorityDriverSoftwareName    string
	PriorityDriverPriorityScore   float64
	PriorityDriverCVEID           string
	RiskySoftwareCount            int64
	RiskComputedAt                any
	PriorityComputedAt            any
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║      PRUEBA PHASE 3 – ENDPOINT RISK/PRIORITY         ║")
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

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo, _, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo, patchRepo, dbHelper,
		provider.NewNistAPIAdapter("https://services.nvd.nist.gov/rest/json/cves/2.0", cfg.NVD.APIKey, 30),
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter())

	fmt.Println("\n[1/5] Limpiando datos previos de prueba...")
	cleanIDs := []int64{projectID, endpointID, 8201, 8202, 9210, 9211, 9220, 9221}
	for _, id := range cleanIDs {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx, `MATCH (n) WHERE n.id IN ["inst-devtool-risk-test", "inst-db-risk-test"] DETACH DELETE n`, nil)
	fmt.Println("    ✓ Limpieza completada.")

	fmt.Println("\n[2/5] Creando endpoint, software installations y findings...")
	now := time.Now().UTC()

	project := &domain.Project{ProjectID: projectID, Nombre: "Phase 3 Endpoint Risk Test"}
	if err := orchestrator.CreateProject(ctx, project); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}
	createdProjectID := project.ProjectID

	endpoint := &domain.Endpoint{
		EndpointID:         endpointID,
		Hostname:           "endpoint-phase3-risk-test",
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
			InstallationID:   inst.installationID,
			FirstSeen:        now,
			Status:           "INSTALLED",
			CriticalityLevel: inst.criticalityLevel,
		}

		if err := orchestrator.RegisterSoftwareInstallation(ctx, createdEndpointID, software, softwareInstallation); err != nil {
			log.Fatalf("Error registrando instalación %s: %v", inst.installationID, err)
		}
		createdInstallationIDs[inst.installationID] = softwareInstallation.InstallationID
	}

	for _, item := range findings {
		createdInstallationID := createdInstallationIDs[item.installationID]
		if createdInstallationID == "" {
			log.Fatalf("No existe instalación creada para %s", item.installationID)
		}

		finding := &domain.Finding{
			FindingID:         item.findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			RemediationFactor: item.remediationFactor,
		}
		if err := orchestrator.GenerateFinding(ctx, createdInstallationID, finding); err != nil {
			log.Fatalf("Error creando finding %d: %v", item.findingID, err)
		}

		vulnerability := &domain.Vulnerability{
			VulnerabilityID: item.cveID,
			CVEID:           item.cveID,
			CVSSVector:      item.cvssVector,
			BaseScore:       item.baseScore,
			Exploit:         item.exploit,
		}
		remediation := &domain.Remediation{
			RemediationID: item.remediationID,
			Status:        "OPEN",
		}

		if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, item.findingID, vulnerability, remediation); err != nil {
			log.Fatalf("Error vinculando vulnerabilidad al finding %d: %v", item.findingID, err)
		}
	}

	fmt.Println("    ✓ Infraestructura de prueba creada.")
	expectedTechnicalDriverID := createdInstallationIDs["inst-devtool-risk-test"]
	expectedPriorityDriverID := createdInstallationIDs["inst-db-risk-test"]
	fmt.Printf("      Technical driver esperado: inst-devtool-risk-test (%s)\n", expectedTechnicalDriverID)
	fmt.Printf("      Priority driver esperado : inst-db-risk-test (%s)\n", expectedPriorityDriverID)

	fmt.Println("\n[3/5] Ejecutando ComputeEndpointRisk...")
	start := time.Now()
	if err := orchestrator.ComputeEndpointRisk(ctx, createdEndpointID); err != nil {
		log.Fatalf("Error calculando riesgo del endpoint: %v", err)
	}
	fmt.Printf("    ✓ Cálculo completado en %.1fs.\n", time.Since(start).Seconds())

	fmt.Println("\n[4/5] Leyendo resultados persistidos...")
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{})
	defer session.Close(ctx)

	softwareRows, err := readSoftwareSummaries(ctx, session, createdEndpointID)
	if err != nil {
		log.Fatalf("Error leyendo software summaries: %v", err)
	}

	endpointRow, err := readEndpointSummary(ctx, session, createdEndpointID)
	if err != nil {
		log.Fatalf("Error leyendo endpoint summary: %v", err)
	}

	printResults(softwareRows, endpointRow)

	fmt.Println("\n[5/5] Validando aserciones Phase 3...")
	assertPhase3(softwareRows, endpointRow, expectedTechnicalDriverID, expectedPriorityDriverID)

	fmt.Println("\n✓ PRUEBA PHASE 3 COMPLETADA")
}

func readSoftwareSummaries(ctx context.Context, session neo4jdriver.SessionWithContext, endpointID int64) ([]softwareSummary, error) {
	result, err := session.Run(ctx, `
		MATCH (:Endpoint {id: $endpoint_id})-[:HAS_INSTALLATION]->(si:SoftwareInstallation)-[:INSTANCE_OF]->(s:Software)
		RETURN si.id AS installation_id,
		       s.name AS software_name,
		       si.risk_score AS risk_score,
		       si.risk_tier AS risk_tier,
		       coalesce(si.criticality_level, 'STANDARD') AS criticality_level,
		       coalesce(si.criticality_multiplier, 1.0) AS criticality_multiplier,
		       si.priority_score AS priority_score,
		       si.priority_tier AS priority_tier,
		       si.driver_cve_id AS driver_cve_id
		ORDER BY priority_score DESC
	`, map[string]any{"endpoint_id": endpointID})
	if err != nil {
		return nil, err
	}

	rows := make([]softwareSummary, 0)
	for result.Next(ctx) {
		rec := result.Record()
		installationID, _ := rec.Get("installation_id")
		softwareName, _ := rec.Get("software_name")
		riskScore, _ := rec.Get("risk_score")
		riskTier, _ := rec.Get("risk_tier")
		criticalityLevel, _ := rec.Get("criticality_level")
		criticalityMultiplier, _ := rec.Get("criticality_multiplier")
		priorityScore, _ := rec.Get("priority_score")
		priorityTier, _ := rec.Get("priority_tier")
		driverCVEID, _ := rec.Get("driver_cve_id")

		rows = append(rows, softwareSummary{
			InstallationID:        toS(installationID),
			SoftwareName:          toS(softwareName),
			RiskScore:             toF(riskScore),
			RiskTier:              toS(riskTier),
			CriticalityLevel:      toS(criticalityLevel),
			CriticalityMultiplier: toF(criticalityMultiplier),
			PriorityScore:         toF(priorityScore),
			PriorityTier:          toS(priorityTier),
			DriverCVEID:           toS(driverCVEID),
		})
	}

	return rows, result.Err()
}

func readEndpointSummary(ctx context.Context, session neo4jdriver.SessionWithContext, endpointID int64) (endpointSummary, error) {
	result, err := session.Run(ctx, `
		MATCH (e:Endpoint {id: $endpoint_id})
		RETURN e.risk_score AS risk_score,
		       e.risk_tier AS risk_tier,
		       e.priority_score AS priority_score,
		       e.priority_tier AS priority_tier,
		       e.technical_driver_installation_id AS technical_driver_installation_id,
		       e.technical_driver_software_name AS technical_driver_software_name,
		       e.technical_driver_risk_score AS technical_driver_risk_score,
		       e.technical_driver_cve_id AS technical_driver_cve_id,
		       e.priority_driver_installation_id AS priority_driver_installation_id,
		       e.priority_driver_software_name AS priority_driver_software_name,
		       e.priority_driver_priority_score AS priority_driver_priority_score,
		       e.priority_driver_cve_id AS priority_driver_cve_id,
		       e.risky_software_count AS risky_software_count,
		       e.risk_computed_at AS risk_computed_at,
		       e.priority_computed_at AS priority_computed_at
	`, map[string]any{"endpoint_id": endpointID})
	if err != nil {
		return endpointSummary{}, err
	}
	if !result.Next(ctx) {
		return endpointSummary{}, fmt.Errorf("endpoint %d no encontrado", endpointID)
	}

	rec := result.Record()
	riskScore, _ := rec.Get("risk_score")
	riskTier, _ := rec.Get("risk_tier")
	priorityScore, _ := rec.Get("priority_score")
	priorityTier, _ := rec.Get("priority_tier")
	technicalDriverInstallationID, _ := rec.Get("technical_driver_installation_id")
	technicalDriverSoftwareName, _ := rec.Get("technical_driver_software_name")
	technicalDriverRiskScore, _ := rec.Get("technical_driver_risk_score")
	technicalDriverCVEID, _ := rec.Get("technical_driver_cve_id")
	priorityDriverInstallationID, _ := rec.Get("priority_driver_installation_id")
	priorityDriverSoftwareName, _ := rec.Get("priority_driver_software_name")
	priorityDriverPriorityScore, _ := rec.Get("priority_driver_priority_score")
	priorityDriverCVEID, _ := rec.Get("priority_driver_cve_id")
	riskySoftwareCount, _ := rec.Get("risky_software_count")
	riskComputedAt, _ := rec.Get("risk_computed_at")
	priorityComputedAt, _ := rec.Get("priority_computed_at")

	return endpointSummary{
		RiskScore:                     toF(riskScore),
		RiskTier:                      toS(riskTier),
		PriorityScore:                 toF(priorityScore),
		PriorityTier:                  toS(priorityTier),
		TechnicalDriverInstallationID: toS(technicalDriverInstallationID),
		TechnicalDriverSoftwareName:   toS(technicalDriverSoftwareName),
		TechnicalDriverRiskScore:      toF(technicalDriverRiskScore),
		TechnicalDriverCVEID:          toS(technicalDriverCVEID),
		PriorityDriverInstallationID:  toS(priorityDriverInstallationID),
		PriorityDriverSoftwareName:    toS(priorityDriverSoftwareName),
		PriorityDriverPriorityScore:   toF(priorityDriverPriorityScore),
		PriorityDriverCVEID:           toS(priorityDriverCVEID),
		RiskySoftwareCount:            toI(riskySoftwareCount),
		RiskComputedAt:                riskComputedAt,
		PriorityComputedAt:            priorityComputedAt,
	}, result.Err()
}

func printResults(softwareRows []softwareSummary, endpointRow endpointSummary) {
	fmt.Println("\nSOFTWARE INSTALLATIONS")
	for _, row := range softwareRows {
		fmt.Printf("%s\n", row.InstallationID)
		fmt.Printf("  Software              : %s\n", row.SoftwareName)
		fmt.Printf("  Risk Score            : %.4f\n", row.RiskScore)
		fmt.Printf("  Risk Tier             : %s\n", row.RiskTier)
		fmt.Printf("  Criticality Level     : %s\n", row.CriticalityLevel)
		fmt.Printf("  Criticality Multiplier: %.2f\n", row.CriticalityMultiplier)
		fmt.Printf("  Priority Score        : %.4f\n", row.PriorityScore)
		fmt.Printf("  Priority Tier         : %s\n", row.PriorityTier)
		fmt.Printf("  Driver CVE            : %s\n", row.DriverCVEID)
	}

	fmt.Println("\nENDPOINT")
	fmt.Printf("  Risk Score          : %.4f\n", endpointRow.RiskScore)
	fmt.Printf("  Risk Tier           : %s\n", endpointRow.RiskTier)
	fmt.Printf("  Priority Score      : %.4f\n", endpointRow.PriorityScore)
	fmt.Printf("  Priority Tier       : %s\n", endpointRow.PriorityTier)
	fmt.Printf("  Risk Computed At    : %v\n", endpointRow.RiskComputedAt)
	fmt.Printf("  Priority Computed At: %v\n", endpointRow.PriorityComputedAt)

	fmt.Println("\nTECHNICAL DRIVER")
	fmt.Printf("  Installation: %s\n", endpointRow.TechnicalDriverInstallationID)
	fmt.Printf("  Software    : %s\n", endpointRow.TechnicalDriverSoftwareName)
	fmt.Printf("  Risk Score  : %.4f\n", endpointRow.TechnicalDriverRiskScore)
	fmt.Printf("  Driver CVE  : %s\n", endpointRow.TechnicalDriverCVEID)

	fmt.Println("\nPRIORITY DRIVER")
	fmt.Printf("  Installation  : %s\n", endpointRow.PriorityDriverInstallationID)
	fmt.Printf("  Software      : %s\n", endpointRow.PriorityDriverSoftwareName)
	fmt.Printf("  Priority Score: %.4f\n", endpointRow.PriorityDriverPriorityScore)
	fmt.Printf("  Driver CVE    : %s\n", endpointRow.PriorityDriverCVEID)
	fmt.Printf("  Risky Software: %d\n", endpointRow.RiskySoftwareCount)
}

func assertPhase3(softwareRows []softwareSummary, endpointRow endpointSummary, expectedTechnicalDriverID string, expectedPriorityDriverID string) {
	if len(softwareRows) != 2 {
		log.Fatalf("ASSERT FAIL: se esperaban 2 instalaciones, recibidas %d", len(softwareRows))
	}

	byID := make(map[string]softwareSummary, len(softwareRows))
	for _, row := range softwareRows {
		byID[row.InstallationID] = row
		if row.RiskTier == "" {
			log.Fatalf("ASSERT FAIL: %s no tiene risk_tier", row.InstallationID)
		}
		if row.PriorityTier == "" {
			log.Fatalf("ASSERT FAIL: %s no tiene priority_tier", row.InstallationID)
		}
		if row.DriverCVEID == "" {
			log.Fatalf("ASSERT FAIL: %s no tiene driver_cve_id", row.InstallationID)
		}
	}

	devTool := byID["inst-devtool-risk-test"]
	database := byID["inst-db-risk-test"]

	if devTool.RiskScore <= database.RiskScore {
		log.Fatalf("ASSERT FAIL: devtool risk %.4f debe ser mayor que database risk %.4f", devTool.RiskScore, database.RiskScore)
	}
	if database.PriorityScore <= devTool.PriorityScore {
		log.Fatalf("ASSERT FAIL: database priority %.4f debe ser mayor que devtool priority %.4f", database.PriorityScore, devTool.PriorityScore)
	}
	if endpointRow.TechnicalDriverInstallationID != expectedTechnicalDriverID {
		log.Fatalf("ASSERT FAIL: technical_driver = %s, esperado %s", endpointRow.TechnicalDriverInstallationID, expectedTechnicalDriverID)
	}
	if endpointRow.PriorityDriverInstallationID != expectedPriorityDriverID {
		log.Fatalf("ASSERT FAIL: priority_driver = %s, esperado %s", endpointRow.PriorityDriverInstallationID, expectedPriorityDriverID)
	}
	if endpointRow.RiskScore < endpointRow.TechnicalDriverRiskScore {
		log.Fatalf("ASSERT FAIL: endpoint risk %.4f debe ser >= technical driver risk %.4f", endpointRow.RiskScore, endpointRow.TechnicalDriverRiskScore)
	}
	if endpointRow.PriorityScore < endpointRow.PriorityDriverPriorityScore {
		log.Fatalf("ASSERT FAIL: endpoint priority %.4f debe ser >= priority driver %.4f", endpointRow.PriorityScore, endpointRow.PriorityDriverPriorityScore)
	}
	if endpointRow.PriorityTier == "" {
		log.Fatalf("ASSERT FAIL: endpoint priority_tier está vacío")
	}
	if endpointRow.RiskySoftwareCount < 2 {
		log.Fatalf("ASSERT FAIL: risky_software_count = %d, esperado >= 2", endpointRow.RiskySoftwareCount)
	}
	if endpointRow.RiskComputedAt == nil {
		log.Fatalf("ASSERT FAIL: endpoint risk_computed_at está vacío")
	}
	if endpointRow.PriorityComputedAt == nil {
		log.Fatalf("ASSERT FAIL: endpoint priority_computed_at está vacío")
	}

	fmt.Println("    ✓ devtool.risk_score > database.risk_score")
	fmt.Println("    ✓ database.priority_score > devtool.priority_score")
	fmt.Println("    ✓ endpoint.technical_driver_installation_id == inst-devtool-risk-test")
	fmt.Println("    ✓ endpoint.priority_driver_installation_id == inst-db-risk-test")
	fmt.Println("    ✓ endpoint.risk_score >= technical_driver.risk_score")
	fmt.Println("    ✓ endpoint.priority_score >= priority_driver.priority_score")
	fmt.Println("    ✓ endpoint risk/priority timestamps persistidos")
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
