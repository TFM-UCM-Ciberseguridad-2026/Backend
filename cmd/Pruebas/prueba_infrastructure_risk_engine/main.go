package main

// Prueba de integración end-to-end para Phase 4.
//
// Valida:
//   Finding risk -> SoftwareInstallation risk/priority -> Endpoint risk/priority -> Project risk/priority
//
// Objetivo principal:
//   demostrar que el technical_driver y el priority_driver del Project pueden ser distintos.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_infrastructure_risk_engine

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

const projectID = int64(9301)

var endpointCases = []struct {
	endpointID        int64
	hostname          string
	softwareID        int64
	installationID    string
	softwareName      string
	softwareVersion   string
	softwareVendor    string
	criticalityLevel  string
	findingID         int64
	remediationID     int64
	cveID             string
	cvssVector        string
	baseScore         float64
	exploit           bool
	remediationFactor float64
}{
	{
		endpointID:        9302,
		hostname:          "endpoint-tech-driver-risk-test",
		softwareID:        8301,
		installationID:    "inst-tech-driver-risk-test",
		softwareName:      "dev-utility",
		softwareVersion:   "1.0.0",
		softwareVendor:    "internal",
		criticalityLevel:  "LOW",
		findingID:         9310,
		remediationID:     9320,
		cveID:             "CVE-2023-12345",
		cvssVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		baseScore:         10.0,
		exploit:           true,
		remediationFactor: 1.0,
	},
	{
		endpointID:        9303,
		hostname:          "endpoint-priority-driver-risk-test",
		softwareID:        8302,
		installationID:    "inst-priority-driver-risk-test",
		softwareName:      "postgresql",
		softwareVersion:   "14.0",
		softwareVendor:    "postgresql",
		criticalityLevel:  "CRITICAL",
		findingID:         9311,
		remediationID:     9321,
		cveID:             "CVE-2023-12346",
		cvssVector:        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
		baseScore:         7.6,
		exploit:           true,
		remediationFactor: 1.0,
	},
	{
		endpointID:        9304,
		hostname:          "endpoint-low-risk-test",
		softwareID:        8303,
		installationID:    "inst-low-risk-test",
		softwareName:      "custom-app",
		softwareVersion:   "1.0.0",
		softwareVendor:    "internal",
		criticalityLevel:  "LOW",
		findingID:         9312,
		remediationID:     9322,
		cveID:             "CVE-2023-12347",
		cvssVector:        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:L",
		baseScore:         1.8,
		exploit:           false,
		remediationFactor: 1.0,
	},
}

type projectSummary struct {
	RiskScore                       float64
	RiskTier                        string
	PriorityScore                   float64
	PriorityTier                    string
	TechnicalDriverEndpointID       int64
	TechnicalDriverEndpointHostname string
	TechnicalDriverRiskScore        float64
	TechnicalDriverSoftwareName     string
	TechnicalDriverCVEID            string
	PriorityDriverEndpointID        int64
	PriorityDriverEndpointHostname  string
	PriorityDriverPriorityScore     float64
	PriorityDriverSoftwareName      string
	PriorityDriverCVEID             string
	RiskyEndpointCount              int64
	RiskComputedAt                  any
	PriorityComputedAt              any
}

type endpointSummary struct {
	EndpointID                  int64
	Hostname                    string
	RiskScore                   float64
	RiskTier                    string
	PriorityScore               float64
	PriorityTier                string
	TechnicalDriverSoftwareName string
	TechnicalDriverCVEID        string
	PriorityDriverSoftwareName  string
	PriorityDriverCVEID         string
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║   PRUEBA PHASE 4 – INFRASTRUCTURE PROJECT RISK       ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

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
	cleanPhase4Data(ctx, dbHelper)
	fmt.Println("    ✓ Limpieza completada.")

	fmt.Println("\n[2/5] Creando proyecto, endpoints, software installations y findings...")
	now := time.Now().UTC()

	project := &domain.Project{ProjectID: projectID, Name: "Phase 4 Infrastructure Risk Test"}
	if err := orchestrator.CreateProject(ctx, project); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	for _, item := range endpointCases {
		endpoint := &domain.Endpoint{
			EndpointID:         item.endpointID,
			Hostname:           item.hostname,
			Type:               "Linux",
			Status:             "ACTIVE",
			InternetExposed:    false,
			Environment:        "prod",
			ConfidentialityReq: "High",
			IntegrityReq:       "Medium",
			AvailabilityReq:    "High",
		}
		if err := orchestrator.AddEndpointToProject(ctx, project.ProjectID, endpoint); err != nil {
			log.Fatalf("Error creando endpoint %s: %v", item.hostname, err)
		}

		software := &domain.Software{
			SoftwareID: item.softwareID,
			Name:       item.softwareName,
			Version:    item.softwareVersion,
			Vendor:     item.softwareVendor,
			Type:       "application",
		}
		softwareInstallation := &domain.SoftwareInstallation{
			InstallationID:   item.installationID,
			FirstSeen:        now,
			Status:           "INSTALLED",
			CriticalityLevel: item.criticalityLevel,
		}
		if err := orchestrator.RegisterSoftwareInstallation(ctx, endpoint.EndpointID, software, softwareInstallation); err != nil {
			log.Fatalf("Error registrando instalación %s: %v", item.installationID, err)
		}

		finding := &domain.Finding{
			FindingID:         item.findingID,
			Status:            "OPEN",
			FirstSeen:         now,
			RemediationFactor: item.remediationFactor,
		}
		if err := orchestrator.GenerateFinding(ctx, softwareInstallation.InstallationID, finding); err != nil {
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
		if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, finding.FindingID, vulnerability, remediation); err != nil {
			log.Fatalf("Error vinculando vulnerabilidad al finding %d: %v", finding.FindingID, err)
		}
	}

	fmt.Println("    ✓ Infraestructura de prueba creada.")
	fmt.Println("      Technical driver esperado: endpoint-tech-driver-risk-test")
	fmt.Println("      Priority driver esperado : endpoint-priority-driver-risk-test")

	fmt.Println("\n[3/5] Ejecutando ComputeProjectRisk...")
	start := time.Now()
	if err := orchestrator.ComputeProjectRisk(ctx, project.ProjectID); err != nil {
		log.Fatalf("Error calculando riesgo del proyecto: %v", err)
	}
	fmt.Printf("    ✓ Cálculo completado en %.1fs.\n", time.Since(start).Seconds())

	fmt.Println("\n[4/5] Leyendo resultados persistidos...")
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{})
	defer session.Close(ctx)

	projectRow, err := readProjectSummary(ctx, session, project.ProjectID)
	if err != nil {
		log.Fatalf("Error leyendo project summary: %v", err)
	}

	endpointRows, err := readEndpointSummaries(ctx, session, project.ProjectID)
	if err != nil {
		log.Fatalf("Error leyendo endpoint summaries: %v", err)
	}

	printResults(projectRow, endpointRows)

	fmt.Println("\n[5/5] Validando aserciones Phase 4...")
	assertPhase4(projectRow, endpointRows)

	fmt.Println("\n✓ PRUEBA PHASE 4 COMPLETADA")
}

func cleanPhase4Data(ctx context.Context, dbHelper interface {
	ExecuteWrite(context.Context, string, map[string]any) error
}) {
	ids := []int64{9301, 9302, 9303, 9304, 8301, 8302, 8303, 9310, 9311, 9312, 9320, 9321, 9322}
	for _, id := range ids {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}

	_ = dbHelper.ExecuteWrite(ctx, `
        MATCH (n)
        WHERE n.hostname IN [
            'endpoint-tech-driver-risk-test',
            'endpoint-priority-driver-risk-test',
            'endpoint-low-risk-test'
        ]
        OR n.nombre = 'Phase 4 Infrastructure Risk Test'
        OR n.name IN ['dev-utility', 'postgresql', 'custom-app']
        OR n.cve_id IN ['CVE-2023-12345', 'CVE-2023-12346', 'CVE-2023-12347']
        OR n.id IN ['inst-tech-driver-risk-test', 'inst-priority-driver-risk-test', 'inst-low-risk-test']
        DETACH DELETE n
    `, nil)
}

func readProjectSummary(ctx context.Context, session neo4jdriver.SessionWithContext, projectID int64) (projectSummary, error) {
	result, err := session.Run(ctx, `
        MATCH (p:Project {id: $project_id})
        RETURN p.risk_score AS risk_score,
               p.risk_tier AS risk_tier,
               p.priority_score AS priority_score,
               p.priority_tier AS priority_tier,
               p.technical_driver_endpoint_id AS technical_driver_endpoint_id,
               p.technical_driver_endpoint_hostname AS technical_driver_endpoint_hostname,
               p.technical_driver_risk_score AS technical_driver_risk_score,
               p.technical_driver_software_name AS technical_driver_software_name,
               p.technical_driver_cve_id AS technical_driver_cve_id,
               p.priority_driver_endpoint_id AS priority_driver_endpoint_id,
               p.priority_driver_endpoint_hostname AS priority_driver_endpoint_hostname,
               p.priority_driver_priority_score AS priority_driver_priority_score,
               p.priority_driver_software_name AS priority_driver_software_name,
               p.priority_driver_cve_id AS priority_driver_cve_id,
               p.risky_endpoint_count AS risky_endpoint_count,
               p.risk_computed_at AS risk_computed_at,
               p.priority_computed_at AS priority_computed_at
    `, map[string]any{"project_id": projectID})
	if err != nil {
		return projectSummary{}, err
	}
	if !result.Next(ctx) {
		return projectSummary{}, fmt.Errorf("project %d no encontrado", projectID)
	}

	rec := result.Record()
	riskScore, _ := rec.Get("risk_score")
	riskTier, _ := rec.Get("risk_tier")
	priorityScore, _ := rec.Get("priority_score")
	priorityTier, _ := rec.Get("priority_tier")
	technicalDriverEndpointID, _ := rec.Get("technical_driver_endpoint_id")
	technicalDriverEndpointHostname, _ := rec.Get("technical_driver_endpoint_hostname")
	technicalDriverRiskScore, _ := rec.Get("technical_driver_risk_score")
	technicalDriverSoftwareName, _ := rec.Get("technical_driver_software_name")
	technicalDriverCVEID, _ := rec.Get("technical_driver_cve_id")
	priorityDriverEndpointID, _ := rec.Get("priority_driver_endpoint_id")
	priorityDriverEndpointHostname, _ := rec.Get("priority_driver_endpoint_hostname")
	priorityDriverPriorityScore, _ := rec.Get("priority_driver_priority_score")
	priorityDriverSoftwareName, _ := rec.Get("priority_driver_software_name")
	priorityDriverCVEID, _ := rec.Get("priority_driver_cve_id")
	riskyEndpointCount, _ := rec.Get("risky_endpoint_count")
	riskComputedAt, _ := rec.Get("risk_computed_at")
	priorityComputedAt, _ := rec.Get("priority_computed_at")

	return projectSummary{
		RiskScore:                       toF(riskScore),
		RiskTier:                        toS(riskTier),
		PriorityScore:                   toF(priorityScore),
		PriorityTier:                    toS(priorityTier),
		TechnicalDriverEndpointID:       toI(technicalDriverEndpointID),
		TechnicalDriverEndpointHostname: toS(technicalDriverEndpointHostname),
		TechnicalDriverRiskScore:        toF(technicalDriverRiskScore),
		TechnicalDriverSoftwareName:     toS(technicalDriverSoftwareName),
		TechnicalDriverCVEID:            toS(technicalDriverCVEID),
		PriorityDriverEndpointID:        toI(priorityDriverEndpointID),
		PriorityDriverEndpointHostname:  toS(priorityDriverEndpointHostname),
		PriorityDriverPriorityScore:     toF(priorityDriverPriorityScore),
		PriorityDriverSoftwareName:      toS(priorityDriverSoftwareName),
		PriorityDriverCVEID:             toS(priorityDriverCVEID),
		RiskyEndpointCount:              toI(riskyEndpointCount),
		RiskComputedAt:                  riskComputedAt,
		PriorityComputedAt:              priorityComputedAt,
	}, result.Err()
}

func readEndpointSummaries(ctx context.Context, session neo4jdriver.SessionWithContext, projectID int64) ([]endpointSummary, error) {
	result, err := session.Run(ctx, `
        MATCH (:Project {id: $project_id})-[:HAS_ENDPOINT]->(e:Endpoint)
        RETURN e.id AS endpoint_id,
               e.hostname AS hostname,
               e.risk_score AS risk_score,
               e.risk_tier AS risk_tier,
               e.priority_score AS priority_score,
               e.priority_tier AS priority_tier,
               e.technical_driver_software_name AS technical_driver_software_name,
               e.technical_driver_cve_id AS technical_driver_cve_id,
               e.priority_driver_software_name AS priority_driver_software_name,
               e.priority_driver_cve_id AS priority_driver_cve_id
        ORDER BY priority_score DESC
    `, map[string]any{"project_id": projectID})
	if err != nil {
		return nil, err
	}

	rows := make([]endpointSummary, 0)
	for result.Next(ctx) {
		rec := result.Record()
		endpointID, _ := rec.Get("endpoint_id")
		hostname, _ := rec.Get("hostname")
		riskScore, _ := rec.Get("risk_score")
		riskTier, _ := rec.Get("risk_tier")
		priorityScore, _ := rec.Get("priority_score")
		priorityTier, _ := rec.Get("priority_tier")
		technicalDriverSoftwareName, _ := rec.Get("technical_driver_software_name")
		technicalDriverCVEID, _ := rec.Get("technical_driver_cve_id")
		priorityDriverSoftwareName, _ := rec.Get("priority_driver_software_name")
		priorityDriverCVEID, _ := rec.Get("priority_driver_cve_id")

		rows = append(rows, endpointSummary{
			EndpointID:                  toI(endpointID),
			Hostname:                    toS(hostname),
			RiskScore:                   toF(riskScore),
			RiskTier:                    toS(riskTier),
			PriorityScore:               toF(priorityScore),
			PriorityTier:                toS(priorityTier),
			TechnicalDriverSoftwareName: toS(technicalDriverSoftwareName),
			TechnicalDriverCVEID:        toS(technicalDriverCVEID),
			PriorityDriverSoftwareName:  toS(priorityDriverSoftwareName),
			PriorityDriverCVEID:         toS(priorityDriverCVEID),
		})
	}

	return rows, result.Err()
}

func printResults(projectRow projectSummary, endpointRows []endpointSummary) {
	fmt.Println("\nPROJECT")
	fmt.Printf("  Risk Score          : %.4f\n", projectRow.RiskScore)
	fmt.Printf("  Risk Tier           : %s\n", projectRow.RiskTier)
	fmt.Printf("  Priority Score      : %.4f\n", projectRow.PriorityScore)
	fmt.Printf("  Priority Tier       : %s\n", projectRow.PriorityTier)
	fmt.Printf("  Risky Endpoints     : %d\n", projectRow.RiskyEndpointCount)
	fmt.Printf("  Risk Computed At    : %v\n", projectRow.RiskComputedAt)
	fmt.Printf("  Priority Computed At: %v\n", projectRow.PriorityComputedAt)

	fmt.Println("\nENDPOINTS")
	for _, row := range endpointRows {
		fmt.Printf("%s\n", row.Hostname)
		fmt.Printf("  Risk Score               : %.4f\n", row.RiskScore)
		fmt.Printf("  Risk Tier                : %s\n", row.RiskTier)
		fmt.Printf("  Priority Score           : %.4f\n", row.PriorityScore)
		fmt.Printf("  Priority Tier            : %s\n", row.PriorityTier)
		fmt.Printf("  Technical Driver Software: %s\n", row.TechnicalDriverSoftwareName)
		fmt.Printf("  Technical Driver CVE     : %s\n", row.TechnicalDriverCVEID)
		fmt.Printf("  Priority Driver Software : %s\n", row.PriorityDriverSoftwareName)
		fmt.Printf("  Priority Driver CVE      : %s\n", row.PriorityDriverCVEID)
	}

	fmt.Println("\nTECHNICAL DRIVER")
	fmt.Printf("  Endpoint: %s\n", projectRow.TechnicalDriverEndpointHostname)
	fmt.Printf("  Risk    : %.4f\n", projectRow.TechnicalDriverRiskScore)
	fmt.Printf("  Software: %s\n", projectRow.TechnicalDriverSoftwareName)
	fmt.Printf("  CVE     : %s\n", projectRow.TechnicalDriverCVEID)

	fmt.Println("\nPRIORITY DRIVER")
	fmt.Printf("  Endpoint: %s\n", projectRow.PriorityDriverEndpointHostname)
	fmt.Printf("  Priority: %.4f\n", projectRow.PriorityDriverPriorityScore)
	fmt.Printf("  Software: %s\n", projectRow.PriorityDriverSoftwareName)
	fmt.Printf("  CVE     : %s\n", projectRow.PriorityDriverCVEID)
}

func assertPhase4(projectRow projectSummary, endpointRows []endpointSummary) {
	if len(endpointRows) != 3 {
		log.Fatalf("ASSERT FAIL: se esperaban 3 endpoints, recibidos %d", len(endpointRows))
	}
	if projectRow.RiskTier == "" {
		log.Fatalf("ASSERT FAIL: project risk_tier vacío")
	}
	if projectRow.PriorityTier == "" {
		log.Fatalf("ASSERT FAIL: project priority_tier vacío")
	}
	if projectRow.RiskComputedAt == nil {
		log.Fatalf("ASSERT FAIL: project risk_computed_at vacío")
	}
	if projectRow.PriorityComputedAt == nil {
		log.Fatalf("ASSERT FAIL: project priority_computed_at vacío")
	}
	if projectRow.TechnicalDriverEndpointID == 0 {
		log.Fatalf("ASSERT FAIL: project technical_driver_endpoint_id vacío")
	}
	if projectRow.PriorityDriverEndpointID == 0 {
		log.Fatalf("ASSERT FAIL: project priority_driver_endpoint_id vacío")
	}
	if projectRow.RiskyEndpointCount < 2 {
		log.Fatalf("ASSERT FAIL: risky_endpoint_count = %d, esperado >= 2", projectRow.RiskyEndpointCount)
	}
	if projectRow.TechnicalDriverEndpointHostname != "endpoint-tech-driver-risk-test" {
		log.Fatalf("ASSERT FAIL: technical driver hostname = %s, esperado endpoint-tech-driver-risk-test", projectRow.TechnicalDriverEndpointHostname)
	}
	if projectRow.PriorityDriverEndpointHostname != "endpoint-priority-driver-risk-test" {
		log.Fatalf("ASSERT FAIL: priority driver hostname = %s, esperado endpoint-priority-driver-risk-test", projectRow.PriorityDriverEndpointHostname)
	}
	if projectRow.TechnicalDriverEndpointID == projectRow.PriorityDriverEndpointID {
		log.Fatalf("ASSERT FAIL: technical y priority driver deberían ser endpoints distintos")
	}

	var technicalDriverEndpoint endpointSummary
	var priorityDriverEndpoint endpointSummary
	for _, row := range endpointRows {
		if row.EndpointID == projectRow.TechnicalDriverEndpointID {
			technicalDriverEndpoint = row
		}
		if row.EndpointID == projectRow.PriorityDriverEndpointID {
			priorityDriverEndpoint = row
		}
	}

	if projectRow.RiskScore < technicalDriverEndpoint.RiskScore {
		log.Fatalf("ASSERT FAIL: project risk %.4f debe ser >= technical driver endpoint risk %.4f", projectRow.RiskScore, technicalDriverEndpoint.RiskScore)
	}
	if projectRow.PriorityScore < priorityDriverEndpoint.PriorityScore {
		log.Fatalf("ASSERT FAIL: project priority %.4f debe ser >= priority driver endpoint priority %.4f", projectRow.PriorityScore, priorityDriverEndpoint.PriorityScore)
	}

	fmt.Println("    ✓ project.risk_tier no está vacío")
	fmt.Println("    ✓ project.priority_tier no está vacío")
	fmt.Println("    ✓ project risk/priority timestamps persistidos")
	fmt.Println("    ✓ project technical_driver_endpoint_id persistido")
	fmt.Println("    ✓ project priority_driver_endpoint_id persistido")
	fmt.Println("    ✓ project.risky_endpoint_count >= 2")
	fmt.Println("    ✓ technical driver == endpoint-tech-driver-risk-test")
	fmt.Println("    ✓ priority driver == endpoint-priority-driver-risk-test")
	fmt.Println("    ✓ technical y priority driver son distintos")
	fmt.Println("    ✓ project.risk_score >= technical_driver_endpoint.risk_score")
	fmt.Println("    ✓ project.priority_score >= priority_driver_endpoint.priority_score")
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
