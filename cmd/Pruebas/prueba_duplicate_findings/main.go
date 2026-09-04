package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

const (
	projectID      int64  = 9901
	endpointID     int64  = 9902
	softwareID     int64  = 9903
	installationID string = "inst-duplicate-findings-tomcat"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║     PRUEBA – FINDINGS IDEMPOTENTES POR CVE/INST     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo,
		_, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo :=
		neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)

	orchestrator := service.NewOrchestrator(
		projectRepo,
		endpointRepo,
		hardwareRepo,
		networkRepo,
		softwareInstRepo,
		softwareRepo,
		findingRepo,
		vulnRepo,
		remediationRepo,
		relRepo,
		infraRepo,
		containerRepo,
		patchRepo,
		dbHelper,
		provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds),
	)

	fmt.Println("\n[1/6] Limpiando datos previos...")
	clean(ctx, dbHelper)
	fmt.Println("    ✓ Limpieza completada")

	fmt.Println("\n[2/6] Creando proyecto, endpoint e instalación...")
	now := time.Now().UTC()

	if err := orchestrator.CreateProject(ctx, &domain.Project{
		ProjectID: projectID,
		Nombre:    "Duplicate Findings Test",
	}); err != nil {
		log.Fatalf("Proyecto: %v", err)
	}

	endpoint := &domain.Endpoint{
		EndpointID:         endpointID,
		Hostname:           "duplicate-findings-tomcat",
		Type:               "Linux",
		Status:             "ACTIVE",
		InternetExposed:    true,
		Environment:        "production",
		ConfidentialityReq: "High",
		IntegrityReq:       "High",
		AvailabilityReq:    "Medium",
	}
	if err := orchestrator.AddEndpointToProject(ctx, projectID, endpoint); err != nil {
		log.Fatalf("Endpoint: %v", err)
	}

	software := &domain.Software{
		SoftwareID: softwareID,
		Name:       "tomcat",
		Version:    "9.0.37",
		Vendor:     "apache",
		Type:       "application",
		CPE:        "cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*",
	}
	installation := &domain.SoftwareInstallation{
		InstallationID: installationID,
		FirstSeen:      now,
		Status:         "INSTALLED",
		InstallPath:    "/opt/tomcat",
		DetectedBy:     "test",
		PackageManager: "manual",
	}
	if err := orchestrator.RegisterSoftwareInstallation(ctx, endpointID, software, installation); err != nil {
		log.Fatalf("Software installation: %v", err)
	}
	fmt.Println("    ✓ Infraestructura creada")

	fmt.Println("\n[3/6] Ejecutando primer AutoScan...")
	if _, err := orchestrator.AutoScanAndRegisterVulnerabilities(ctx, installationID, softwareID, domain.VulnerabilityScanOptions{Limit: 20}); err != nil {
		log.Fatalf("Primer scan: %v", err)
	}

	findingsFirst := countFindings(ctx, dbHelper)
	duplicatedFirst := countDuplicatedCVEs(ctx, dbHelper)
	badKeysFirst := countBadKeys(ctx, dbHelper)

	fmt.Printf("    Findings tras primer scan: %d\n", findingsFirst)

	if findingsFirst <= 0 {
		log.Fatalf("ASSERT FAIL: el primer scan debería crear findings")
	}
	if duplicatedFirst != 0 {
		log.Fatalf("ASSERT FAIL: duplicados tras primer scan = %d", duplicatedFirst)
	}
	if badKeysFirst != 0 {
		log.Fatalf("ASSERT FAIL: finding_key incorrectas tras primer scan = %d", badKeysFirst)
	}

	fmt.Println("\n[4/6] Ejecutando segundo AutoScan sobre la misma instalación...")
	if _, err := orchestrator.AutoScanAndRegisterVulnerabilities(ctx, installationID, softwareID, domain.VulnerabilityScanOptions{Limit: 20}); err != nil {
		log.Fatalf("Segundo scan: %v", err)
	}

	findingsSecond := countFindings(ctx, dbHelper)
	duplicatedSecond := countDuplicatedCVEs(ctx, dbHelper)
	badKeysSecond := countBadKeys(ctx, dbHelper)

	fmt.Printf("    Findings tras segundo scan: %d\n", findingsSecond)

	if findingsSecond != findingsFirst {
		log.Fatalf("ASSERT FAIL: el segundo scan duplicó findings: %d -> %d", findingsFirst, findingsSecond)
	}
	if duplicatedSecond != 0 {
		log.Fatalf("ASSERT FAIL: duplicados tras segundo scan = %d", duplicatedSecond)
	}
	if badKeysSecond != 0 {
		log.Fatalf("ASSERT FAIL: finding_key incorrectas tras segundo scan = %d", badKeysSecond)
	}
	fmt.Println("    ✓ El segundo scan no duplica findings")

	fmt.Println("\n[5/6] Verificando que un PATCHED no se reabre...")
	patchedCVE := markFirstFindingAsPatched(ctx, dbHelper)
	if patchedCVE == "" {
		log.Fatalf("ASSERT FAIL: no se pudo marcar finding como PATCHED")
	}
	fmt.Printf("    CVE marcada como PATCHED: %s\n", patchedCVE)

	if _, err := orchestrator.AutoScanAndRegisterVulnerabilities(ctx, installationID, softwareID, domain.VulnerabilityScanOptions{Limit: 20}); err != nil {
		log.Fatalf("Tercer scan: %v", err)
	}

	status, remediationFactor, riskScore, priorityScore := readFindingState(ctx, dbHelper, patchedCVE)
	fmt.Printf(
		"    Estado tras re-scan: status=%s RF=%.2f risk=%.4f priority=%.4f\n",
		status,
		remediationFactor,
		riskScore,
		priorityScore,
	)

	if status != "PATCHED" {
		log.Fatalf("ASSERT FAIL: el re-scan reabrió el finding, status=%s", status)
	}
	if remediationFactor != 0.0 {
		log.Fatalf("ASSERT FAIL: remediation_factor = %.2f, esperado 0.0", remediationFactor)
	}
	if riskScore != 0.0 || priorityScore != 0.0 {
		log.Fatalf("ASSERT FAIL: scores parcheados no se mantienen a cero: risk=%.4f priority=%.4f", riskScore,
			priorityScore)
	}
	fmt.Println("    ✓ El finding PATCHED no se reabre")

	fmt.Println("\n[6/6] Validación final...")
	findingsFinal := countFindings(ctx, dbHelper)
	duplicatedFinal := countDuplicatedCVEs(ctx, dbHelper)
	badKeysFinal := countBadKeys(ctx, dbHelper)

	if findingsFinal != findingsFirst {
		log.Fatalf("ASSERT FAIL: findings finales cambiaron: %d -> %d", findingsFirst, findingsFinal)
	}
	if duplicatedFinal != 0 {
		log.Fatalf("ASSERT FAIL: duplicados finales = %d", duplicatedFinal)
	}
	if badKeysFinal != 0 {
		log.Fatalf("ASSERT FAIL: finding_key incorrectas finales = %d", badKeysFinal)
	}

	fmt.Println("    ✓ No hay duplicados finales")
	fmt.Println("    ✓ Todas las finding_key son correctas")
	fmt.Println("\n✓ PRUEBA COMPLETADA")
}

func clean(ctx context.Context, db ports.DatabaseHelper) {
	if err := db.ExecuteWrite(ctx, `
			MATCH (p:Project {id: $project_id})
			OPTIONAL MATCH (p)-[:HAS_ENDPOINT]->(e)
			OPTIONAL MATCH (e)-[:HAS_INSTALLATION]->(si)
			OPTIONAL MATCH (si)-[:INSTANCE_OF]->(s)
			OPTIONAL MATCH (si)-[:HAS_FINDING]->(f)
			OPTIONAL MATCH (f)-[:HAS_REMEDIATION]->(r)
			WITH collect(p) + collect(e) + collect(si) + collect(s) + collect(f) + collect(r) AS nodes
			UNWIND nodes AS n
			WITH DISTINCT n
			WHERE n IS NOT NULL
			DETACH DELETE n
	`, map[string]any{"project_id": projectID}); err != nil {
		log.Fatalf("clean project: %v", err)
	}

	if err := db.ExecuteWrite(ctx, `
			MATCH (n)
			WHERE n.id IN [$project_id, $endpoint_id, $software_id]
				OR n.id = $installation_id
				OR n.hostname = 'duplicate-findings-tomcat'
				OR n.nombre = 'Duplicate Findings Test'
			DETACH DELETE n
	`, map[string]any{
		"project_id":      projectID,
		"endpoint_id":     endpointID,
		"software_id":     softwareID,
		"installation_id": installationID,
	}); err != nil {
		log.Fatalf("clean orphan nodes: %v", err)
	}
}

func countFindings(ctx context.Context, db ports.DatabaseHelper) int64 {
	row := mustReadMap(ctx, db, `
			MATCH (:SoftwareInstallation {id: $installation_id})-[:HAS_FINDING]->(f:Finding)
			RETURN count(f) AS total
	`, map[string]any{"installation_id": installationID}, "countFindings")

	return toInt64(row["total"])
}

func countDuplicatedCVEs(ctx context.Context, db ports.DatabaseHelper) int64 {
	row := mustReadMap(ctx, db, `
			MATCH (:SoftwareInstallation {id:
			$installation_id})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WITH v.cve_id AS cve_id, count(f) AS total
			WHERE total > 1
			RETURN count(cve_id) AS duplicated
	`, map[string]any{"installation_id": installationID}, "countDuplicatedCVEs")

	return toInt64(row["duplicated"])
}

func countBadKeys(ctx context.Context, db ports.DatabaseHelper) int64 {
	row := mustReadMap(ctx, db, `
			MATCH (:SoftwareInstallation {id:
			$installation_id})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE f.finding_key IS NULL OR f.finding_key <> $installation_id + '|' + v.cve_id
			RETURN count(f) AS bad_keys
	`, map[string]any{"installation_id": installationID}, "countBadKeys")

	return toInt64(row["bad_keys"])
}

func markFirstFindingAsPatched(ctx context.Context, db ports.DatabaseHelper) string {
	row := mustReadMap(ctx, db, `
			MATCH (:SoftwareInstallation {id:
			$installation_id})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			RETURN f.id AS finding_id, v.cve_id AS cve_id
			ORDER BY v.cve_id
			LIMIT 1
	`, map[string]any{"installation_id": installationID}, "markFirstFindingAsPatched read")

	findingID := toInt64(row["finding_id"])
	cveID := toString(row["cve_id"])

	if findingID == 0 || cveID == "" {
		return ""
	}

	if err := db.ExecuteWrite(ctx, `
			MATCH (f:Finding {id: $finding_id})
			SET f.status = 'PATCHED',
				f.remediation_factor = 0.0,
				f.risk_score = 0.0,
				f.priority_score = 0.0,
				f.resolved_at = datetime()
	`, map[string]any{"finding_id": findingID}); err != nil {
		log.Fatalf("markFirstFindingAsPatched write: %v", err)
	}

	return cveID
}

func readFindingState(ctx context.Context, db ports.DatabaseHelper, cveID string) (string, float64, float64,
	float64) {
	row := mustReadMap(ctx, db, `
			MATCH (:SoftwareInstallation {id:
			$installation_id})-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(:Vulnerability {cve_id: $cve_id})
			RETURN f.status AS status,
					f.remediation_factor AS remediation_factor,
					f.risk_score AS risk_score,
					f.priority_score AS priority_score
	`, map[string]any{
		"installation_id": installationID,
		"cve_id":          cveID,
	}, "readFindingState")

	return toString(row["status"]),
		toFloat64(row["remediation_factor"]),
		toFloat64(row["risk_score"]),
		toFloat64(row["priority_score"])
}

func mustReadMap(ctx context.Context, db ports.DatabaseHelper, query string, params map[string]any, label string) map[string]any {
	raw, err := db.ExecuteRead(ctx, query, params)
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}

	row, ok := raw.(map[string]any)
	if !ok || row == nil {
		log.Fatalf("%s: respuesta vacía o inesperada", label)
	}

	return row
}

func toInt64(v any) int64 {
	switch value := v.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func toFloat64(v any) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case int64:
		return float64(value)
	case int:
		return float64(value)
	default:
		return 0
	}
}

func toString(v any) string {
	if value, ok := v.(string); ok {
		return value
	}
	return ""
}
