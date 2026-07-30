package main

// Prueba de integración end-to-end para la issue #20: recuperar parches por vulnerabilidad.
//
// Valida:
//   1. Se pueden recuperar los parches asociados a un CVE  (Patch)-[:FIXES]->(Vulnerability)
//   2. La deduplicación por URL evita nodos Patch repetidos entre escaneos sucesivos
//   3. release_date se persiste y se recupera correctamente
//   4. El motor de riesgo detecta has_patch por el camino FIXES (antes solo veía USES_PATCH),
//      lo que se refleja en el urgency_boost del finding (+0.10 por patch_available)
//   5. El provider externo (OSV.dev) aporta versiones corregidas y fecha de publicación,
//      que el NVD no da, y la versión corregida se propaga a Remediation.fixed_version
//   6. Un CVE que OSV no cubre (software propietario) devuelve nil sin error
//
// Requiere conexión a Internet: el paso 7 consulta api.osv.dev.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_patches

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
	projectID      = int64(9301)
	endpointID     = int64(9302)
	softwareID     = int64(9310)
	findingID      = int64(9320)
	remediationID  = int64(9330)
	installationID = "inst-patch-test"

	// CVE con parche disponible
	cveWithPatch = "CVE-2021-44228"
	// CVE sin ningún parche registrado: sirve de control negativo
	cveWithoutPatch = "CVE-FAKE-NOPATCH-01"
)

// Parches de prueba. La tercera entrada repite la URL de la primera a propósito:
// debe deduplicarse y no crear un nodo nuevo.
var testPatches = []domain.Patch{
	{
		Description: "Apache Log4j 2.15.0 release notes",
		URL:         "https://logging.apache.org/log4j/2.x/security.html",
	},
	{
		Description: "Commit de corrección en GitHub",
		URL:         "https://github.com/apache/logging-log4j2/commit/abc123",
	},
	{
		Description: "Duplicado exacto de la primera URL",
		URL:         "https://logging.apache.org/log4j/2.x/security.html",
	},
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║   PRUEBA ISSUE #20 – RECUPERACIÓN DE PARCHES         ║")
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

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo,
		_, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)
	riskRepo := neo4j.NewRiskRepository(driver)

	orchestrator := service.NewOrchestrator(
		projectRepo, endpointRepo, hardwareRepo, networkRepo,
		softwareInstRepo, softwareRepo, findingRepo, vulnRepo,
		remediationRepo, relRepo, infraRepo, containerRepo, patchRepo, dbHelper,
		provider.NewNistAPIAdapter(cfg.NVD.BaseURL, cfg.NVD.APIKey, cfg.NVD.TimeoutSeconds),
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter()).
		WithPatchProvider(provider.NewOSVAdapter())

	// ── 1. Limpieza ────────────────────────────────────────────────────────
	fmt.Println("\n[1/7] Limpiando datos previos de prueba...")
	for _, id := range []int64{projectID, endpointID, softwareID, findingID, remediationID} {
		_ = dbHelper.ExecuteWrite(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": id})
	}
	_ = dbHelper.ExecuteWrite(ctx,
		`MATCH (n) WHERE n.id IN [$inst] DETACH DELETE n`,
		map[string]any{"inst": installationID})
	// Borramos todo parche enlazado al CVE de prueba, no solo los de testPatches:
	// el paso 7 registra además los que devuelve OSV, y si sobrevivieran a la limpieza
	// la aserción de "exactamente 2 parches" fallaría en la siguiente ejecución.
	_ = dbHelper.ExecuteWrite(ctx,
		`MATCH (p:Patch)-[:FIXES]->(:Vulnerability {cve_id: $cve}) DETACH DELETE p`,
		map[string]any{"cve": cveWithPatch})
	// Y los de testPatches por URL, por si quedaron huérfanos de una ejecución fallida.
	for _, p := range testPatches {
		_ = dbHelper.ExecuteWrite(ctx,
			`MATCH (p:Patch {url: $url}) DETACH DELETE p`,
			map[string]any{"url": p.URL})
	}
	_ = dbHelper.ExecuteWrite(ctx,
		`MATCH (v:Vulnerability) WHERE v.cve_id IN [$c1, $c2] DETACH DELETE v`,
		map[string]any{"c1": cveWithPatch, "c2": cveWithoutPatch})
	fmt.Println("    ✓ Limpieza completada.")

	// ── 2. Infraestructura mínima ──────────────────────────────────────────
	fmt.Println("\n[2/7] Creando infraestructura de prueba...")
	now := time.Now().UTC()

	if err := orchestrator.CreateProject(ctx, &domain.Project{
		ProjectID: projectID, Nombre: "Patch Retrieval Test",
	}); err != nil {
		log.Fatalf("Error creando proyecto: %v", err)
	}

	endpoint := &domain.Endpoint{
		EndpointID:         endpointID,
		Hostname:           "srv-patch-test",
		Type:               "Linux",
		Status:             "ACTIVE",
		InternetExposed:    true,
		Environment:        "prod",
		ConfidentialityReq: "High",
		IntegrityReq:       "High",
		AvailabilityReq:    "High",
	}
	if err := orchestrator.AddEndpointToProject(ctx, projectID, endpoint); err != nil {
		log.Fatalf("Error creando endpoint: %v", err)
	}

	software := &domain.Software{
		SoftwareID: softwareID, Name: "log4j-core", Version: "2.14.1",
		Vendor: "apache", Type: "application",
	}
	installation := &domain.SoftwareInstallation{
		InstallationID: installationID, FirstSeen: now, Status: "INSTALLED",
	}
	if err := orchestrator.RegisterSoftwareInstallation(ctx, endpointID, software, installation); err != nil {
		log.Fatalf("Error registrando instalación: %v", err)
	}

	finding := &domain.Finding{
		FindingID: findingID, Status: "OPEN", FirstSeen: now, RemediationFactor: 1.0,
	}
	if err := orchestrator.GenerateFinding(ctx, installationID, finding); err != nil {
		log.Fatalf("Error creando finding: %v", err)
	}

	vulnerability := &domain.Vulnerability{
		VulnerabilityID: cveWithPatch,
		CVEID:           cveWithPatch,
		CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		BaseScore:       10.0,
	}
	remediation := &domain.Remediation{RemediationID: remediationID, Status: "OPEN"}
	if err := orchestrator.AssociateVulnerabilitiesAndRemediations(ctx, findingID, vulnerability, remediation); err != nil {
		log.Fatalf("Error vinculando vulnerabilidad: %v", err)
	}
	fmt.Println("    ✓ Endpoint, instalación, finding y CVE creados.")

	// ── 3. Registrar parches (primera pasada) ──────────────────────────────
	fmt.Println("\n[3/7] Registrando parches (primera pasada)...")
	releaseDate := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	patchesToRegister := make([]domain.Patch, len(testPatches))
	copy(patchesToRegister, testPatches)
	patchesToRegister[0].ReleaseDate = &releaseDate

	if err := orchestrator.RegisterPatchesForVulnerability(ctx, cveWithPatch, patchesToRegister); err != nil {
		log.Fatalf("Error registrando parches: %v", err)
	}
	fmt.Printf("    ✓ Enviados %d parches (2 URLs únicas + 1 duplicada).\n", len(patchesToRegister))

	// ── 4. Registrar de nuevo (simula un segundo escaneo) ──────────────────
	fmt.Println("\n[4/7] Repitiendo el registro (simula un segundo escaneo)...")
	if err := orchestrator.RegisterPatchesForVulnerability(ctx, cveWithPatch, patchesToRegister); err != nil {
		log.Fatalf("Error en el segundo registro: %v", err)
	}
	fmt.Println("    ✓ Segundo registro completado.")

	// ── 5. Recuperar y mostrar ─────────────────────────────────────────────
	fmt.Println("\n[5/7] Recuperando parches del CVE...")
	patches, err := orchestrator.GetPatchesForVulnerability(ctx, cveWithPatch)
	if err != nil {
		log.Fatalf("Error recuperando parches: %v", err)
	}

	fmt.Printf("\nPARCHES DE %s\n", cveWithPatch)
	for _, p := range patches {
		fmt.Printf("  ┌─ Patch #%d\n", p.PatchID)
		fmt.Printf("  │  Descripción : %s\n", p.Description)
		fmt.Printf("  │  URL         : %s\n", p.URL)
		if p.ReleaseDate != nil {
			fmt.Printf("  │  Release Date: %s\n", p.ReleaseDate.Format("2006-01-02"))
		} else {
			fmt.Printf("  │  Release Date: (no informada)\n")
		}
		fmt.Println("  └─")
	}

	noPatches, err := orchestrator.GetPatchesForVulnerability(ctx, cveWithoutPatch)
	if err != nil {
		log.Fatalf("Error recuperando parches del CVE de control: %v", err)
	}
	fmt.Printf("\nCVE de control %s → %d parches\n", cveWithoutPatch, len(noPatches))

	// ── 6. Aserciones ──────────────────────────────────────────────────────
	fmt.Println("\n[6/7] Validando aserciones...")

	if len(patches) != 2 {
		log.Fatalf("ASSERT FAIL: se esperaban 2 parches únicos, recibidos %d (deduplicación por URL rota)", len(patches))
	}
	fmt.Println("    ✓ Se recuperan exactamente 2 parches únicos (URL duplicada deduplicada)")

	fmt.Println("    ✓ Un segundo registro no crea nodos Patch adicionales")

	if len(noPatches) != 0 {
		log.Fatalf("ASSERT FAIL: el CVE de control debería tener 0 parches, tiene %d", len(noPatches))
	}
	fmt.Println("    ✓ Un CVE sin parches devuelve lista vacía, no error")

	var withDate *domain.Patch
	for i := range patches {
		if patches[i].URL == testPatches[0].URL {
			withDate = &patches[i]
		}
		if patches[i].URL == "" {
			log.Fatalf("ASSERT FAIL: parche #%d sin URL persistida", patches[i].PatchID)
		}
		if patches[i].PatchID == 0 {
			log.Fatalf("ASSERT FAIL: parche sin ID asignado")
		}
	}
	if withDate == nil {
		log.Fatalf("ASSERT FAIL: no se encontró el parche con release_date")
	}
	if withDate.ReleaseDate == nil {
		log.Fatalf("ASSERT FAIL: release_date no se persistió")
	}
	if !withDate.ReleaseDate.UTC().Equal(releaseDate) {
		log.Fatalf("ASSERT FAIL: release_date = %v, esperado %v", withDate.ReleaseDate.UTC(), releaseDate)
	}
	fmt.Println("    ✓ release_date se persiste y se recupera correctamente")

	// El motor de riesgo debe ver el parche por el camino FIXES
	if err := orchestrator.ComputeEndpointRisk(ctx, endpointID); err != nil {
		log.Fatalf("Error calculando riesgo: %v", err)
	}

	res, err := dbHelper.ExecuteRead(ctx,
		`MATCH (f:Finding {id: $id}) RETURN f.urgency_boost AS urgency`,
		map[string]any{"id": findingID})
	if err != nil {
		log.Fatalf("Error leyendo urgency_boost: %v", err)
	}

	urgency := 0.0
	if m, ok := res.(map[string]any); ok {
		urgency, _ = m["urgency"].(float64)
	}

	// Log4Shell: impact ≥ 0.95 (+0.50) + KEV (+0.30) + patch disponible (+0.10) = 1.90
	// Sin la corrección del camino FIXES el patch_available no se aplicaría y daría 1.80.
	fmt.Printf("\n    urgency_boost del finding: %.4f\n", urgency)
	if urgency < 1.90 {
		log.Fatalf("ASSERT FAIL: urgency_boost = %.4f; se esperaba ≥ 1.90 (el +0.10 de patch_available no se está aplicando)", urgency)
	}
	fmt.Println("    ✓ El motor de riesgo detecta has_patch por el camino (Patch)-[:FIXES]->(Vulnerability)")

	// ── 7. Fuente externa de parches (OSV) ─────────────────────────────────
	fmt.Println("\n[7/7] Consultando la fuente externa OSV.dev...")

	info, err := orchestrator.EnrichPatchesFromProvider(ctx, cveWithPatch)
	if err != nil {
		log.Fatalf("Error consultando OSV: %v", err)
	}
	if info == nil {
		log.Fatalf("ASSERT FAIL: OSV debería cubrir %s (es un CVE de Maven/Log4j)", cveWithPatch)
	}

	fmt.Printf("\nOSV → %s\n", info.CVEID)
	fmt.Printf("  Fuente            : %s\n", info.Source)
	if info.Published != nil {
		fmt.Printf("  Publicado         : %s\n", info.Published.Format("2006-01-02"))
	}
	fmt.Printf("  Versiones corregidas: %v\n", info.FixedVersions)
	fmt.Printf("  Referencias FIX   : %d\n", len(info.Patches))

	if len(info.FixedVersions) == 0 {
		log.Fatalf("ASSERT FAIL: OSV no devolvió ninguna versión corregida para %s", cveWithPatch)
	}
	fmt.Printf("    ✓ OSV aporta %d versiones corregidas (el NVD no da ninguna)\n", len(info.FixedVersions))

	if info.Published == nil {
		log.Fatalf("ASSERT FAIL: OSV no devolvió fecha de publicación")
	}
	fmt.Println("    ✓ OSV aporta fecha de publicación (el NVD no la da por referencia)")

	// La versión corregida debe haberse propagado a la remediación del finding
	remRes, err := dbHelper.ExecuteRead(ctx,
		`MATCH (rem:Remediation {id: $id}) RETURN rem.fixed_version AS fv`,
		map[string]any{"id": remediationID})
	if err != nil {
		log.Fatalf("Error leyendo fixed_version: %v", err)
	}

	persistedFixedVersion := ""
	if m, ok := remRes.(map[string]any); ok {
		persistedFixedVersion, _ = m["fv"].(string)
	}
	fmt.Printf("\n    Remediation.fixed_version persistido: %q\n", persistedFixedVersion)
	if persistedFixedVersion == "" {
		log.Fatalf("ASSERT FAIL: fixed_version no se propagó a la remediación")
	}
	fmt.Println("    ✓ La versión corregida se propaga a Remediation.fixed_version")

	// Control negativo: OSV no cubre software propietario (CVE de Microsoft)
	msInfo, err := orchestrator.EnrichPatchesFromProvider(ctx, "CVE-2021-34527")
	if err != nil {
		log.Fatalf("ASSERT FAIL: un CVE no cubierto no debe devolver error, devolvió: %v", err)
	}
	if msInfo != nil {
		fmt.Println("    · Nota: OSV ahora sí cubre CVE-2021-34527 (PrintNightmare)")
	} else {
		fmt.Println("    ✓ Un CVE no cubierto (PrintNightmare, Microsoft) devuelve nil sin error")
	}

	fmt.Println("\n✓ PRUEBA ISSUE #20 COMPLETADA")
}
