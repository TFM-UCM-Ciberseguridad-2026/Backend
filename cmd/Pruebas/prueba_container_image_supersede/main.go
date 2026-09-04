package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	repository "github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

const (
	testEndpointID  = int64(77991)
	testContainerID = "__test_supersede_container__"
	testOldImageID  = "__test_supersede_image_old__"
	testNewImageID  = "__test_supersede_image_new__"
	testCVEID       = "CVE-2099-77991"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("cargando configuración: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	driver, err := repository.NewDriver(ctx, cfg)
	if err != nil {
		return fmt.Errorf("conectando a Neo4j: %w", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, softwareRepo, softwareInstRepo, findingRepo, remediationRepo,
		_, hardwareRepo, networkRepo, patchRepo, projectRepo, dbHelper, relRepo, containerRepo := repository.NewRepository(driver)
	infraRepo := repository.NewInfrastructureRepository(driver)
	riskRepo := repository.NewRiskRepository(driver)

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
	).WithRisk(riskRepo, provider.NewEPSSAdapter(), provider.NewKEVAdapter())

	cleanup := func() {
		_ = dbHelper.ExecuteWrite(context.Background(), `
			MATCH (f:Finding)
			WHERE f.finding_key STARTS WITH $finding_prefix
			DETACH DELETE f
		`, map[string]any{"finding_prefix": testContainerID + "|"})
		_ = dbHelper.ExecuteWrite(context.Background(), `
			MATCH (n)
			WHERE n.id IN [$endpoint_id, $container_id, $old_image_id, $new_image_id]
			   OR n.cve_id = $cve_id
			DETACH DELETE n
		`, map[string]any{
			"endpoint_id":  testEndpointID,
			"container_id": testContainerID,
			"old_image_id": testOldImageID,
			"new_image_id": testNewImageID,
			"cve_id":       testCVEID,
		})
	}

	cleanup()
	defer cleanup()

	if err := dbHelper.ExecuteWrite(ctx, `
		CREATE (:Endpoint {
			id: $endpoint_id,
			hostname: 'supersede-test-host',
			status: 'ACTIVE'
		})
		CREATE (oldImage:ContainerImage {
			id: $old_image_id,
			name: $old_image_id
		})
		CREATE (v:Vulnerability {
			cve_id: $cve_id,
			base_score: 0.98
		})
		CREATE (oldImage)-[:HAS_VULNERABILITY]->(v)
	`, map[string]any{
		"endpoint_id":  testEndpointID,
		"old_image_id": testOldImageID,
		"cve_id":       testCVEID,
	}); err != nil {
		return fmt.Errorf("creando fixture: %w", err)
	}

	container := &domain.Container{
		ContainerID: testContainerID,
		Name:        "supersede-test-container",
		State:       "running",
		ImageID:     testOldImageID,
		HostID:      testEndpointID,
	}
	if err := orchestrator.SaveContainer(ctx, container); err != nil {
		return fmt.Errorf("guardando contenedor con imagen original: %w", err)
	}

	finding, created, err := findingRepo.EnsureForContainerImageContextAndCVE(
		ctx,
		testContainerID,
		testOldImageID,
		testCVEID,
		&domain.Finding{FindingID: 0, Status: "OPEN"},
	)
	if err != nil {
		return fmt.Errorf("recuperando finding contextual original: %w", err)
	}
	if created {
		return fmt.Errorf("el finding contextual no fue sincronizado al guardar el contenedor")
	}

	container.ImageID = testNewImageID
	if err := orchestrator.SaveContainer(ctx, container); err != nil {
		return fmt.Errorf("cambiando la imagen del contenedor: %w", err)
	}

	persistedFinding, err := findingRepo.GetByID(ctx, finding.FindingID)
	if err != nil {
		return fmt.Errorf("el finding histórico fue eliminado o no puede recuperarse: %w", err)
	}
	if persistedFinding.Status != "SUPERSEDED" {
		return fmt.Errorf("status=%q; esperado SUPERSEDED", persistedFinding.Status)
	}
	if persistedFinding.RemediationFactor != 0 || persistedFinding.RiskScore != 0 || persistedFinding.PriorityScore != 0 {
		return fmt.Errorf(
			"scores no invalidados: remediation_factor=%v risk_score=%v priority_score=%v",
			persistedFinding.RemediationFactor,
			persistedFinding.RiskScore,
			persistedFinding.PriorityScore,
		)
	}
	if persistedFinding.ResolvedAt == nil {
		return fmt.Errorf("resolved_at no fue persistido")
	}

	persistedContainer, err := containerRepo.GetContainer(ctx, testContainerID)
	if err != nil {
		return fmt.Errorf("recuperando contenedor actualizado: %w", err)
	}
	if persistedContainer.ImageID != testNewImageID {
		return fmt.Errorf("image_id=%q; esperado %q", persistedContainer.ImageID, testNewImageID)
	}

	activeFindings, err := riskRepo.GetDirectFindingScoresByContainer(ctx, testContainerID)
	if err != nil {
		return fmt.Errorf("consultando findings activos del contenedor: %w", err)
	}
	if len(activeFindings) != 0 {
		return fmt.Errorf("el finding SUPERSEDED continúa activo en riesgo: %+v", activeFindings)
	}

	affectedAgain, err := findingRepo.SupersedeContainerImageFindings(
		ctx,
		testContainerID,
		testOldImageID,
		time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("repitiendo invalidación: %w", err)
	}
	if affectedAgain != 0 {
		return fmt.Errorf("la invalidación no es idempotente: affected=%d", affectedAgain)
	}

	fmt.Printf("✓ Finding #%d conservado como SUPERSEDED\n", finding.FindingID)
	fmt.Println("✓ remediation_factor, risk_score y priority_score establecidos a 0")
	fmt.Println("✓ resolved_at persistido")
	fmt.Printf("✓ Contenedor actualizado de %s a %s\n", testOldImageID, testNewImageID)
	fmt.Println("✓ Finding SUPERSEDED excluido del riesgo activo")
	fmt.Println("✓ Invalidación idempotente")

	return nil
}
