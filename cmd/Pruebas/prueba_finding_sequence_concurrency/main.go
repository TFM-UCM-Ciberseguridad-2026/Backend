package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

const (
	testContainerID = "container-finding-sequence-concurrency"
	testImageID     = "sequence-test:1.0"
	testCVEOne      = "CVE-2099-99001"
	testCVETwo      = "CVE-2099-99002"
	testKeyPrefix   = testContainerID + "|"
)

type ensureResult struct {
	cve     string
	finding *domain.Finding
	created bool
	err     error
}

type saveResult struct {
	finding *domain.Finding
	err     error
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	fmt.Println("=== PRUEBA CONCURRENTE DE SECUENCIA finding_id ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("cargando configuración: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		return fmt.Errorf("conectando a Neo4j: %w", err)
	}
	defer driver.Close(ctx)

	_, _, _, _, findingRepo, _, _, _, _, _, _, dbHelper, _, _ := neo4j.NewRepository(driver)

	savedFindingIDs := make([]int64, 0, 2)
	cleanup := func() {
		_ = dbHelper.ExecuteWrite(ctx,
			"MATCH (f:Finding) WHERE f.finding_key STARTS WITH $prefix OR f.id IN $saved_ids DETACH DELETE f",
			map[string]any{
				"prefix":    testKeyPrefix,
				"saved_ids": savedFindingIDs,
			},
		)
		_ = dbHelper.ExecuteWrite(ctx,
			"MATCH (n) WHERE (n:Container AND n.id = $container_id) OR (n:ContainerImage AND n.id = $image_id) OR (n:Vulnerability AND n.cve_id IN $cve_ids) DETACH DELETE n",
			map[string]any{
				"container_id": testContainerID,
				"image_id":     testImageID,
				"cve_ids":      []string{testCVEOne, testCVETwo},
			},
		)
	}

	cleanup()
	defer cleanup()

	if err := dbHelper.ExecuteWrite(ctx,
		"MERGE (ci:ContainerImage {id: $image_id}) "+
			"MERGE (c:Container {id: $container_id}) "+
			"SET c.state = 'running', c.image_id = $image_id "+
			"MERGE (c)-[:USES_IMAGE]->(ci) "+
			"MERGE (:Vulnerability {cve_id: $cve_one}) "+
			"MERGE (:Vulnerability {cve_id: $cve_two})",
		map[string]any{
			"container_id": testContainerID,
			"image_id":     testImageID,
			"cve_one":      testCVEOne,
			"cve_two":      testCVETwo,
		},
	); err != nil {
		return fmt.Errorf("preparando datos: %w", err)
	}

	sequenceBefore, err := readSequence(ctx, dbHelper)
	if err != nil {
		return err
	}

	firstBatch := ensureConcurrently(ctx, findingRepo)
	firstIDs := make(map[string]int64, len(firstBatch))
	for _, result := range firstBatch {
		if result.err != nil {
			return fmt.Errorf("creando %s: %w", result.cve, result.err)
		}
		if !result.created || result.finding == nil || result.finding.FindingID <= 0 {
			return fmt.Errorf("%s no se creó con un ID válido", result.cve)
		}
		firstIDs[result.cve] = result.finding.FindingID
	}

	if firstIDs[testCVEOne] == firstIDs[testCVETwo] {
		return fmt.Errorf("los findings recibieron el mismo ID %d", firstIDs[testCVEOne])
	}

	sequenceAfterCreate, err := readSequence(ctx, dbHelper)
	if err != nil {
		return err
	}
	if sequenceAfterCreate-sequenceBefore != 2 {
		return fmt.Errorf(
			"crear dos findings consumió %d IDs; se esperaban 2",
			sequenceAfterCreate-sequenceBefore,
		)
	}

	retryBatch := ensureConcurrently(ctx, findingRepo)
	for _, result := range retryBatch {
		if result.err != nil {
			return fmt.Errorf("repitiendo %s: %w", result.cve, result.err)
		}
		if result.created {
			return fmt.Errorf("el reintento de %s creó un duplicado", result.cve)
		}
		if result.finding == nil || result.finding.FindingID != firstIDs[result.cve] {
			return fmt.Errorf("el reintento de %s cambió su ID", result.cve)
		}
	}

	sequenceAfterRetry, err := readSequence(ctx, dbHelper)
	if err != nil {
		return err
	}
	if sequenceAfterRetry != sequenceAfterCreate {
		return fmt.Errorf(
			"los reintentos incrementaron la secuencia de %d a %d",
			sequenceAfterCreate,
			sequenceAfterRetry,
		)
	}

	legacyFindings := []*domain.Finding{newFinding(), newFinding()}
	legacyResults := saveConcurrently(ctx, findingRepo, legacyFindings)
	for _, result := range legacyResults {
		if result.err != nil {
			return fmt.Errorf("guardando finding mediante Save: %w", result.err)
		}
		if result.finding == nil || result.finding.FindingID <= 0 {
			return fmt.Errorf("Save no asignó un finding_id válido")
		}
		savedFindingIDs = append(savedFindingIDs, result.finding.FindingID)
	}
	if savedFindingIDs[0] == savedFindingIDs[1] {
		return fmt.Errorf("Save asignó el mismo ID %d a dos findings", savedFindingIDs[0])
	}

	sequenceAfterSave, err := readSequence(ctx, dbHelper)
	if err != nil {
		return err
	}
	if sequenceAfterSave-sequenceAfterRetry != 2 {
		return fmt.Errorf("dos llamadas nuevas a Save no consumieron exactamente 2 IDs")
	}

	legacyRetryResults := saveConcurrently(ctx, findingRepo, legacyFindings)
	for _, result := range legacyRetryResults {
		if result.err != nil {
			return fmt.Errorf("repitiendo Save con ID asignado: %w", result.err)
		}
	}

	sequenceAfterSaveRetry, err := readSequence(ctx, dbHelper)
	if err != nil {
		return err
	}
	if sequenceAfterSaveRetry != sequenceAfterSave {
		return fmt.Errorf("repetir Save con IDs asignados consumió nueva secuencia")
	}

	if err := validateNoDuplicateIDs(ctx, dbHelper); err != nil {
		return err
	}

	fmt.Printf(
		"✓ IDs concurrentes distintos: %d y %d\n",
		firstIDs[testCVEOne],
		firstIDs[testCVETwo],
	)
	fmt.Println("✓ Los reintentos no consumen IDs ni crean findings nuevos")
	fmt.Printf("✓ Save concurrente asignó IDs distintos: %d y %d\n", savedFindingIDs[0], savedFindingIDs[1])
	fmt.Println("✓ Repetir Save con IDs asignados no consume secuencia")
	fmt.Println("✓ No existen Finding.id duplicados")
	fmt.Println("Nota: la limpieza elimina los nodos de prueba, pero no retrocede la secuencia monotónica.")
	return nil
}

func saveConcurrently(
	ctx context.Context,
	repo ports.FindingPort,
	findings []*domain.Finding,
) []saveResult {
	start := make(chan struct{})
	results := make(chan saveResult, len(findings))
	var waitGroup sync.WaitGroup

	for _, finding := range findings {
		finding := finding
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			results <- saveResult{finding: finding, err: repo.Save(ctx, finding)}
		}()
	}

	close(start)
	waitGroup.Wait()
	close(results)

	batch := make([]saveResult, 0, len(findings))
	for result := range results {
		batch = append(batch, result)
	}
	return batch
}

func newFinding() *domain.Finding {
	now := time.Now().UTC()
	return &domain.Finding{
		Status:            "OPEN",
		FirstSeen:         now,
		LastSeen:          &now,
		RemediationFactor: 1,
	}
}

func ensureConcurrently(ctx context.Context, repo ports.FindingPort) []ensureResult {
	cveIDs := []string{testCVEOne, testCVETwo}
	start := make(chan struct{})
	results := make(chan ensureResult, len(cveIDs))
	var waitGroup sync.WaitGroup

	for _, cveID := range cveIDs {
		cveID := cveID
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start

			now := time.Now().UTC()
			finding, created, err := repo.EnsureForContainerImageContextAndCVE(
				ctx,
				testContainerID,
				testImageID,
				cveID,
				&domain.Finding{
					Status:            "OPEN",
					FirstSeen:         now,
					LastSeen:          &now,
					RemediationFactor: 1,
				},
			)
			results <- ensureResult{
				cve:     cveID,
				finding: finding,
				created: created,
				err:     err,
			}
		}()
	}

	close(start)
	waitGroup.Wait()
	close(results)

	batch := make([]ensureResult, 0, len(cveIDs))
	for result := range results {
		batch = append(batch, result)
	}
	return batch
}

func readSequence(ctx context.Context, dbHelper ports.DatabaseHelper) (int64, error) {
	raw, err := dbHelper.ExecuteRead(
		ctx,
		"MATCH (seq:Sequence {name: 'finding_id'}) RETURN seq.value AS value",
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("leyendo secuencia: %w", err)
	}

	row, ok := raw.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("la secuencia finding_id no existe")
	}
	return toInt64(row["value"]), nil
}

func validateNoDuplicateIDs(ctx context.Context, dbHelper ports.DatabaseHelper) error {
	raw, err := dbHelper.ExecuteRead(
		ctx,
		"MATCH (f:Finding) WITH f.id AS finding_id, count(f) AS total "+
			"WHERE finding_id IS NOT NULL AND total > 1 "+
			"RETURN count(*) AS duplicate_ids",
		nil,
	)
	if err != nil {
		return fmt.Errorf("validando duplicados: %w", err)
	}

	row, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("respuesta inválida validando duplicados")
	}
	if duplicates := toInt64(row["duplicate_ids"]); duplicates != 0 {
		return fmt.Errorf("se encontraron %d Finding.id duplicados", duplicates)
	}
	return nil
}

func toInt64(value any) int64 {
	switch converted := value.(type) {
	case int64:
		return converted
	case int:
		return int64(converted)
	case float64:
		return int64(converted)
	default:
		return 0
	}
}
