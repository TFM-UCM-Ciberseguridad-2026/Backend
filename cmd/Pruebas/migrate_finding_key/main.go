package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

func main() {
	fmt.Println("=== MIGRACIÓN finding_key PARA FINDINGS ===")

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

	_, _, _, _, _, _, _, _, _, _, _, dbHelper, _, _ := neo4j.NewRepository(driver)

	fmt.Println("[1/10] Inicializando secuencia finding_id...")

	if err := dbHelper.ExecuteWrite(ctx, `
			MATCH (f:Finding)
			WITH coalesce(max(f.id), 0) AS max_finding_id

			MERGE (seq:Sequence {name: 'finding_id'})
			ON CREATE SET seq.value = max_finding_id
			ON MATCH SET seq.value =
					CASE
							WHEN coalesce(seq.value, 0) < max_finding_id
							THEN max_finding_id
							ELSE seq.value
					END
	`, nil); err != nil {
		log.Fatalf("Error inicializando secuencia finding_id: %v", err)
	}

	fmt.Println("    ✓ Secuencia finding_id inicializada")

	fmt.Println("[2/10] Buscando findings de instalaciones duplicados...")

	installationDuplicatesRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WITH
					toString(si.id) AS installation_id,
					toUpper(trim(v.cve_id)) AS cve_id,
					collect(f.id) AS finding_ids,
					count(f) AS total
			WHERE total > 1
			RETURN count(*) AS duplicate_groups
	`, nil)
	if err != nil {
		log.Fatalf("Error buscando duplicados de instalaciones: %v", err)
	}

	installationDuplicateGroups := int64(0)
	if row, ok := installationDuplicatesRaw.(map[string]any); ok {
		installationDuplicateGroups = toInt64(row["duplicate_groups"])
	}

	if installationDuplicateGroups > 0 {
		fmt.Printf(
			"    ✗ Hay %d grupos duplicados en instalaciones.\n",
			installationDuplicateGroups,
		)
		fmt.Println("    Ejecuta esta query en Neo4j para inspeccionarlos:")
		fmt.Print(`
MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
WITH
	toString(si.id) AS installation_id,
	toUpper(trim(v.cve_id)) AS cve_id,
	collect(f.id) AS finding_ids,
	count(f) AS total
WHERE total > 1
RETURN installation_id, cve_id, total, finding_ids
ORDER BY total DESC;
`)
		log.Fatalf("Resuelve los duplicados de instalaciones antes de continuar")
	}

	fmt.Println("    ✓ No hay findings duplicados en instalaciones")

	fmt.Println("[3/10] Buscando findings contextuales de contenedores duplicados...")

	containerDuplicatesRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (c:Container)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE f.context_type = 'CONTAINER_IMAGE'

			WITH
					f,
					coalesce(f.container_id, c.id) AS container_id,
					coalesce(
							f.image_id,
							head([(c)-[:USES_IMAGE]->(ci:ContainerImage) | ci.id])
					) AS image_id,
					toUpper(trim(v.cve_id)) AS cve_id

			WHERE container_id IS NOT NULL
				AND image_id IS NOT NULL
				AND cve_id IS NOT NULL

			WITH
					trim(toString(container_id)) + '|' +
					trim(toString(image_id)) + '|' +
					cve_id AS proposed_key,
					collect(f.id) AS finding_ids,
					count(f) AS total

			WHERE total > 1

			RETURN count(*) AS duplicate_groups
	`, nil)
	if err != nil {
		log.Fatalf("Error buscando duplicados contextuales: %v", err)
	}

	containerDuplicateGroups := int64(0)
	if row, ok := containerDuplicatesRaw.(map[string]any); ok {
		containerDuplicateGroups = toInt64(row["duplicate_groups"])
	}

	if containerDuplicateGroups > 0 {
		fmt.Printf(
			"    ✗ Hay %d grupos contextuales duplicados.\n",
			containerDuplicateGroups,
		)
		fmt.Println("    Ejecuta esta query en Neo4j para inspeccionarlos:")
		fmt.Print(`
MATCH (c:Container)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
WHERE f.context_type = 'CONTAINER_IMAGE'

WITH
	f,
	coalesce(f.container_id, c.id) AS container_id,
	coalesce(
			f.image_id,
			head([(c)-[:USES_IMAGE]->(ci:ContainerImage) | ci.id])
	) AS image_id,
	toUpper(trim(v.cve_id)) AS cve_id

WHERE container_id IS NOT NULL
AND image_id IS NOT NULL
AND cve_id IS NOT NULL

WITH
	trim(toString(container_id)) + '|' +
	trim(toString(image_id)) + '|' +
	cve_id AS proposed_key,
	collect(f.id) AS finding_ids,
	count(f) AS total

WHERE total > 1

RETURN proposed_key, total, finding_ids
ORDER BY total DESC;
`)
		log.Fatalf("Resuelve los duplicados contextuales antes de continuar")
	}

	fmt.Println("    ✓ No hay findings contextuales duplicados")

	fmt.Println("[4/10] Migrando finding_key de instalaciones...")

	if err := dbHelper.ExecuteWrite(ctx, `
			MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE f.finding_key IS NULL
				AND si.id IS NOT NULL
				AND v.cve_id IS NOT NULL

			SET f.finding_key =
					trim(toString(si.id)) + '|' +
					toUpper(trim(v.cve_id))
	`, nil); err != nil {
		log.Fatalf("Error migrando finding_key de instalaciones: %v", err)
	}

	fmt.Println("    ✓ finding_key de instalaciones migrado")

	fmt.Println("[5/10] Migrando finding_key de contenedores...")

	if err := dbHelper.ExecuteWrite(ctx, `
			MATCH (c:Container)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE f.context_type = 'CONTAINER_IMAGE'
				AND f.finding_key IS NULL

			WITH
					f,
					v,
					coalesce(f.container_id, c.id) AS container_id,
					coalesce(
							f.image_id,
							head([(c)-[:USES_IMAGE]->(ci:ContainerImage) | ci.id])
					) AS image_id

			WHERE container_id IS NOT NULL
				AND image_id IS NOT NULL
				AND v.cve_id IS NOT NULL

			SET
					f.container_id = trim(toString(container_id)),
					f.image_id = trim(toString(image_id)),
					f.finding_key =
							trim(toString(container_id)) + '|' +
							trim(toString(image_id)) + '|' +
							toUpper(trim(v.cve_id))
	`, nil); err != nil {
		log.Fatalf("Error migrando finding_key contextual: %v", err)
	}

	fmt.Println("    ✓ finding_key contextual migrado")

	fmt.Println("[6/10] Validando findings de instalaciones sin finding_key...")

	missingInstallationRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(:Vulnerability)
			WHERE f.finding_key IS NULL
			RETURN count(DISTINCT f) AS findings_without_key
	`, nil)
	if err != nil {
		log.Fatalf("Error validando finding_key de instalaciones: %v", err)
	}

	missingInstallationKeys := int64(0)
	if row, ok := missingInstallationRaw.(map[string]any); ok {
		missingInstallationKeys = toInt64(row["findings_without_key"])
	}

	if missingInstallationKeys > 0 {
		log.Fatalf(
			"ASSERT FAIL: quedan %d findings de instalaciones sin finding_key",
			missingInstallationKeys,
		)
	}

	fmt.Println("    ✓ Todos los findings de instalaciones tienen finding_key")

	fmt.Println("[7/10] Validando findings contextuales sin finding_key...")

	missingContainerRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (c:Container)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(:Vulnerability)
			WHERE f.context_type = 'CONTAINER_IMAGE'
				AND f.finding_key IS NULL
			RETURN count(DISTINCT f) AS findings_without_key
	`, nil)
	if err != nil {
		log.Fatalf("Error validando finding_key contextual: %v", err)
	}

	missingContainerKeys := int64(0)
	if row, ok := missingContainerRaw.(map[string]any); ok {
		missingContainerKeys = toInt64(row["findings_without_key"])
	}

	if missingContainerKeys > 0 {
		log.Fatalf(
			"ASSERT FAIL: quedan %d findings contextuales sin finding_key",
			missingContainerKeys,
		)
	}

	fmt.Println("    ✓ Todos los findings contextuales tienen finding_key")

	fmt.Println("[8/10] Validando finding_key e IDs duplicados...")

	duplicateKeysRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (f:Finding)
			WHERE f.finding_key IS NOT NULL
			WITH f.finding_key AS finding_key, collect(f.id) AS finding_ids, count(f) AS total
			WHERE total > 1
			RETURN count(*) AS duplicate_keys
	`, nil)
	if err != nil {
		log.Fatalf("Error validando claves duplicadas: %v", err)
	}

	duplicateKeys := int64(0)
	if row, ok := duplicateKeysRaw.(map[string]any); ok {
		duplicateKeys = toInt64(row["duplicate_keys"])
	}

	if duplicateKeys > 0 {
		fmt.Printf("    ✗ Hay %d finding_key duplicadas.\n", duplicateKeys)
		fmt.Println("    Ejecuta esta query en Neo4j para inspeccionarlas:")
		fmt.Print(`
MATCH (f:Finding)
WHERE f.finding_key IS NOT NULL
WITH f.finding_key AS finding_key, collect(f.id) AS finding_ids, count(f) AS total
WHERE total > 1
RETURN finding_key, total, finding_ids
ORDER BY total DESC;
`)
		log.Fatalf("No se puede crear la constraint con finding_key duplicadas")
	}

	duplicateIDsRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (f:Finding)
			WHERE f.id IS NOT NULL
			WITH f.id AS finding_id, count(f) AS total
			WHERE total > 1
			RETURN count(*) AS duplicate_ids
	`, nil)
	if err != nil {
		log.Fatalf("Error validando finding_id duplicados: %v", err)
	}

	duplicateIDs := int64(0)
	if row, ok := duplicateIDsRaw.(map[string]any); ok {
		duplicateIDs = toInt64(row["duplicate_ids"])
	}

	if duplicateIDs > 0 {
		fmt.Printf("    ✗ Hay %d finding_id duplicados.\n", duplicateIDs)
		fmt.Println("    Ejecuta esta query en Neo4j para inspeccionarlos:")
		fmt.Print(`
MATCH (f:Finding)
WHERE f.id IS NOT NULL
WITH f.id AS finding_id, collect(f.finding_key) AS finding_keys, count(f) AS total
WHERE total > 1
RETURN finding_id, total, finding_keys
ORDER BY total DESC;
`)
		log.Fatalf("No se puede crear la constraint con finding_id duplicados")
	}

	fmt.Println("    ✓ No hay finding_key ni finding_id duplicados")

	fmt.Println("[9/10] Creando constraints únicas...")

	if err := dbHelper.ExecuteWrite(ctx, `
			CREATE CONSTRAINT finding_key_unique IF NOT EXISTS
			FOR (f:Finding)
			REQUIRE f.finding_key IS UNIQUE
	`, nil); err != nil {
		log.Fatalf("Error creando constraint: %v", err)
	}

	if err := dbHelper.ExecuteWrite(ctx, `
			CREATE CONSTRAINT finding_id_unique IF NOT EXISTS
			FOR (f:Finding)
			REQUIRE f.id IS UNIQUE
	`, nil); err != nil {
		log.Fatalf("Error creando constraint finding_id_unique: %v", err)
	}

	fmt.Println("    ✓ Constraints creadas o ya existentes")

	fmt.Println("[10/10] Validando constraints...")

	constraintsRaw, err := dbHelper.ExecuteRead(ctx, `
			SHOW CONSTRAINTS
			YIELD name, type
			WHERE name IN ['finding_key_unique', 'finding_id_unique']
			RETURN collect(name) AS names, count(*) AS total
	`, nil)
	if err != nil {
		log.Fatalf("Error validando constraint: %v", err)
	}

	constraints := int64(0)
	if row, ok := constraintsRaw.(map[string]any); ok {
		constraints = toInt64(row["total"])
	}

	if constraints != 2 {
		log.Fatalf("ASSERT FAIL: se esperaban 2 constraints de Finding y se encontraron %d", constraints)
	}

	fmt.Println("    ✓ Constraints finding_key_unique y finding_id_unique validadas")
	fmt.Println("\n✓ MIGRACIÓN COMPLETADA")
}

func toInt64(value any) int64 {
	switch converted := value.(type) {
	case int64:
		return converted
	case int:
		return int64(converted)
	case int32:
		return int64(converted)
	case float64:
		return int64(converted)
	case float32:
		return int64(converted)
	default:
		return 0
	}
}
