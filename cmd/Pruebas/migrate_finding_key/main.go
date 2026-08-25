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

	fmt.Println("[1/5] Buscando grupos duplicados...")
	duplicatesRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WITH si.id AS installation_id,
					v.cve_id AS cve_id,
					count(f) AS total
			WHERE total > 1
			RETURN count(*) AS duplicate_groups
	`, nil)
	if err != nil {
		log.Fatalf("Error buscando duplicados: %v", err)
	}

	duplicateGroups := int64(0)
	if row, ok := duplicatesRaw.(map[string]any); ok {
		duplicateGroups = toInt64(row["duplicate_groups"])
	}

	if duplicateGroups > 0 {
		fmt.Printf("    ✗ Hay %d grupos duplicados.\n", duplicateGroups)
		fmt.Println("    Ejecuta esta query en Neo4j para verlos:")
		fmt.Print(`
MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
WITH si.id AS installation_id,
	v.cve_id AS cve_id,
	collect(f.id) AS finding_ids,
	count(f) AS total
WHERE total > 1
RETURN installation_id, cve_id, total, finding_ids
ORDER BY total DESC;
`)
		log.Fatalf("Limpia duplicados antes de crear finding_key/constraint")
	}
	fmt.Println("    ✓ No hay grupos duplicados")

	fmt.Println("[2/5] Migrando finding_key en findings existentes...")
	if err := dbHelper.ExecuteWrite(ctx, `
			MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(v:Vulnerability)
			WHERE f.finding_key IS NULL
			SET f.finding_key = si.id + '|' + v.cve_id
	`, nil); err != nil {
		log.Fatalf("Error migrando finding_key: %v", err)
	}
	fmt.Println("    ✓ finding_key migrado")

	fmt.Println("[3/5] Validando findings sin finding_key...")
	missingRaw, err := dbHelper.ExecuteRead(ctx, `
			MATCH (si:SoftwareInstallation)-[:HAS_FINDING]->(f:Finding)-[:OF_VULNERABILITY]->(:Vulnerability)
			WHERE f.finding_key IS NULL
			RETURN count(f) AS findings_without_key
	`, nil)
	if err != nil {
		log.Fatalf("Error validando finding_key: %v", err)
	}

	missingKeys := int64(0)
	if row, ok := missingRaw.(map[string]any); ok {
		missingKeys = toInt64(row["findings_without_key"])
	}

	if missingKeys > 0 {
		log.Fatalf("ASSERT FAIL: quedan %d findings sin finding_key", missingKeys)
	}
	fmt.Println("    ✓ Todos los findings de CVE tienen finding_key")

	fmt.Println("[4/5] Creando constraint única...")
	if err := dbHelper.ExecuteWrite(ctx, `
			CREATE CONSTRAINT finding_key_unique IF NOT EXISTS
			FOR (f:Finding)
			REQUIRE f.finding_key IS UNIQUE
	`, nil); err != nil {
		log.Fatalf("Error creando constraint: %v", err)
	}
	fmt.Println("    ✓ Constraint creada o ya existente")

	fmt.Println("[5/5] Validando constraint...")
	constraintsRaw, err := dbHelper.ExecuteRead(ctx, `
			SHOW CONSTRAINTS
			YIELD name
			WHERE name = 'finding_key_unique'
			RETURN count(*) AS total
	`, nil)
	if err != nil {
		log.Fatalf("Error validando constraint: %v", err)
	}

	constraints := int64(0)
	if row, ok := constraintsRaw.(map[string]any); ok {
		constraints = toInt64(row["total"])
	}

	if constraints == 0 {
		log.Fatalf("ASSERT FAIL: no se encontró finding_key_unique")
	}
	fmt.Println("    ✓ Constraint finding_key_unique validada")

	fmt.Println("\n✓ MIGRACIÓN COMPLETADA")
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
