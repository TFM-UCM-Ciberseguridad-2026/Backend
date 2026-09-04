package main

import (
	"context"
	"fmt"
	"log"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	driver, err := neo4j.NewDriverWithContext(cfg.Neo4jURI, neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""))
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(context.Background())

	ctx := context.Background()
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := `
		MATCH (c:Container)-[r:USES_IMAGE]->(old:ContainerImage)
		WITH c, old, r, c.id + '_' + coalesce(old.image_id, old.name, old.id) AS new_id, coalesce(old.image_id, old.name, old.id) AS img_name
		MERGE (new_ci:ContainerImage {id: new_id})
		ON CREATE SET new_ci.name = img_name, new_ci.image_id = img_name, new_ci.tag = old.tag, new_ci.digest = old.digest,
		              new_ci.vuln_scan_completed_at = old.vuln_scan_completed_at, new_ci.vuln_scan_processed = old.vuln_scan_processed
		ON MATCH SET new_ci.name = img_name, new_ci.image_id = img_name
		MERGE (c)-[:USES_IMAGE]->(new_ci)
		WITH old, r, new_ci
		OPTIONAL MATCH (old)-[:HAS_FINDING]->(f:Finding)
		WITH old, r, new_ci, collect(f) AS findings
		FOREACH (f IN findings | MERGE (new_ci)-[:HAS_FINDING]->(f))
		WITH old, r, new_ci
		OPTIONAL MATCH (old)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		WITH old, r, new_ci, collect(v) AS vulns
		FOREACH (v IN vulns | MERGE (new_ci)-[:HAS_VULNERABILITY]->(v))
		DELETE r
		WITH old
		WHERE NOT ()-[:USES_IMAGE]->(old)
		DETACH DELETE old
		WITH 1 AS dummy
		MATCH (orphan:ContainerImage) WHERE NOT ()-[:USES_IMAGE]->(orphan)
		DETACH DELETE orphan
	`

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, query, nil)
	})
	if err != nil {
		log.Fatalf("Error migrando nodos de ContainerImage: %v", err)
	}

	fmt.Println("¡Migración de nodos de ContainerImage completada con éxito!")
}
