package main

import (
	"context"
	"fmt"
	"log"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	drv "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error config: %v", err)
	}

	ctx := context.Background()
	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error neo4j: %v", err)
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, drv.SessionConfig{AccessMode: drv.AccessModeWrite})
	defer session.Close(ctx)

	// Inyectar infraestructura de prueba:
	// Project (id: 1) -> Endpoint (id: 1) -> SoftwareInstallation (id: "inst-1") -> Finding (id: 1) -> Vulnerability (cve_id: "CVE-DEMO-0001")
	// Y enlazar Vulnerability -> CWE-79 -> TTP "T1190" (que es explotado por muchos APTs en MITRE)
	query := `
		MERGE (p:Project {id: 1})
		SET p.name = "Demo Project"

		MERGE (e:Endpoint {id: 1})
		SET e.hostname = "demo-server"

		MERGE (p)-[:HAS_ENDPOINT]->(e)

		MERGE (si:SoftwareInstallation {id: "inst-1"})
		SET si.software_id = 1

		MERGE (e)-[:HAS_INSTALLATION]->(si)

		MERGE (f:Finding {id: 1})
		SET f.status = "OPEN"

		MERGE (si)-[:HAS_FINDING]->(f)

		MERGE (v:Vulnerability {cve_id: "CVE-DEMO-0001"})
		SET v.description = "Demo Vulnerability exploiting Exploit Public-Facing Application"

		MERGE (f)-[:OF_VULNERABILITY]->(v)

		MERGE (c:CWE {cwe_id: "CWE-79"})
		MERGE (v)-[:HAS_WEAKNESS]->(c)

		// Buscar el TTP T1190 en el catálogo y enlazarlo con CWE-79
		WITH c
		MATCH (t:TTP {ttp_id: "T1190"})
		MERGE (c)-[rel:MAPS_TO]->(t)
		SET rel.confidence = "high", rel.source = "cwe_mapping", rel.updated_at = timestamp()
	`

	_, err = session.ExecuteWrite(ctx, func(tx drv.ManagedTransaction) (interface{}, error) {
		return tx.Run(ctx, query, nil)
	})
	if err != nil {
		log.Fatalf("Error seeding demo infrastructure: %v", err)
	}

	fmt.Println("Demo infrastructure successfully seeded and linked to MITRE TTP T1190!")
}
