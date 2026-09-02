package main

import (
	"context"
	"fmt"
	"log"

	driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	ctx := context.Background()
	d, err := driver.NewDriverWithContext("bolt://localhost:7687", driver.BasicAuth("neo4j", "password", ""))
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close(ctx)

	session := d.NewSession(ctx, driver.SessionConfig{AccessMode: driver.AccessModeRead})
	defer session.Close(ctx)

	session.ExecuteRead(ctx, func(tx driver.ManagedTransaction) (interface{}, error) {
		query := `
			MATCH (ep:Endpoint {hostname: 'validation-dmz-web'})-[:HOSTS]-(c2:Container {name: 'Contenedor CI/CD'})
			OPTIONAL MATCH (c2)-[:HAS_INSTALLATION|USES_IMAGE*1..2]-()-[:HAS_FINDING]-(fLPE:Finding)-[:OF_VULNERABILITY]-(vLPE:Vulnerability)
			WHERE (toLower(vLPE.description) CONTAINS 'container escape' OR toLower(vLPE.description) CONTAINS 'sandbox escape' OR toLower(vLPE.description) CONTAINS 'escape container' OR toLower(vLPE.description) CONTAINS 'runc escape' OR toLower(vLPE.description) CONTAINS 'docker escape' OR toLower(vLPE.description) CONTAINS 'privilege escalation' OR toLower(vLPE.description) CONTAINS 'privilege' OR toLower(vLPE.description) CONTAINS 'overflow' OR any(cweItem IN coalesce(vLPE.cwe, []) WHERE cweItem IN ['CWE-269', 'CWE-250', 'CWE-270', 'CWE-787', 'CWE-119', 'CWE-120', 'CWE-190', 'CWE-125']))
			  AND NOT (toUpper(coalesce(fLPE.status, 'OPEN')) IN ['PATCHED', 'CLOSED', 'FIXED', 'RESOLVED'])
			  AND coalesce(fLPE.remediation_factor, 1.0) > 0.0
			  AND coalesce(fLPE.risk_score, 0.0) > 0.0
			RETURN fLPE, vLPE
		`
		res, err := tx.Run(ctx, query, nil)
		if err != nil {
			log.Fatal(err)
		}
		for res.Next(ctx) {
			rec := res.Record()
			fmt.Printf("Finding: %v | Vuln: %v\n", rec.Values[0], rec.Values[1])
		}
		return nil, nil
	})
}
