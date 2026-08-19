package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext("bolt://localhost:7687", neo4j.BasicAuth("neo4j", "password", ""))
	if err != nil {
		log.Fatal(err)
	}
	defer driver.Close(ctx)
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (n) WHERE NOT (n:ThreatActor OR n:TTP OR n:IPAddress) OPTIONAL MATCH (n)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t1:TTP) WHERE "Vulnerability" IN labels(n) WITH n, collect(DISTINCT t1) AS t1List OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO]->(t2:TTP) WHERE "Vulnerability" IN labels(n) WITH n, t1List, collect(DISTINCT t2) AS t2List OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t3:TTP) WHERE "Vulnerability" IN labels(n) WITH n, t1List, t2List, collect(DISTINCT t3) AS t3List WITH n, t1List + t2List + t3List AS combinedTTPs UNWIND case when size(combinedTTPs) > 0 then combinedTTPs else [null] end AS t WITH n, collect(DISTINCT case when t is not null and t.ttp_id is not null then {ttp_id: t.ttp_id, name: coalesce(t.name, ''), tactic: coalesce(t.tactic, ''), description: coalesce(t.description, '')} else null end) AS inferredTTPs WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs WITH collect({ id: elementId(n), labels: labels(n), properties: n {.*, ttps: cleanTTPs} }) AS nodes RETURN nodes`
	res, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil { return nil, err }
		if result.Next(ctx) { return result.Record().AsMap(), nil }
		return nil, nil
	})
	recordMap := res.(map[string]interface{})
	
	_, err = json.Marshal(recordMap["nodes"])
	if err != nil {
		fmt.Println("JSON Marshal ERROR:", err)
	} else {
		fmt.Println("JSON Marshal SUCCESS")
	}
}
