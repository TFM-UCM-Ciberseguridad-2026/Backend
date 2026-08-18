package main
import (
	"context"
	"fmt"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)
func main() {
	cfg, _ := config.LoadConfig()
	driver, _ := neo4j.NewDriverWithContext(cfg.Neo4jURI, neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""))
	session := driver.NewSession(context.Background(), neo4j.SessionConfig{})
	res, _ := session.ExecuteRead(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
		MATCH (n:Vulnerability)
		OPTIONAL MATCH (n)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t1:TTP)
		WITH n, collect(DISTINCT t1) AS t1List
		OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t2:TTP)
		WITH n, t1List, collect(DISTINCT t2) AS t2List
		WITH n, t1List + t2List AS combinedTTPs
		UNWIND case when size(combinedTTPs) > 0 then combinedTTPs else [null] end AS t
		WITH n, collect(DISTINCT case when t is not null and t.ttp_id is not null then {ttp_id: t.ttp_id, name: coalesce(t.name, ''), tactic: coalesce(t.tactic, ''), description: coalesce(t.description, '')} else null end) AS inferredTTPs
		WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs
		WHERE size(cleanTTPs) > 0
		WITH collect({
			id: elementId(n), 
			labels: labels(n), 
			properties: n {.*, ttps: cleanTTPs}
		}) AS nodes
		RETURN nodes LIMIT 1
		`
		r, _ := tx.Run(context.Background(), query, nil)
		if r.Next(context.Background()) {
			return r.Record().AsMap(), nil
		}
		return nil, nil
	})
	m := res.(map[string]any)
	nodes := m["nodes"].([]interface{})
	nodeMap := nodes[0].(map[string]interface{})
	props := nodeMap["properties"].(map[string]interface{})
	fmt.Printf("Has ttps: %v\n", props["ttps"] != nil)
}
