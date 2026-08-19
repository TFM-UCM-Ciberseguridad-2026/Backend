package main
import (
	"context"
	"fmt"
	"sort"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)
func main() {
	cfg, _ := config.LoadConfig()
	driver, _ := neo4j.NewDriverWithContext(cfg.Neo4jURI, neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""))
	session := driver.NewSession(context.Background(), neo4j.SessionConfig{})
	session.ExecuteRead(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		qNew := `
		MATCH (n:Vulnerability)
		OPTIONAL MATCH (n)-[:MAPS_TO|EXPLOITS_VIA_TTP]->(t1:TTP)
		WITH n, collect(DISTINCT t1) AS t1List
		OPTIONAL MATCH (n)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)<-[:MAPS_TO_CWE]-(:CAPEC)-[:MAPS_TO_TTP]->(t2:TTP)
		WITH n, t1List, collect(DISTINCT t2) AS t2List
		WITH n, t1List + t2List AS combinedTTPs
		UNWIND case when size(combinedTTPs) > 0 then combinedTTPs else [null] end AS t
		WITH n, collect(DISTINCT case when t is not null and t.ttp_id is not null then t.ttp_id else null end) AS inferredTTPs
		WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs
		WHERE size(cleanTTPs) > 0
		UNWIND cleanTTPs AS ttp
		RETURN DISTINCT ttp
		`
		r, _ := tx.Run(context.Background(), qNew, nil)
		newTTPs := make(map[string]bool)
		for r.Next(context.Background()) {
			newTTPs[r.Record().Values[0].(string)] = true
		}

		qOld := `
		MATCH (n:Vulnerability)
		OPTIONAL MATCH (c:CAPEC)-[:MAPS_TO_CWE]->(w:CWE) WHERE ((n)-[:HAS_CWE]->(w) OR w.cwe_id IN n.cwe)
		OPTIONAL MATCH (c)-[:MAPS_TO_TTP]->(t:TTP)
		WITH n, collect(DISTINCT case when t.ttp_id is not null then t.ttp_id else null end) AS inferredTTPs
		WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs
		WHERE size(cleanTTPs) > 0
		UNWIND cleanTTPs AS ttp
		RETURN DISTINCT ttp
		`
		r2, _ := tx.Run(context.Background(), qOld, nil)
		oldTTPs := make(map[string]bool)
		for r2.Next(context.Background()) {
			oldTTPs[r2.Record().Values[0].(string)] = true
		}

		missingInNew := []string{}
		for t := range oldTTPs {
			if !newTTPs[t] {
				missingInNew = append(missingInNew, t)
			}
		}

		fmt.Printf("New query total distinct TTPs: %d\n", len(newTTPs))
		fmt.Printf("Old query total distinct TTPs: %d\n", len(oldTTPs))
		sort.Strings(missingInNew)
		fmt.Printf("TTPs in OLD but missing in NEW (%d): %v\n", len(missingInNew), missingInNew)
		return nil, nil
	})
}
