package main
import (
	"context"
	"fmt"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)
func main() {
	cfg, _ := config.LoadConfig()
	driver, _ := neo4j.NewDriverWithContext(cfg.Database.URI, neo4j.BasicAuth(cfg.Database.Username, cfg.Database.Password, ""))
	session := driver.NewSession(context.Background(), neo4j.SessionConfig{})
	res, err := session.ExecuteRead(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `MATCH (n:Vulnerability) OPTIONAL MATCH (n)-[:EXPLOITS_VIA_TTP]->(t:TTP) WITH n, collect(DISTINCT t) AS ts UNWIND case when size(ts) > 0 then ts else [null] end AS t WITH n, collect(DISTINCT case when t is not null then {ttp_id: t.ttp_id, name: coalesce(t.name, ''), tactic: coalesce(t.tactic, ''), description: coalesce(t.description, '')} else null end) AS inferredTTPs WITH n, [x IN inferredTTPs WHERE x IS NOT NULL] AS cleanTTPs RETURN n {.*, ttps: cleanTTPs} AS props LIMIT 1`
		r, _ := tx.Run(context.Background(), query, nil)
		if r.Next(context.Background()) {
			return r.Record().AsMap(), nil
		}
		return nil, nil
	})
	fmt.Printf("res: %+v, err: %v\n", res, err)
}
