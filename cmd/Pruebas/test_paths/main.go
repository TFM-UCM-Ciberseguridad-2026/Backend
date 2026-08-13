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
	if err != nil { log.Fatal(err) }
	defer d.Close(ctx)

	session := d.NewSession(ctx, driver.SessionConfig{AccessMode: driver.AccessModeRead})
	defer session.Close(ctx)

	query := `
		MATCH (ci:ContainerImage)
		OPTIONAL MATCH (ci)-[r]-(n)
		RETURN labels(ci), properties(ci), type(r), labels(n), properties(n) LIMIT 5
	`
	res, _ := session.ExecuteRead(ctx, func(tx driver.ManagedTransaction) (interface{}, error) {
		result, _ := tx.Run(ctx, query, nil)
		for result.Next(ctx) {
			fmt.Println(result.Record().Values)
		}
		return nil, nil
	})
	_ = res
}
