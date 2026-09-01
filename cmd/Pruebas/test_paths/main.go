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
		res, _ := tx.Run(ctx, "MATCH (p:Project)-[r]-(n) RETURN labels(p), p.id, type(r), labels(n), n.name, n.hostname, n.id", nil)
		for res.Next(ctx) {
			fmt.Println("Project relationship:", res.Record().Values)
		}
		return nil, nil
	})
}
