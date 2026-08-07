package main

import (
	"context"
	"fmt"
	"log"
	"time"

	neo4jDriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4jDriver.SessionConfig{AccessMode: neo4jDriver.AccessModeWrite})
	defer session.Close(ctx)

	query2 := `
		MATCH (t:TTP) WHERE t.id IS NULL
		DETACH DELETE t
	`
	_, _ = session.ExecuteWrite(ctx, func(tx neo4jDriver.ManagedTransaction) (interface{}, error) {
		result, _ := tx.Run(ctx, query2, nil)
		summary, _ := result.Consume(ctx)
		fmt.Printf("Deleted %v duplicate TTPs\n", summary.Counters().NodesDeleted())
		return nil, nil
	})

	if err != nil {
		log.Printf("Error actualizando mocks: %v\n", err)
	} else {
		fmt.Println("CWEs insertados correctamente en los mocks de Neo4j.")
	}
}
