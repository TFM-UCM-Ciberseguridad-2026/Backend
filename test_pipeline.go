package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext("bolt://localhost:7687", neo4j.BasicAuth("neo4j", "password", ""))
	if err != nil {
		log.Fatal(err)
	}
	defer driver.Close(ctx)

	repo := backendneo4j.NewInfrastructureRepository(driver)
	graph, err := repo.GetGraphData(ctx)
	if err != nil {
		log.Fatal("GetGraphData error:", err)
	}

	fmt.Println("Nodes count:", len(graph.Nodes))
	if len(graph.Nodes) > 0 {
		data, err := json.Marshal(graph)
		if err != nil {
			fmt.Println("JSON Marshal error:", err)
		} else {
			fmt.Println("JSON Marshal SUCCESS, length:", len(data))
		}
	}
}
