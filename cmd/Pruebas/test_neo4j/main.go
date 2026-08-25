package main

import (
	"context"
	"fmt"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/joho/godotenv"
	neo4j_driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	godotenv.Load(".env")
	driver, _ := neo4j_driver.NewDriverWithContext("neo4j://localhost:7687", neo4j_driver.BasicAuth("neo4j", "password", ""))
	repo := neo4j.NewInfrastructureRepository(driver)
	paths, err := repo.GetExploitationPaths(context.Background(), 10001)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Printf("Paths: %d\n", len(paths))
	}
}
