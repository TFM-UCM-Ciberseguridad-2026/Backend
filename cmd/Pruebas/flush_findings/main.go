package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	_, _, _, _, _, _, _, _, _, _, _, dbHelper, _, _ := neo4j.NewRepository(driver)

	// Eliminar todos los nodos Finding y sus relaciones
	cypherFindings := "MATCH (f:Finding) DETACH DELETE f"
	err = dbHelper.ExecuteWrite(ctx, cypherFindings, nil)
	if err != nil {
		log.Fatalf("Error eliminando hallazgos (Finding): %v", err)
	}

	// Eliminar nodos Vulnerabilidad huérfanos si los hubiera
	cypherVulns := "MATCH (v:Vulnerability) WHERE NOT (v)<-[:HAS_VULNERABILITY]-() DETACH DELETE v"
	_ = dbHelper.ExecuteWrite(ctx, cypherVulns, nil)

	fmt.Println("[OK] Flush completado: Todos los hallazgos (Finding) y vulnerabilidades huérfanas han sido eliminados de la base de datos Neo4j.")
}
