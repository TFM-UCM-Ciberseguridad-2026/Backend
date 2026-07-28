package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

func main() {
	fmt.Println("=== INICIANDO PRUEBA ERRORES CRUD ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, _, _, _, _, _, _, _, _, _, _, dbHelper, _ , _ := neo4j.NewRepository(driver)

	fmt.Println("[*] Limpiando base de datos para la prueba...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	endpointID := int64(9999)
	testEndpoint := &domain.Endpoint{
		EndpointID: endpointID,
		Hostname:   "test-host",
		Type:       "Server",
	}

	fmt.Println("\n--- PRUEBA 1: Update de un nodo que no existe ---")
	err = endpointRepo.Update(ctx, testEndpoint)
	if err != nil {
		if errors.Is(err, domain.ErrNodeNotFound) {
			fmt.Println("ÉXITO: Update devolvió domain.ErrNodeNotFound (el nodo no existía).")
		} else {
			fmt.Printf("FALLO: Update devolvió un error inesperado: %v\n", err)
		}
	} else {
		fmt.Println("FALLO: Update NO devolvió error, pero el nodo no existía.")
	}

	fmt.Println("\n--- PRUEBA 2: Save de un nodo nuevo ---")
	err = endpointRepo.Save(ctx, testEndpoint)
	if err != nil {
		fmt.Printf("FALLO: Save devolvió error al intentar crear: %v\n", err)
	} else {
		fmt.Println("ÉXITO: Save creó el nodo correctamente.")
	}

	fmt.Println("\n--- PRUEBA 3: Save de un nodo que YA existe ---")
	err = endpointRepo.Save(ctx, testEndpoint)
	if err != nil {
		if errors.Is(err, domain.ErrNodeAlreadyExists) {
			fmt.Println("ÉXITO: Save devolvió domain.ErrNodeAlreadyExists (el nodo ya estaba creado).")
		} else {
			fmt.Printf("FALLO: Save devolvió un error inesperado: %v\n", err)
		}
	} else {
		fmt.Println("FALLO: Save NO devolvió error al intentar sobrescribir el nodo existente.")
	}

	fmt.Println("\n--- PRUEBA 4: Update de un nodo existente ---")
	testEndpoint.Hostname = "test-host-updated"
	err = endpointRepo.Update(ctx, testEndpoint)
	if err != nil {
		fmt.Printf("FALLO: Update devolvió error al actualizar: %v\n", err)
	} else {
		fmt.Println("ÉXITO: Update modificó el nodo correctamente.")
	}

	fmt.Println("\n=== FIN DE LA PRUEBA ===")
}
