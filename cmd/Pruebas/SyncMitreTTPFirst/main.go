package main

import (
	"context"
	"fmt"
	"log"
	"time"

	neo4jDriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("Iniciando Sincronización Completa: Catálogo MITRE CTI + Mapeo Retrospectivo...")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// Inicializar los puertos para el ETL
	mitreCTIProvider := provider.NewMitreCTIProvider()
	mitreCatalogRepo := neo4j.NewMitreCatalogRepository(driver)

	// Inicializar un orquestador mínimo
	orchestrator := service.NewOrchestrator(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	).WithMitreCatalog(mitreCTIProvider, mitreCatalogRepo)

	fmt.Println("1. Descargando e insertando STIX 2.1 (CAPEC y ATT&CK). Esto puede tomar unos minutos...")
	
	if err := orchestrator.SyncMitreCatalogDaily(ctx); err != nil {
		log.Fatalf("Error ejecutando SyncMitreCatalogDaily: %v", err)
	}

	fmt.Println("¡Catálogo MITRE sincronizado con éxito!")

	fmt.Println("2. Preparando entorno de pruebas: Inyectando CWEs en vulnerabilidades dummy...")
	session := driver.NewSession(ctx, neo4jDriver.SessionConfig{AccessMode: neo4jDriver.AccessModeWrite})
	defer session.Close(ctx)

	mockQueries := []string{
		`MATCH (v:Vulnerability {cve_id: 'CVE-2021-44228'}) SET v.cwe = 'CWE-502'`,
		`MATCH (v:Vulnerability {cve_id: 'CVE-2017-0144'}) SET v.cwe = 'CWE-119'`,
		`MATCH (v:Vulnerability {cve_id: 'CVE-2020-0601'}) SET v.cwe = 'CWE-295'`,
		`MATCH (v:Vulnerability {cve_id: 'CVE-2021-4034'}) SET v.cwe = 'CWE-787'`,
		`MATCH (v:Vulnerability {cve_id: 'CVE-TOMCAT-RCE'}) SET v.cwe = 'CWE-94'`,
	}
	for _, q := range mockQueries {
		_, _ = session.ExecuteWrite(ctx, func(tx neo4jDriver.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, q, nil)
			return nil, err
		})
	}
	
	fmt.Println("3. Ejecutando mapeo retrospectivo para todas las CVEs históricas...")

	globalMappingQuery := `
	MATCH (v:Vulnerability)
	WHERE v.cwe IS NOT NULL OR (v)-[:HAS_WEAKNESS]->(:CWE)
	// Tratar de enlazar por propiedad o por relación
	OPTIONAL MATCH (v)-[:HAS_WEAKNESS]->(wRel:CWE)
	WITH v, coalesce(wRel.id, v.cwe) AS cwe_id
	WHERE cwe_id IS NOT NULL

	MATCH (w:CWE) WHERE w.id = cwe_id
	MATCH (w)-[:MAPPED_TO]->(capec:CAPEC)-[:MAPPED_TO]->(t:TTP)
	MERGE (v)-[rel:EXPLOITS_VIA_TTP]->(t)
	ON CREATE SET rel.via_capec = capec.id, rel.method = 'cwe-capec-graph-traversal', rel.created_at = datetime()

	WITH v, collect(DISTINCT t.ttp_id) AS mapped_ttps
	SET v.ttp_related = reduce(s = '', x IN mapped_ttps | s + CASE WHEN s = '' THEN '' ELSE ', ' END + x),
	    v.TTPs = reduce(s = '', x IN mapped_ttps | s + CASE WHEN s = '' THEN '' ELSE ',' END + x)
	RETURN count(DISTINCT v) as updatedCVEs
	`

	res, err := session.ExecuteWrite(ctx, func(tx neo4jDriver.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, globalMappingQuery, nil)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			return result.Record().Values[0], nil
		}
		return 0, nil
	})

	if err != nil {
		log.Printf("Advertencia al mapear CVEs históricas: %v\n", err)
	} else {
		fmt.Printf("¡Mapeo retrospectivo completado! %v CVEs actualizadas con sus TTPs.\n", res)
	}
}
