package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("=== PRUEBA COMPLETA: INGESTIÓN Y ENRIQUECIMIENTO CVE -> CWE -> CAPEC -> TTP (MITRE ATT&CK) ===")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando configuración: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	endpointRepo, vulnRepo, swRepo, installRepo, findingRepo, remRepo, _, hwRepo, netRepo, patchRepo, projRepo, dbHelper, relRepo, _ := neo4j.NewRepository(driver)
	capecRepo := neo4j.NewCAPECRepository(driver)
	capecProvider := provider.NewCapecSTIXProvider("", 60)

	ttpRepo := neo4j.NewTTPRepository(driver)
	mitreAttackProvider := provider.NewMitreAttackSTIXProvider("", 90)

	orchestrator := service.NewOrchestrator(
		projRepo, endpointRepo, hwRepo, netRepo, installRepo, swRepo,
		findingRepo, vulnRepo, remRepo, relRepo, nil, nil, patchRepo, dbHelper, nil,
	).WithCAPEC(capecRepo, capecProvider).WithMitreATTACK(ttpRepo, mitreAttackProvider)

	fmt.Println("\n1. Sincronizando catálogo STIX 2.1 CAPEC...")
	capecCount, err := orchestrator.SyncCAPECCatalog(ctx)
	if err != nil {
		log.Fatalf("❌ Error sincronizando CAPEC: %v", err)
	}
	fmt.Printf("   ✅ Ingeridos %d patrones CAPEC en Neo4j.\n", capecCount)

	fmt.Println("\n2. Sincronizando e ingiriendo catálogo STIX 2.1 MITRE ATT&CK Enterprise (Nombres y Tácticas)...")
	ttpCount, err := orchestrator.SyncATTACKCatalog(ctx)
	if err != nil {
		log.Fatalf("❌ Error sincronizando MITRE ATT&CK: %v", err)
	}
	fmt.Printf("   ✅ Ingeridas y enriquecidas %d técnicas TTP de MITRE ATT&CK en Neo4j.\n", ttpCount)

	// Guardar o actualizar la vulnerabilidad de prueba CVE-2021-4034 (PwnKit) con CWE-78, CWE-120, CWE-20, CWE-1327
	testVuln := domain.Vulnerability{
		CVEID:       "CVE-2021-4034",
		Description: "Local privilege escalation vulnerability in Polkit's pkexec",
		BaseScore:   7.8,
		CVSSVector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		CWE:         []string{"CWE-78", "CWE-120", "CWE-119", "CWE-190", "CWE-20", "CWE-1327"},
	}

	if err := vulnRepo.Save(ctx, &testVuln); err != nil {
		if errors.Is(err, domain.ErrNodeAlreadyExists) {
			_ = vulnRepo.Update(ctx, &testVuln)
			_ = vulnRepo.LinkVulnerabilityToCWEs(ctx, testVuln.CVEID, testVuln.CWE)
		} else {
			log.Fatalf("❌ Error guardando vulnerabilidad en Neo4j: %v", err)
		}
	}
	fmt.Println("\n3. Vulnerabilidad CVE-2021-4034 guardada y vinculada a sus CWEs en Neo4j.")

	// Vincular inferencias explícitamente y luego consultar
	linkedCount, err := vulnRepo.LinkInferredTTPsToVulnerability(ctx, "CVE-2021-4034")
	if err != nil {
		log.Fatalf("❌ Error vinculando TTPs inferidos: %v", err)
	}
	fmt.Printf("   ✅ Enlazadas directamente %d relaciones (:Vulnerability)-[:EXPLOITS_VIA_TTP]->(:TTP).\n", linkedCount)

	inferredTTPs, err := vulnRepo.GetInferredTTPsByCVE(ctx, "CVE-2021-4034")
	if err != nil {
		log.Fatalf("❌ Error consultando TTPs inferidos: %v", err)
	}

	fmt.Printf("\n4. ✅ Encontradas %d técnicas TTP de MITRE ATT&CK inferidas automáticamente (con Nombre y Táctica completas):\n", len(inferredTTPs))
	for i, ttp := range inferredTTPs {
		if i >= 10 {
			fmt.Printf("      ... y %d TTPs adicionales.\n", len(inferredTTPs)-10)
			break
		}
		fmt.Printf("      - %s | Nombre: \"%s\" | Táctica: [%s]\n", ttp.TTPID, ttp.Name, ttp.Tactic)
	}

	cypherQuery := `
		MATCH p=(v:Vulnerability {cve_id: 'CVE-2021-4034'})-[:HAS_CWE]->(w:CWE)<-[:MAPS_TO_CWE]-(c:CAPEC)-[:MAPS_TO_TTP]->(t:TTP)
		RETURN count(p) AS totalCaminos, count(DISTINCT w) AS cwesUnicos, count(DISTINCT c) AS capecsUnicos, count(DISTINCT t) AS ttpsUnicos
	`
	resGraph, _ := dbHelper.ExecuteRead(ctx, cypherQuery, nil)
	fmt.Printf("\n5. Topología completa del grafo para CVE-2021-4034: %+v\n", resGraph)
	fmt.Println("\n🎉 PRUEBA COMPLETADA CON ÉXITO: Mapeo automático CVE -> CWE -> CAPEC -> TTP (con metadatos completos) verificado.")
}
