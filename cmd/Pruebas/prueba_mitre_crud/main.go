package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

func main() {
	fmt.Println("Iniciando Prueba CRUD MITRE (TTP y ThreatActor)...")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando la configuración: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)
	fmt.Println("Conexión a Neo4j establecida con éxito.")

	// Instanciamos los repositorios
	ttpRepo := neo4j.NewTTPRepository(driver)
	actorRepo := neo4j.NewThreatActorRepository(driver)
	_, vulnRepo, _, _, _, _, _, _, _, _, _, dbHelper, _ , _ := neo4j.NewRepository(driver)

	// Limpiamos la base de datos para la prueba
	fmt.Println("Limpiando base de datos...")
	_ = dbHelper.ExecuteWrite(ctx, "MATCH (n) DETACH DELETE n", nil)

	fmt.Println("\n=== CREANDO TTP Y THREAT ACTOR ===")

	// 1. TTP
	ttp := &domain.TTP{
		TTPID:       "T1059",
		Name:        "Command and Scripting Interpreter",
		Tactic:      "Execution",
		Description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
	}
	if err := ttpRepo.Save(ctx, ttp); err != nil {
		log.Fatalf("Error guardando TTP: %v", err)
	}
	fmt.Println("TTP Guardado")

	// 2. Threat Actor
	actor := &domain.ThreatActor{
		ActorID:     "G0007",
		Name:        "APT28",
		Description: "APT28 is a threat group that has been active since at least 2004.",
		Aliases:     "Fancy Bear, Pawn Storm",
	}
	if err := actorRepo.Save(ctx, actor); err != nil {
		log.Fatalf("Error guardando ThreatActor: %v", err)
	}
	fmt.Println("Threat Actor Guardado")

	// 3. Vulnerability (para la relación)
	vuln := &domain.Vulnerability{
		CVEID:       "CVE-2025-0001",
		Description: "RCE Vulnerability",
		BaseScore:   9.8,
	}
	if err := vulnRepo.Save(ctx, vuln); err != nil {
		log.Fatalf("Error guardando Vulnerability: %v", err)
	}

	fmt.Println("\n=== CREANDO RELACIONES ===")
	// Relacionar ThreatActor con TTP
	if err := actorRepo.RelateToTTP(ctx, "G0007", "T1059"); err != nil {
		log.Fatalf("Error relacionando ThreatActor con TTP: %v", err)
	}
	fmt.Println("Relación USES (ThreatActor -> TTP) creada")

	// Relacionar TTP con Vulnerability
	if err := ttpRepo.RelateToVulnerability(ctx, "CVE-2025-0001", "T1059"); err != nil {
		log.Fatalf("Error relacionando Vulnerabilidad con TTP: %v", err)
	}
	fmt.Println("Relación EXPLOITS_VIA_TTP (Vulnerability -> TTP) creada")

	fmt.Println("\n=== RECUPERANDO ENTIDADES ===")
	
	ttpDB, err := ttpRepo.GetByID(ctx, "T1059")
	if err != nil {
		log.Fatalf("Error recuperando TTP: %v", err)
	}
	fmt.Printf("TTP Recuperado: %+v\n", ttpDB)

	actorDB, err := actorRepo.GetByID(ctx, "G0007")
	if err != nil {
		log.Fatalf("Error recuperando ThreatActor: %v", err)
	}
	fmt.Printf("Threat Actor Recuperado: %+v\n", actorDB)

	topActors, err := actorRepo.GetTopThreatActors(ctx, 5)
	if err != nil {
		log.Fatalf("Error obteniendo Top Threat Actors: %v", err)
	}
	fmt.Printf("Top Threat Actors (limit 5): %+v\n", topActors)

	fmt.Println("\n=== ELIMINANDO ENTIDADES ===")
	if err := ttpRepo.DeleteByID(ctx, "T1059"); err != nil {
		log.Fatalf("Error eliminando TTP: %v", err)
	}
	fmt.Println("TTP Eliminado")

	if err := actorRepo.DeleteByID(ctx, "G0007"); err != nil {
		log.Fatalf("Error eliminando ThreatActor: %v", err)
	}
	fmt.Println("Threat Actor Eliminado")

	fmt.Println("\n¡PRUEBA SUPERADA! El CRUD de MITRE (TTP y ThreatActor) funciona con Neo4j.")
}
