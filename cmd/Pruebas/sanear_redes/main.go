// Saneamiento de las redes anteriores a la validación de CIDR, y recálculo del
// emparejamiento activo↔red con la regla de subred más específica.
//
// En la base hay redes creadas antes de que existiera domain.NormalizeCIDR:
//
//   - CIDR inválido ("ab/24"): net.ParseCIDR falla. Con la regla antigua, guardar la red
//     enganchaba activos por VLAN ignorando el rango, así que hay activos colgando de ellas.
//     Con la regla nueva no emparejan con nada. Además hoy son ineditables desde la API,
//     porque ValidateAndNormalizeNetwork las rechaza.
//   - CIDR válido pero no canónico ("10.0.0.1/24"): empareja bien, pero cualquier
//     comparación textual lo trata como distinto de "10.0.0.0/24".
//
// El script NO borra nada. Canoniza lo que se puede canonizar, marca como huérfana
// explícita lo que no, y deja constancia de todo por pantalla. Las decisiones que necesitan
// criterio humano (dos redes con el mismo rango) se listan para revisión manual.
//
// Uso:
//
//	go run ./cmd/Pruebas/sanear_redes           # solo informa, no escribe
//	go run ./cmd/Pruebas/sanear_redes -aplicar  # aplica los cambios
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type redEnBase struct {
	id        int64
	nombre    string
	cidr      string
	proyectos []int64
}

func main() {
	aplicar := flag.Bool("aplicar", false, "escribe los cambios; sin esta bandera solo informa")
	flag.Parse()

	fmt.Println("=== SANEAMIENTO DE REDES ===")
	if !*aplicar {
		fmt.Println("(modo informe: no se escribe nada. Añade -aplicar para ejecutar)")
	}
	fmt.Println()

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error conectando a Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	_, _, _, _, _, _, _, _, networkPort, _, _, _, _, _ := neo4j.NewRepository(driver)

	redes, err := cargarRedes(ctx, driver)
	if err != nil {
		log.Fatalf("Error leyendo las redes: %v", err)
	}
	fmt.Printf("Redes en base: %d\n\n", len(redes))

	var invalidas, noCanonicas []redEnBase
	porRango := make(map[string][]redEnBase)

	for _, red := range redes {
		canonico, err := domain.NormalizeCIDR(red.cidr)
		if err != nil {
			invalidas = append(invalidas, red)
			continue
		}
		if canonico != red.cidr {
			noCanonicas = append(noCanonicas, red)
		}
		clave := fmt.Sprintf("%v|%s", red.proyectos, canonico)
		porRango[clave] = append(porRango[clave], red)
	}

	// --- 1. CIDR no canónicos: se canonizan, no cambia con qué emparejan ---
	fmt.Printf("[1/4] CIDR no canónicos: %d\n", len(noCanonicas))
	for _, red := range noCanonicas {
		canonico, _ := domain.NormalizeCIDR(red.cidr)
		fmt.Printf("      red %d '%s': %q -> %q\n", red.id, red.nombre, red.cidr, canonico)
		if *aplicar {
			if err := ejecutar(ctx, driver, `
				MATCH (n:Network) WHERE toString(n.id) = $id
				SET n.cidr = $cidr
			`, map[string]any{"id": fmt.Sprintf("%d", red.id), "cidr": canonico}); err != nil {
				log.Fatalf("Error canonizando la red %d: %v", red.id, err)
			}
		}
	}
	fmt.Println()

	// --- 2. CIDR inválidos: se marcan como huérfanas explícitas, nunca se borran ---
	fmt.Printf("[2/4] CIDR inválidos: %d\n", len(invalidas))
	for _, red := range invalidas {
		fmt.Printf("      red %d '%s': cidr=%q INVÁLIDO -> se marca como huérfana explícita\n", red.id, red.nombre, red.cidr)
		fmt.Println("        (ya no emparejará con ningún activo; corrige su CIDR desde la app para reactivarla)")
		if !*aplicar {
			continue
		}
		// Se ancla al proyecto antes de soltar las aristas, para que la red siga siendo
		// visible en el grafo y se pueda corregir a mano en vez de quedar inaccesible.
		if err := ejecutar(ctx, driver, `
			MATCH (n:Network) WHERE toString(n.id) = $id
			SET n.cidr_invalido = true, n.saneada_en = datetime()
			WITH n
			OPTIONAL MATCH (p:Project)-[:HAS_ENDPOINT]->()-[:CONNECTED_TO]->(n)
			FOREACH (x IN CASE WHEN p IS NOT NULL THEN [p] ELSE [] END |
				MERGE (x)-[:CONTAINS_NETWORK]->(n)
			)
			WITH n
			OPTIONAL MATCH (p2:Project)-[:HAS_ENDPOINT]->()-[:HOSTS]->()-[:CONNECTED_TO]->(n)
			FOREACH (x IN CASE WHEN p2 IS NOT NULL THEN [p2] ELSE [] END |
				MERGE (x)-[:CONTAINS_NETWORK]->(n)
			)
			WITH n
			MATCH ()-[rel:CONNECTED_TO]->(n)
			DELETE rel
		`, map[string]any{"id": fmt.Sprintf("%d", red.id)}); err != nil {
			log.Fatalf("Error marcando la red %d: %v", red.id, err)
		}
	}
	fmt.Println()

	// --- 3. Rangos duplicados dentro del mismo ámbito: solo se informa ---
	fmt.Println("[3/4] Rangos duplicados dentro del mismo ámbito (requieren decisión manual):")
	duplicados := 0
	claves := make([]string, 0, len(porRango))
	for clave := range porRango {
		claves = append(claves, clave)
	}
	sort.Strings(claves)
	for _, clave := range claves {
		grupo := porRango[clave]
		if len(grupo) < 2 {
			continue
		}
		duplicados++
		canonico, _ := domain.NormalizeCIDR(grupo[0].cidr)
		fmt.Printf("      %s en proyectos %v:\n", canonico, grupo[0].proyectos)
		for _, red := range grupo {
			fmt.Printf("        - red %d '%s'\n", red.id, red.nombre)
		}
		fmt.Printf("        El desempate automático elegirá la de id menor. Decide tú si sobra alguna.\n")
	}
	if duplicados == 0 {
		fmt.Println("      (ninguno)")
	}
	fmt.Println()

	// --- 4. Recálculo del emparejamiento con la regla nueva ---
	fmt.Println("[4/4] Recálculo del emparejamiento activo↔red por ámbito de proyecto:")
	ambitos, err := cargarAmbitos(ctx, driver)
	if err != nil {
		log.Fatalf("Error listando los proyectos: %v", err)
	}

	for _, ambito := range ambitos {
		etiqueta := fmt.Sprintf("proyecto %d", ambito)
		scope := []int64{ambito}
		if ambito == 0 {
			etiqueta = "redes sin proyecto"
			scope = nil
		}

		if !*aplicar {
			fmt.Printf("      %s: se recalcularía\n", etiqueta)
			continue
		}

		resumen, err := networkPort.ReconcileProjectNetworkLinks(ctx, scope)
		if err != nil {
			log.Fatalf("Error reconciliando %s: %v", etiqueta, err)
		}
		fmt.Printf("      %s: %d redes, %d activos, +%d/-%d aristas, %d relaciones de subred\n",
			etiqueta, resumen.Networks, resumen.Assets, resumen.LinksAdded, resumen.LinksRemoved, resumen.SubnetEdges)
		for _, mov := range resumen.Moves {
			fmt.Printf("        · '%s': %v -> %v\n", mov.AssetName, mov.From, mov.To)
		}
	}

	fmt.Println()
	if *aplicar {
		fmt.Println("=== SANEAMIENTO APLICADO ===")
	} else {
		fmt.Println("=== INFORME COMPLETADO (no se ha escrito nada) ===")
	}
}

func cargarRedes(ctx context.Context, driver neo4jdriver.DriverWithContext) ([]redEnBase, error) {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (n:Network)
			OPTIONAL MATCH (p:Project)-[:CONTAINS_NETWORK]->(n)
			OPTIONAL MATCH (p2:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:CONNECTED_TO]->(n)
			OPTIONAL MATCH (p3:Project)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:CONNECTED_TO]->(n)
			WITH n, [x IN collect(DISTINCT p.id) + collect(DISTINCT p2.id) + collect(DISTINCT p3.id) WHERE x IS NOT NULL] AS projs
			RETURN n.id AS id, coalesce(n.nombre, '') AS nombre, coalesce(n.cidr, '') AS cidr, projs
			ORDER BY n.id
		`, nil)
		if err != nil {
			return nil, err
		}

		var redes []redEnBase
		for result.Next(ctx) {
			rec := result.Record()
			idVal, _ := rec.Get("id")
			nombreVal, _ := rec.Get("nombre")
			cidrVal, _ := rec.Get("cidr")
			projsVal, _ := rec.Get("projs")

			red := redEnBase{
				id:     comoInt64(idVal),
				nombre: comoString(nombreVal),
				cidr:   comoString(cidrVal),
			}
			if lista, ok := projsVal.([]any); ok {
				for _, item := range lista {
					red.proyectos = append(red.proyectos, comoInt64(item))
				}
			}
			sort.Slice(red.proyectos, func(i, j int) bool { return red.proyectos[i] < red.proyectos[j] })
			redes = append(redes, red)
		}
		return redes, result.Err()
	})
	if err != nil {
		return nil, err
	}
	redes, _ := res.([]redEnBase)
	return redes, nil
}

// cargarAmbitos devuelve los ids de proyecto más el ámbito 0, que representa "redes sin
// proyecto". Ese ámbito existe y hay que reconciliarlo igual que los demás.
func cargarAmbitos(ctx context.Context, driver neo4jdriver.DriverWithContext) ([]int64, error) {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (p:Project) RETURN p.id AS id ORDER BY p.id`, nil)
		if err != nil {
			return nil, err
		}
		ambitos := []int64{0}
		for result.Next(ctx) {
			idVal, _ := result.Record().Get("id")
			ambitos = append(ambitos, comoInt64(idVal))
		}
		return ambitos, result.Err()
	})
	if err != nil {
		return nil, err
	}
	ambitos, _ := res.([]int64)
	return ambitos, nil
}

func ejecutar(ctx context.Context, driver neo4jdriver.DriverWithContext, query string, params map[string]any) error {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})
	return err
}

func comoInt64(v any) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	}
	return 0
}

func comoString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
