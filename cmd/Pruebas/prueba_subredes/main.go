// Prueba end-to-end del emparejamiento activo↔red por subred más específica.
//
// Monta un proyecto desechable con un supernet 10.0.0.0/16 y endpoints dentro, y comprueba
// contra Neo4j real:
//
//  1. Con solo la /16, los endpoints cuelgan de ella.
//  2. Al declarar después una /24 más específica, los endpoints que caen dentro se REASIGNAN
//     a la /24 y dejan de colgar de la /16 (recálculo del ámbito completo, no solo de lo nuevo).
//  3. El endpoint que cae en la /16 pero fuera de la /24 se queda en la /16.
//  4. Se materializa la jerarquía derivada (:Network)-[:CONTAINS_SUBNET]->(:Network).
//  5. Al borrar la /24, sus endpoints vuelven solos a la /16.
//  6. Un endpoint multi-homed sigue conectado a una red por cada IP.
//  7. Una IP que no cae en ninguna red no genera arista, y la red sin activos directos
//     sigue colgando del proyecto por CONTAINS_NETWORK.
//
// Al terminar borra todo lo que ha creado.
//
// Uso: go run ./cmd/Pruebas/prueba_subredes
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

var fallos int

func main() {
	fmt.Println("=== PRUEBA: EMPAREJAMIENTO POR SUBRED MÁS ESPECÍFICA ===")

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

	endpointRepo, vulnRepo, swRepo, installRepo, findingRepo, remRepo, _, hwRepo, netRepo, patchRepo, projRepo, dbHelper, relRepo, containerRepo := neo4j.NewRepository(driver)
	infraRepo := neo4j.NewInfrastructureRepository(driver)

	orch := service.NewOrchestrator(
		projRepo, endpointRepo, hwRepo, netRepo, installRepo, swRepo,
		findingRepo, vulnRepo, remRepo, relRepo, infraRepo, containerRepo, patchRepo, dbHelper, nil,
	)

	proyectoID := time.Now().UnixNano()
	defer limpiar(ctx, driver, proyectoID)

	if err := crearProyecto(ctx, driver, proyectoID); err != nil {
		log.Fatalf("Error creando el proyecto de prueba: %v", err)
	}
	fmt.Printf("Proyecto de prueba: %d\n\n", proyectoID)

	// --- Endpoints ---
	// dentro-a y dentro-b caen en la futura /24; fuera cae en la /16 pero no en la /24;
	// multi tiene una IP en cada rango; huerfano tiene una IP que no cae en ninguna red.
	endpoints := map[string]*domain.Endpoint{
		"dentro-a": {Hostname: "sub-dentro-a", IPs: []domain.EndpointIP{{IP: "10.0.1.5"}}},
		"dentro-b": {Hostname: "sub-dentro-b", IPs: []domain.EndpointIP{{IP: "10.0.1.6"}}},
		"fuera":    {Hostname: "sub-fuera", IPs: []domain.EndpointIP{{IP: "10.0.9.5"}}},
		"multi":    {Hostname: "sub-multi", IPs: []domain.EndpointIP{{IP: "10.0.1.7"}, {IP: "10.0.9.7"}}},
		"huerfano": {Hostname: "sub-huerfano", IPs: []domain.EndpointIP{{IP: "192.168.77.5"}}},
	}
	orden := []string{"dentro-a", "dentro-b", "fuera", "multi", "huerfano"}
	for _, clave := range orden {
		if err := orch.AddEndpointToProject(ctx, proyectoID, endpoints[clave]); err != nil {
			log.Fatalf("Error creando el endpoint %s: %v", clave, err)
		}
	}

	// --- Paso 1: solo la /16 ---
	padre := &domain.Network{Nombre: "sub-padre", CIDR: "10.0.0.0/16", Gateway: "10.0.0.1", VLANID: 0}
	padreID, _, err := orch.CreateNetwork(ctx, padre, proyectoID)
	if err != nil {
		log.Fatalf("Error creando la /16: %v", err)
	}
	fmt.Printf("[1] Creada la /16 (id %d)\n", padreID)

	comprobar(ctx, driver, "dentro-a cuelga de la /16", endpoints["dentro-a"].EndpointID, []string{"10.0.0.0/16"})
	comprobar(ctx, driver, "fuera cuelga de la /16", endpoints["fuera"].EndpointID, []string{"10.0.0.0/16"})
	comprobar(ctx, driver, "huerfano no cuelga de nada", endpoints["huerfano"].EndpointID, nil)
	fmt.Println()

	// --- Paso 2: se declara la /24 más específica ---
	hija := &domain.Network{Nombre: "sub-hija", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", VLANID: 0}
	hijaID, enlazados, err := orch.CreateNetwork(ctx, hija, proyectoID)
	if err != nil {
		log.Fatalf("Error creando la /24: %v", err)
	}
	fmt.Printf("[2] Creada la /24 (id %d), %d activos enlazados\n", hijaID, enlazados)

	comprobar(ctx, driver, "dentro-a REASIGNADO a la /24", endpoints["dentro-a"].EndpointID, []string{"10.0.1.0/24"})
	comprobar(ctx, driver, "dentro-b REASIGNADO a la /24", endpoints["dentro-b"].EndpointID, []string{"10.0.1.0/24"})
	comprobar(ctx, driver, "fuera sigue en la /16", endpoints["fuera"].EndpointID, []string{"10.0.0.0/16"})
	comprobar(ctx, driver, "multi en las dos (una IP en cada una)", endpoints["multi"].EndpointID, []string{"10.0.0.0/16", "10.0.1.0/24"})
	comprobar(ctx, driver, "huerfano sigue sin red", endpoints["huerfano"].EndpointID, nil)
	comprobarInt(ctx, driver, "la /24 declara 3 activos", contarActivos(ctx, driver, hijaID), 3)
	fmt.Println()

	// --- Paso 3: jerarquía derivada ---
	fmt.Println("[3] Jerarquía CONTAINS_SUBNET")
	comprobarSubred(ctx, driver, padreID, hijaID)
	fmt.Println()

	// --- Paso 4: la /16 sigue en el grafo del proyecto pese a perder activos ---
	fmt.Println("[4] La /16 sigue anclada al proyecto")
	comprobarBool(ctx, driver, "la /16 cuelga del proyecto por CONTAINS_NETWORK",
		redEnProyecto(ctx, driver, proyectoID, padreID), true)

	// La vista de redes del frontend pinta la anidación leyendo CONTAINS_SUBNET del grafo,
	// así que la arista tiene que llegarle: no basta con que exista en Neo4j.
	grafo, err := infraRepo.GetGraphData(ctx, proyectoID)
	if err != nil {
		log.Fatalf("Error obteniendo el grafo: %v", err)
	}
	subredesEnGrafo := 0
	redesEnGrafo := 0
	for _, rel := range grafo.Relationships {
		if rel.Type == "CONTAINS_SUBNET" {
			subredesEnGrafo++
		}
	}
	for _, nodo := range grafo.Nodes {
		for _, l := range nodo.Labels {
			if l == "Network" {
				redesEnGrafo++
			}
		}
	}
	comprobarInt(ctx, driver, "el grafo del proyecto incluye la arista CONTAINS_SUBNET", subredesEnGrafo, 1)
	comprobarInt(ctx, driver, "el grafo del proyecto incluye las 2 redes", redesEnGrafo, 2)
	fmt.Println()

	// --- Paso 5: se borra la /24 y los activos vuelven al padre ---
	if err := orch.DeleteNetwork(ctx, hijaID); err != nil {
		log.Fatalf("Error borrando la /24: %v", err)
	}
	fmt.Println("[5] Borrada la /24")
	comprobar(ctx, driver, "dentro-a vuelve solo a la /16", endpoints["dentro-a"].EndpointID, []string{"10.0.0.0/16"})
	comprobar(ctx, driver, "dentro-b vuelve solo a la /16", endpoints["dentro-b"].EndpointID, []string{"10.0.0.0/16"})
	comprobar(ctx, driver, "multi vuelve a la /16", endpoints["multi"].EndpointID, []string{"10.0.0.0/16"})
	fmt.Println()

	// --- Paso 6: aislamiento entre proyectos ---
	// Otro proyecto declara el MISMO rango. Ninguno de los dos debe robarle activos al otro.
	otroID := proyectoID + 1
	defer limpiar(ctx, driver, otroID)
	if err := crearProyecto(ctx, driver, otroID); err != nil {
		log.Fatalf("Error creando el segundo proyecto: %v", err)
	}
	ajeno := &domain.Endpoint{Hostname: "sub-ajeno", IPs: []domain.EndpointIP{{IP: "10.0.1.5"}}}
	if err := orch.AddEndpointToProject(ctx, otroID, ajeno); err != nil {
		log.Fatalf("Error creando el endpoint ajeno: %v", err)
	}
	gemela := &domain.Network{Nombre: "sub-gemela", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", VLANID: 0}
	gemelaID, _, err := orch.CreateNetwork(ctx, gemela, otroID)
	if err != nil {
		log.Fatalf("Error creando la red gemela: %v", err)
	}
	fmt.Printf("[6] Otro proyecto declara el mismo 10.0.1.0/24 (id %d)\n", gemelaID)
	comprobar(ctx, driver, "el ajeno cuelga de SU /24", ajeno.EndpointID, []string{"10.0.1.0/24"})
	comprobarInt(ctx, driver, "la /24 ajena solo tiene 1 activo", contarActivos(ctx, driver, gemelaID), 1)
	comprobar(ctx, driver, "dentro-a NO se cruza al otro proyecto", endpoints["dentro-a"].EndpointID, []string{"10.0.0.0/16"})
	fmt.Println()

	if fallos > 0 {
		fmt.Printf("=== %d COMPROBACIONES FALLIDAS ===\n", fallos)
		limpiar(ctx, driver, proyectoID)
		limpiar(ctx, driver, otroID)
		os.Exit(1)
	}
	fmt.Println("=== TODAS LAS COMPROBACIONES OK ===")
}

// --- comprobaciones ---

func comprobar(ctx context.Context, driver neo4jdriver.DriverWithContext, titulo string, endpointID int64, esperado []string) {
	obtenido := redesDe(ctx, driver, endpointID)
	sort.Strings(obtenido)
	sort.Strings(esperado)

	ok := len(obtenido) == len(esperado)
	if ok {
		for i := range obtenido {
			if obtenido[i] != esperado[i] {
				ok = false
				break
			}
		}
	}
	informar(ok, titulo, fmt.Sprintf("%v", esperado), fmt.Sprintf("%v", obtenido))
}

func comprobarInt(ctx context.Context, driver neo4jdriver.DriverWithContext, titulo string, obtenido, esperado int) {
	informar(obtenido == esperado, titulo, fmt.Sprintf("%d", esperado), fmt.Sprintf("%d", obtenido))
}

func comprobarBool(ctx context.Context, driver neo4jdriver.DriverWithContext, titulo string, obtenido, esperado bool) {
	informar(obtenido == esperado, titulo, fmt.Sprintf("%v", esperado), fmt.Sprintf("%v", obtenido))
}

func comprobarSubred(ctx context.Context, driver neo4jdriver.DriverWithContext, padreID, hijaID int64) {
	res := leer(ctx, driver, `
		MATCH (p:Network)-[:CONTAINS_SUBNET]->(h:Network)
		WHERE toString(p.id) = $padre AND toString(h.id) = $hija
		RETURN count(*) AS total
	`, map[string]any{"padre": fmt.Sprintf("%d", padreID), "hija": fmt.Sprintf("%d", hijaID)}, "total")
	informar(comoInt64(res) == 1, "la /16 CONTAINS_SUBNET la /24", "1", fmt.Sprintf("%v", res))
}

func informar(ok bool, titulo, esperado, obtenido string) {
	if ok {
		fmt.Printf("    OK   %s\n", titulo)
		return
	}
	fallos++
	fmt.Printf("    FALLO %s\n         esperado: %s\n         obtenido: %s\n", titulo, esperado, obtenido)
}

// --- consultas ---

func redesDe(ctx context.Context, driver neo4jdriver.DriverWithContext, endpointID int64) []string {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `
			MATCH (e:Endpoint)-[:CONNECTED_TO]->(n:Network)
			WHERE toString(e.id) = $id
			RETURN collect(n.cidr) AS cidrs
		`, map[string]any{"id": fmt.Sprintf("%d", endpointID)})
		if err != nil {
			return nil, err
		}
		var cidrs []string
		if result.Next(ctx) {
			val, _ := result.Record().Get("cidrs")
			if lista, ok := val.([]any); ok {
				for _, item := range lista {
					if s, ok := item.(string); ok {
						cidrs = append(cidrs, s)
					}
				}
			}
		}
		return cidrs, result.Err()
	})
	if err != nil {
		log.Fatalf("Error consultando las redes del endpoint %d: %v", endpointID, err)
	}
	cidrs, _ := res.([]string)
	return cidrs
}

func contarActivos(ctx context.Context, driver neo4jdriver.DriverWithContext, networkID int64) int {
	res := leer(ctx, driver, `
		MATCH (e)-[:CONNECTED_TO]->(n:Network)
		WHERE (e:Endpoint OR e:Container) AND toString(n.id) = $id
		RETURN count(DISTINCT e) AS total
	`, map[string]any{"id": fmt.Sprintf("%d", networkID)}, "total")
	return int(comoInt64(res))
}

func redEnProyecto(ctx context.Context, driver neo4jdriver.DriverWithContext, proyectoID, networkID int64) bool {
	res := leer(ctx, driver, `
		MATCH (p:Project)-[:CONTAINS_NETWORK]->(n:Network)
		WHERE toString(p.id) = $proyecto AND toString(n.id) = $red
		RETURN count(*) AS total
	`, map[string]any{"proyecto": fmt.Sprintf("%d", proyectoID), "red": fmt.Sprintf("%d", networkID)}, "total")
	return comoInt64(res) > 0
}

func leer(ctx context.Context, driver neo4jdriver.DriverWithContext, query string, params map[string]any, campo string) any {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeRead})
	defer session.Close(ctx)

	res, err := session.ExecuteRead(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		if result.Next(ctx) {
			val, _ := result.Record().Get(campo)
			return val, nil
		}
		return nil, result.Err()
	})
	if err != nil {
		log.Fatalf("Error en consulta: %v", err)
	}
	return res
}

// --- montaje y limpieza ---

func crearProyecto(ctx context.Context, driver neo4jdriver.DriverWithContext, id int64) error {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
			CREATE (p:Project {id: $id, name: $name, prueba_subredes: true})
		`, map[string]any{"id": id, "name": fmt.Sprintf("prueba-subredes-%d", id)})
		return nil, err
	})
	return err
}

// limpiar borra el proyecto de prueba con todo lo que cuelga de él. Solo toca nodos marcados
// con prueba_subredes o alcanzables desde el proyecto de prueba.
func limpiar(ctx context.Context, driver neo4jdriver.DriverWithContext, proyectoID int64) {
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
			MATCH (p:Project {prueba_subredes: true})
			WHERE toString(p.id) = $id
			OPTIONAL MATCH (p)-[:HAS_ENDPOINT]->(e:Endpoint)
			OPTIONAL MATCH (e)-[:HAS_IP]->(ip:IPAddress)
			OPTIONAL MATCH (p)-[:CONTAINS_NETWORK]->(n:Network)
			DETACH DELETE ip, e, n, p
		`, map[string]any{"id": fmt.Sprintf("%d", proyectoID)})
		return nil, err
	})
	if err != nil {
		log.Printf("Aviso: la limpieza del proyecto %d falló: %v", proyectoID, err)
	}
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
