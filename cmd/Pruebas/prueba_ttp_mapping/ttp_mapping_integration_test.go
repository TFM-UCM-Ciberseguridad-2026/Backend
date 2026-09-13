package prueba_ttp_mapping

import (
	"context"
	"os"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

/*
Pruebas de integración sobre el grafo real. Solo se ejecutan si se apunta a una
instancia de Neo4j:

	NEO4J_TEST_URI=bolt://localhost:7687 NEO4J_TEST_USER=neo4j NEO4J_TEST_PASS=password \
	  go test ./cmd/Pruebas/prueba_ttp_mapping/ -run Grafo -v

Son pruebas de LECTURA: no escriben ni borran nada. Comprueban invariantes que
deberían cumplirse en cualquier grafo poblado por el pipeline TTP, y que en el
entorno de validación no se cumplían.
*/

func conectar(t *testing.T) neo4j.DriverWithContext {
	t.Helper()
	uri := os.Getenv("NEO4J_TEST_URI")
	if uri == "" {
		t.Skip("define NEO4J_TEST_URI/NEO4J_TEST_USER/NEO4J_TEST_PASS para ejecutar las pruebas de grafo")
	}
	usuario := os.Getenv("NEO4J_TEST_USER")
	if usuario == "" {
		usuario = "neo4j"
	}
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(usuario, os.Getenv("NEO4J_TEST_PASS"), ""))
	if err != nil {
		t.Fatalf("no se pudo crear el driver: %v", err)
	}
	if err := driver.VerifyConnectivity(context.Background()); err != nil {
		t.Skipf("Neo4j no accesible en %s: %v", uri, err)
	}
	t.Cleanup(func() { _ = driver.Close(context.Background()) })
	return driver
}

// leerUnaFila ejecuta una consulta de lectura y devuelve la primera fila.
func leerUnaFila(t *testing.T, driver neo4j.DriverWithContext, cypher string) map[string]any {
	t.Helper()
	ses := driver.NewSession(context.Background(), neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer ses.Close(context.Background())

	res, err := ses.ExecuteRead(context.Background(), func(tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(context.Background(), cypher, nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(context.Background())
		if err != nil {
			return nil, err
		}
		return rec.AsMap(), nil
	})
	if err != nil {
		t.Fatalf("consulta fallida: %v\n%s", err, cypher)
	}
	return res.(map[string]any)
}

// DEFECTO: la vía LLM produce un mapeo específico de la CVE —el prompt incluye
// su descripción y su vector CVSS— pero LinkTTPsToVulnerability lo persiste en
// la arista (CWE)-[:MAPS_TO]->(TTP), que es compartida por todas las CVE con ese
// mismo CWE. Con MERGE, cada CVE nueva ACUMULA sus técnicas sobre esa arista, y
// todas las demás las heredan retroactivamente.
//
// La vía CAPEC no tiene este problema: CWE→CAPEC→ATT&CK es genérico del CWE por
// construcción, así que persistirlo a nivel de CWE es lo correcto.
//
// Esta prueba mide la inflación: cuántas técnicas se atribuyen de media a una
// CVE mapeada por LLM. El modelo devuelve del orden de 4 por CVE.
func TestGrafoPropagacionDeMapeosLLMPorCWE(t *testing.T) {
	driver := conectar(t)

	fila := leerUnaFila(t, driver, `
		MATCH (v:Vulnerability)-[:HAS_WEAKNESS|HAS_CWE]->(:CWE)-[:MAPS_TO {source:'llm_enriched'}]->(t:TTP)
		WITH v, count(DISTINCT t) AS n
		RETURN avg(n) AS media, max(n) AS maximo, count(v) AS cves
	`)

	cves, _ := fila["cves"].(int64)
	if cves == 0 {
		t.Skip("no hay mapeos llm_enriched en este grafo")
	}
	media, _ := fila["media"].(float64)
	maximo, _ := fila["maximo"].(int64)
	t.Logf("CVEs mapeadas por LLM: %d | media de tecnicas atribuidas: %.1f | maximo: %d", cves, media, maximo)

	// El LLM devuelve del orden de 4-6 técnicas por CVE. Una media muy por
	// encima solo puede venir de la herencia a través del CWE compartido.
	const umbral = 7.0
	if media > umbral {
		t.Errorf("DEFECTO CONFIRMADO: se atribuyen %.1f tecnicas por CVE de media "+
			"(umbral %.1f). El modelo no afirma tantas: la diferencia es herencia "+
			"desde la arista CWE->TTP compartida.", media, umbral)
	}
}

// Caso nominal del mismo defecto: una CVE concreta acumula técnicas que el
// modelo nunca propuso para ella. Se busca la CVE con mayor discrepancia entre
// las técnicas atribuidas por su CWE y las que tendría un mapeo directo.
func TestGrafoCVEsHeredanTecnicasDeOtrasCVEs(t *testing.T) {
	driver := conectar(t)

	fila := leerUnaFila(t, driver, `
		MATCH (w:CWE)-[:MAPS_TO {source:'llm_enriched'}]->(t:TTP)
		WITH w, count(DISTINCT t) AS tecnicas
		MATCH (v:Vulnerability)-[:HAS_WEAKNESS|HAS_CWE]->(w)
		WITH w.cwe_id AS cwe, tecnicas, count(DISTINCT v) AS cves
		WHERE cves > 1
		RETURN cwe, tecnicas, cves ORDER BY cves * tecnicas DESC LIMIT 1
	`)

	cwe, _ := fila["cwe"].(string)
	tecnicas, _ := fila["tecnicas"].(int64)
	cves, _ := fila["cves"].(int64)

	t.Logf("peor caso: %s acumula %d tecnicas del LLM, heredadas por %d CVEs distintas",
		cwe, tecnicas, cves)

	if cves > 1 && tecnicas > 8 {
		t.Errorf("DEFECTO CONFIRMADO: las %d CVEs con %s comparten las mismas %d "+
			"tecnicas, que son la union de lo que el modelo dijo para cada una por "+
			"separado, no lo que dijo para cada CVE.", cves, cwe, tecnicas)
	}
}

// DEFECTO: 274 CVEs tienen a la vez (v)-[:HAS_WEAKNESS]->(w) y (v)-[:HAS_CWE]->(w)
// hacia el MISMO nodo CWE. Son dos aristas para un solo hecho.
//
// Las consultas del panel (confidenceQuery, topTTPsQuery) están protegidas: usan
// UNION y agrupan por (v,t), así que sus KPIs NO salen inflados. El riesgo es
// para cualquier consulta futura que recorra HAS_WEAKNESS|HAS_CWE sin DISTINCT:
// contará el doble sin que nada lo señale.
func TestGrafoNoHayAristasCVEaCWEDuplicadas(t *testing.T) {
	driver := conectar(t)

	fila := leerUnaFila(t, driver, `
		MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->(w:CWE)
		WHERE (v)-[:HAS_CWE]->(w)
		RETURN count(DISTINCT v) AS duplicadas
	`)

	n, _ := fila["duplicadas"].(int64)
	if n > 0 {
		t.Errorf("DEFECTO CONFIRMADO: %d CVEs tienen HAS_WEAKNESS y HAS_CWE hacia "+
			"el mismo CWE. Toda consulta que recorra ambas sin DISTINCT contara doble.", n)
	}
}

// Invariante: ninguna arista MAPS_TO debe apuntar a un nodo TTP sin nombre. Un
// TTP sin nombre sería un nodo creado por MERGE desde una alucinación del
// modelo, en vez de una técnica del catálogo. LinkTTPsToVulnerability usa MATCH
// justamente para impedirlo; esta prueba lo verifica sobre datos reales.
func TestGrafoNoHayTTPsFantasma(t *testing.T) {
	driver := conectar(t)

	fila := leerUnaFila(t, driver, `
		MATCH (t:TTP) WHERE t.name IS NULL OR t.name = ''
		RETURN count(t) AS fantasma
	`)

	n, _ := fila["fantasma"].(int64)
	if n > 0 {
		t.Errorf("hay %d nodos TTP sin nombre: se estan creando por MERGE en vez de "+
			"enlazarse por MATCH contra el catalogo", n)
	}
}

// Invariante de procedencia: una arista MAPS_TO marcada capec_static debe llevar
// confianza alta, y una llm_enriched confianza media. Si aparece una mezcla,
// significa que una escritura posterior sobrescribió la procedencia de la otra
// vía (MERGE + SET sobre la misma arista compartida).
func TestGrafoCoherenciaEntreOrigenYConfianza(t *testing.T) {
	driver := conectar(t)

	fila := leerUnaFila(t, driver, `
		MATCH (:CWE)-[r:MAPS_TO]->(:TTP)
		WITH r.source AS src, r.confidence AS conf, count(*) AS n
		WITH collect({src: src, conf: conf, n: n}) AS combos
		RETURN [c IN combos WHERE NOT (
		  (c.src = 'capec_static'  AND c.conf = 'high') OR
		  (c.src = 'llm_enriched' AND c.conf = 'medium')
		)] AS incoherentes
	`)

	if lista, ok := fila["incoherentes"].([]any); ok && len(lista) > 0 {
		t.Errorf("combinaciones origen/confianza incoherentes: %v", lista)
	}
}
