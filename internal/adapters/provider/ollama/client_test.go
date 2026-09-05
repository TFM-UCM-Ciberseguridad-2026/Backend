package ollama

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

/*
Pruebas del adaptador Ollama (puerto TTPMapper).

Estas pruebas NO llaman al LLM real: levantan un servidor HTTP de prueba que
imita /api/generate y devuelve respuestas controladas. Así se puede fijar el
comportamiento del parseo, de la caché y del reintento sin depender de que el
modelo esté cargado ni de su no determinismo.

Lo que se prueba es la frontera que de verdad decide qué acaba en el grafo: la
extracción de identificadores de la respuesta del modelo. Esa extracción es una
expresión regular sobre el texto completo, no una lectura del JSON, y ahí es
donde aparecen los defectos que documentan las pruebas marcadas como DEFECTO.
*/

// newTestClient levanta un servidor falso de Ollama que responde con el texto
// indicado y devuelve un cliente ya apuntado a él.
func newTestClient(t *testing.T, respuestaModelo string) (*OllamaClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(generateResponse{Response: respuestaModelo})
	}))
	t.Cleanup(srv.Close)
	return NewOllamaClient(srv.URL, "modelo-de-prueba"), srv
}

func TestExtraccionDeTTPs(t *testing.T) {
	casos := []struct {
		nombre    string
		respuesta string
		esperado  []string
		wantErr   bool
	}{
		{
			nombre:    "respuesta JSON limpia",
			respuesta: `{"ttps": ["T1190", "T1059.001"]}`,
			esperado:  []string{"T1190", "T1059.001"},
		},
		{
			nombre:    "deduplica identificadores repetidos",
			respuesta: `{"ttps": ["T1190", "T1190", "T1059.001", "T1190"]}`,
			esperado:  []string{"T1190", "T1059.001"},
		},
		{
			nombre:    "conserva el orden de aparicion",
			respuesta: `{"ttps": ["T1059.001", "T1190", "T1078"]}`,
			esperado:  []string{"T1059.001", "T1190", "T1078"},
		},
		{
			nombre:    "sin identificadores devuelve error",
			respuesta: `{"ttps": []}`,
			wantErr:   true,
		},
		{
			nombre:    "texto libre sin identificadores devuelve error",
			respuesta: `No puedo determinar tecnicas para esta debilidad.`,
			wantErr:   true,
		},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			cli, _ := newTestClient(t, c.respuesta)
			ttps, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-79", "desc", "AV:N")

			if c.wantErr {
				if err == nil {
					t.Fatalf("se esperaba error, se obtuvo %v", ttps)
				}
				return
			}
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if strings.Join(ttps, ",") != strings.Join(c.esperado, ",") {
				t.Errorf("esperado %v, obtenido %v", c.esperado, ttps)
			}
		})
	}
}

// DEFECTO 1: la expresión regular `T\d{4}(?:\.\d{3})?` no está anclada, así que
// un identificador de cinco dígitos se recorta a los cuatro primeros y se
// convierte en OTRO identificador distinto, este sí existente en el catálogo.
// Una alucinación evidente (T11905, que no existe) entra en el grafo disfrazada
// de T1190 "Exploit Public-Facing Application", que es una técnica real y de
// alto impacto. El descarte por MATCH en Neo4j no protege de esto: el ID ya es
// válido cuando llega.
func TestDefectoIdentificadorDeCincoDigitosSeTrunca(t *testing.T) {
	cli, _ := newTestClient(t, `{"ttps": ["T11905"]}`)
	ttps, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-79", "d", "v")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if len(ttps) == 1 && ttps[0] == "T1190" {
		t.Errorf("DEFECTO CONFIRMADO: 'T11905' (inexistente) se recorto a %q, "+
			"una tecnica real. La alucinacion se vuelve indetectable.", ttps[0])
	}
}

// DEFECTO 2: mismo origen, sobre la subtécnica. `T1059.0011` se recorta a
// `T1059.001` (PowerShell).
func TestDefectoSubtecnicaDeCuatroDigitosSeTrunca(t *testing.T) {
	cli, _ := newTestClient(t, `{"ttps": ["T1059.0011"]}`)
	ttps, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-79", "d", "v")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(ttps) == 1 && ttps[0] == "T1059.001" {
		t.Errorf("DEFECTO CONFIRMADO: 'T1059.0011' se recorto a %q", ttps[0])
	}
}

// DEFECTO 3: la extracción se hace sobre el texto completo de la respuesta, sin
// mirar la estructura JSON. Cualquier identificador que el modelo mencione fuera
// del array "ttps" — en un campo de razonamiento, en una lista de descartes, o
// repitiendo el ejemplo del propio prompt — se persiste como si fuera una
// técnica afirmada por el modelo.
func TestDefectoSeExtraenIdentificadoresFueraDelArrayTtps(t *testing.T) {
	// El modelo responde correctamente que NO aplica ninguna técnica, y explica
	// cuáles ha descartado. Todas las descartadas acaban mapeadas.
	respuesta := `{"ttps": [], "descartadas": ["T1190", "T1566.001"], "motivo": "no aplica"}`
	cli, _ := newTestClient(t, respuesta)

	ttps, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-79", "d", "v")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(ttps) > 0 {
		t.Errorf("DEFECTO CONFIRMADO: el modelo devolvio ttps=[] y aun asi se "+
			"extrajeron %v desde campos ajenos al array de respuesta", ttps)
	}
}

// DEFECTO 4: la expresión distingue mayúsculas de minúsculas. Si el modelo
// responde en minúsculas — variación habitual — no se extrae nada y la llamada
// se reporta como fallo, cuando la respuesta era correcta. Que
// LinkTTPsToVulnerability normalice a mayúsculas al escribir demuestra que se
// contaba con recibir minúsculas; la normalización llega demasiado tarde.
func TestDefectoIdentificadoresEnMinusculasSeIgnoran(t *testing.T) {
	cli, _ := newTestClient(t, `{"ttps": ["t1190", "t1059.001"]}`)
	_, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-79", "d", "v")
	if err != nil {
		t.Errorf("DEFECTO CONFIRMADO: respuesta valida en minusculas rechazada: %v", err)
	}
}

func TestCacheSoloParaConsultaSimple(t *testing.T) {
	var llamadas int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&llamadas, 1)
		_ = json.NewEncoder(w).Encode(generateResponse{Response: `{"ttps": ["T1190"]}`})
	}))
	defer srv.Close()
	cli := NewOllamaClient(srv.URL, "m")
	ctx := context.Background()

	// Consulta simple (solo CWE): la segunda debe servirse de caché.
	if _, _, err := cli.MapEnrichedToTTPRaw(ctx, "CWE-79", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := cli.MapEnrichedToTTPRaw(ctx, "CWE-79", "", ""); err != nil {
		t.Fatal(err)
	} else if raw != "[CACHE HIT - NO RAW RESPONSE]" {
		t.Errorf("se esperaba acierto de cache, raw=%q", raw)
	}
	if n := atomic.LoadInt32(&llamadas); n != 1 {
		t.Errorf("se esperaba 1 llamada al modelo, hubo %d", n)
	}

	// Consulta enriquecida: nunca se cachea, siempre golpea al modelo.
	for i := 0; i < 2; i++ {
		if _, _, err := cli.MapEnrichedToTTPRaw(ctx, "CWE-79", "descripcion", "AV:N"); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(&llamadas); n != 3 {
		t.Errorf("la consulta enriquecida no debe cachearse: esperadas 3 llamadas, hubo %d", n)
	}
}

func TestErrorHTTPNoSeReintenta(t *testing.T) {
	var llamadas int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&llamadas, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cli := NewOllamaClient(srv.URL, "m")

	if _, err := cli.MapCWEToTTP(context.Background(), "CWE-79"); err == nil {
		t.Fatal("se esperaba error con status 500")
	}
	// Un 500 no es un error de red: no debe consumir reintentos.
	if n := atomic.LoadInt32(&llamadas); n != 1 {
		t.Errorf("un 500 no debe reintentarse: %d llamadas", n)
	}
}

// DEFECTO 5: "sin TTPs en la respuesta" se trata como error no reintentable,
// pero el fallo tampoco se distingue de un error de infraestructura aguas
// arriba. processSingleCVE devuelve ese error, la CVE nunca se marca de ningun
// modo, y el barrido periodico la vuelve a encolar cada 10 minutos: el mismo
// prompt se reenvia al LLM indefinidamente sin posibilidad de exito distinto.
func TestRespuestaVaciaNoSeReintentaEnLaMismaLlamada(t *testing.T) {
	var llamadas int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&llamadas, 1)
		_ = json.NewEncoder(w).Encode(generateResponse{Response: `{"ttps": []}`})
	}))
	defer srv.Close()
	cli := NewOllamaClient(srv.URL, "m")

	if _, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-79", "d", "v"); err == nil {
		t.Fatal("se esperaba error")
	}
	if n := atomic.LoadInt32(&llamadas); n != 1 {
		t.Errorf("esperada 1 llamada, hubo %d", n)
	}
}

func TestSemaforoLimitaConcurrencia(t *testing.T) {
	var enVuelo, maxEnVuelo int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&enVuelo, 1)
		for {
			m := atomic.LoadInt32(&maxEnVuelo)
			if n <= m || atomic.CompareAndSwapInt32(&maxEnVuelo, m, n) {
				break
			}
		}
		_ = json.NewEncoder(w).Encode(generateResponse{Response: `{"ttps": ["T1190"]}`})
		atomic.AddInt32(&enVuelo, -1)
	}))
	defer srv.Close()
	cli := NewOllamaClient(srv.URL, "m")

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// CWE distinto en cada goroutine para no servir desde caché.
			_, _, _ = cli.MapEnrichedToTTPRaw(context.Background(), fmt.Sprintf("CWE-%d", i), "d", "v")
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxEnVuelo); got > maxConcurrent {
		t.Errorf("el semaforo permitio %d llamadas simultaneas, el limite es %d", got, maxConcurrent)
	}
}

func TestPromptIncluyeElContextoEnriquecido(t *testing.T) {
	var recibido string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		recibido = req.Prompt
		_ = json.NewEncoder(w).Encode(generateResponse{Response: `{"ttps": ["T1190"]}`})
	}))
	defer srv.Close()
	cli := NewOllamaClient(srv.URL, "m")

	_, _, err := cli.MapEnrichedToTTPRaw(context.Background(), "CWE-89",
		"SQL injection en el parametro id", "CVSS:3.1/AV:N/AC:L")
	if err != nil {
		t.Fatal(err)
	}

	for _, fragmento := range []string{"CWE-89", "SQL injection en el parametro id", "CVSS:3.1/AV:N/AC:L"} {
		if !strings.Contains(recibido, fragmento) {
			t.Errorf("el prompt no incluye %q", fragmento)
		}
	}
}

// El prompt incrusta el ejemplo {"ttps": ["T1190", "T1059.001"]}. Un modelo
// pequeño que repita el ejemplo produce exactamente esas dos técnicas y el
// pipeline no puede distinguirlo de una respuesta razonada.
func TestElPromptSugiereDosTecnicasConcretas(t *testing.T) {
	cli := NewOllamaClient("http://localhost:0", "m")
	prompt := cli.buildEnrichedPrompt("CWE-89", "", "")
	for _, id := range []string{"T1190", "T1059.001"} {
		if !strings.Contains(prompt, id) {
			t.Fatalf("el prompt ya no contiene %s; revisar esta prueba", id)
		}
	}
	t.Logf("AVISO: el prompt sugiere literalmente %s y %s; ambas encabezan el "+
		"top de TTPs del panel, lo que es compatible con sesgo por el ejemplo.",
		"T1190", "T1059.001")
}
