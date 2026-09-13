package prueba_ollama_client

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

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider/ollama"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

/*
Pruebas del adaptador Ollama (puerto TTPMapper).

Estas pruebas NO llaman al LLM real: levantan un servidor HTTP de prueba que
imita /api/generate y devuelve respuestas controladas. Así se puede fijar el
comportamiento del parseo, de la caché y del reintento sin depender de que el
modelo esté cargado ni de su no determinismo.
*/

// newTestClient levanta un servidor falso de Ollama que responde con el texto
// indicado y devuelve un cliente ya apuntado a él.
func newTestClient(t *testing.T, respuestaModelo string) (*ollama.OllamaClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"response": respuestaModelo})
	}))
	t.Cleanup(srv.Close)
	return ollama.NewOllamaClient(srv.URL, "modelo-de-prueba"), srv
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
			ttps, _, err := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
				CWE:         "CWE-79",
				Description: "desc",
				CVSSVector:  "AV:N",
			})

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

// Verifica que un identificador inválido de 5 dígitos (T11905) no sea truncado
// a una técnica existente (T1190).
func TestDefectoIdentificadorDeCincoDigitosSeTrunca(t *testing.T) {
	cli, _ := newTestClient(t, `{"ttps": ["T11905"]}`)
	ttps, _, _ := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
		CWE:         "CWE-79",
		Description: "d",
		CVSSVector:  "v",
	})

	for _, ttp := range ttps {
		if ttp == "T1190" {
			t.Errorf("DEFECTO CONFIRMADO: 'T11905' (inexistente) se recorto a %q", ttp)
		}
	}
}

// Verifica que una subtécnica inválida de cuatro dígitos (T1059.0011) no sea
// truncada a T1059.001.
func TestDefectoSubtecnicaDeCuatroDigitosSeTrunca(t *testing.T) {
	cli, _ := newTestClient(t, `{"ttps": ["T1059.0011"]}`)
	ttps, _, _ := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
		CWE:         "CWE-79",
		Description: "d",
		CVSSVector:  "v",
	})

	for _, ttp := range ttps {
		if ttp == "T1059.001" {
			t.Errorf("DEFECTO CONFIRMADO: 'T1059.0011' se recorto a %q", ttp)
		}
	}
}

// Verifica que solo se extraigan técnicas dentro del campo estructurado "ttps".
func TestDefectoSeExtraenIdentificadoresFueraDelArrayTtps(t *testing.T) {
	respuesta := `{"ttps": [], "descartadas": ["T1190", "T1566.001"], "motivo": "no aplica"}`
	cli, _ := newTestClient(t, respuesta)

	ttps, _, _ := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
		CWE:         "CWE-79",
		Description: "d",
		CVSSVector:  "v",
	})

	if len(ttps) > 0 {
		t.Errorf("DEFECTO CONFIRMADO: se extrajeron identificadores ajenos al array ttps: %v", ttps)
	}
}

// Verifica que identificadores en minúsculas sean normalizados y aceptados.
func TestDefectoIdentificadoresEnMinusculasSeIgnoran(t *testing.T) {
	cli, _ := newTestClient(t, `{"ttps": ["t1190", "t1059.001"]}`)
	ttps, _, err := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
		CWE:         "CWE-79",
		Description: "d",
		CVSSVector:  "v",
	})
	if err != nil {
		t.Errorf("respuesta valida en minusculas rechazada: %v", err)
	}
	if len(ttps) != 2 || ttps[0] != "T1190" || ttps[1] != "T1059.001" {
		t.Errorf("esperado [T1190 T1059.001], obtenido %v", ttps)
	}
}

func TestCacheSoloParaConsultaSimple(t *testing.T) {
	var llamadas int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&llamadas, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"response": `{"ttps": ["T1190"]}`})
	}))
	defer srv.Close()
	cli := ollama.NewOllamaClient(srv.URL, "m")
	ctx := context.Background()

	// Consulta simple (solo CWE): la segunda debe servirse de caché.
	if _, _, err := cli.MapEnrichedToTTPRaw(ctx, domain.TTPMappingRequest{CWE: "CWE-79"}); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := cli.MapEnrichedToTTPRaw(ctx, domain.TTPMappingRequest{CWE: "CWE-79"}); err != nil {
		t.Fatal(err)
	} else if raw != "[CACHE HIT - NO RAW RESPONSE]" {
		t.Errorf("se esperaba acierto de cache, raw=%q", raw)
	}
	if n := atomic.LoadInt32(&llamadas); n != 1 {
		t.Errorf("se esperaba 1 llamada al modelo, hubo %d", n)
	}

	// Consulta enriquecida: nunca se cachea, siempre golpea al modelo.
	for i := 0; i < 2; i++ {
		if _, _, err := cli.MapEnrichedToTTPRaw(ctx, domain.TTPMappingRequest{
			CWE:         "CWE-79",
			Description: "descripcion",
			CVSSVector:  "AV:N",
		}); err != nil {
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
	cli := ollama.NewOllamaClient(srv.URL, "m")

	if _, err := cli.MapCWEToTTP(context.Background(), "CWE-79"); err == nil {
		t.Fatal("se esperaba error con status 500")
	}
	// Un 500 no es un error de red: no debe consumir reintentos.
	if n := atomic.LoadInt32(&llamadas); n != 1 {
		t.Errorf("un 500 no debe reintentarse: %d llamadas", n)
	}
}

func TestRespuestaVaciaNoSeReintentaEnLaMismaLlamada(t *testing.T) {
	var llamadas int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&llamadas, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"response": `{"ttps": []}`})
	}))
	defer srv.Close()
	cli := ollama.NewOllamaClient(srv.URL, "m")

	if _, _, err := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
		CWE:         "CWE-79",
		Description: "d",
		CVSSVector:  "v",
	}); err == nil {
		t.Fatal("se esperaba error")
	}
	if n := atomic.LoadInt32(&llamadas); n != 1 {
		t.Errorf("esperada 1 llamada, hubo %d", n)
	}
}

func TestSemaforoLimitaConcurrencia(t *testing.T) {
	const maxConcurrent = 2
	var enVuelo, maxEnVuelo int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&enVuelo, 1)
		for {
			m := atomic.LoadInt32(&maxEnVuelo)
			if n <= m || atomic.CompareAndSwapInt32(&maxEnVuelo, m, n) {
				break
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"response": `{"ttps": ["T1190"]}`})
		atomic.AddInt32(&enVuelo, -1)
	}))
	defer srv.Close()
	cli := ollama.NewOllamaClient(srv.URL, "m")

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// CWE distinto en cada goroutine para no servir desde caché.
			_, _, _ = cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
				CWE:         fmt.Sprintf("CWE-%d", i),
				Description: "d",
				CVSSVector:  "v",
			})
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
		var req struct {
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		recibido = req.Prompt
		_ = json.NewEncoder(w).Encode(map[string]any{"response": `{"ttps": ["T1190"]}`})
	}))
	defer srv.Close()
	cli := ollama.NewOllamaClient(srv.URL, "m")

	_, _, err := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{
		CWE:         "CWE-89",
		Description: "SQL injection en el parametro id",
		CVSSVector:  "CVSS:3.1/AV:N/AC:L",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, fragmento := range []string{"CWE-89", "SQL injection en el parametro id", "CVSS:3.1/AV:N/AC:L"} {
		if !strings.Contains(recibido, fragmento) {
			t.Errorf("el prompt no incluye %q", fragmento)
		}
	}
}

func TestElPromptUsaMarcadoresGenericos(t *testing.T) {
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		prompt = req.Prompt
		_ = json.NewEncoder(w).Encode(map[string]any{"response": `{"ttps": ["T1190"]}`})
	}))
	defer srv.Close()
	cli := ollama.NewOllamaClient(srv.URL, "m")

	_, _, err := cli.MapEnrichedToTTPRaw(context.Background(), domain.TTPMappingRequest{CWE: "CWE-89"})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(prompt, "Txxxx") {
		t.Errorf("el prompt deberia usar marcadores genericos Txxxx, obtenido: %s", prompt)
	}
	if strings.Contains(prompt, "T1059.001") {
		t.Errorf("el prompt no deberia sugerir la tecnica concreta T1059.001 como ejemplo")
	}
}
