package prueba_mitre_attack

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
)

/*
Pruebas del ingestor del catálogo STIX 2.1 de MITRE ATT&CK.

Las pruebas de parseo usan bundles mínimos escritos a mano. La prueba de
cobertura (TestBundleRealContieneLaFamiliaT1562) necesita el bundle oficial
completo y solo se ejecuta si se le indica dónde está:

	MITRE_BUNDLE=/ruta/enterprise-attack.json go test ./cmd/Pruebas/prueba_mitre_attack/ -run T1562 -v

Existe porque en el grafo del entorno de pruebas faltaba la familia T1562
("Impair Defenses") entera —técnica padre y sus 13 subtécnicas—, mientras que
otras 17 técnicas de uso común comprobadas sí estaban. La pregunta que responde
esta prueba es si el ingestor las descarta o si el catálogo del grafo
simplemente está desactualizado.
*/

// sirveBundle levanta un servidor que devuelve el JSON indicado, y construye un
// provider apuntado a él.
func sirveBundle(t *testing.T, cuerpo string) *provider.MitreAttackSTIXProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cuerpo))
	}))
	t.Cleanup(srv.Close)
	return provider.NewMitreAttackSTIXProvider(srv.URL, 30)
}

func TestSeIgnoranTecnicasDeprecadasYRevocadas(t *testing.T) {
	bundle := `{"objects":[
		{"type":"attack-pattern","id":"a--1","name":"Vigente",
		 "external_references":[{"source_name":"mitre-attack","external_id":"T1000"}],
		 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"execution"}]},
		{"type":"attack-pattern","id":"a--2","name":"Deprecada","x_mitre_deprecated":true,
		 "external_references":[{"source_name":"mitre-attack","external_id":"T2000"}]},
		{"type":"attack-pattern","id":"a--3","name":"Revocada","revoked":true,
		 "external_references":[{"source_name":"mitre-attack","external_id":"T3000"}]}
	]}`

	catalog, err := sirveBundle(t, bundle).FetchATTACKBundle(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(catalog.TTPs) != 1 || catalog.TTPs[0].TTPID != "T1000" {
		t.Fatalf("esperada solo T1000, obtenido %+v", catalog.TTPs)
	}
}

func TestSeIgnoranReferenciasDeOtrasFuentes(t *testing.T) {
	// Un attack-pattern cuyo external_id viene de CAPEC y no de mitre-attack no
	// debe entrar como TTP: crearía un nodo con un identificador de otro esquema.
	bundle := `{"objects":[
		{"type":"attack-pattern","id":"a--1","name":"Solo CAPEC",
		 "external_references":[{"source_name":"capec","external_id":"CAPEC-66"}]}
	]}`

	catalog, err := sirveBundle(t, bundle).FetchATTACKBundle(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(catalog.TTPs) != 0 {
		t.Errorf("no debia ingerirse ninguna TTP, obtenido %+v", catalog.TTPs)
	}
}

func TestSeConservanLasTacticasMultiples(t *testing.T) {
	// El 29% de las técnicas pertenecen a más de una táctica. Si el ingestor se
	// queda con la primera, la matriz del panel pierde columnas.
	bundle := `{"objects":[
		{"type":"attack-pattern","id":"a--1","name":"Valid Accounts",
		 "external_references":[{"source_name":"mitre-attack","external_id":"T1078"}],
		 "kill_chain_phases":[
		   {"kill_chain_name":"mitre-attack","phase_name":"defense-evasion"},
		   {"kill_chain_name":"mitre-attack","phase_name":"persistence"},
		   {"kill_chain_name":"mitre-attack","phase_name":"privilege-escalation"},
		   {"kill_chain_name":"mitre-attack","phase_name":"initial-access"}]}
	]}`

	catalog, err := sirveBundle(t, bundle).FetchATTACKBundle(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(catalog.TTPs) != 1 {
		t.Fatalf("esperada 1 TTP, obtenidas %d", len(catalog.TTPs))
	}
	for _, tactica := range []string{"persistence", "privilege-escalation", "initial-access"} {
		if !strings.Contains(catalog.TTPs[0].Tactic, tactica) {
			t.Errorf("la tactica %q se perdio; Tactic=%q", tactica, catalog.TTPs[0].Tactic)
		}
	}
}

func TestBundleVacioNoEsError(t *testing.T) {
	catalog, err := sirveBundle(t, `{"objects":[]}`).FetchATTACKBundle(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(catalog.TTPs) != 0 || len(catalog.Actors) != 0 || len(catalog.Relations) != 0 {
		t.Errorf("se esperaba todo vacio: %d/%d/%d", len(catalog.TTPs), len(catalog.Actors), len(catalog.Relations))
	}
}

func TestStatusNoOKEsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := provider.NewMitreAttackSTIXProvider(srv.URL, 30).FetchATTACKBundle(context.Background())
	if err == nil {
		t.Fatal("se esperaba error con status 404")
	}
}

// TestBundleRealExcluyeLaFamiliaT1562Revocada documenta el resultado de la
// investigación: T1562 "Impair Defenses" figura en el bundle oficial con
// revoked=true, y sus subtécnicas igual. El ingestor las excluye correctamente,
// y por eso no están en el grafo.
//
// La prueba se conserva porque el hueco tiene consecuencias aguas abajo: el LLM
// sigue proponiendo T1562.x —su conocimiento corresponde a una versión anterior
// de ATT&CK— y esas propuestas se descartan sin dejar rastro al escribir en
// Neo4j. Si una futura versión del catálogo reintrodujera la familia, esta
// prueba lo detectaría.
func TestBundleRealExcluyeLaFamiliaT1562Revocada(t *testing.T) {
	ruta := os.Getenv("MITRE_BUNDLE")
	if ruta == "" {
		t.Skip("define MITRE_BUNDLE con la ruta al enterprise-attack.json para ejecutar esta prueba")
	}

	datos, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer el bundle: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			_, _ = gz.Write(datos)
			return
		}
		_, _ = w.Write(datos)
	}))
	defer srv.Close()

	catalog, err := provider.NewMitreAttackSTIXProvider(srv.URL, 300).FetchATTACKBundle(context.Background())
	if err != nil {
		t.Fatalf("error parseando el bundle real: %v", err)
	}
	ttps := catalog.TTPs
	t.Logf("el ingestor extrajo %d TTPs vigentes del bundle oficial", len(ttps))

	presentes := make(map[string]string, len(ttps))
	for _, x := range ttps {
		presentes[x.TTPID] = x.Name
	}

	if nombre, ok := presentes["T1562"]; ok {
		t.Errorf("T1562 (%q) ha vuelto al catalogo vigente: revisar el hueco "+
			"documentado y resincronizar SyncATTACKCatalog", nombre)
	}

	var subs int
	for id := range presentes {
		if strings.HasPrefix(id, "T1562.") {
			subs++
		}
	}
	if subs != 0 {
		t.Errorf("han reaparecido %d subtecnicas T1562.x en el catalogo vigente", subs)
	}

	// Comprobación de cordura: si el ingestor devolviera muy pocas técnicas, el
	// resultado anterior no probaría nada.
	if len(ttps) < 600 {
		t.Fatalf("solo %d TTPs extraidas: el bundle o el filtrado no son los esperados", len(ttps))
	}
	t.Logf("catalogo vigente: %d TTPs; familia T1562 ausente por revoked=true en origen", len(ttps))
}
