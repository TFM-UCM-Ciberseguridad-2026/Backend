package service

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func sacar(t *testing.T, c *colaMapeoTTP) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cveID, ok := c.Siguiente(ctx)
	if !ok {
		t.Fatalf("se esperaba una CVE en cola y no había ninguna")
	}
	return cveID
}

func debeEstarVacia(t *testing.T, c *colaMapeoTTP) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if cveID, ok := c.Siguiente(ctx); ok {
		t.Fatalf("la cola debía estar vacía y devolvió %s", cveID)
	}
}

func esperarResultado(t *testing.T, got, want ResultadoEncolado) {
	t.Helper()
	if got != want {
		t.Fatalf("resultado de encolar: %d, esperado %d", got, want)
	}
}

// Defecto reproducido: con dos proyectos a la vez, las CVE compartidas solo
// constaban para el primero que las encolaba.
func TestCVECompartidaSeProcesaUnaVezYSeAtribuyeAAmbos(t *testing.T) {
	c := nuevaColaMapeoTTP(10, 10)
	esperarResultado(t, c.Encolar("X", 1), EncoladoNuevo)
	esperarResultado(t, c.Encolar("X", 2), EncoladoYaPendiente)

	for _, pid := range []int64{1, 2} {
		if st := c.Estado(pid); st.QueueLength != 1 || !st.Processing {
			t.Fatalf("proyecto %d: queue_length=%d processing=%v, se esperaba 1/true", pid, st.QueueLength, st.Processing)
		}
	}

	if got := sacar(t, c); got != "X" {
		t.Fatalf("salió %s", got)
	}
	debeEstarVacia(t, c) // la copia del proyecto 2 es obsoleta

	if got := c.Terminar("X"); !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Fatalf("interesados: %v", got)
	}
	for _, pid := range []int64{1, 2} {
		if st := c.Estado(pid); st.QueueLength != 0 || st.Processing {
			t.Fatalf("proyecto %d sigue procesando tras terminar", pid)
		}
	}
}

// Defecto reproducido: si el barrido global había encolado la CVE, el disparo
// manual no hacía nada y el proyecto no la seguía.
func TestBarridoGlobalPrimeroSePromueveYSeAtribuye(t *testing.T) {
	c := nuevaColaMapeoTTP(10, 10)
	esperarResultado(t, c.Encolar("G1", 0), EncoladoNuevo)
	esperarResultado(t, c.Encolar("X", 0), EncoladoNuevo)
	esperarResultado(t, c.Encolar("X", 1), EncoladoPromovido)

	if st := c.Estado(1); st.QueueLength != 1 || !st.Processing {
		t.Fatalf("el proyecto no sigue la CVE promovida: %+v", st)
	}
	if got := sacar(t, c); got != "X" {
		t.Fatalf("la promovida debía salir antes que el global, salió %s", got)
	}
	if got := c.Terminar("X"); !reflect.DeepEqual(got, []int64{0, 1}) {
		t.Fatalf("interesados: %v", got)
	}
	if got := sacar(t, c); got != "G1" {
		t.Fatalf("salió %s", got)
	}
	c.Terminar("G1")
	debeEstarVacia(t, c) // la copia de baja de X es obsoleta
}

func TestProyectosSeAtiendenPorTurnos(t *testing.T) {
	c := nuevaColaMapeoTTP(100, 100)
	for i := 1; i <= 5; i++ {
		c.Encolar(fmt.Sprintf("a%d", i), 1)
	}
	c.Encolar("b1", 2)
	c.Encolar("b2", 2)

	var orden []string
	for i := 0; i < 7; i++ {
		cveID := sacar(t, c)
		orden = append(orden, cveID)
		c.Terminar(cveID)
	}
	want := []string{"a1", "b1", "a2", "b2", "a3", "a4", "a5"}
	if !reflect.DeepEqual(orden, want) {
		t.Fatalf("orden %v, esperado %v", orden, want)
	}
}

func TestInteresDuranteElProcesoRecibeElResultado(t *testing.T) {
	c := nuevaColaMapeoTTP(10, 10)
	c.Encolar("X", 1)
	sacar(t, c)

	esperarResultado(t, c.Encolar("X", 2), EncoladoEnProceso)
	if st := c.Estado(2); st.QueueLength != 1 || st.CurrentCVE != "X" {
		t.Fatalf("estado del proyecto que llega tarde: %+v", st)
	}
	if got := c.Terminar("X"); !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Fatalf("interesados: %v", got)
	}
	debeEstarVacia(t, c)
}

func TestColaLlenaDescartaSinDejarEstadoColgado(t *testing.T) {
	c := nuevaColaMapeoTTP(1, 1)
	esperarResultado(t, c.Encolar("a", 1), EncoladoNuevo)
	esperarResultado(t, c.Encolar("b", 2), EncoladoDescartado)
	if st := c.Estado(2); st.Processing || st.QueueLength != 0 {
		t.Fatalf("un descarte no debe dejar el proyecto procesando: %+v", st)
	}

	esperarResultado(t, c.Encolar("g", 0), EncoladoNuevo)
	esperarResultado(t, c.Encolar("h", 0), EncoladoDescartado)

	// Con la alta llena, g no se promueve, pero el proyecto la sigue igualmente.
	esperarResultado(t, c.Encolar("g", 1), EncoladoYaPendiente)
	if st := c.Estado(1); st.QueueLength != 2 {
		t.Fatalf("queue_length del proyecto 1: %d, esperado 2", st.QueueLength)
	}

	if got := sacar(t, c); got != "a" {
		t.Fatalf("salió %s", got)
	}
	c.Terminar("a")
	if got := sacar(t, c); got != "g" {
		t.Fatalf("salió %s", got)
	}
	if got := c.Terminar("g"); !reflect.DeepEqual(got, []int64{0, 1}) {
		t.Fatalf("interesados de g: %v", got)
	}
	debeEstarVacia(t, c)
}

func TestOlvidarProyectoConservaLoCompartido(t *testing.T) {
	c := nuevaColaMapeoTTP(10, 10)
	c.Encolar("x", 1)
	c.Encolar("x", 2)
	c.Encolar("y", 1)
	c.Encolar("w", 1)
	c.Encolar("w", 0) // el global la sigue sin copia propia

	c.Olvidar(1)
	if st := c.Estado(1); st.QueueLength != 0 || len(st.Logs) != 0 {
		t.Fatalf("quedó estado del proyecto borrado: %+v", st)
	}

	procesadas := map[string][]int64{}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		cveID, ok := c.Siguiente(ctx)
		cancel()
		if !ok {
			break
		}
		procesadas[cveID] = c.Terminar(cveID)
	}

	want := map[string][]int64{"x": {2}, "w": {0}}
	if !reflect.DeepEqual(procesadas, want) {
		t.Fatalf("procesadas %v, esperado %v (y era solo del proyecto borrado)", procesadas, want)
	}
}

func TestBajaAvanzaTrasDiezAltasSeguidas(t *testing.T) {
	c := nuevaColaMapeoTTP(100, 100)
	c.Encolar("g", 0)
	for i := 1; i <= 11; i++ {
		c.Encolar(fmt.Sprintf("h%02d", i), 1)
	}

	var orden []string
	for i := 0; i < 12; i++ {
		cveID := sacar(t, c)
		orden = append(orden, cveID)
		c.Terminar(cveID)
	}
	if orden[10] != "g" || orden[11] != "h11" {
		t.Fatalf("la de baja debía salir en la posición 11: %v", orden)
	}
}

func TestCopiaObsoletaNoReprocesaTrasReencolar(t *testing.T) {
	c := nuevaColaMapeoTTP(10, 10)
	c.Encolar("x", 0)
	esperarResultado(t, c.Encolar("x", 1), EncoladoPromovido)
	sacar(t, c)
	c.Terminar("x")

	// Vuelve a pedirse: la copia antigua de baja sigue en la FIFO con otra gen.
	esperarResultado(t, c.Encolar("x", 0), EncoladoNuevo)
	if got := sacar(t, c); got != "x" {
		t.Fatalf("salió %s", got)
	}
	c.Terminar("x")
	debeEstarVacia(t, c)
}

// Con -race: productores de varios proyectos compitiendo con el worker. Toda
// petición aceptada debe acabar en un Terminar que incluya a su proyecto.
func TestConcurrenciaTodaPeticionRecibeSuResultado(t *testing.T) {
	const proyectos, cves = 4, 200
	c := nuevaColaMapeoTTP(10000, 10000)

	type par struct {
		cve string
		pid int64
	}
	var muRes sync.Mutex
	atendidos := map[par]bool{}
	pedidos := map[par]bool{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		for {
			cveID, ok := c.Siguiente(ctx)
			if !ok {
				return
			}
			ids := c.Terminar(cveID)
			muRes.Lock()
			for _, pid := range ids {
				atendidos[par{cveID, pid}] = true
			}
			muRes.Unlock()
		}
	}()

	var productores sync.WaitGroup
	for p := int64(0); p < proyectos; p++ {
		productores.Add(1)
		go func(pid int64) {
			defer productores.Done()
			for i := 0; i < cves; i++ {
				cveID := fmt.Sprintf("CVE-%03d", i)
				if c.Encolar(cveID, pid) != EncoladoDescartado {
					muRes.Lock()
					pedidos[par{cveID, pid}] = true
					muRes.Unlock()
				}
			}
		}(p)
	}
	productores.Wait()

	limite := time.Now().Add(5 * time.Second)
	for {
		pendientes := 0
		for pid := int64(0); pid < proyectos; pid++ {
			pendientes += c.Estado(pid).QueueLength
		}
		if pendientes == 0 || time.Now().After(limite) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	worker.Wait()

	muRes.Lock()
	defer muRes.Unlock()
	for p := range pedidos {
		if !atendidos[p] {
			t.Errorf("petición sin resultado: %s para el proyecto %d", p.cve, p.pid)
		}
	}
}
