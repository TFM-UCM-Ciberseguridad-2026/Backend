package service

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
Cola del worker de mapeo de TTPs.

Hay un único worker para toda la aplicación y se mantiene así: el cuello de
botella es el LLM local, y paralelizar las inferencias no ganaría nada. Lo que
resuelve esta cola es a QUIÉN se atribuye el trabajo y en QUÉ ORDEN se atiende:

 1. Deduplicación separada de la atribución. Una CVE se procesa una sola vez,
    pero todos los proyectos que la pidieron quedan registrados como interesados
    y reciben el resultado. Antes la deduplicación era global por CVE y el
    segundo proyecto que la pedía simplemente no la veía: ni en su progreso, ni
    en sus logs, ni por WebSocket.
 2. Promoción. Si el barrido global (prioridad baja) ya había encolado una CVE,
    el disparo manual de un proyecto la sube a prioridad alta en lugar de
    ignorarse mientras la interfaz anunciaba el mapeo como iniciado.
 3. Turnos. La prioridad alta tiene una FIFO por proyecto y se atienden por
    turnos: un proyecto con muchas CVEs ya no hace esperar a los demás hasta
    vaciarse (medido: un proyecto esperó 6 min 42 s detrás de otro).

Las copias de una misma CVE en varias colas no se retiran al procesarla: los
canales no permiten sacar elementos del medio. Cada copia lleva la generación
de su entrada y, al salir, se descarta si ya no corresponde a una entrada viva.
*/

// maxTTPLogs acota el histórico de líneas que el servidor conserva por proyecto.
// Es el mismo tope que ya aplicaba el cliente (.slice(-200)); sin él, el barrido
// periódico —que se repite cada 10 minutos indefinidamente— hacía crecer el slice
// sin límite y engordaba cada respuesta de estado, que además se sondea cada 1,5 s.
const maxTTPLogs = 200

// maxAltasSeguidas: tras este número de CVEs de prioridad alta seguidas se da
// paso a una de baja, si la hay, para que el barrido global no se detenga
// mientras haya disparos manuales.
const maxAltasSeguidas = 10

type ProjectTTPSyncState struct {
	CurrentCVE string
	Logs       []string
	QueuedCVEs map[string]bool
}

type TTPBackgroundSyncResponse struct {
	Processing  bool     `json:"processing"`
	CurrentCVE  string   `json:"current_cve"`
	QueueLength int      `json:"queue_length"`
	Logs        []string `json:"logs"`
}

// ResultadoEncolado describe qué ocurrió al pedir una CVE para un proyecto.
type ResultadoEncolado int

const (
	EncoladoNuevo       ResultadoEncolado = iota // no estaba pendiente: entra en cola
	EncoladoYaPendiente                          // ya estaba en cola: se añade el proyecto como interesado
	EncoladoPromovido                            // estaba solo en prioridad baja: pasa a alta
	EncoladoEnProceso                            // el worker la está procesando: el proyecto recibirá el resultado
	EncoladoDescartado                           // cola llena: no queda registrada
)

// ResumenBarrido cuenta el resultado de un barrido. Seguidas() es lo que el
// proyecto verá progresar: coincide con su queue_length justo después.
type ResumenBarrido struct {
	Encontradas  int
	Nuevas       int
	YaPendientes int
	Promovidas   int
	Descartadas  int
}

func (r ResumenBarrido) Seguidas() int {
	return r.Nuevas + r.YaPendientes + r.Promovidas
}

func (r *ResumenBarrido) Contar(res ResultadoEncolado) {
	switch res {
	case EncoladoNuevo:
		r.Nuevas++
	case EncoladoYaPendiente, EncoladoEnProceso:
		r.YaPendientes++
	case EncoladoPromovido:
		r.Promovidas++
	case EncoladoDescartado:
		r.Descartadas++
	}
}

type claseCola int

const (
	claseNinguna claseCola = iota
	claseAlta
	claseBaja
)

type entradaCVE struct {
	interesados map[int64]struct{} // proyectos que la han pedido; 0 = barrido global
	gen         uint64             // vida de la entrada en cola; las copias de otra gen son obsoletas
	enProceso   bool
	enAlta      map[int64]bool // proyectos con una copia viva en su FIFO de alta
	enBaja      bool           // tiene una copia viva en la FIFO de baja
}

type tareaTTP struct {
	cveID string
	gen   uint64
}

type colaMapeoTTP struct {
	mu         sync.Mutex
	pendientes map[string]*entradaCVE
	alta       map[int64][]tareaTTP // una FIFO por proyecto > 0
	turnos     []int64              // proyectos con trabajo en alta, en orden de turno
	baja       []tareaTTP           // FIFO del barrido global
	estados    map[int64]*ProjectTTPSyncState
	aviso      chan struct{}

	topeAlta, topeBaja int
	// CVEs distintas pendientes en cada nivel (no copias), para aplicar los topes.
	pendientesAlta, pendientesBaja int
	altasSeguidas                  int
	ultimaGen                      uint64
}

func nuevaColaMapeoTTP(topeAlta, topeBaja int) *colaMapeoTTP {
	return &colaMapeoTTP{
		pendientes: make(map[string]*entradaCVE),
		alta:       make(map[int64][]tareaTTP),
		estados:    make(map[int64]*ProjectTTPSyncState),
		aviso:      make(chan struct{}, 1),
		topeAlta:   topeAlta,
		topeBaja:   topeBaja,
	}
}

// Encolar pide el mapeo de una CVE en nombre de un proyecto (0 = barrido global).
func (c *colaMapeoTTP) Encolar(cveID string, projectID int64) ResultadoEncolado {
	c.mu.Lock()
	defer c.mu.Unlock()

	e := c.pendientes[cveID]
	if e == nil {
		if (projectID > 0 && c.pendientesAlta >= c.topeAlta) || (projectID == 0 && c.pendientesBaja >= c.topeBaja) {
			return EncoladoDescartado
		}
		c.ultimaGen++
		e = &entradaCVE{
			interesados: make(map[int64]struct{}),
			gen:         c.ultimaGen,
			enAlta:      make(map[int64]bool),
		}
		c.pendientes[cveID] = e
		c.registrarInteresLocked(e, cveID, projectID)
		c.ponerEnColaLocked(e, cveID, projectID)
		return EncoladoNuevo
	}

	c.registrarInteresLocked(e, cveID, projectID)
	if e.enProceso {
		c.estadoLocked(projectID).CurrentCVE = cveID
		return EncoladoEnProceso
	}
	if projectID == 0 || e.enAlta[projectID] {
		return EncoladoYaPendiente
	}

	// Proyecto sin copia propia en alta. Si la CVE ya ocupa un hueco de alta (por
	// otro proyecto) añadir la copia no consume cupo; si solo estaba en baja, sí.
	antes := c.claseLocked(e)
	if antes != claseAlta && c.pendientesAlta >= c.topeAlta {
		// No cabe en alta: seguirá por baja, pero ya atribuida al proyecto.
		return EncoladoYaPendiente
	}
	c.ponerEnColaLocked(e, cveID, projectID)
	if antes == claseBaja {
		return EncoladoPromovido
	}
	return EncoladoYaPendiente
}

// Siguiente bloquea hasta que haya una CVE que procesar o se cancele ctx.
func (c *colaMapeoTTP) Siguiente(ctx context.Context) (string, bool) {
	for {
		if ctx.Err() != nil {
			return "", false
		}
		c.mu.Lock()
		cveID, ok := c.tomarLocked()
		c.mu.Unlock()
		if ok {
			return cveID, true
		}
		select {
		case <-ctx.Done():
			return "", false
		case <-c.aviso:
		}
	}
}

// Terminar cierra el procesamiento de una CVE y devuelve los proyectos que la
// habían pedido, incluidos los que la pidieron mientras se procesaba.
func (c *colaMapeoTTP) Terminar(cveID string) []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	e := c.pendientes[cveID]
	if e == nil {
		return nil
	}
	c.moverLocked(c.claseLocked(e), claseNinguna)
	delete(c.pendientes, cveID)

	ids := make([]int64, 0, len(e.interesados))
	for pid := range e.interesados {
		ids = append(ids, pid)
		if st := c.estados[pid]; st != nil {
			delete(st.QueuedCVEs, cveID)
			if st.CurrentCVE == cveID {
				st.CurrentCVE = ""
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Olvidar descarta todo rastro de un proyecto borrado. Sin esto, su estado (y su
// histórico de logs) seguía ocupando memoria mientras el proceso siguiera vivo.
func (c *colaMapeoTTP) Olvidar(projectID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.estados, projectID)
	delete(c.alta, projectID)
	for i, pid := range c.turnos {
		if pid == projectID {
			c.turnos = append(c.turnos[:i], c.turnos[i+1:]...)
			break
		}
	}

	for cveID, e := range c.pendientes {
		if _, ok := e.interesados[projectID]; !ok {
			continue
		}
		antes := c.claseLocked(e)
		delete(e.interesados, projectID)
		delete(e.enAlta, projectID)
		if !e.enProceso {
			if len(e.interesados) == 0 {
				c.moverLocked(antes, claseNinguna)
				delete(c.pendientes, cveID)
				continue
			}
			// Otros interesados sin copia propia (el global, o un proyecto que la
			// pidió con la alta llena): sin esto la CVE no volvería a salir nunca.
			if len(e.enAlta) == 0 && !e.enBaja {
				c.baja = append(c.baja, tareaTTP{cveID: cveID, gen: e.gen})
				e.enBaja = true
				c.avisarLocked()
			}
		}
		c.moverLocked(antes, c.claseLocked(e))
	}
}

// Registrar añade una línea al histórico de cada proyecto indicado y la escribe
// una sola vez en el log del proceso.
func (c *colaMapeoTTP) Registrar(msg string, projectIDs []int64) {
	log.Printf("%s %s", prefijoLogTTP(projectIDs), msg)

	linea := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pid := range projectIDs {
		st := c.estadoLocked(pid)
		st.Logs = append(st.Logs, linea)
		if len(st.Logs) > maxTTPLogs {
			st.Logs = st.Logs[len(st.Logs)-maxTTPLogs:]
		}
	}
}

// PendientesDe devuelve cuántas CVEs le quedan en cola a cada proyecto.
func (c *colaMapeoTTP) PendientesDe(projectIDs []int64) map[int64]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[int64]int, len(projectIDs))
	for _, pid := range projectIDs {
		if st := c.estados[pid]; st != nil {
			out[pid] = len(st.QueuedCVEs)
		} else {
			out[pid] = 0
		}
	}
	return out
}

// Estado devuelve el progreso de un proyecto. Processing se deriva de lo que le
// queda en cola en lugar de guardarse como bandera: una bandera que alguien
// olvidaba bajar dejaba el modal del frontend girando para siempre.
func (c *colaMapeoTTP) Estado(projectID int64) TTPBackgroundSyncResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.estados[projectID]
	if st == nil {
		return TTPBackgroundSyncResponse{Logs: []string{}}
	}
	logs := make([]string, len(st.Logs))
	copy(logs, st.Logs)
	return TTPBackgroundSyncResponse{
		Processing:  len(st.QueuedCVEs) > 0,
		CurrentCVE:  st.CurrentCVE,
		QueueLength: len(st.QueuedCVEs),
		Logs:        logs,
	}
}

func (c *colaMapeoTTP) estadoLocked(projectID int64) *ProjectTTPSyncState {
	st := c.estados[projectID]
	if st == nil {
		st = &ProjectTTPSyncState{Logs: []string{}, QueuedCVEs: make(map[string]bool)}
		c.estados[projectID] = st
	}
	return st
}

func (c *colaMapeoTTP) registrarInteresLocked(e *entradaCVE, cveID string, projectID int64) {
	e.interesados[projectID] = struct{}{}
	c.estadoLocked(projectID).QueuedCVEs[cveID] = true
}

func (c *colaMapeoTTP) ponerEnColaLocked(e *entradaCVE, cveID string, projectID int64) {
	antes := c.claseLocked(e)
	tarea := tareaTTP{cveID: cveID, gen: e.gen}
	if projectID > 0 {
		if len(c.alta[projectID]) == 0 {
			c.turnos = append(c.turnos, projectID)
		}
		c.alta[projectID] = append(c.alta[projectID], tarea)
		e.enAlta[projectID] = true
	} else {
		c.baja = append(c.baja, tarea)
		e.enBaja = true
	}
	c.moverLocked(antes, c.claseLocked(e))
	c.avisarLocked()
}

func (c *colaMapeoTTP) tomarLocked() (string, bool) {
	if c.altasSeguidas >= maxAltasSeguidas {
		c.altasSeguidas = 0
		if cveID, ok := c.tomarBajaLocked(); ok {
			return cveID, true
		}
	}
	if cveID, ok := c.tomarAltaLocked(); ok {
		c.altasSeguidas++
		return cveID, true
	}
	if cveID, ok := c.tomarBajaLocked(); ok {
		c.altasSeguidas = 0
		return cveID, true
	}
	return "", false
}

// tomarAltaLocked atiende al proyecto que tiene el turno y, si le queda trabajo,
// lo devuelve al final de la ronda.
func (c *colaMapeoTTP) tomarAltaLocked() (string, bool) {
	for len(c.turnos) > 0 {
		pid := c.turnos[0]
		c.turnos = c.turnos[1:]

		fifo := c.alta[pid]
		var elegida *entradaCVE
		var cveID string
		for len(fifo) > 0 && elegida == nil {
			t := fifo[0]
			fifo = fifo[1:]
			if e := c.pendientes[t.cveID]; e != nil && e.gen == t.gen && !e.enProceso && e.enAlta[pid] {
				elegida, cveID = e, t.cveID
			}
		}

		if len(fifo) > 0 {
			c.alta[pid] = fifo
			c.turnos = append(c.turnos, pid)
		} else {
			delete(c.alta, pid)
		}

		if elegida != nil {
			c.iniciarLocked(elegida, cveID)
			return cveID, true
		}
	}
	return "", false
}

func (c *colaMapeoTTP) tomarBajaLocked() (string, bool) {
	for len(c.baja) > 0 {
		t := c.baja[0]
		c.baja = c.baja[1:]
		if e := c.pendientes[t.cveID]; e != nil && e.gen == t.gen && !e.enProceso && e.enBaja {
			c.iniciarLocked(e, t.cveID)
			return t.cveID, true
		}
	}
	c.baja = nil
	return "", false
}

func (c *colaMapeoTTP) iniciarLocked(e *entradaCVE, cveID string) {
	antes := c.claseLocked(e)
	e.enProceso = true
	e.enAlta = make(map[int64]bool)
	e.enBaja = false
	c.moverLocked(antes, claseNinguna)
	for pid := range e.interesados {
		c.estadoLocked(pid).CurrentCVE = cveID
	}
}

func (c *colaMapeoTTP) claseLocked(e *entradaCVE) claseCola {
	switch {
	case e.enProceso:
		return claseNinguna
	case len(e.enAlta) > 0:
		return claseAlta
	case e.enBaja:
		return claseBaja
	default:
		return claseNinguna
	}
}

func (c *colaMapeoTTP) moverLocked(antes, despues claseCola) {
	if antes == despues {
		return
	}
	switch antes {
	case claseAlta:
		c.pendientesAlta--
	case claseBaja:
		c.pendientesBaja--
	}
	switch despues {
	case claseAlta:
		c.pendientesAlta++
	case claseBaja:
		c.pendientesBaja++
	}
}

func (c *colaMapeoTTP) avisarLocked() {
	select {
	case c.aviso <- struct{}{}:
	default:
	}
}

func prefijoLogTTP(projectIDs []int64) string {
	if len(projectIDs) == 0 || (len(projectIDs) == 1 && projectIDs[0] == 0) {
		return "[TTP-BG-GLOBAL]"
	}
	ids := make([]string, 0, len(projectIDs))
	for _, pid := range projectIDs {
		ids = append(ids, strconv.FormatInt(pid, 10))
	}
	return "[TTP-PROJ-" + strings.Join(ids, ",") + "]"
}
