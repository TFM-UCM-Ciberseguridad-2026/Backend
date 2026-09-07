package domain

import "strings"

/*
Lectura del vector CVSS v3.x para acotar qué técnicas de ATT&CK son plausibles
para una vulnerabilidad concreta.

Motivo: el vector ya viaja en el prompt del mapeador, pero el modelo lo ignora.
Medido sobre 30 CVE reales, el 20,7% de las que declaran UI:N —sin interacción
del usuario— recibían T1566.001 "Spearphishing Attachment", que por definición
exige que alguien abra un adjunto. Son afirmaciones que el propio dato de entrada
contradice, así que no hace falta juicio experto para descartarlas.
*/

// VectorCVSS recoge los campos del vector que condicionan la plausibilidad de
// una técnica. El resto de métricas no cambian qué hace un atacante, solo la
// gravedad, así que no se modelan.
type VectorCVSS struct {
	AttackVector     string // N (red), A (adyacente), L (local), P (físico)
	Privilegios      string // N, L, H
	RequiereUsuario  bool   // UI:R
	Confidencialidad string // N, L, H
	Integridad       string // N, L, H
	Disponibilidad   string // N, L, H
	Presente         bool   // false si no se pudo interpretar el vector
}

// ParsearVectorCVSS interpreta un vector "CVSS:3.1/AV:N/AC:L/...".
//
// Un vector ausente o ilegible devuelve Presente=false. Ese caso NO debe tratarse
// como "nada es plausible": sin dato no se puede descartar nada, y filtrar
// entonces sería inventar una restricción.
func ParsearVectorCVSS(vector string) VectorCVSS {
	v := VectorCVSS{}
	if strings.TrimSpace(vector) == "" {
		return v
	}

	for _, parte := range strings.Split(strings.ToUpper(vector), "/") {
		clave, valor, ok := strings.Cut(strings.TrimSpace(parte), ":")
		if !ok {
			continue
		}
		switch clave {
		case "AV":
			v.AttackVector = valor
			v.Presente = true
		case "PR":
			v.Privilegios = valor
		case "UI":
			v.RequiereUsuario = valor == "R"
			v.Presente = true
		case "C":
			v.Confidencialidad = valor
		case "I":
			v.Integridad = valor
		case "A":
			v.Disponibilidad = valor
		}
	}
	return v
}

// EsRemoto indica si el vector de ataque es de red o adyacente.
func (v VectorCVSS) EsRemoto() bool {
	return v.AttackVector == "N" || v.AttackVector == "A"
}

// familiasQueExigenInteraccion enumera las técnicas cuyo procedimiento requiere,
// por definición, que una persona haga algo: abrir un adjunto, seguir un enlace,
// visitar una página o conectar un medio extraíble.
//
// Se comparan por familia, de modo que la entrada T1566 cubre también
// T1566.001, T1566.002, etc.
//
// La lista es corta y curada a propósito. ATT&CK no publica un campo legible por
// máquina que diga "esto necesita una víctima", así que ampliarla es una decisión
// deliberada: incluir de más descartaría mapeos legítimos.
var familiasQueExigenInteraccion = map[string]string{
	"T1566": "Phishing: la víctima abre el adjunto o el enlace",
	"T1598": "Phishing for Information: la víctima responde",
	"T1534": "Internal Spearphishing: la víctima abre el mensaje",
	"T1204": "User Execution: la técnica es, literalmente, que el usuario ejecute algo",
	"T1203": "Exploitation for Client Execution: la víctima abre el contenido malicioso",
	"T1189": "Drive-by Compromise: la víctima visita el sitio",
	"T1091": "Replication Through Removable Media: alguien conecta el medio",
	"T1080": "Taint Shared Content: la víctima abre el fichero compartido",
}

// familiaTTP devuelve la técnica padre de un identificador ("T1566.001" → "T1566").
func familiaTTP(ttpID string) string {
	if punto := strings.Index(ttpID, "."); punto > 0 {
		return ttpID[:punto]
	}
	return ttpID
}

// TecnicaExigeInteraccion indica si la técnica necesita que una persona actúe.
// Devuelve también el motivo, para poder registrarlo al descartar.
func TecnicaExigeInteraccion(ttpID string) (string, bool) {
	motivo, ok := familiasQueExigenInteraccion[familiaTTP(strings.ToUpper(strings.TrimSpace(ttpID)))]
	return motivo, ok
}

// EsCoherenteConVector dice si una técnica puede aplicarse a una vulnerabilidad
// con este vector CVSS.
//
// Solo se comprueba una incompatibilidad, la que es objetiva: UI:N declara que no
// hace falta interacción del usuario, luego una técnica que la exige no puede ser
// el modo de explotar esa vulnerabilidad. Sin vector legible no se descarta nada.
func (v VectorCVSS) EsCoherenteConVector(ttpID string) (string, bool) {
	if !v.Presente || v.RequiereUsuario {
		return "", true
	}
	if motivo, exige := TecnicaExigeInteraccion(ttpID); exige {
		return motivo, false
	}
	return "", true
}

// TacticasPlausibles deriva del vector qué tácticas de ATT&CK tienen sentido.
//
// El criterio es deliberadamente generoso: el objetivo es acotar un catálogo de
// 697 técnicas a un tamaño que un modelo pequeño pueda recorrer, no adivinar la
// respuesta. Ante la duda se incluye, porque excluir una táctica hace imposible
// acertar dentro de ella.
//
// Un vector ausente devuelve nil, que aguas arriba significa "sin restricción".
func (v VectorCVSS) TacticasPlausibles() []string {
	if !v.Presente {
		return nil
	}

	set := map[string]bool{
		// Explotar una vulnerabilidad es, casi siempre, conseguir ejecución o
		// evadir un control. Estas dos acompañan a cualquier vector.
		"execution": true,
		"stealth":   true,
	}

	if v.EsRemoto() {
		set["initial-access"] = true
		set["command-and-control"] = true
		set["lateral-movement"] = true
	} else {
		// Local o físico: el atacante ya está dentro y busca subir o afianzarse.
		set["privilege-escalation"] = true
		set["persistence"] = true
		set["defense-impairment"] = true
		set["discovery"] = true
	}

	// Un fallo que otorga privilegios permite escalar aunque se explote en remoto.
	if v.Privilegios == "N" || v.Privilegios == "L" {
		set["privilege-escalation"] = true
	}
	if v.Confidencialidad != "N" && v.Confidencialidad != "" {
		set["credential-access"] = true
		set["collection"] = true
		set["exfiltration"] = true
		set["discovery"] = true
	}
	if v.Integridad != "N" && v.Integridad != "" {
		set["impact"] = true
		set["defense-impairment"] = true
	}
	if v.Disponibilidad != "N" && v.Disponibilidad != "" {
		set["impact"] = true
	}
	if v.RequiereUsuario {
		set["initial-access"] = true
	}

	tacticas := make([]string, 0, len(set))
	for t := range set {
		tacticas = append(tacticas, t)
	}
	return tacticas
}

// SoloTecnicasPadre devuelve las técnicas padre del catálogo, descartando las
// subtécnicas.
//
// NO sirve para acotar lo que el sistema puede mapear: hacerlo dejaría 387 de
// las 475 subtécnicas fuera de alcance de forma permanente —el 55% del
// catálogo—, porque la vía determinista CAPEC solo alcanza 88 de ellas. Sería
// cambiar un límite de calidad, que un modelo mejor puede levantar, por uno
// estructural que no levanta nadie.
//
// Su uso es acotar la PRIMERA fase del mapeo: ofrecer las 697 de golpe hace que
// un modelo de 8B elija por posición en la lista en vez de por significado (las
// respuestas se agrupaban en rangos contiguos de identificador). Se elige primero
// entre padres y después entre las subtécnicas de los padres elegidos, de modo
// que ninguna lista es larga y ninguna técnica queda inalcanzable.
func SoloTecnicasPadre(catalogo []TTP) []TTP {
	padres := make([]TTP, 0, len(catalogo))
	for _, t := range catalogo {
		if !strings.Contains(t.TTPID, ".") {
			padres = append(padres, t)
		}
	}
	return padres
}

// RamaDeTecnicas devuelve, para unas técnicas padre dadas, esas mismas técnicas
// junto con todas sus subtécnicas presentes en el catálogo.
//
// Es la lista de la segunda fase: entre 2 y 15 opciones por padre, un tamaño que
// el modelo sí recorre por significado. Los padres se conservan porque no siempre
// hay una subtécnica aplicable, y forzar a bajar un nivel inventaría precisión
// que el texto de la CVE no sostiene.
func RamaDeTecnicas(catalogo []TTP, padres []string) []TTP {
	elegido := make(map[string]bool, len(padres))
	for _, p := range padres {
		elegido[familiaTTP(p)] = true
	}

	rama := make([]TTP, 0, len(padres)*8)
	for _, t := range catalogo {
		if elegido[familiaTTP(t.TTPID)] {
			rama = append(rama, t)
		}
	}
	return rama
}

// CandidatasParaVulnerabilidad recorta el catálogo a las técnicas que pueden
// aplicarse a una vulnerabilidad con este vector.
//
// Es la lista que se ofrece al modelo. Que sea una lista cerrada es lo que
// impide de raíz tres fallos que se midieron en producción: identificadores
// inventados, técnicas retiradas por MITRE en versiones anteriores del catálogo
// (T1562, T1079…) y la imposibilidad de proponer técnicas nuevas —las 56 de
// TA0112 Defense Impairment— que ningún modelo con corte de entrenamiento previo
// a ATT&CK v19 puede conocer.
func CandidatasParaVulnerabilidad(catalogo []TTP, vector string) []TTP {
	v := ParsearVectorCVSS(vector)
	tacticas := v.TacticasPlausibles()

	permitida := make(map[string]bool, len(tacticas))
	for _, t := range tacticas {
		permitida[t] = true
	}

	candidatas := make([]TTP, 0, len(catalogo))
	for _, t := range catalogo {
		if _, coherente := v.EsCoherenteConVector(t.TTPID); !coherente {
			continue
		}
		if len(permitida) > 0 && !tieneTacticaPermitida(t.Tactic, permitida) {
			continue
		}
		candidatas = append(candidatas, t)
	}
	return candidatas
}

// tieneTacticaPermitida comprueba si alguna de las tácticas de la técnica está
// permitida. El backend une las fases en un solo texto ("stealth, persistence"),
// y el 29% de las técnicas pertenecen a más de una.
func tieneTacticaPermitida(tacticas string, permitida map[string]bool) bool {
	for _, fase := range strings.Split(tacticas, ",") {
		if permitida[strings.TrimSpace(strings.ToLower(fase))] {
			return true
		}
	}
	return false
}
