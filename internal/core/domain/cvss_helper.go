package domain

import (
	"fmt"
	"math"
	"strings"
)

/*
CVSS4ToCVSS31 convierte una cadena de vector CVSS v4.0 a un vector CVSS v3.1 y calcula su puntuación base.
*/
func CVSS4ToCVSS31(cvssv4Str string) (string, float64, error) {
	m, err := parseCVSS4Vector(cvssv4Str)
	if err != nil {
		return "", 0, err
	}

	ssNone := m["SC"] == "N" && m["SI"] == "N" && m["SA"] == "N"
	scope := "U"
	if !ssNone {
		scope = "C"
	}

	avMap := map[string]string{"N": "N", "A": "A", "L": "L", "P": "P"}
	prMap := map[string]string{"N": "N", "L": "L", "H": "H"}
	uiMap := map[string]string{"N": "N", "P": "R", "A": "R"}

	av, ok := avMap[m["AV"]]
	if !ok {
		return "", 0, fmt.Errorf("invalid CVSS4 AV value: %s", m["AV"])
	}
	pr, ok := prMap[m["PR"]]
	if !ok {
		return "", 0, fmt.Errorf("invalid CVSS4 PR value: %s", m["PR"])
	}
	ui, ok := uiMap[m["UI"]]
	if !ok {
		return "", 0, fmt.Errorf("invalid CVSS4 UI value: %s", m["UI"])
	}

	var ac string
	if m["AT"] == "P" {
		ac = "H"
	} else if m["AC"] == "L" {
		ac = "L"
	} else if m["AC"] == "H" {
		ac = "H"
	} else {
		return "", 0, fmt.Errorf("invalid CVSS4 AC value: %s", m["AC"])
	}

	cvssv31Metrics := map[string]string{
		"AV": av,
		"AC": ac,
		"PR": pr,
		"UI": ui,
		"S":  scope,
	}

	ciaMap := map[string]string{"N": "N", "L": "L", "H": "H"}
	if scope == "U" {
		c, okC := ciaMap[m["VC"]]
		i, okI := ciaMap[m["VI"]]
		a, okA := ciaMap[m["VA"]]
		if !okC || !okI || !okA {
			return "", 0, fmt.Errorf("invalid CVSS4 V(C/I/A) values: %s/%s/%s", m["VC"], m["VI"], m["VA"])
		}
		cvssv31Metrics["C"] = c
		cvssv31Metrics["I"] = i
		cvssv31Metrics["A"] = a
	} else {
		c, okC := ciaMap[m["SC"]]
		i, okI := ciaMap[m["SI"]]
		a, okA := ciaMap[m["SA"]]
		if !okC || !okI || !okA {
			return "", 0, fmt.Errorf("invalid CVSS4 S(C/I/A) values: %s/%s/%s", m["SC"], m["SI"], m["SA"])
		}
		cvssv31Metrics["C"] = c
		cvssv31Metrics["I"] = i
		cvssv31Metrics["A"] = a
	}

	sortedCVSSv31String := createOrderedVector(cvssv31Metrics)
	baseScore, err := CalculateCVSS31BaseScore(
		cvssv31Metrics["AV"],
		cvssv31Metrics["AC"],
		cvssv31Metrics["PR"],
		cvssv31Metrics["UI"],
		cvssv31Metrics["S"],
		cvssv31Metrics["C"],
		cvssv31Metrics["I"],
		cvssv31Metrics["A"],
	)
	if err != nil {
		return "", 0, err
	}

	return sortedCVSSv31String, baseScore, nil
}

/*
CVSS2ToCVSS31 convierte una cadena de vector CVSS v2.0 a un vector CVSS v3.1 y calcula su puntuación base.
*/
func CVSS2ToCVSS31(cvssv2Str string) (string, float64, error) {
	m, err := parseCVSS2Vector(cvssv2Str)
	if err != nil {
		return "", 0, err
	}

	v2ToV31 := map[string]map[string]string{
		"AV": {
			"L": "AV:L",
			"A": "AV:A",
			"N": "AV:N",
		},
		"AC": {
			"L": "AC:L",
			"M": "AC:L",
			"H": "AC:H",
		},
		"Au": {
			"N": "PR:N",
			"S": "PR:L",
			"M": "PR:H",
		},
		"C": {
			"N": "C:N",
			"P": "C:L",
			"C": "C:H",
		},
		"I": {
			"N": "I:N",
			"P": "I:L",
			"C": "I:H",
		},
		"A": {
			"N": "A:N",
			"P": "A:L",
			"C": "A:H",
		},
	}

	cvssv31Metrics := map[string]string{
		"S":  "U",
		"UI": "R",
	}

	for key, val := range m {
		keyMap, ok := v2ToV31[key]
		if !ok {
			continue
		}
		mappedVal, ok := keyMap[val]
		if !ok {
			return "", 0, fmt.Errorf("invalid CVSS2 %s value: %s", key, val)
		}
		parts := strings.Split(mappedVal, ":")
		cvssv31Metrics[parts[0]] = parts[1]
	}

	// Validate we got all mandatory metrics mapped
	requiredKeys := []string{"AV", "AC", "PR", "C", "I", "A"}
	for _, k := range requiredKeys {
		if _, ok := cvssv31Metrics[k]; !ok {
			return "", 0, fmt.Errorf("missing converted CVSS 3.1 metric: %s", k)
		}
	}

	sortedCVSSv31String := createOrderedVector(cvssv31Metrics)
	baseScore, err := CalculateCVSS31BaseScore(
		cvssv31Metrics["AV"],
		cvssv31Metrics["AC"],
		cvssv31Metrics["PR"],
		cvssv31Metrics["UI"],
		cvssv31Metrics["S"],
		cvssv31Metrics["C"],
		cvssv31Metrics["I"],
		cvssv31Metrics["A"],
	)
	if err != nil {
		return "", 0, err
	}

	return sortedCVSSv31String, baseScore, nil
}

/*
parseCVSS4Vector procesa una cadena de vector CVSS v4.0 y extrae sus métricas en un mapa clave-valor.
*/
func parseCVSS4Vector(vectorStr string) (map[string]string, error) {
	if !strings.Contains(vectorStr, "CVSS:4.0") {
		return nil, fmt.Errorf("invalid CVSS 4 vector string: missing CVSS:4.0 prefix")
	}

	cleaned := strings.TrimSpace(vectorStr)
	cleaned = strings.Trim(cleaned, "()")

	parts := strings.Split(cleaned, "/")
	metrics := make(map[string]string)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "CVSS:") {
			continue
		}
		subparts := strings.SplitN(part, ":", 2)
		if len(subparts) != 2 {
			continue
		}
		metrics[strings.TrimSpace(subparts[0])] = strings.TrimSpace(subparts[1])
	}

	required := []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
	for _, req := range required {
		if _, ok := metrics[req]; !ok {
			return nil, fmt.Errorf("invalid CVSS 4 vector string: missing metric %s", req)
		}
	}

	return metrics, nil
}

/*
parseCVSS2Vector procesa una cadena de vector CVSS v2.0 y extrae sus métricas en un mapa clave-valor.
*/
func parseCVSS2Vector(vectorStr string) (map[string]string, error) {
	cleaned := strings.TrimSpace(vectorStr)
	cleaned = strings.Trim(cleaned, "()")

	parts := strings.Split(cleaned, "/")
	metrics := make(map[string]string)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "CVSS:") {
			continue
		}
		subparts := strings.SplitN(part, ":", 2)
		if len(subparts) != 2 {
			continue
		}
		metrics[strings.TrimSpace(subparts[0])] = strings.TrimSpace(subparts[1])
	}

	required := []string{"AV", "AC", "Au", "C", "I", "A"}
	for _, req := range required {
		if _, ok := metrics[req]; !ok {
			return nil, fmt.Errorf("invalid CVSS 2 vector string: missing metric %s", req)
		}
	}

	return metrics, nil
}

/*
createOrderedVector genera una cadena de vector CVSS v3.1 ordenada en el formato estándar a partir de un mapa de métricas.
*/
func createOrderedVector(cvssv31Metrics map[string]string) string {
	v31VectorOrder := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	var sb strings.Builder
	sb.WriteString("CVSS:3.1")
	for _, key := range v31VectorOrder {
		sb.WriteString(fmt.Sprintf("/%s:%s", key, cvssv31Metrics[key]))
	}
	return sb.String()
}

/*
CalculateCVSS31BaseScore calcula la puntuación base (Base Score) de CVSS v3.1 siguiendo las fórmulas matemáticas oficiales del estándar.
*/
func CalculateCVSS31BaseScore(av, ac, pr, ui, s, c, i, a string) (float64, error) {
	var avVal float64
	switch av {
	case "N":
		avVal = 0.85
	case "A":
		avVal = 0.62
	case "L":
		avVal = 0.55
	case "P":
		avVal = 0.20
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 AV value: %s", av)
	}

	var acVal float64
	switch ac {
	case "L":
		acVal = 0.77
	case "H":
		acVal = 0.44
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 AC value: %s", ac)
	}

	var prVal float64
	switch s {
	case "U":
		switch pr {
		case "N":
			prVal = 0.85
		case "L":
			prVal = 0.62
		case "H":
			prVal = 0.27
		default:
			return 0, fmt.Errorf("invalid CVSS 3.1 PR value: %s", pr)
		}
	case "C":
		switch pr {
		case "N":
			prVal = 0.85
		case "L":
			prVal = 0.68
		case "H":
			prVal = 0.50
		default:
			return 0, fmt.Errorf("invalid CVSS 3.1 PR value: %s", pr)
		}
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 S value: %s", s)
	}

	var uiVal float64
	switch ui {
	case "N":
		uiVal = 0.85
	case "R":
		uiVal = 0.62
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 UI value: %s", ui)
	}

	var cVal float64
	switch c {
	case "H":
		cVal = 0.56
	case "L":
		cVal = 0.22
	case "N":
		cVal = 0.0
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 C value: %s", c)
	}

	var iVal float64
	switch i {
	case "H":
		iVal = 0.56
	case "L":
		iVal = 0.22
	case "N":
		iVal = 0.0
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 I value: %s", i)
	}

	var aVal float64
	switch a {
	case "H":
		aVal = 0.56
	case "L":
		aVal = 0.22
	case "N":
		aVal = 0.0
	default:
		return 0, fmt.Errorf("invalid CVSS 3.1 A value: %s", a)
	}

	iss := 1.0 - (1.0-cVal)*(1.0-iVal)*(1.0-aVal)
	if iss <= 0 {
		return 0.0, nil
	}

	var impact float64
	if s == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0.0, nil
	}

	exploitability := 8.22 * avVal * acVal * prVal * uiVal

	var baseScore float64
	if s == "U" {
		baseScore = impact + exploitability
	} else {
		baseScore = 1.08 * (impact + exploitability)
	}

	if baseScore > 10.0 {
		baseScore = 10.0
	}

	return roundup(baseScore), nil
}

// CalculateCVSS31EnvironmentalScore calcula el Environmental Score de CVSS 3.1
// aplicando los Security Requirements (CR/IR/AR) del endpoint al vector base del CVE.
// cr, ir, ar aceptan "Low", "Medium" o "High" (case-insensitive).
// Devuelve un valor normalizado [0, 1].
func CalculateCVSS31EnvironmentalScore(cvssVector, cr, ir, ar string) (float64, error) {
	metrics, err := parseCVSS31Vector(cvssVector)
	if err != nil {
		return 0, err
	}

	// Security Requirements: High=1.5, Medium=1.0, Low=0.5
	crVal := requirementValue(cr)
	irVal := requirementValue(ir)
	arVal := requirementValue(ar)

	// CIA numeric values (mismos que el base score)
	cVal, err := ciaValue(metrics["C"])
	if err != nil {
		return 0, err
	}
	iVal, err := ciaValue(metrics["I"])
	if err != nil {
		return 0, err
	}
	aVal, err := ciaValue(metrics["A"])
	if err != nil {
		return 0, err
	}

	// ISCModified = min(1 − (1−C·CR)(1−I·IR)(1−A·AR), 0.915)
	iscMod := 1.0 - (1.0-cVal*crVal)*(1.0-iVal*irVal)*(1.0-aVal*arVal)
	if iscMod > 0.915 {
		iscMod = 0.915
	}

	if iscMod <= 0 {
		return 0.0, nil
	}

	// Modified Impact (misma lógica que base, usando ISCModified)
	s := metrics["S"]
	var modImpact float64
	if s == "U" {
		modImpact = 6.42 * iscMod
	} else {
		modImpact = 7.52*(iscMod-0.029) - 3.25*math.Pow(iscMod-0.02, 15)
	}

	if modImpact <= 0 {
		return 0.0, nil
	}

	// Modified Exploitability = base exploitability (no hay métricas Modified de ataque)
	modExp, err := baseExploitability(metrics)
	if err != nil {
		return 0, err
	}

	// Environmental Score (sin métricas Temporal → E/RL/RC = 1.0)
	var envScore float64
	if s == "U" {
		envScore = math.Min(modImpact+modExp, 10.0)
	} else {
		envScore = math.Min(1.08*(modImpact+modExp), 10.0)
	}

	return roundup(envScore) / 10.0, nil // normalizado a [0,1]
}

// requirementValue convierte Low/Medium/High al coeficiente numérico de la spec.
func requirementValue(req string) float64 {
	switch strings.ToLower(req) {
	case "high", "h":
		return 1.5
	case "low", "l":
		return 0.5
	default: // Medium, Not Defined, vacío
		return 1.0
	}
}

// ciaValue convierte N/L/H al coeficiente CIA del base score CVSS 3.1.
func ciaValue(v string) (float64, error) {
	switch v {
	case "H":
		return 0.56, nil
	case "L":
		return 0.22, nil
	case "N":
		return 0.0, nil
	default:
		return 0, fmt.Errorf("invalid CIA value: %s", v)
	}
}

// baseExploitability recalcula la exploitability del vector CVSS 3.1.
func baseExploitability(m map[string]string) (float64, error) {
	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}

	av, ok := avMap[m["AV"]]
	if !ok {
		return 0, fmt.Errorf("invalid AV: %s", m["AV"])
	}
	ac, ok := acMap[m["AC"]]
	if !ok {
		return 0, fmt.Errorf("invalid AC: %s", m["AC"])
	}
	ui, ok := uiMap[m["UI"]]
	if !ok {
		return 0, fmt.Errorf("invalid UI: %s", m["UI"])
	}

	var pr float64
	switch m["S"] {
	case "U":
		prMap := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
		pr, ok = prMap[m["PR"]]
	case "C":
		prMap := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
		pr, ok = prMap[m["PR"]]
	default:
		return 0, fmt.Errorf("invalid S: %s", m["S"])
	}
	if !ok {
		return 0, fmt.Errorf("invalid PR: %s", m["PR"])
	}

	return 8.22 * av * ac * pr * ui, nil
}

// parseCVSS31Vector parsea un vector CVSS:3.1/AV:N/AC:L/... en un mapa de métricas.
func parseCVSS31Vector(vectorStr string) (map[string]string, error) {
	if !strings.HasPrefix(vectorStr, "CVSS:3.1") {
		return nil, fmt.Errorf("vector no es CVSS 3.1: %s", vectorStr)
	}

	parts := strings.Split(vectorStr, "/")
	metrics := make(map[string]string, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(p, "CVSS:") {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, k := range required {
		if _, ok := metrics[k]; !ok {
			return nil, fmt.Errorf("vector CVSS 3.1 incompleto: falta métrica %s", k)
		}
	}

	return metrics, nil
}

/*
roundup implementa el redondeo hacia arriba a un decimal.
*/
func roundup(input float64) float64 {
	intInput := math.Round(input * 100000)
	if int(intInput)%10000 == 0 {
		return intInput / 100000.0
	}
	return (math.Floor(intInput/10000) + 1) * 10000 / 100000.0
}
