package service

import "math"

// Parámetros de diseño documentados (ver spec del sistema).
// Ajustar tras calibración con criterio experto sobre 20-30 endpoints conocidos.
const (
	exploitFloorWeaponized = 0.5 // suelo EPSS para CVE con módulo Metasploit/Nuclei
	exploitFloorPoC        = 0.2 // suelo EPSS para CVE con PoC en ExploitDB
	massFactor             = 0.3 // amortiguación de la masa de findings secundarios
	kevMultiplier          = 2.0 // multiplicador de prioridad si el CVE está en CISA KEV
	patchMultiplier        = 1.3 // multiplicador de prioridad si hay parche oficial disponible
	workaroundMultiplier   = 0.8 // multiplicador de prioridad si solo hay workaround manual
)

// CalculateLikelihood deriva la probabilidad de explotación (0–1) según las reglas de la spec:
//
//	KEV confirmado          → 1.0
//	Exploit weaponizado     → max(EPSS, 0.5)
//	Solo PoC                → max(EPSS, 0.2)  [en v1 se trata igual que weaponizado]
//	Sin exploit conocido    → EPSS directamente
func CalculateLikelihood(isKEV bool, hasExploit bool, epss float64) float64 {
	if isKEV {
		return 1.0
	}
	if hasExploit {
		return math.Max(epss, exploitFloorWeaponized)
	}
	return epss
}

// CalculateFindingRisk aplica la fórmula:  riesgo = L × R × impacto
// Todos los parámetros deben estar normalizados a [0, 1].
func CalculateFindingRisk(likelihood, remediationFactor, impactScore float64) float64 {
	return likelihood * remediationFactor * impactScore
}

// CalculatePriorityScore deriva la cola de priorización de parcheo.
// Se calcula sobre el riesgo del finding y se multiplica por factores contextuales.
// KEV y patch/workaround son independientes y acumulables.
// El resultado se acota a [0, 1] aunque los multiplicadores pueden superarlo.
func CalculatePriorityScore(riskScore float64, isKEV bool, patchAvailable bool, workaroundOnly bool) float64 {
	priority := riskScore

	if isKEV {
		priority *= kevMultiplier
	}
	switch {
	case patchAvailable:
		priority *= patchMultiplier
	case workaroundOnly:
		priority *= workaroundMultiplier
	}

	if priority > 1.0 {
		priority = 1.0
	}
	return priority
}

// AggregateEndpointRisk combina los scores de todos los findings de un endpoint
// en un único score representativo con las siguientes propiedades:
//   - Monotónico: mitigar un finding nunca sube el score
//   - Acotado [0, 1]
//   - Dominado por el finding más crítico (driver)
//   - La densidad de findings secundarios empuja hacia arriba de forma amortiguada
func AggregateEndpointRisk(findingScores []float64) float64 {
	if len(findingScores) == 0 {
		return 0.0
	}

	// Identificar el driver (finding de mayor riesgo)
	driver := 0.0
	for _, s := range findingScores {
		if s > driver {
			driver = s
		}
	}

	// Masa probabilística del resto de findings (excluye una instancia del driver)
	driverExcluded := false
	masaProduct := 1.0
	for _, s := range findingScores {
		if s == driver && !driverExcluded {
			driverExcluded = true
			continue
		}
		masaProduct *= (1.0 - s)
	}
	masa := 1.0 - masaProduct

	return driver + (1.0-driver)*masa*massFactor
}

// ClassifyRiskTier convierte un score [0,1] en el tier de riesgo textual.
// Umbrales: ≥0.9 CRITICAL | 0.7–0.9 HIGH | 0.4–0.7 MEDIUM | <0.4 LOW
func ClassifyRiskTier(riskScore float64) string {
	switch {
	case riskScore >= 0.9:
		return "CRITICAL"
	case riskScore >= 0.7:
		return "HIGH"
	case riskScore >= 0.4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
