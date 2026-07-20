package service

import (
	"math"
	"strings"
)

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

// CalculateExposureFactor deriva la exposición del endpoint según las reglas de la spec:
//
//	Exposicion inicial      → 0.70
//	Expuesto a internet     → +0.30
//	Expuesto via red(AV:N)  → +0.15
//	Esta en operacion        → +0.05
func CalculateExposureFactor(internetExposed bool, environment string, cvssVector string) float64 {
	exposure := 0.70
	if internetExposed {
		exposure += 0.30
	}
	if hasNetworkAttackVector(cvssVector) {
		exposure += 0.15
	}
	if isProductionEnvironment(environment) {
		exposure += 0.05
	}
	return clamp(exposure, 0.0, 1.0)
}

// HELPERS
func hasNetworkAttackVector(cvssVector string) bool {
	return strings.Contains(strings.ToUpper(cvssVector), "AV:N")
}

func isProductionEnvironment(environment string) bool {
	normalized := strings.ToLower(strings.TrimSpace(environment))
	return normalized == "prod" || normalized == "production" || normalized == "produccion" || normalized == "producción"
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// CalculateFindingRisk aplica la fórmula:  riesgo = L × R x exposicion × impacto
// Todos los parámetros deben estar normalizados a [0, 1].
func CalculateFindingRisk(likelihood, exposureFactor, remediationFactor, impactScore float64) float64 {
	return clamp(likelihood*exposureFactor*remediationFactor*impactScore, 0.0, 1.0)
}

const (
	maxAssetCriticality = 1.75
	minAssetCriticality = 0.75
	maxUrgencyBoost     = 2.00
	minUrgencyBoost     = 1.00
)

// CalculateAssetCriticality deriva la criticidad del activo según los requisitos CIA, exposición a Internet y entorno.
func CalculateAssetCriticality(internetExposed bool, environment, confidentialityReq, integrityReq, availabilityReq string) float64 {
	criticality := 1.00

	if isProductionEnvironment(environment) {
		criticality += 0.30
	} else if isStagingEnvironment(environment) {
		criticality += 0.10
	}

	criticality += ciaRequirementBoost(confidentialityReq)
	criticality += ciaRequirementBoost(integrityReq)
	criticality += ciaRequirementBoost(availabilityReq)

	if internetExposed {
		criticality += 0.15
	}

	return clamp(criticality, minAssetCriticality, maxAssetCriticality)
}

// HELPERS
// verifica si el entorno es de staging/preproducción para ajustar la criticidad del activo.
func isStagingEnvironment(environment string) bool {
	normalized := strings.ToLower(strings.TrimSpace(environment))
	return normalized == "staging" || normalized == "pre" || normalized == "preproduction" || normalized == "preprod"
}

// asigna un valor de criticidad según los requisitos de confidencialidad, integridad y disponibilidad (CIA) del activo.
func ciaRequirementBoost(requirement string) float64 {
	normalized := strings.ToLower(strings.TrimSpace(requirement))
	switch normalized {
	case "h", "high", "alto", "alta":
		return 0.15
	case "m", "medium", "medio", "media":
		return 0.07
	default:
		return 0.00
	}
}

// Urgencia sobre la prioridad de parcheo: se calcula con la siguiente fórmula:
//
//	urgency_boost = 1.0 + impact_boost + kev_boost + exploit_boost + patch_boost
//
// Donde cada boost es un valor entre 0 y 1, y el resultado final se clampa entre [1.0, 2.0].
func CalculateUrgencyBoost(impact float64, isKEV bool, hasExploit bool, patchAvailable bool) float64 {
	boost := 1.00

	switch {
	case impact >= 0.95:
		boost += 0.50
	case impact >= 0.80:
		boost += 0.35
	case impact >= 0.60:
		boost += 0.15
	}

	if isKEV {
		boost += 0.30
	}
	if hasExploit {
		boost += 0.20
	}
	if patchAvailable {
		boost += 0.10
	}

	return clamp(boost, minUrgencyBoost, maxUrgencyBoost)
}

// CalculatePriorityScore deriva la cola de priorización de parcheo.
// Se calcula con la siguiente formula:
//  priority_score = risk_score * asset_criticality * urgency_boost

func CalculatePriorityScore(riskScore, assetCriticality, urgencyBoost float64) float64 {
	return clamp(riskScore*assetCriticality*urgencyBoost, 0.0, 1.0)
}

// AggregateRiskScores combina los scores de riesgo de todos los findings asociados a una instalación de software
// en un único score representativo con las siguientes propiedades:
//   - Monotónico: mitigar un finding nunca sube el score
//   - Acotado [0, 1]
//   - Dominado por el finding más crítico (driver)
//   - La densidad de findings secundarios empuja hacia arriba de forma amortiguada
func AggregateRiskScores(scores []float64) float64 {
	if len(scores) == 0 {
		return 0.0
	}

	driver := 0.0
	for _, score := range scores {
		if score > driver {
			driver = score
		}
	}

	driverExcluded := false
	massProduct := 1.0
	for _, score := range scores {
		if score == driver && !driverExcluded {
			driverExcluded = true
			continue
		}
		massProduct *= (1.0 - score)
	}

	secondaryMass := 1.0 - massProduct
	return clamp(driver+(1.0-driver)*secondaryMass*massFactor, 0.0, 1.0)
}

// AggregateEndpointRisk combina los scores de riesgo de todos los findings asociados a un endpoint
func AggregateEndpointRisk(scores []float64) float64 {
	return AggregateRiskScores(scores)
}

// AggregateSoftwareInstallationRisk combina los scores de riesgo de todos los findings asociados a una instalación de software
func AggregateSoftwareInstallationRisk(scores []float64) float64 {
	return AggregateRiskScores(scores)
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

func CalculateSoftwarePriorityScore(priorityBase, criticalityMultiplier float64) float64 {
	return clamp(priorityBase*criticalityMultiplier, 0.0, 1.0)
}

func AggregateEndpointPriority(scores []float64) float64 {
	return AggregateRiskScores(scores)
}

// CalculateSoftwareCriticalityMultiplier convierte LOW/STANDARD/HIGH/CRITICAL
// en un multiplicador de prioridad de software.
func CalculateSoftwareCriticalityMultiplier(level string) float64 {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "LOW":
		return 0.75
	case "HIGH":
		return 1.25
	case "CRITICAL":
		return 1.50
	default:
		return 1.00
	}
}
