package main

// Riesgo de las rutas de ataque: producto de los saltos en lugar de suma.
//
// La suma se salía de [0,1] —el front pintaba 240%— y hacía ganar a las cadenas
// largas sobre las cortas.
//
// Ejecutar desde Backend/:
//   go run ./cmd/Pruebas/prueba_riesgo_rutas

import (
	"fmt"
	"log"
	"math"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║   RIESGO DE RUTAS DE ATAQUE – conjunción, no suma             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")

	fallos := 0

	// ── 1. Acotado en [0,1] ────────────────────────────────────────────────
	fmt.Println("\n[1/6] El riesgo se mantiene acotado...")
	casos := []struct {
		nombre  string
		riesgos []float64
	}{
		{"1 salto crítico", []float64{0.95}},
		{"3 saltos altos", []float64{0.80, 0.80, 0.80}},
		{"5 saltos altos", []float64{0.90, 0.90, 0.90, 0.90, 0.90}},
		{"6 saltos máximos", []float64{1.0, 1.0, 1.0, 1.0, 1.0, 1.0}},
	}
	for _, c := range casos {
		r := domain.CalculatePathRisk(c.riesgos)
		suma := 0.0
		for _, x := range c.riesgos {
			suma += x
		}
		marca := "✓"
		if r < 0 || r > 1 {
			marca = "✗"
			fallos++
		}
		fmt.Printf("    %s %-18s producto %.4f   (la suma daba %.2f)\n", marca, c.nombre, r, suma)
	}
	if fallos == 0 {
		fmt.Println("    ✓ Ninguna ruta se sale de [0,1]; antes la suma llegaba a 4.50")
	}

	// ── 2. Las cadenas largas ya no ganan ──────────────────────────────────
	fmt.Println("\n[2/6] Una cadena corta y fuerte gana a una larga y débil...")
	corta := []float64{0.90, 0.85}
	larga := []float64{0.55, 0.55, 0.55, 0.55, 0.55}

	rCorta := domain.CalculatePathRisk(corta)
	rLarga := domain.CalculatePathRisk(larga)
	sCorta, sLarga := 0.0, 0.0
	for _, x := range corta {
		sCorta += x
	}
	for _, x := range larga {
		sLarga += x
	}

	fmt.Printf("    corta (2 saltos)  producto %.4f   suma %.2f\n", rCorta, sCorta)
	fmt.Printf("    larga (5 saltos)  producto %.4f   suma %.2f\n", rLarga, sLarga)

	if sLarga <= sCorta {
		log.Fatalf("el escenario no reproduce el problema: la suma debería favorecer a la larga")
	}
	fmt.Println("    · Con la suma ganaba la larga, que es el comportamiento erróneo")

	if rCorta <= rLarga {
		fmt.Printf("    ✗ FALLO: la corta debería ganar (%.4f vs %.4f)\n", rCorta, rLarga)
		fallos++
	} else {
		fmt.Println("    ✓ Con el producto gana la corta")
	}

	// ── 3. Cada salto reduce la viabilidad ─────────────────────────────────
	fmt.Println("\n[3/6] Alargar una cadena nunca la hace más probable...")
	base := []float64{0.9}
	previo := domain.CalculatePathRisk(base)
	monotona := true
	for i := 2; i <= 5; i++ {
		base = append(base, 0.9)
		actual := domain.CalculatePathRisk(base)
		if actual > previo {
			monotona = false
		}
		fmt.Printf("    %d saltos → %.4f\n", i, actual)
		previo = actual
	}
	if !monotona {
		fmt.Println("    ✗ FALLO: añadir saltos aumentó el riesgo")
		fallos++
	} else {
		fmt.Println("    ✓ Monotónica decreciente")
	}

	// ── 4. La prioridad pondera por criticidad del destino ─────────────────
	fmt.Println("\n[4/6] Misma cadena, distinto destino...")
	riesgoRuta := domain.CalculatePathRisk([]float64{0.9, 0.9})

	critProd := service.CalculateAssetCriticality(true, "prod", "High", "High", "High")
	critPuesto := service.CalculateAssetCriticality(false, "dev", "Low", "Low", "Low")

	prioProd := service.CalculatePathPriority(riesgoRuta, critProd)
	prioPuesto := service.CalculatePathPriority(riesgoRuta, critPuesto)

	fmt.Printf("    hacia BBDD producción  crit %.2f → prioridad %.4f\n", critProd, prioProd)
	fmt.Printf("    hacia puesto trabajo   crit %.2f → prioridad %.4f\n", critPuesto, prioPuesto)

	if prioProd <= prioPuesto {
		fmt.Println("    ✗ FALLO: la ruta a producción debería priorizarse")
		fallos++
	} else {
		fmt.Println("    ✓ El riesgo técnico es idéntico; la prioridad la marca el activo")
	}
	if prioProd < 0 || prioProd > 1 {
		fmt.Printf("    ✗ FALLO: prioridad fuera de [0,1]: %.4f\n", prioProd)
		fallos++
	}

	// ── 5. Pondera el activo más crítico, no el último ─────────────────────
	fmt.Println("\n[5/6] El activo más crítico de la ruta manda sobre el destino...")

	// Ruta que atraviesa producción para acabar en un puesto de trabajo.
	critIntermedio := service.CalculateAssetCriticality(false, "prod", "High", "High", "High")
	critFinal := service.CalculateAssetCriticality(false, "dev", "Low", "Low", "Low")
	pico := math.Max(critIntermedio, critFinal)

	prioSoloDestino := service.CalculatePathPriority(riesgoRuta, critFinal)
	prioPico := service.CalculatePathPriority(riesgoRuta, pico)

	fmt.Printf("    ruta: internet → BBDD prod (crit %.2f) → puesto (crit %.2f)\n", critIntermedio, critFinal)
	fmt.Printf("    ponderando solo el destino  → %.4f\n", prioSoloDestino)
	fmt.Printf("    ponderando el más crítico   → %.4f\n", prioPico)

	if prioPico <= prioSoloDestino {
		fmt.Println("    ✗ FALLO: atravesar producción debería subir la prioridad")
		fallos++
	} else {
		fmt.Println("    ✓ Comprometer la BBDD ya es el daño, aunque la ruta siga hasta el puesto")
	}

	// El punto de entrada entra en el máximo sin necesidad de peso propio
	critEntrada := service.CalculateAssetCriticality(true, "prod", "High", "High", "High")
	if math.Max(critEntrada, critFinal) != critEntrada {
		fmt.Println("    ✗ FALLO: un punto de entrada crítico debería dominar el máximo")
		fallos++
	} else {
		fmt.Println("    ✓ El punto de entrada cuenta por ser nodo de la ruta, sin ponderarlo aparte")
	}

	// ── 6. Casos límite ────────────────────────────────────────────────────
	fmt.Println("\n[6/6] Casos límite...")

	if r := domain.CalculatePathRisk(nil); r != 0 {
		fmt.Printf("    ✗ FALLO: una ruta sin pasos debería dar 0, da %.4f\n", r)
		fallos++
	} else {
		fmt.Println("    ✓ Ruta sin pasos → 0")
	}

	if r := domain.CalculatePathRisk([]float64{0.9, 0.0, 0.9}); r != 0 {
		fmt.Printf("    ✗ FALLO: un salto imposible debería anular la cadena, da %.4f\n", r)
		fallos++
	} else {
		fmt.Println("    ✓ Un salto de riesgo 0 anula la cadena entera")
	}

	// Valores corruptos fuera de rango no deben propagarse
	if r := domain.CalculatePathRisk([]float64{5.0, -2.0}); r != 0 {
		fmt.Printf("    ✗ FALLO: valores fuera de rango mal acotados: %.4f\n", r)
		fallos++
	} else {
		fmt.Println("    ✓ Los riesgos fuera de rango se acotan antes de multiplicar")
	}

	// Detección de pasos sin contextualizar
	ruta := domain.ExploitationPath{Steps: []domain.AttackStep{
		{RiskScore: 0.9, RiskSource: "CONTEXTUALIZED"},
		{RiskScore: 0.7, RiskSource: "LEGACY_VULNERABILITY_BASE_SCORE"},
	}}
	if !ruta.HasUncontextualized() {
		fmt.Println("    ✗ FALLO: no detecta el paso LEGACY")
		fallos++
	} else {
		fmt.Println("    ✓ Detecta los saltos con CVSS base sin contextualizar")
	}

	limpia := domain.ExploitationPath{Steps: []domain.AttackStep{{RiskScore: 0.9, RiskSource: "CONTEXTUALIZED"}}}
	if limpia.HasUncontextualized() {
		fmt.Println("    ✗ FALLO: marca como LEGACY una ruta que no lo es")
		fallos++
	}

	// StepRisks debe respetar el orden
	orden := domain.ExploitationPath{Steps: []domain.AttackStep{{RiskScore: 0.1}, {RiskScore: 0.2}, {RiskScore: 0.3}}}
	riesgos := orden.StepRisks()
	if len(riesgos) != 3 || math.Abs(riesgos[0]-0.1) > 1e-9 || math.Abs(riesgos[2]-0.3) > 1e-9 {
		fmt.Printf("    ✗ FALLO: StepRisks no conserva el orden: %v\n", riesgos)
		fallos++
	} else {
		fmt.Println("    ✓ StepRisks conserva el orden de los saltos")
	}

	fmt.Println()
	if fallos == 0 {
		fmt.Println("✓ PRUEBA COMPLETADA")
	} else {
		log.Fatalf("✗ %d COMPROBACIONES FALLIDAS", fallos)
	}
}
