package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider/ollama"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
)

type runDetail struct {
	Attempt      int      `json:"attempt"`
	TTPs         []string `json:"ttps,omitempty"`
	RawResponse  string   `json:"raw_response,omitempty"`
	DurationMs   int64    `json:"duration_ms"`
	Timestamp    string   `json:"timestamp"`
	Error        string   `json:"error,omitempty"`
	CacheHit     bool     `json:"cache_hit"`
}

type cveTestResult struct {
	CVE               string      `json:"cve"`
	CWE               string      `json:"cwe"`
	ControlDurationMs int64       `json:"control_duration_ms"`
	ControlTTPs       []string    `json:"control_ttps"`
	Runs              []runDetail `json:"runs"`
	ExactMatchRate    float64     `json:"exact_match_rate"`
	AvgDurationMs     float64     `json:"avg_duration_ms"`
	TotalErrors       int         `json:"total_errors"`
	Variations        []string    `json:"variations"`
}

func main() {
	// 1. Cargar configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[TEST] Error loading config: %v", err)
	}

	fmt.Printf("[TEST] Starting Determinism Test...\n")
	fmt.Printf("[TEST] Ollama Host: %s\n", cfg.Ollama.Host)
	fmt.Printf("[TEST] Ollama Model: %s\n", cfg.Ollama.Model)

	client := ollama.NewOllamaClient(cfg.Ollama.Host, cfg.Ollama.Model)
	ctx := context.Background()

	tests := []struct {
		CVE string
		CWE string
	}{
		{"CVE-2016-4450", "CWE-476"},
		{"CVE-2016-1247", "CWE-59"},
		{"CVE-2017-7529", "CWE-190"},
	}

	K := 5
	results := []cveTestResult{}

	for _, tc := range tests {
		fmt.Printf("\n=========================================\n")
		fmt.Printf("[TEST] Running determinism test for %s (%s)\n", tc.CVE, tc.CWE)

		// A. CORRIDA DE CONTROL (Con Caché activo)
		// Hacemos una llamada para asegurarnos de que la caché tenga el valor (warm-up)
		_, _, _ = client.MapCWEToTTPRaw(ctx, tc.CWE)

		// Hacemos la llamada de control real y medimos el tiempo (sin invalidar)
		controlStart := time.Now()
		controlTTPs, controlRaw, err := client.MapCWEToTTPRaw(ctx, tc.CWE)
		controlDuration := time.Since(controlStart).Milliseconds()
		if err != nil {
			log.Fatalf("[TEST] Error in control run for %s: %v", tc.CVE, err)
		}
		isControlCacheHit := strings.Contains(controlRaw, "CACHE HIT") || controlRaw == "[CACHE HIT - NO RAW RESPONSE]"
		fmt.Printf("[CONTROL] TTPs: %v, Duration: %d ms, Cache Hit: %t\n", 
			controlTTPs, controlDuration, isControlCacheHit)

		// B. BUCLE SIN CACHÉ (K=5)
		runs := []runDetail{}
		var totalDuration int64 = 0
		var successfulRunsCount int64 = 0
		var totalErrors = 0

		for attempt := 1; attempt <= K; attempt++ {
			// 1. Invalidación DENTRO del bucle antes de cada llamada
			client.InvalidateCache(tc.CWE)
			fmt.Printf("[TEST] Invalidada caché para %s antes del intento %d/%d\n", tc.CWE, attempt, K)

			start := time.Now()
			ttps, raw, err := client.MapCWEToTTPRaw(ctx, tc.CWE)
			duration := time.Since(start).Milliseconds()

			// 2. Manejo de errores sin abortar
			if err != nil {
				log.Printf("[TEST] Error en intento %d para %s: %v", attempt, tc.CVE, err)
				totalErrors++
				runs = append(runs, runDetail{
					Attempt:    attempt,
					DurationMs: duration,
					Timestamp:  time.Now().Format(time.RFC3339),
					Error:      err.Error(),
				})
				continue
			}

			isCacheHit := raw == "[CACHE HIT - NO RAW RESPONSE]"

			// 3. Excluir cache-hits accidentales de las estadísticas de tiempo
			if isCacheHit {
				log.Printf("[WARNING] ¡Cache-hit accidental detectado en intento %d! Excluyendo de métricas de tiempo.", attempt)
			} else {
				totalDuration += duration
				successfulRunsCount++
			}

			// Asegurarse de ordenar para la comparación
			sort.Strings(ttps)

			runs = append(runs, runDetail{
				Attempt:     attempt,
				TTPs:        ttps,
				RawResponse: raw,
				DurationMs:  duration,
				Timestamp:   time.Now().Format(time.RFC3339),
				CacheHit:    isCacheHit,
			})

			fmt.Printf("  -> Attempt %d: TTPs=%v, Time=%d ms, Cache Hit: %t\n", attempt, ttps, duration, isCacheHit)
		}

		// C. CALCULAR MÉTRICAS
		var successfulRuns []runDetail
		for _, r := range runs {
			if r.Error == "" && !r.CacheHit {
				successfulRuns = append(successfulRuns, r)
			}
		}

		if len(successfulRuns) == 0 {
			log.Printf("[TEST] No successful non-cached runs for %s\n", tc.CVE)
			results = append(results, cveTestResult{
				CVE:               tc.CVE,
				CWE:               tc.CWE,
				ControlDurationMs: controlDuration,
				ControlTTPs:       controlTTPs,
				Runs:              runs,
				ExactMatchRate:    0.0,
				AvgDurationMs:     0.0,
				TotalErrors:       totalErrors,
				Variations:        []string{"No successful non-cached runs to evaluate"},
			})
			continue
		}

		// Ordenamos el control para comparar
		sort.Strings(controlTTPs)

		exactMatches := 0
		firstRunTTPs := successfulRuns[0].TTPs
		firstRunKey := strings.Join(firstRunTTPs, ",")

		variations := []string{}

		for _, run := range successfulRuns {
			runKey := strings.Join(run.TTPs, ",")
			if runKey == firstRunKey {
				exactMatches++
			} else {
				diff := fmt.Sprintf("Run %d differed: got %v (expected %v)", run.Attempt, run.TTPs, firstRunTTPs)
				variations = append(variations, diff)
			}
		}

		matchRate := (float64(exactMatches) / float64(len(successfulRuns))) * 100
		var avgDuration float64 = 0
		if successfulRunsCount > 0 {
			avgDuration = float64(totalDuration) / float64(successfulRunsCount)
		}

		fmt.Printf("\n[METRICAS] %s (%s)\n", tc.CVE, tc.CWE)
		fmt.Printf("  - Exact Match Rate: %.2f%% (%d/%d corridas exitosas)\n", matchRate, exactMatches, len(successfulRuns))
		fmt.Printf("  - Average Response Time (No Cache): %.2f ms\n", avgDuration)
		fmt.Printf("  - Total Errors: %d\n", totalErrors)
		if len(variations) > 0 {
			fmt.Printf("  - Variations detected:\n")
			for _, v := range variations {
				fmt.Printf("    * %s\n", v)
			}
		} else {
			fmt.Printf("  - Estabilidad completa observada (Exact Match: 100%%)\n")
		}

		results = append(results, cveTestResult{
			CVE:               tc.CVE,
			CWE:               tc.CWE,
			ControlDurationMs: controlDuration,
			ControlTTPs:       controlTTPs,
			Runs:              runs,
			ExactMatchRate:    matchRate,
			AvgDurationMs:     avgDuration,
			TotalErrors:       totalErrors,
			Variations:        variations,
		})
	}

	// 5. Guardar en JSON
	timestamp := time.Now().Format("20060102_150405")
	resultsDir := "results"
	_ = os.MkdirAll(resultsDir, 0755)

	outputPath := filepath.Join(resultsDir, fmt.Sprintf("determinism_test_%s.json", timestamp))
	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("[TEST] Error marshaling results JSON: %v", err)
	}

	err = os.WriteFile(outputPath, jsonBytes, 0644)
	if err != nil {
		log.Fatalf("[TEST] Error writing results to file: %v", err)
	}

	fmt.Printf("\n=========================================\n")
	fmt.Printf("[TEST] Determinism test finished successfully!\n")
	fmt.Printf("[TEST] Results written to: %s\n", outputPath)
}
