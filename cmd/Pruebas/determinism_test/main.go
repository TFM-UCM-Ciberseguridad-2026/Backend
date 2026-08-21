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
	ExactMatchRate    float64     `json:"exact_match_rate"` // Pairwise Match Rate
	AvgDurationMs     float64     `json:"avg_duration_ms"`
	TotalErrors       int         `json:"total_errors"`
	Variations        []string    `json:"variations"`
}

func calculatePairwiseMatchRate(runs []runDetail) (float64, int, int) {
	N := len(runs)
	if N <= 1 {
		return 100.0, 0, 0
	}
	totalPairs := N * (N - 1) / 2
	matchingPairs := 0
	for i := 0; i < N; i++ {
		for j := i + 1; j < N; j++ {
			if strings.Join(runs[i].TTPs, ",") == strings.Join(runs[j].TTPs, ",") {
				matchingPairs++
			}
		}
	}
	return (float64(matchingPairs) / float64(totalPairs)) * 100.0, matchingPairs, totalPairs
}

func main() {
	// 1. Cargar configuración
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[TEST] Error loading config: %v", err)
	}

	fmt.Printf("[TEST] Starting Determinism Test with Enriched Context...\n")
	fmt.Printf("[TEST] Ollama Host: %s\n", cfg.Ollama.Host)
	fmt.Printf("[TEST] Ollama Model: %s\n", cfg.Ollama.Model)

	client := ollama.NewOllamaClient(cfg.Ollama.Host, cfg.Ollama.Model)
	ctx := context.Background()

	tests := []struct {
		CVE         string
		CWE         string
		Description string
		CVSSVector  string
	}{
		{
			CVE:         "CVE-2016-4450",
			CWE:         "CWE-476",
			Description: "os/unix/ngx_files.c in nginx before 1.10.1 and 1.11.x before 1.11.1 allows remote attackers to cause a denial of service (NULL pointer dereference and worker process crash) via a crafted request, involving writing a client request body to a temporary file.",
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		},
		{
			CVE:         "CVE-2016-1247",
			CWE:         "CWE-59",
			Description: "The nginx package before 1.6.2-5+deb8u3 on Debian, and before 1.10.0-1+deb.syi on other systems, creates log directories with insecure permissions, which allows local users to gain root privileges via a symlink attack on the error log. The www-data user can create a symlink from /var/log/nginx/error.log to any file on the filesystem, and when nginx is restarted (via logrotate), the target file will be overwritten as root.",
			CVSSVector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			CVE:         "CVE-2017-7529",
			CWE:         "CWE-190",
			Description: "Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting in the potential leakage of cached or other data from the backend servers, revealing potentially sensitive information.",
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		},
	}

	K := 5
	results := []cveTestResult{}

	for _, tc := range tests {
		fmt.Printf("\n=========================================\n")
		fmt.Printf("[TEST] Running determinism test for %s (%s)\n", tc.CVE, tc.CWE)

		// A. CORRIDA DE CONTROL
		// Hacemos una llamada warm-up
		_, _, _ = client.MapEnrichedToTTPRaw(ctx, tc.CWE, tc.Description, tc.CVSSVector)

		controlStart := time.Now()
		controlTTPs, controlRaw, err := client.MapEnrichedToTTPRaw(ctx, tc.CWE, tc.Description, tc.CVSSVector)
		controlDuration := time.Since(controlStart).Milliseconds()
		if err != nil {
			log.Fatalf("[TEST] Error in control run for %s: %v", tc.CVE, err)
		}
		isControlCacheHit := strings.Contains(controlRaw, "CACHE HIT") || controlRaw == "[CACHE HIT - NO RAW RESPONSE]"
		fmt.Printf("[CONTROL] TTPs: %v, Duration: %d ms, Cache Hit: %t\n", 
			controlTTPs, controlDuration, isControlCacheHit)

		// B. BUCLE K=5 CORRIDAS (sin caché en producción)
		runs := []runDetail{}
		var totalDuration int64 = 0
		var successfulRunsCount int64 = 0
		var totalErrors = 0

		for attempt := 1; attempt <= K; attempt++ {
			// No hace falta InvalidateCache porque la consulta es enriquecida (no cachea)
			start := time.Now()
			ttps, raw, err := client.MapEnrichedToTTPRaw(ctx, tc.CWE, tc.Description, tc.CVSSVector)
			duration := time.Since(start).Milliseconds()

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
			totalDuration += duration
			successfulRunsCount++

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
			if r.Error == "" {
				successfulRuns = append(successfulRuns, r)
			}
		}

		if len(successfulRuns) == 0 {
			log.Printf("[TEST] No successful runs for %s\n", tc.CVE)
			results = append(results, cveTestResult{
				CVE:               tc.CVE,
				CWE:               tc.CWE,
				ControlDurationMs: controlDuration,
				ControlTTPs:       controlTTPs,
				Runs:              runs,
				ExactMatchRate:    0.0,
				AvgDurationMs:     0.0,
				TotalErrors:       totalErrors,
				Variations:        []string{"No successful runs to evaluate"},
			})
			continue
		}

		sort.Strings(controlTTPs)
		matchRate, matchingPairs, totalPairs := calculatePairwiseMatchRate(successfulRuns)
		
		var avgDuration float64 = 0
		if successfulRunsCount > 0 {
			avgDuration = float64(totalDuration) / float64(successfulRunsCount)
		}

		// Analizar variaciones para logs legibles
		variations := []string{}
		firstRunTTPs := successfulRuns[0].TTPs
		firstRunKey := strings.Join(firstRunTTPs, ",")
		for _, run := range successfulRuns {
			runKey := strings.Join(run.TTPs, ",")
			if runKey != firstRunKey {
				diff := fmt.Sprintf("Run %d differed: got %v (expected %v)", run.Attempt, run.TTPs, firstRunTTPs)
				variations = append(variations, diff)
			}
		}

		fmt.Printf("\n[METRICAS] %s (%s)\n", tc.CVE, tc.CWE)
		fmt.Printf("  - Pairwise Match Rate: %.2f%% (%d/%d pares idénticos)\n", matchRate, matchingPairs, totalPairs)
		fmt.Printf("  - Average Response Time: %.2f ms\n", avgDuration)
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
