package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/provider"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/adapters/repository/neo4j"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/service"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)


// ============= DATA TYPES =============

type cveTestCase struct {
	CVE         string
	CWE         string
	Description string
	CVSSVector  string
}

type approachResult struct {
	TTPs       []string `json:"ttps"`
	DurationMs int64    `json:"duration_ms"`
	Raw        string   `json:"raw_response,omitempty"`
	Source     string   `json:"source"`
	HasData    bool     `json:"has_data"`
}

type cveComparison struct {
	CVE         string         `json:"cve"`
	CWE         string         `json:"cwe"`
	Description string         `json:"description_preview"`
	ApproachA   approachResult `json:"approach_a_static_capec"`
	ApproachB   approachResult `json:"approach_b_llm_cwe_only"`
	ApproachC   approachResult `json:"approach_c_llm_enriched"`
	Overlap     overlapData    `json:"overlap"`
}

type overlapData struct {
	AB         []string `json:"a_intersect_b"`
	AC         []string `json:"a_intersect_c"`
	BC         []string `json:"b_intersect_c"`
	ExclusiveC []string `json:"exclusive_to_c"`
	ExclusiveA []string `json:"exclusive_to_a"`
}

// ============= HELPERS =============

func intersect(a, b []string) []string {
	set := make(map[string]bool)
	for _, x := range b {
		set[x] = true
	}
	var result []string
	for _, x := range a {
		if set[x] {
			result = append(result, x)
		}
	}
	sort.Strings(result)
	return result
}

func difference(a, b []string) []string {
	set := make(map[string]bool)
	for _, x := range b {
		set[x] = true
	}
	var result []string
	for _, x := range a {
		if !set[x] {
			result = append(result, x)
		}
	}
	sort.Strings(result)
	return result
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ============= APPROACH C: Enriched LLM =============

type ollamaGenReq struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format"`
	Options map[string]any `json:"options"`
}

type ollamaGenResp struct {
	Response string `json:"response"`
}

func callOllamaEnriched(host, model, cwe, description, cvssVector string) ([]string, string, time.Duration, error) {
	prompt := fmt.Sprintf(`You are a cybersecurity expert mapping vulnerabilities to MITRE ATT&CK.

Given the following vulnerability details, identify the MITRE ATT&CK TTP IDs (Techniques) 
that an attacker would use to exploit this specific weakness. Consider the attack vector, 
the affected component, and the exploitation conditions described.

CWE: %s
CVSS Vector: %s
Vulnerability Description: %s

You MUST return ONLY a JSON object with a single key "ttps" containing an array of TTP ID strings.
Example: {"ttps": ["T1190", "T1059.001"]}`, cwe, cvssVector, description)

	reqBody := ollamaGenReq{
		Model:  model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
		Options: map[string]any{
			"temperature": 0.2,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", 0, err
	}

	url := fmt.Sprintf("%s/api/generate", strings.TrimRight(host, "/"))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	httpClient := &http.Client{Timeout: 120 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", time.Since(start), fmt.Errorf("ollama API error: %w", err)
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", duration, err
	}

	var genResp ollamaGenResp
	if err := json.Unmarshal(body, &genResp); err != nil {
		return nil, "", duration, err
	}

	re := regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)
	matches := re.FindAllString(genResp.Response, -1)

	seen := make(map[string]bool)
	var ttps []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			ttps = append(ttps, m)
		}
	}
	sort.Strings(ttps)

	return ttps, genResp.Response, duration, nil
}

// ============= APPROACH B: Read from existing results =============

type existingRun struct {
	Attempt     int      `json:"attempt"`
	TTPs        []string `json:"ttps"`
	RawResponse string   `json:"raw_response"`
	DurationMs  int64    `json:"duration_ms"`
}

type existingResult struct {
	CVE  string        `json:"cve"`
	CWE  string        `json:"cwe"`
	Runs []existingRun `json:"runs"`
}

func loadApproachBData(filePath string) (map[string]approachResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read determinism results: %w", err)
	}

	var results []existingResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("cannot parse determinism results: %w", err)
	}

	out := make(map[string]approachResult)
	for _, r := range results {
		if len(r.Runs) > 0 {
			run := r.Runs[0] // warmup run = run 1
			ttps := make([]string, len(run.TTPs))
			copy(ttps, run.TTPs)
			sort.Strings(ttps)
			out[r.CVE] = approachResult{
				TTPs:       ttps,
				DurationMs: run.DurationMs,
				Raw:        run.RawResponse,
				Source:     "determinism_test_run1",
				HasData:    true,
			}
		}
	}
	return out, nil
}

// ============= MAIN =============

func main() {
	fmt.Println("======================================================================")
	fmt.Println("  EXPERIMENTO COMPARATIVO: 3 ENFOQUES DE MAPEO CVE -> TTP")
	fmt.Println("======================================================================")

	// Test cases with real NVD descriptions and CVSS vectors
	testCases := []cveTestCase{
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

	// 1. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	fmt.Printf("\n[CONFIG] Ollama Host: %s | Model: %s\n", cfg.Ollama.Host, cfg.Ollama.Model)
	fmt.Printf("[CONFIG] Neo4j URI: %s\n\n", cfg.Neo4jURI)

	// ===== APPROACH A: Static CAPEC traversal =====
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("ENFOQUE A: Baseline estatico CWE -> CAPEC -> TTP")
	fmt.Println("----------------------------------------------------------------------")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	driver, err := neo4j.NewDriver(ctx, cfg)
	if err != nil {
		log.Fatalf("Error connecting to Neo4j: %v", err)
	}
	defer driver.Close(ctx)

	// Initialize CAPEC components and sync
	endpointRepo, vulnRepo, swRepo, installRepo, findingRepo, remRepo, _, hwRepo, netRepo, patchRepo, projRepo, dbHelper, relRepo, _ := neo4j.NewRepository(driver)
	capecRepo := neo4j.NewCAPECRepository(driver)
	capecProvider := provider.NewCapecSTIXProvider("", 120)



	orchestrator := service.NewOrchestrator(
		projRepo, endpointRepo, hwRepo, netRepo, installRepo, swRepo,
		findingRepo, vulnRepo, remRepo, relRepo, nil, nil, patchRepo, dbHelper, nil,
	).WithCAPEC(capecRepo, capecProvider)


	fmt.Println("  Sincronizando catalogo CAPEC STIX 2.1...")
	capecCount, err := orchestrator.SyncCAPECCatalog(ctx)
	if err != nil {
		log.Fatalf("Error syncing CAPEC catalog: %v", err)
	}
	fmt.Printf("  OK - %d patrones de ataque CAPEC sincronizados.\n\n", capecCount)

	// Query static traversal for each CWE using raw session
	approachAResults := make(map[string]approachResult)
	for _, tc := range testCases {
		fmt.Printf("  Consultando CWE %s -> CAPEC -> TTP ...\n", tc.CWE)

		query := `
			MATCH (w:CWE {cwe_id: $cwe})
			      <-[:MAPS_TO_CWE]-(c:CAPEC)
			      -[:MAPS_TO_TTP]->(t:TTP)
			RETURN DISTINCT t.ttp_id AS ttp_id
			ORDER BY ttp_id
		`
		queryStart := time.Now()

		session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeRead})
		res, err := session.ExecuteRead(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
			cursor, err := tx.Run(ctx, query, map[string]any{"cwe": tc.CWE})
			if err != nil {
				return nil, err
			}
			var ids []string
			for cursor.Next(ctx) {
				rec := cursor.Record()
				if v, ok := rec.Get("ttp_id"); ok && v != nil {
					ids = append(ids, fmt.Sprintf("%v", v))
				}
			}
			return ids, cursor.Err()
		})
		session.Close(ctx)
		queryDuration := time.Since(queryStart)

		var ttps []string
		if err != nil {
			fmt.Printf("    ERROR: %v\n", err)
		} else if res != nil {
			ttps = res.([]string)
		}

		sort.Strings(ttps)
		approachAResults[tc.CVE] = approachResult{
			TTPs:       ttps,
			DurationMs: queryDuration.Milliseconds(),
			Source:     "capec_static_traversal",
			HasData:    len(ttps) > 0,
		}

		if len(ttps) == 0 {
			fmt.Printf("    SIN COBERTURA CAPEC para %s - 0 TTPs. Tiempo: %dms\n", tc.CWE, queryDuration.Milliseconds())
		} else {
			fmt.Printf("    OK - %s -> %d TTPs: %v. Tiempo: %dms\n", tc.CWE, len(ttps), ttps, queryDuration.Milliseconds())
		}
	}

	// ===== APPROACH B: Load from determinism test =====
	fmt.Println("\n----------------------------------------------------------------------")
	fmt.Println("ENFOQUE B: LLM con solo CWE (datos del test de determinismo, run 1)")
	fmt.Println("----------------------------------------------------------------------")

	approachBResults, err := loadApproachBData(filepath.Join("results", "determinism_test_20260814_153055.json"))
	if err != nil {
		log.Fatalf("Error loading approach B data: %v", err)
	}

	for _, tc := range testCases {
		if r, ok := approachBResults[tc.CVE]; ok {
			fmt.Printf("  OK - %s -> TTPs: %v. Tiempo: %dms (cached from determinism test)\n", tc.CVE, r.TTPs, r.DurationMs)
		} else {
			fmt.Printf("  Sin datos para %s\n", tc.CVE)
		}
	}

	// ===== APPROACH C: LLM with enriched prompt =====
	fmt.Println("\n----------------------------------------------------------------------")
	fmt.Println("ENFOQUE C: LLM con descripcion enriquecida (CWE + Description + CVSS)")
	fmt.Println("----------------------------------------------------------------------")

	approachCResults := make(map[string]approachResult)
	for _, tc := range testCases {
		fmt.Printf("  Llamando a Ollama con prompt enriquecido para %s (%s)...\n", tc.CVE, tc.CWE)

		ttps, raw, dur, err := callOllamaEnriched(cfg.Ollama.Host, cfg.Ollama.Model, tc.CWE, tc.Description, tc.CVSSVector)
		if err != nil {
			fmt.Printf("    ERROR: %v (despues de %v)\n", err, dur.Round(time.Millisecond))
			approachCResults[tc.CVE] = approachResult{
				TTPs:       nil,
				DurationMs: dur.Milliseconds(),
				Raw:        fmt.Sprintf("ERROR: %v", err),
				Source:     "enriched_llm",
				HasData:    false,
			}
			continue
		}

		approachCResults[tc.CVE] = approachResult{
			TTPs:       ttps,
			DurationMs: dur.Milliseconds(),
			Raw:        raw,
			Source:     "enriched_llm",
			HasData:    len(ttps) > 0,
		}
		fmt.Printf("    OK - %s -> %d TTPs: %v. Tiempo: %dms\n", tc.CVE, len(ttps), ttps, dur.Milliseconds())
		fmt.Printf("    Raw: %s\n", raw)
	}

	// ===== COMPARATIVE ANALYSIS =====
	fmt.Println("\n----------------------------------------------------------------------")
	fmt.Println("ANALISIS COMPARATIVO")
	fmt.Println("----------------------------------------------------------------------")

	var comparisons []cveComparison
	for _, tc := range testCases {
		a := approachAResults[tc.CVE]
		b := approachBResults[tc.CVE]
		c := approachCResults[tc.CVE]

		allAB := append(a.TTPs, b.TTPs...)

		comp := cveComparison{
			CVE:         tc.CVE,
			CWE:         tc.CWE,
			Description: truncateStr(tc.Description, 120),
			ApproachA:   a,
			ApproachB:   b,
			ApproachC:   c,
			Overlap: overlapData{
				AB:         intersect(a.TTPs, b.TTPs),
				AC:         intersect(a.TTPs, c.TTPs),
				BC:         intersect(b.TTPs, c.TTPs),
				ExclusiveC: difference(c.TTPs, allAB),
				ExclusiveA: difference(a.TTPs, append(b.TTPs, c.TTPs...)),
			},
		}
		comparisons = append(comparisons, comp)

		fmt.Printf("\n  -- %s (%s) --\n", tc.CVE, tc.CWE)
		fmt.Printf("    A (CAPEC estatico): %v (%dms)\n", a.TTPs, a.DurationMs)
		fmt.Printf("    B (LLM solo CWE):   %v (%dms)\n", b.TTPs, b.DurationMs)
		fmt.Printf("    C (LLM enriquecido): %v (%dms)\n", c.TTPs, c.DurationMs)
		fmt.Printf("    Overlap A^B: %v\n", comp.Overlap.AB)
		fmt.Printf("    Overlap A^C: %v\n", comp.Overlap.AC)
		fmt.Printf("    Overlap B^C: %v\n", comp.Overlap.BC)
		fmt.Printf("    Exclusivas de C (no en A ni B): %v\n", comp.Overlap.ExclusiveC)
		fmt.Printf("    Exclusivas de A (no en B ni C): %v\n", comp.Overlap.ExclusiveA)
	}

	// Save results
	os.MkdirAll("results", 0755)
	outFile := filepath.Join("results", fmt.Sprintf("comparative_test_%s.json", time.Now().Format("20060102_150405")))
	jsonData, _ := json.MarshalIndent(comparisons, "", "  ")
	os.WriteFile(outFile, jsonData, 0644)
	fmt.Printf("\n\nOK - Resultados guardados en: %s\n", outFile)
}
