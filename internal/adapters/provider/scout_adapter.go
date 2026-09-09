package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

// ScoutAdapter implementa la interfaz ContainerScannerPort utilizando el CLI de Docker Scout.
type ScoutAdapter struct {
	mockData []byte // Usado para inyectar respuestas de prueba en ausencia del CLI real
}

func NewScoutAdapter() *ScoutAdapter {
	return &ScoutAdapter{}
}

// SetMockData permite inyectar un JSON de prueba para evitar ejecutar Docker en los tests.
func (s *ScoutAdapter) SetMockData(data []byte) {
	s.mockData = data
}

// --- Structs para parsear la salida SARIF de Docker Scout ---

type sarifReport struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifText       `json:"shortDescription"`
	Help             sarifText       `json:"help"`
	Properties       sarifProperties `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifProperties struct {
	CvssV3Severity   string  `json:"cvssV3_severity"`
	CvssV3           float64 `json:"cvssV3"`            // score numérico directo (ej: 7.5)
	CvssV3Vector     string  `json:"cvssV3_vector"`     // vector alternativo en properties
	SecuritySeverity string  `json:"security-severity"` // score como string (ej: "7.5")
	PackageName      string  `json:"package_name"`
	PackageVersion   string  `json:"package_version"`
}

type sarifResult struct {
	RuleID string `json:"ruleId"`
}

// cvssVectorRegex extrae el CVSS vector de la salida de texto de Docker Scout.
var cvssVectorRegex = regexp.MustCompile(`CVSS Vector:\s*(CVSS:[^\s]+)`)

// ScanImage llama a Docker Scout y devuelve las vulnerabilidades encontradas.
// Si Docker Scout no está disponible o falla, devuelve error (sin datos de demostración).
func (s *ScoutAdapter) ScanImage(ctx context.Context, imageName string) ([]domain.Vulnerability, error) {
	// Normalizar el nombre de imagen: quitar tags duplicados como "nginx:1.19:latest"
	imageName = normalizeImageName(imageName)

	var outputBytes []byte

	if s.mockData != nil {
		outputBytes = s.mockData
	} else {
		// Ejecutar Docker Scout con formato SARIF (estándar de seguridad abierto)
		cmd := exec.CommandContext(ctx, "docker", "scout", "cves", "--platform", "linux/amd64", imageName, "--format", "sarif")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("[ScoutAdapter] Docker Scout no disponible para '%s': %v\n", imageName, err)
			return nil, fmt.Errorf("docker scout no disponible para '%s': %w", imageName, err)
		}
		outputBytes = out.Bytes()

		// Borrar la imagen de forma asíncrona para ahorrar espacio en disco
		go func(img string) {
			fmt.Printf("[ScoutAdapter] Borrando imagen analizada para liberar espacio: %s\n", img)
			rmCmd := exec.Command("docker", "rmi", "-f", img)
			if err := rmCmd.Run(); err != nil {
				fmt.Printf("[ScoutAdapter] WARNING: No se pudo borrar la imagen %s: %v\n", img, err)
			}
		}(imageName)
	}

	return parseSarifOrMock(outputBytes)
}

// parseSarifOrMock intenta parsear como SARIF real; si falla, trata el JSON como formato mock legacy.
func parseSarifOrMock(data []byte) ([]domain.Vulnerability, error) {
	// Intentar parsear como SARIF
	var sarif sarifReport
	if err := json.Unmarshal(data, &sarif); err == nil && len(sarif.Runs) > 0 {
		return parseSarif(&sarif), nil
	}

	// Fallback: parsear como formato mock (array de objetos con campo "cve")
	type mockVuln struct {
		CVE         string `json:"cve"`
		Description string `json:"description"`
		CVSSVector  string `json:"cvss_vector"`
		Package     string `json:"package"`
		Version     string `json:"version"`
	}
	var mocks []mockVuln
	if err := json.Unmarshal(data, &mocks); err != nil {
		return nil, fmt.Errorf("error parseando respuesta de Docker Scout: %w", err)
	}

	var vulns []domain.Vulnerability
	for _, m := range mocks {
		if m.CVE == "" {
			continue
		}
		baseScore := 0.0
		if m.CVSSVector != "" {
			if bs, err := domain.CalculateCVSS31BaseScoreFromVector(m.CVSSVector); err == nil {
				baseScore = bs
			}
		}
		vulns = append(vulns, domain.Vulnerability{
			CVEID:       m.CVE,
			Description: m.Description,
			CVSSVector:  m.CVSSVector,
			BaseScore:   baseScore,
		})
	}
	return vulns, nil
}

// parseSarif convierte un reporte SARIF al modelo de dominio.
// Las rules de SARIF contienen los detalles del CVE; los results son las ocurrencias.
func parseSarif(sarif *sarifReport) []domain.Vulnerability {
	// Construir un mapa de ruleId -> Rule para acceso rápido
	ruleMap := make(map[string]sarifRule)
	for _, run := range sarif.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = rule
		}
	}

	// Deduplicar por ruleId (un mismo CVE puede aparecer en múltiples paquetes)
	seen := make(map[string]bool)
	var vulns []domain.Vulnerability

	for _, run := range sarif.Runs {
		for _, result := range run.Results {
			if seen[result.RuleID] {
				continue
			}
			seen[result.RuleID] = true

			rule, ok := ruleMap[result.RuleID]
			if !ok {
				continue
			}

			cveID := strings.TrimSpace(rule.ID)
			if cveID == "" || strings.EqualFold(cveID, "UNSPECIFIED") || strings.EqualFold(cveID, "UNKNOWN") || strings.EqualFold(cveID, "N/A") {
				continue
			}

			// Extraer CVSS vector y BaseScore con prioridad decreciente de fuentes:
			// 1. cvssV3_vector en properties (presente en npm packages de node:10, etc.)
			// 2. CVSS Vector en help.text (presente en apk/deb packages)
			// 3. cvssV3 numérico en properties
			// 4. security-severity en properties
			// 5. Estimación por severidad textual (CRITICAL/HIGH/MEDIUM/LOW)
			cvssVector := rule.Properties.CvssV3Vector
			if cvssVector == "" {
				if m := cvssVectorRegex.FindStringSubmatch(rule.Help.Text); len(m) > 1 {
					cvssVector = strings.TrimSpace(m[1])
				}
			}

			baseScore := 0.0
			if cvssVector != "" {
				if bs, err := domain.CalculateCVSS31BaseScoreFromVector(cvssVector); err == nil && bs > 0 {
					baseScore = bs
				}
			}
			// Fallback: usar el score numérico directo de properties
			if baseScore == 0 && rule.Properties.CvssV3 > 0 {
				baseScore = rule.Properties.CvssV3
			}
			// Fallback: usar security-severity (string) de properties
			if baseScore == 0 && rule.Properties.SecuritySeverity != "" {
				if parsed, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err == nil {
					baseScore = parsed
				}
			}
			// Último recurso: mapear severidad textual a score representativo
			if baseScore == 0 {
				baseScore = severityToScore(rule.Properties.CvssV3Severity)
			}

			vulns = append(vulns, domain.Vulnerability{
				CVEID:       cveID,
				Description: rule.ShortDescription.Text,
				CVSSVector:  cvssVector,
				BaseScore:   baseScore,
			})
		}
	}

	return vulns
}

// normalizeImageName evita nombres malformados como "nginx:1.19:latest".
// Docker representa las imágenes como "nombre:tag". Si hay más de un ':', se limpia.
func normalizeImageName(name string) string {
	parts := strings.Split(name, ":")
	switch len(parts) {
	case 1:
		// Sin tag: dejar como está (docker scout usará :latest implícitamente)
		return name
	case 2:
		// Formato normal "imagen:tag" — correcto
		return name
	default:
		// Más de un ':', ej: "httpd:2.4.49:latest" → "httpd:2.4.49"
		last := parts[len(parts)-1]
		if last == "latest" {
			return strings.Join(parts[:len(parts)-1], ":")
		}
		// Otro formato raro: quedarse con los dos primeros segmentos
		return parts[0] + ":" + parts[1]
	}
}

// severityToScore convierte una severidad textual a un CVSS BaseScore representativo.
// Se usa como último recurso cuando no hay CVSS vector ni score numérico disponible.
func severityToScore(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 2.0
	default:
		return 0.0
	}
}

// getFallbackMockData devuelve datos de demostración con un CVE real y conocido
// para que el motor de riesgos pueda funcionar en entornos sin Docker Scout disponible.
// CVE-2021-41773: Path traversal crítico en Apache httpd 2.4.49 (CVSS 9.8).
func getFallbackMockData(_ string) []byte {
	return []byte(`[
		{
			"cve": "CVE-2021-41773",
			"description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.",
			"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"package": "httpd",
			"version": "2.4.49"
		}
	]`)
}

