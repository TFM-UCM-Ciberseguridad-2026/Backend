package provider

/*
Este archivo implementa el Adaptador de Salida (Outbound/Driven Adapter) para la API v2.0 del NIST NVD (National Vulnerability Database).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/provider`, actuando como el adaptador técnico externo que interactúa con la API del NIST NVD e implementa el puerto correspondiente.
2. Adaptador en Arquitectura Hexagonal: Concreta la interfaz CVEProvider (Puerto) mediante una implementación técnica real conectada a un servicio web de terceros.
3. Encapsulación de Infraestructura HTTP: Centraliza la lógica de peticiones REST, control de cabeceras de autorización (apiKey), timeouts de red, manejo de códigos de estado HTTP y procesamiento de límites de peticiones (rate limiting).
4. Mapeo y Normalización de Datos: Traduce la respuesta estructurada de la API del NIST al modelo limpio del dominio (domain.CVE), abstrayendo al resto de la aplicación del formato externo.
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

// --- Formato JSON de NIST v2.0 ---

type NistResponseDTO struct {
	ResultsPerPage  int                    `json:"resultsPerPage"`
	StartIndex      int                    `json:"startIndex"`
	TotalResults    int                    `json:"totalResults"`
	Vulnerabilities []NistVulnerabilityDTO `json:"vulnerabilities"`
}

type NistVulnerabilityDTO struct {
	CVE NistCveDTO `json:"cve"`
}

type NistCveDTO struct {
	ID             string               `json:"id"`
	Descriptions   []NistDescriptionDTO `json:"descriptions"`
	Metrics        NistMetricsDTO       `json:"metrics"`
	Weaknesses     []NistWeaknessDTO    `json:"weaknesses"`
	Configurations []NistConfigDTO      `json:"configurations"`
	References     []NistReferenceDTO   `json:"references"`
}

type NistReferenceDTO struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type NistDescriptionDTO struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NistMetricsDTO struct {
	CVSSMetricV40 []CVSSV40DTO `json:"cvssMetricV40"`
	CVSSMetricV31 []CVSSV31DTO `json:"cvssMetricV31"`
	CVSSMetricV2  []CVSSV2DTO  `json:"cvssMetricV2"`
}

type CVSSV40DTO struct {
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type CVSSV31DTO struct {
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type CVSSV2DTO struct {
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type NistWeaknessDTO struct {
	Description []NistDescriptionDTO `json:"description"`
}

type NistConfigDTO struct {
	Nodes []NistNodeDTO `json:"nodes"`
}

type NistNodeDTO struct {
	CPEMatch []struct {
		Criteria string `json:"criteria"`
	} `json:"cpeMatch"`
}

// NistAPIAdapter implementa la interfaz ports.VulnerabilityScanner
type NistAPIAdapter struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewNistAPIAdapter inicializa el adaptador de infraestructura
func NewNistAPIAdapter(baseURL string, apiKey string, timeoutSeconds int) *NistAPIAdapter {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 90
	}
	return &NistAPIAdapter{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// FetchVulnerabilities consume la API de NIST y parsea los resultados al dominio
func (a *NistAPIAdapter) FetchVulnerabilities(ctx context.Context, limit int, offset int) ([]domain.Vulnerability, error) {
	reqURL := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", a.baseURL, limit, offset)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando request para NIST: %w", err)
	}

	if a.apiKey != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return []domain.Vulnerability{}, nil
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido: %d", resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST: %w", err)
	}

	// Mapeo de DTOs externos a Entidades de Dominio Puras
	var vulnerabilities []domain.Vulnerability
	for _, item := range apiResponse.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, toDomainEntity(item))
	}

	return vulnerabilities, nil
}

/*
FetchByCPE consulta la API REST oficial de NIST NVD v2.0 usando un CPE (Common Platform Enumeration) dado.
1. Recibe el identificador CPE (ej. cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*) y lo escapa de manera segura.
2. Construye la URL agregando el parámetro de consulta ?cpeName={cpe}.
3. Inyecta la API Key en las cabeceras (si está configurada) para evitar bloqueos por límite de peticiones.
4. Envía la solicitud y decodifica la respuesta JSON en DTOs, mapeando el resultado a entidades limpias de dominio.
*/
func (a *NistAPIAdapter) FetchByCPE(ctx context.Context, cpe string) ([]domain.Vulnerability, error) {
	escapedCPE := url.QueryEscape(cpe)
	reqURL := fmt.Sprintf("%s?cpeName=%s&resultsPerPage=100", a.baseURL, escapedCPE)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando request para NIST por CPE: %w", err)
	}

	if a.apiKey != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST por CPE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			// NIST NVD v2.0 devuelve HTTP 404 cuando el CPE no existe en su base de datos o no coincide con ninguna vulnerabilidad.
			return []domain.Vulnerability{}, nil
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido por CPE: %d", resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST por CPE: %w", err)
	}

	var vulnerabilities []domain.Vulnerability
	for _, item := range apiResponse.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, toDomainEntity(item))
	}

	return vulnerabilities, nil
}

/*
FetchByDate consulta la API REST oficial de NIST NVD v2.0 usando fechas de modificación.
Usa lastModStartDate y lastModEndDate. Las fechas deben estar en formato ISO 8601 (YYYY-MM-DDTHH:MM:SS.000).
*/
func (a *NistAPIAdapter) FetchByDate(ctx context.Context, startDate, endDate time.Time) ([]domain.Vulnerability, error) {
	// Formato ISO 8601: 2021-08-04T13:00:00.000
	startStr := startDate.UTC().Format("2006-01-02T15:04:05.000")
	endStr := endDate.UTC().Format("2006-01-02T15:04:05.000")

	reqURL := fmt.Sprintf("%s?lastModStartDate=%s&lastModEndDate=%s", a.baseURL, url.QueryEscape(startStr), url.QueryEscape(endStr))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando request para NIST por fecha: %w", err)
	}

	if a.apiKey != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST por fecha: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return []domain.Vulnerability{}, nil
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido por fecha: %d", resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST por fecha: %w", err)
	}

	var vulnerabilities []domain.Vulnerability
	for _, item := range apiResponse.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, toDomainEntity(item))
	}

	return vulnerabilities, nil
}

// toDomainEntity es el "Traductor" (Mapper) de Infraestructura -> Dominio
func toDomainEntity(dto NistVulnerabilityDTO) domain.Vulnerability {
	cve := dto.CVE

	// 1. Extraer descripción (Prioridad Español, fallback a Inglés)
	var finalDesc string
	for _, d := range cve.Descriptions {
		if d.Lang == "es" {
			finalDesc = d.Value
			break
		}
		if d.Lang == "en" {
			finalDesc = d.Value
		}
	}

	// 2. Extraer score y vector CVSS (Prioridad v4.0 -> v3.1 -> v2.0)
	var baseScore float64
	var cvssVector string
	var nvdVector string

	if len(cve.Metrics.CVSSMetricV40) > 0 {
		rawVec := cve.Metrics.CVSSMetricV40[0].CVSSData.VectorString
		v31Vector, v31Score, err := domain.CVSS4ToCVSS31(rawVec)
		if err == nil {
			cvssVector = v31Vector
			nvdVector = v31Vector
			baseScore = v31Score
		} else {
			cvssVector = ""
			nvdVector = ""
			baseScore = cve.Metrics.CVSSMetricV40[0].CVSSData.BaseScore
		}
	} else if len(cve.Metrics.CVSSMetricV31) > 0 {
		rawVec := cve.Metrics.CVSSMetricV31[0].CVSSData.VectorString
		cvssVector = rawVec
		nvdVector = rawVec
		baseScore = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		rawVec := cve.Metrics.CVSSMetricV2[0].CVSSData.VectorString
		v31Vector, v31Score, err := domain.CVSS2ToCVSS31(rawVec)
		if err == nil {
			cvssVector = v31Vector
			nvdVector = v31Vector
			baseScore = v31Score
		} else {
			cvssVector = ""
			nvdVector = ""
			baseScore = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		}
	}

	// 3. Extraer CWE
	cwe := "N/A"
	if len(cve.Weaknesses) > 0 && len(cve.Weaknesses[0].Description) > 0 {
		cwe = cve.Weaknesses[0].Description[0].Value
	}

	// 4. Extraer el primer CPE identificable
	cpe := "N/A"
	if len(cve.Configurations) > 0 && len(cve.Configurations[0].Nodes) > 0 && len(cve.Configurations[0].Nodes[0].CPEMatch) > 0 {
		cpe = cve.Configurations[0].Nodes[0].CPEMatch[0].Criteria
	}

	// 5. Extraer Parches (URLs con el tag "Patch")
	// ReleaseDate se deja nulo a propósito: el NVD no publica fecha por referencia
	// (NistReferenceDTO solo expone url y tags), y usar la fecha del CVE falsearía
	// la fecha real de publicación del parche. Se rellena al declarar el parche aplicado.
	var patches []domain.Patch
	for _, ref := range cve.References {
		for _, tag := range ref.Tags {
			if tag == "Patch" {
				patches = append(patches, domain.Patch{
					PatchID:     0, // El ID se asignará antes de guardarlo en base de datos
					Description: "Parche oficial (" + cve.ID + ")",
					URL:         ref.URL,
				})
				break
			}
		}
	}

	// Construimos la entidad de dominio pura
	return domain.Vulnerability{
		VulnerabilityID: cve.ID, // Usamos temporalmente el CVEID como ID del nodo principal
		CVEID:           cve.ID,
		Description:     finalDesc,
		BaseScore:       baseScore,
		CVSSVector:      cvssVector,
		NVDVector:       nvdVector,
		CWE:             cwe,
		CPE:             cpe,
		TTPRelated:      "",    // Se rellenará en la capa de aplicación mediante integraciones de MITRE
		Exploit:         false, // Valores por defecto (se alimentan desde otras APIs como FIRST o CISA)
		KEV:             false,
		EPSSScore:       0.0,
		Patches:         patches,
	}
}
