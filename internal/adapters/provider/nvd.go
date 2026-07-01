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
}

type NistDescriptionDTO struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NistMetricsDTO struct {
	CVSSMetricV31 []CVSSV31DTO `json:"cvssMetricV31"`
	CVSSMetricV2  []CVSSV2DTO  `json:"cvssMetricV2"`
}

type CVSSV31DTO struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type CVSSV2DTO struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
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
func NewNistAPIAdapter(baseURL string, apiKey string) *NistAPIAdapter {
	return &NistAPIAdapter{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
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

	// 2. Extraer score (Prioridad CVSS v3.1, fallback a v2)
	var baseScore float64
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		baseScore = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		baseScore = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
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

	// Construimos la entidad de dominio pura
	return domain.Vulnerability{
		VulnerabilityID: cve.ID, // Usamos temporalmente el CVEID como ID del nodo principal
		CVEID:           cve.ID,
		Description:     finalDesc,
		BaseScore:       baseScore,
		CWE:             cwe,
		CPE:             cpe,
		TTPRelated:      "",    // Se rellenará en la capa de aplicación mediante integraciones de MITRE
		Exploit:         false, // Valores por defecto (se alimentan desde otras APIs como FIRST o CISA)
		KEV:             false,
		EPSSScore:       0.0,
	}
}
