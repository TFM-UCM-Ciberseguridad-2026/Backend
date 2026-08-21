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
	"strconv"
	"strings"
	"sync"
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

	minInterval time.Duration
	lastRequest time.Time
	rateMu      sync.Mutex

	cacheTTL time.Duration
	cacheMu  sync.RWMutex
	cpeCache map[string]nvdCacheEntry
}

// nvdMaxRetries define el número máximo de reintentos para llamadas a la API del NIST en caso de errores.
const nvdMaxRetries = 3

// nvdCacheEntry representa una entrada en caché de vulnerabilidades obtenidas de NVD, junto con su fecha de expiración.
type nvdCacheEntry struct {
	vulnerabilities []domain.Vulnerability
	expiresAt       time.Time
}

// NewNistAPIAdapter inicializa el adaptador de infraestructura
func NewNistAPIAdapter(baseURL string, apiKey string, timeoutSeconds int) *NistAPIAdapter {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 90
	}

	minInterval := 6 * time.Second
	if strings.TrimSpace(apiKey) != "" {
		minInterval = 1200 * time.Millisecond
	}

	return &NistAPIAdapter{
		baseURL:     baseURL,
		apiKey:      apiKey,
		minInterval: minInterval,
		cacheTTL:    24 * time.Hour,
		cpeCache:    make(map[string]nvdCacheEntry),
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// waitTurn implementa un mecanismo de rate limiting para cumplir con las restricciones de la API del NIST.
func (a *NistAPIAdapter) waitTurn(ctx context.Context) error {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()

	if !a.lastRequest.IsZero() {
		elapsed := time.Since(a.lastRequest)
		wait := a.minInterval - elapsed
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	a.lastRequest = time.Now()
	return nil
}

// FetchVulnerabilities consume la API de NIST y parsea los resultados al dominio.
func (a *NistAPIAdapter) FetchVulnerabilities(ctx context.Context, limit int, offset int) ([]domain.Vulnerability,
	error) {
	reqURL := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", a.baseURL, limit, offset)

	resp, err := a.doRequestWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creando request para NIST: %w", err)
		}
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return []domain.Vulnerability{}, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("api nist rate limit: status 429 tras reintentos")
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido: %d", resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST: %w", err)
	}

	vulnerabilities := make([]domain.Vulnerability, 0, len(apiResponse.Vulnerabilities))
	for _, item := range apiResponse.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, toDomainEntity(item))
	}

	return vulnerabilities, nil
}

// doRequestWithRetry realiza la solicitud HTTP con reintentos en caso de errores transitorios o límites de tasa.
func (a *NistAPIAdapter) doRequestWithRetry(ctx context.Context, reqFactory func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= nvdMaxRetries; attempt++ {
		if err := a.waitTurn(ctx); err != nil {
			return nil, err
		}

		req, err := reqFactory()
		if err != nil {
			return nil, err
		}

		if strings.TrimSpace(a.apiKey) != "" {
			req.Header.Set("apiKey", a.apiKey)
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt == nvdMaxRetries {
				return nil, err
			}
			if waitErr := sleepBackoff(ctx, attempt, 0); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		if !isRetryableNVDStatus(resp.StatusCode) {
			return resp, nil
		}

		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		resp.Body.Close()

		if attempt == nvdMaxRetries {
			return resp, nil
		}

		if waitErr := sleepBackoff(ctx, attempt, retryAfter); waitErr != nil {
			return nil, waitErr
		}
	}

	return nil, lastErr
}

// isRetryableNVDStatus determina si un código de estado HTTP de NVD es elegible para reintento.
func isRetryableNVDStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// parseRetryAfter analiza el valor del encabezado "Retry-After" y devuelve la duración de espera correspondiente.
func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	seconds, err := strconv.Atoi(value)
	if err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	if when, err := http.ParseTime(value); err == nil {
		wait := time.Until(when)
		if wait > 0 {
			return wait
		}
	}

	return 0
}

// sleepBackoff implementa un backoff exponencial con jitter para reintentos de solicitudes HTTP a NVD.
func sleepBackoff(ctx context.Context, attempt int, retryAfter time.Duration) error {
	wait := retryAfter
	if wait <= 0 {
		wait = time.Duration(1<<attempt) * 2 * time.Second
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// getCPECache obtiene las vulnerabilidades en caché para un CPE dado, si existen y no han expirado.
func (a *NistAPIAdapter) getCPECache(cpe string) ([]domain.Vulnerability, bool) {
	a.cacheMu.RLock()
	entry, ok := a.cpeCache[cpe]
	a.cacheMu.RUnlock()

	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		a.cacheMu.Lock()
		delete(a.cpeCache, cpe)
		a.cacheMu.Unlock()
		return nil, false
	}

	out := make([]domain.Vulnerability, len(entry.vulnerabilities))
	copy(out, entry.vulnerabilities)
	return out, true
}

func (a *NistAPIAdapter) setCPECache(cpe string, vulns []domain.Vulnerability) {
	copyVulns := make([]domain.Vulnerability, len(vulns))
	copy(copyVulns, vulns)

	a.cacheMu.Lock()
	a.cpeCache[cpe] = nvdCacheEntry{
		vulnerabilities: copyVulns,
		expiresAt:       time.Now().Add(a.cacheTTL),
	}
	a.cacheMu.Unlock()
}

/*
FetchByCPE consulta la API REST oficial de NIST NVD v2.0 usando un CPE (Common Platform Enumeration) dado.
1. Recibe el identificador CPE (ej. cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*) y lo escapa de manera segura.
2. Construye la URL agregando el parámetro de consulta ?cpeName={cpe}.
3. Inyecta la API Key en las cabeceras (si está configurada) para evitar bloqueos por límite de peticiones.
4. Envía la solicitud y decodifica la respuesta JSON en DTOs, mapeando el resultado a entidades limpias de dominio.
*/
func (a *NistAPIAdapter) FetchByCPE(ctx context.Context, cpe string) ([]domain.Vulnerability, error) {
	if vulns, ok := a.getCPECache(cpe); ok {
		return vulns, nil
	}

	escapedCPE := url.QueryEscape(cpe)
	reqURL := fmt.Sprintf("%s?cpeName=%s&resultsPerPage=100", a.baseURL, escapedCPE)

	resp, err := a.doRequestWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creando request para NIST por CPE: %w", err)
		}
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST por CPE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			empty := []domain.Vulnerability{}
			a.setCPECache(cpe, empty)
			return empty, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("api nist rate limit por CPE %s: status 429 tras reintentos", cpe)
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido por CPE %s: %d", cpe, resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST por CPE: %w", err)
	}

	vulnerabilities := make([]domain.Vulnerability, 0, len(apiResponse.Vulnerabilities))
	for _, item := range apiResponse.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, toDomainEntity(item))
	}

	a.setCPECache(cpe, vulnerabilities)
	return vulnerabilities, nil
}

// FetchByDate consulta la API REST oficial de NIST NVD v2.0 usando fechas de modificación.
// Usa lastModStartDate y lastModEndDate. Las fechas deben estar en formato ISO 8601.
func (a *NistAPIAdapter) FetchByDate(ctx context.Context, startDate, endDate time.Time) ([]domain.Vulnerability,
	error) {
	startStr := startDate.UTC().Format("2006-01-02T15:04:05.000")
	endStr := endDate.UTC().Format("2006-01-02T15:04:05.000")

	reqURL := fmt.Sprintf(
		"%s?lastModStartDate=%s&lastModEndDate=%s",
		a.baseURL,
		url.QueryEscape(startStr),
		url.QueryEscape(endStr),
	)

	resp, err := a.doRequestWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creando request para NIST por fecha: %w", err)
		}
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST por fecha: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return []domain.Vulnerability{}, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("api nist rate limit por fecha: status 429 tras reintentos")
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido por fecha: %d", resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST por fecha: %w", err)
	}

	vulnerabilities := make([]domain.Vulnerability, 0, len(apiResponse.Vulnerabilities))
	for _, item := range apiResponse.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, toDomainEntity(item))
	}

	return vulnerabilities, nil
}

// FetchByCVE consulta la API REST oficial de NIST NVD v2.0 usando un identificador CVE.
func (a *NistAPIAdapter) FetchByCVE(ctx context.Context, cve string) (*domain.Vulnerability, error) {
	escapedCVE := url.QueryEscape(cve)
	reqURL := fmt.Sprintf("%s?cveId=%s", a.baseURL, escapedCVE)

	resp, err := a.doRequestWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creando request para NIST por CVE: %w", err)
		}
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST por CVE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil // No se encontró
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("api nist rate limit por CVE %s: status 429 tras reintentos", cve)
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido por CVE %s: %d", cve, resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST por CVE: %w", err)
	}

	if len(apiResponse.Vulnerabilities) == 0 {
		return nil, nil // Sin resultados
	}

	// Como buscamos por ID exacto, devolvemos el primero
	vuln := toDomainEntity(apiResponse.Vulnerabilities[0])
	return &vuln, nil
}

// toDomainEntity es el "Traductor" (Mapper) de Infraestructura -> Dominio
func toDomainEntity(dto NistVulnerabilityDTO) domain.Vulnerability {
	cve := dto.CVE

	// 1. Extraer descripción (Prioridad Inglés, fallback a Español)
	var finalDesc string
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			finalDesc = d.Value
			break
		}
		if d.Lang == "es" {
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

	// 3. Extraer CWE (Soporte para múltiples CWEs y filtrado por idioma preferente)
	var cweList []string
	seenCWE := make(map[string]bool)

	for _, w := range cve.Weaknesses {
		var selectedValue string
		for _, d := range w.Description {
			if d.Value == "" {
				continue
			}
			if d.Lang == "en" {
				selectedValue = d.Value
				break
			}
			if selectedValue == "" {
				selectedValue = d.Value
			}
		}
		if selectedValue != "" && !seenCWE[selectedValue] {
			seenCWE[selectedValue] = true
			cweList = append(cweList, selectedValue)
		}
	}

	if cweList == nil {
		cweList = []string{}
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
		CWE:             cweList,
		CPE:             cpe,
		TTPRelated:      "",    // Se rellenará en la capa de aplicación mediante integraciones de MITRE
		Exploit:         false, // Valores por defecto (se alimentan desde otras APIs como FIRST o CISA)
		KEV:             false,
		EPSSScore:       0.0,
		Patches:         patches,
	}
}
