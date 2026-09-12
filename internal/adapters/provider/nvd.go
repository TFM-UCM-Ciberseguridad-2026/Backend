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
	"log"
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
	VulnStatus     string               `json:"vulnStatus"`
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
		Vulnerable bool   `json:"vulnerable"`
		Criteria   string `json:"criteria"`
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

// nvdCPEPageSize define el tamaño de página para consultas NVD por CPE.
// Se mantiene conservador para evitar timeouts/rate limits en análisis síncronos.
const nvdCPEPageSize = 100

// nvdCacheEntry representa una entrada en caché de vulnerabilidades obtenidas de NVD, junto con su fecha de expiración.
type nvdCacheEntry struct {
	vulnerabilities []domain.Vulnerability
	cachedAt        time.Time
	expiresAt       time.Time
	totalAvailable  int
	pagesFetched    int
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
		cacheTTL:    6 * time.Hour,
		cpeCache:    make(map[string]nvdCacheEntry),
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// SetCacheTTL permite configurar cuánto tiempo se reutilizan resultados NVD cacheados por CPE.
func (a *NistAPIAdapter) SetCacheTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	a.cacheTTL = ttl
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

		// Detección automática de API Key no activada o rechazada por el NIST
		if strings.TrimSpace(a.apiKey) != "" && (strings.EqualFold(strings.TrimSpace(resp.Header.Get("message")), "Invalid apiKey.") || (resp.StatusCode == http.StatusNotFound && strings.Contains(strings.ToLower(resp.Header.Get("message")), "invalid apikey"))) {
			log.Printf("[NVD Provider] ADVERTENCIA: La NVD_API_KEY no es válida o aún no está activada por el NIST ('message: Invalid apiKey.'). Desactivando cabecera y reintentando de forma pública...")
			a.rateMu.Lock()
			a.apiKey = ""
			a.minInterval = 6 * time.Second
			a.rateMu.Unlock()
			resp.Body.Close()

			reqNoKey, err := reqFactory()
			if err != nil {
				return nil, err
			}
			respNoKey, err := a.httpClient.Do(reqNoKey)
			if err == nil {
				return respNoKey, nil
			}
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
func (a *NistAPIAdapter) getCPECache(cpe string) (*domain.VulnerabilityFetchResult, bool) {
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
	cachedAt := entry.cachedAt
	expiresAt := entry.expiresAt
	return &domain.VulnerabilityFetchResult{
		Vulnerabilities: out,
		CacheHit:        true,
		CachedAt:        &cachedAt,
		CacheExpiresAt:  &expiresAt,
		TotalAvailable:  entry.totalAvailable,
		PagesFetched:    entry.pagesFetched,
	}, true
}

func (a *NistAPIAdapter) setCPECache(cpe string, vulns []domain.Vulnerability, totalAvailable int, pagesFetched int) *domain.VulnerabilityFetchResult {
	copyVulns := make([]domain.Vulnerability, len(vulns))
	copy(copyVulns, vulns)
	now := time.Now()
	expiresAt := now.Add(a.cacheTTL)

	a.cacheMu.Lock()
	a.cpeCache[cpe] = nvdCacheEntry{
		vulnerabilities: copyVulns,
		cachedAt:        now,
		expiresAt:       expiresAt,
		totalAvailable:  totalAvailable,
		pagesFetched:    pagesFetched,
	}
	a.cacheMu.Unlock()

	return &domain.VulnerabilityFetchResult{
		Vulnerabilities: copyVulns,
		CacheHit:        false,
		CachedAt:        &now,
		CacheExpiresAt:  &expiresAt,
		TotalAvailable:  totalAvailable,
		PagesFetched:    pagesFetched,
	}
}

/*
FetchByCPE consulta la API REST oficial de NIST NVD v2.0 usando un CPE (Common Platform Enumeration) dado.
1. Recibe el identificador CPE (ej. cpe:2.3:a:apache:tomcat:9.0.37:*:*:*:*:*:*:*) y lo escapa de manera segura.
2. Construye la URL agregando el parámetro de consulta ?cpeName={cpe}.
3. Inyecta la API Key en las cabeceras (si está configurada) para evitar bloqueos por límite de peticiones.
4. Envía la solicitud y decodifica la respuesta JSON en DTOs, mapeando el resultado a entidades limpias de dominio.
*/
func (a *NistAPIAdapter) FetchByCPE(ctx context.Context, cpe string, opts ...domain.VulnerabilityFetchOptions) (*domain.VulnerabilityFetchResult, error) {
	fetchOpts := domain.VulnerabilityFetchOptions{}
	if len(opts) > 0 {
		fetchOpts = opts[0]
	}

	if !fetchOpts.ForceRefresh {
		if cached, ok := a.getCPECache(cpe); ok {
			return cached, nil
		}
	}

	all := make([]domain.Vulnerability, 0)
	seen := make(map[string]bool)
	startIndex := 0
	totalAvailable := 0
	pagesFetched := 0
	pageSize := fetchOpts.PageSize
	if pageSize <= 0 {
		pageSize = nvdCPEPageSize
	}

	for {
		page, err := a.fetchByCPEPage(ctx, cpe, pageSize, startIndex)
		if err != nil {
			return nil, err
		}
		pagesFetched++
		if page.TotalResults > totalAvailable {
			totalAvailable = page.TotalResults
		}

		for _, item := range page.Vulnerabilities {
			if !isVulnerableTargetForCPE(item, cpe) {
				continue
			}

			vuln := toDomainEntity(item)
			if vuln.CVEID == "" || seen[vuln.CVEID] {
				continue
			}

			seen[vuln.CVEID] = true
			all = append(all, vuln)
		}

		if len(page.Vulnerabilities) == 0 {
			break
		}

		resultsPerPage := page.ResultsPerPage
		if resultsPerPage <= 0 {
			resultsPerPage = len(page.Vulnerabilities)
		}
		if resultsPerPage <= 0 {
			break
		}

		startIndex += resultsPerPage
		if startIndex >= page.TotalResults {
			break
		}
	}

	return a.setCPECache(cpe, all, totalAvailable, pagesFetched), nil
}

// fetchByCPEPage realiza una consulta paginada a la API de NIST NVD para un CPE específico, devolviendo un DTO con los resultados.
func (a *NistAPIAdapter) fetchByCPEPage(ctx context.Context, cpe string, resultsPerPage int, startIndex int) (*NistResponseDTO, error) {
	if resultsPerPage <= 0 {
		resultsPerPage = nvdCPEPageSize
	}
	if startIndex < 0 {
		startIndex = 0
	}

	escapedCPE := url.QueryEscape(cpe)
	reqURL := fmt.Sprintf(
		"%s?cpeName=%s&resultsPerPage=%d&startIndex=%d",
		a.baseURL,
		escapedCPE,
		resultsPerPage,
		startIndex,
	)

	resp, err := a.doRequestWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creando request para NIST por CPE: %w", err)
		}
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error ejecutando llamada HTTP a NIST por CPE %s startIndex=%d: %w", cpe, startIndex, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return &NistResponseDTO{
				ResultsPerPage:  0,
				StartIndex:      startIndex,
				TotalResults:    0,
				Vulnerabilities: []NistVulnerabilityDTO{},
			}, nil
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("api nist rate limit por CPE %s: status 429 tras reintentos", cpe)
		}
		return nil, fmt.Errorf("api nist devolvió status code inválido por CPE %s startIndex=%d: %d", cpe, startIndex,
			resp.StatusCode)
	}

	var apiResponse NistResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NIST por CPE %s startIndex=%d: %w", cpe, startIndex, err)
	}

	return &apiResponse, nil
}

// getPrimaryVulnerableCPE obtiene el componente primario marcado como vulnerable=true en las configuraciones del CVE.
func getPrimaryVulnerableCPE(dto NistVulnerabilityDTO) (part, vendor, product string, criteria string) {
	for _, config := range dto.CVE.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if match.Vulnerable && match.Criteria != "" {
					parts := strings.Split(match.Criteria, ":")
					if len(parts) >= 5 {
						return strings.ToLower(parts[2]), strings.ToLower(parts[3]), strings.ToLower(parts[4]), match.Criteria
					}
				}
			}
		}
	}
	return "", "", "", ""
}

// isVulnerableTargetForCPE comprueba si el CPE buscado corresponde a un componente marcado como vulnerable=true
// en las configuraciones del CVE. Si las configuraciones del CVE no coinciden con el CPE objetivo o si el CPE
// objetivo solo aparece marcado como entorno anfitrión no vulnerable (vulnerable=false), la vulnerabilidad se descarta.
// Además, evita asignar vulnerabilidades primarias de aplicación (part='a') a un sistema operativo objetivo (part='o').
func isVulnerableTargetForCPE(dto NistVulnerabilityDTO, targetCPE string) bool {
	targetParts := strings.Split(targetCPE, ":")
	if len(targetParts) < 5 {
		return true
	}
	targetPart := strings.ToLower(targetParts[2])
	targetVendor := strings.ToLower(targetParts[3])
	targetProduct := strings.ToLower(targetParts[4])

	primaryPart, primaryVendor, primaryProduct, _ := getPrimaryVulnerableCPE(dto)

	// Regla de desambiguación: Si escaneamos un Sistema Operativo (part == "o"), la vulnerabilidad no debe
	// pertenecer primariamente a una aplicación de terceros (part == "a") cuyo fabricante/producto difiera del SO.
	if targetPart == "o" {
		if primaryPart == "a" && (primaryVendor != targetVendor && primaryProduct != targetProduct) {
			return false
		}
	}

	// Si escaneamos una Aplicación (part == "a"), descartar vulnerabilidades primarias de Hardware (part == "h").
	if targetPart == "a" && primaryPart == "h" {
		return false
	}

	hasMatchingCriteria := false
	isVulnerableMatch := false

	for _, config := range dto.CVE.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				mParts := strings.Split(match.Criteria, ":")
				if len(mParts) < 5 {
					continue
				}
				mPart := strings.ToLower(mParts[2])
				mVendor := strings.ToLower(mParts[3])
				mProduct := strings.ToLower(mParts[4])

				vendorMatch := mVendor == "*" || targetVendor == "*" || mVendor == targetVendor
				productMatch := mProduct == "*" || targetProduct == "*" || mProduct == targetProduct
				partMatch := mPart == "*" || targetPart == "*" || mPart == targetPart

				// Coincidencia especial: Para activos SO (part == "o"), el kernel Linux base (vendor="linux", product="linux_kernel")
				// también se considera coincidente con distribuciones Linux (como canonical/ubuntu_linux).
				if targetPart == "o" && mPart == "o" {
					if (mVendor == "linux" && mProduct == "linux_kernel") || (targetVendor == "linux" && targetProduct == "linux_kernel") {
						vendorMatch = true
						productMatch = true
					}
				}

				if partMatch && vendorMatch && productMatch {
					hasMatchingCriteria = true
					if match.Vulnerable {
						isVulnerableMatch = true
					}
				}
			}
		}
	}

	if len(dto.CVE.Configurations) > 0 {
		if !hasMatchingCriteria {
			return false
		}
		if !isVulnerableMatch {
			return false
		}
	}
	return true
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
	now := time.Now().UTC()

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
	if strings.EqualFold(cve.VulnStatus, "REJECTED") && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(finalDesc)), "rejected reason:") {
		if finalDesc == "" {
			finalDesc = "Rejected reason: This CVE has been rejected by NVD."
		} else {
			finalDesc = "Rejected reason: " + finalDesc
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

	// 4. Extraer el primer CPE identificable que sea realmente el objetivo vulnerable (vulnerable=true)
	cpe := "N/A"
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if match.Vulnerable && match.Criteria != "" {
					cpe = match.Criteria
					break
				}
			}
			if cpe != "N/A" {
				break
			}
		}
		if cpe != "N/A" {
			break
		}
	}
	if cpe == "N/A" && len(cve.Configurations) > 0 && len(cve.Configurations[0].Nodes) > 0 && len(cve.Configurations[0].Nodes[0].CPEMatch) > 0 {
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
					PatchID:       0, // El ID se asignará antes de guardarlo en base de datos
					Description:   "Parche oficial (" + cve.ID + ")",
					URL:           ref.URL,
					Source:        "NVD",
					ReferenceType: "PATCH",
					Official:      true,
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
		NVDEnriched:     true,
		NVDEnrichedAt:   &now,
	}
}

// --- DTOs para la API cpes/2.0 de NIST ---

type NVDCPERefDTO struct {
	Ref  string `json:"ref"`
	Type string `json:"type"`
}

type NVDCPEMatchDTO struct {
	CPEName      string `json:"cpeName"`
	CPENameID    string `json:"cpeNameId"`
	Deprecated   bool   `json:"deprecated"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Titles       []struct {
		Title string `json:"title"`
		Lang  string `json:"lang"`
	} `json:"titles"`
	Refs []NVDCPERefDTO `json:"refs"`
}

func extractURLFromRefs(refs []NVDCPERefDTO) string {
	if len(refs) == 0 {
		return ""
	}
	for _, r := range refs {
		if strings.EqualFold(r.Type, "Product") || strings.EqualFold(r.Type, "Vendor") {
			if strings.TrimSpace(r.Ref) != "" {
				return r.Ref
			}
		}
	}
	for _, r := range refs {
		if strings.TrimSpace(r.Ref) != "" {
			return r.Ref
		}
	}
	return ""
}

type NVDCPENodeDTO struct {
	CPE NVDCPEMatchDTO `json:"cpe"`
}

type NVDCPEResponseDTO struct {
	ResultsPerPage int             `json:"resultsPerPage"`
	StartIndex     int             `json:"startIndex"`
	TotalResults   int             `json:"totalResults"`
	Products       []NVDCPENodeDTO `json:"products"`
}

// SearchCPECandidates realiza la búsqueda por palabras clave en la API de NIST NVD CPEs v2.0
func (a *NistAPIAdapter) SearchCPECandidates(ctx context.Context, vendor, product, version string) ([]domain.CPESuggestion, error) {
	cleanQuery := strings.TrimSpace(fmt.Sprintf("%s %s", vendor, product))
	if cleanQuery == "" {
		return []domain.CPESuggestion{}, nil
	}

	if err := a.waitTurn(ctx); err != nil {
		return nil, err
	}

	cpeBaseURL := "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	reqURL := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=20", cpeBaseURL, url.QueryEscape(cleanQuery))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando request para NVD CPE: %w", err)
	}

	if strings.TrimSpace(a.apiKey) != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando request NVD CPE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return []domain.CPESuggestion{}, nil
		}
		return nil, fmt.Errorf("api nist cpe devolvió status code invalido: %d", resp.StatusCode)
	}

	var apiResp NVDCPEResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("error decodificando respuesta JSON de NVD CPE: %w", err)
	}

	suggestions := make([]domain.CPESuggestion, 0, len(apiResp.Products))
	seenCPEs := make(map[string]bool)

	for _, p := range apiResp.Products {
		cpeStr := p.CPE.CPEName
		if seenCPEs[cpeStr] {
			continue
		}
		seenCPEs[cpeStr] = true

		candVendor, candProduct, _ := parseCPE23Parts(cpeStr)

		var titleStr string
		for _, t := range p.CPE.Titles {
			if t.Lang == "en" {
				titleStr = t.Title
				break
			}
			if titleStr == "" {
				titleStr = t.Title
			}
		}
		if titleStr == "" {
			titleStr = fmt.Sprintf("%s %s", candVendor, candProduct)
		}

		matchType := "FUZZY_SUGGESTION"
		requiresConfirmation := true
		if strings.EqualFold(candVendor, vendor) && strings.EqualFold(candProduct, product) {
			matchType = "EXACT_MATCH"
			requiresConfirmation = false
		}

		suggestions = append(suggestions, domain.CPESuggestion{
			CPE:                      cpeStr,
			Vendor:                   candVendor,
			Product:                  candProduct,
			Title:                    titleStr,
			MatchType:                matchType,
			RequiresUserConfirmation: requiresConfirmation,
		})
	}

	if len(suggestions) > 10 {
		suggestions = suggestions[:10]
	}

	return suggestions, nil
}

// ValidateExactCPE comprueba si una cadena CPE 2.3 dada existe literalmente en el catálogo de NIST NVD
func (a *NistAPIAdapter) ValidateExactCPE(ctx context.Context, cpeString string) (bool, error) {
	if strings.TrimSpace(cpeString) == "" || cpeString == "N/A" {
		return false, nil
	}

	if err := a.waitTurn(ctx); err != nil {
		return false, err
	}

	cpeBaseURL := "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	reqURL := fmt.Sprintf("%s?cpeMatchString=%s", cpeBaseURL, url.QueryEscape(cpeString))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creando request para validación CPE: %w", err)
	}

	if strings.TrimSpace(a.apiKey) != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error ejecutando validación CPE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var apiResp NVDCPEResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return false, err
	}

	return apiResp.TotalResults > 0, nil
}

func parseCPE23Parts(cpeStr string) (vendor, product, version string) {
	parts := strings.Split(cpeStr, ":")
	if len(parts) >= 6 {
		return parts[3], parts[4], parts[5]
	}
	return "", "", "*"
}

// FetchNVDProductsByCPEMatch consulta la API v2.0 de NVD para la Fase 3 del pipeline usando cpeMatchString
func (a *NistAPIAdapter) FetchNVDProductsByCPEMatch(ctx context.Context, cpeBase string, limit int) ([]domain.NVDProductItem, error) {
	if strings.TrimSpace(cpeBase) == "" {
		return []domain.NVDProductItem{}, nil
	}
	if limit <= 0 {
		limit = 20
	}

	if err := a.waitTurn(ctx); err != nil {
		return nil, err
	}

	// Asegurar comodín al final si no lo tiene
	matchStr := cpeBase
	if !strings.HasSuffix(matchStr, ":*") && !strings.HasSuffix(matchStr, "*") {
		matchStr = matchStr + ":*"
	}

	cpeBaseURL := "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	reqURL := fmt.Sprintf("%s?cpeMatchString=%s&resultsPerPage=%d", cpeBaseURL, url.QueryEscape(matchStr), limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando petición HTTP a NVD CPE API: %w", err)
	}

	if strings.TrimSpace(a.apiKey) != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando consulta HTTP a NVD CPE API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD CPE API devolvió HTTP %d", resp.StatusCode)
	}

	var apiResp NVDCPEResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("error decodificando JSON de NVD CPE API: %w", err)
	}

	items := []domain.NVDProductItem{}
	for _, p := range apiResp.Products {
		titleEn := ""
		for _, t := range p.CPE.Titles {
			if t.Lang == "en" {
				titleEn = t.Title
				break
			}
		}
		if titleEn == "" && len(p.CPE.Titles) > 0 {
			titleEn = p.CPE.Titles[0].Title
		}

		lastMod, _ := time.Parse("2006-01-02T15:04:05.999", p.CPE.LastModified)
		if lastMod.IsZero() {
			lastMod, _ = time.Parse(time.RFC3339, p.CPE.LastModified)
		}

		refURL := extractURLFromRefs(p.CPE.Refs)

		items = append(items, domain.NVDProductItem{
			CPEName:      p.CPE.CPEName,
			CPENameID:    p.CPE.CPENameID,
			Title:        titleEn,
			Deprecated:   p.CPE.Deprecated,
			LastModified: lastMod,
			URL:          refURL,
		})
	}

	return items, nil
}
