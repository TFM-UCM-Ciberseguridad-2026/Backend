package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

/*
Este archivo implementa el Adaptador de salida contra OSV.dev (Open Source Vulnerabilities).

Propósito arquitectónico y teórico:
1. Complemento al NVD: El NVD solo expone referencias etiquetadas como "Patch", sin versión
   corregida ni fecha. OSV publica referencias tipadas FIX y, sobre todo, las versiones que
   corrigen la vulnerabilidad, que es lo que permite razonar sobre el parcheo.
2. Cobertura: OSV agrega ecosistemas open source (Maven, npm, PyPI, Go, Debian, Ubuntu,
   Alpine, ...). No cubre software propietario: un CVE de Microsoft devuelve 404.
*/

const osvBaseURL = "https://api.osv.dev"

// osvEventDTO representa un evento dentro de un rango de versiones afectadas.
// Solo uno de los campos viene informado en cada evento.
type osvEventDTO struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type osvRangeDTO struct {
	Type   string        `json:"type"`
	Repo   string        `json:"repo"`
	Events []osvEventDTO `json:"events"`
}

type osvPackageDTO struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvAffectedDTO struct {
	Package  osvPackageDTO `json:"package"`
	Ranges   []osvRangeDTO `json:"ranges"`
	Versions []string      `json:"versions"`
}

type osvReferenceDTO struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvDatabaseSpecificDTO struct {
	CNAAssigner string `json:"cna_assigner"`
}

type osvVulnerabilityDTO struct {
	ID               string                 `json:"id"`
	Aliases          []string               `json:"aliases"`
	Summary          string                 `json:"summary"`
	Published        string                 `json:"published"`
	Modified         string                 `json:"modified"`
	Affected         []osvAffectedDTO       `json:"affected"`
	References       []osvReferenceDTO      `json:"references"`
	DatabaseSpecific osvDatabaseSpecificDTO `json:"database_specific"`
}

func normalizedHost(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(parsed.Hostname(), "www."))
}

func sameUpstreamReference(referenceURL, upstreamURL string) bool {
	reference, err := url.Parse(strings.TrimSpace(referenceURL))
	if err != nil || (reference.Scheme != "http" && reference.Scheme != "https") {
		return false
	}
	upstream, err := url.Parse(strings.TrimSpace(upstreamURL))
	if err != nil || upstream.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(reference.Hostname(), upstream.Hostname()) {
		return false
	}

	upstreamPath := strings.TrimRight(upstream.Path, "/")
	referencePath := strings.TrimRight(reference.Path, "/")
	return upstreamPath == "" || strings.HasPrefix(referencePath, upstreamPath)
}

func officialHostForAssigner(host, assigner string) bool {
	host = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(host), "www."))
	assigner = strings.ToLower(strings.TrimSpace(assigner))
	if host == "" || assigner == "" {
		return false
	}
	for _, label := range strings.FieldsFunc(host, func(r rune) bool {
		return r == '.' || r == '-'
	}) {
		if label == assigner {
			return true
		}
	}
	return false
}

func isOfficialReference(referenceURL, referenceType, cnaAssigner string, upstreamRepos []string) bool {
	parsed, err := url.Parse(strings.TrimSpace(referenceURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}

	host := normalizedHost(referenceURL)
	if host == "osv.dev" || host == "api.osv.dev" || host == "nvd.nist.gov" {
		return false
	}

	for _, repo := range upstreamRepos {
		if sameUpstreamReference(referenceURL, repo) {
			return true
		}
	}

	return (strings.EqualFold(referenceType, "ADVISORY") || strings.EqualFold(referenceType, "WEB")) &&
		officialHostForAssigner(host, cnaAssigner)
}

// OSVAdapter implementa ports.PatchProvider consumiendo la API pública de OSV.dev.
// No requiere clave de API.
type OSVAdapter struct {
	baseURL    string
	httpClient *http.Client
}

func NewOSVAdapter() *OSVAdapter {
	return &OSVAdapter{
		baseURL: osvBaseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// maxAliasLookups acota cuántos avisos enlazados consultamos, para que un CVE con muchos
// alias no dispare una ráfaga de peticiones.
const maxAliasLookups = 5

// FetchPatchInfo recupera de OSV los parches y versiones corregidas de un CVE.
//
// Devuelve (nil, nil) si OSV no conoce el CVE (HTTP 404). Es el caso habitual con
// software propietario —Microsoft, Cisco, Oracle— y no debe tratarse como un error:
// significa que esta fuente no aporta datos, no que la consulta haya fallado.
//
// OSV guarda la información en dos niveles y hay que recorrer los dos: el registro del
// CVE solo trae rangos de tipo GIT (hashes de commit, inservibles para comparar versiones),
// mientras que las versiones semánticas viven en los avisos de ecosistema enlazados por
// aliases (GHSA, PYSEC, ...). Por eso, si el registro del CVE no aporta versiones usables,
// se consultan sus alias.
func (a *OSVAdapter) FetchPatchInfo(ctx context.Context, cveID string) (*domain.PatchIntelligence, error) {
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return nil, fmt.Errorf("cve_id vacío")
	}

	dto, err := a.fetchVuln(ctx, cveID)
	if err != nil {
		return nil, err
	}
	if dto == nil {
		return nil, nil
	}

	info := a.toDomain(cveID, *dto)

	// El registro del CVE rara vez trae versiones de ecosistema: las aporta el aviso
	// enlazado (GHSA y equivalentes). Solo bajamos a los alias si hace falta.
	if len(info.FixedVersions) == 0 {
		lookups := 0
		for _, alias := range dto.Aliases {
			if lookups >= maxAliasLookups {
				break
			}
			if strings.EqualFold(alias, cveID) || strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
				continue
			}
			lookups++

			aliasDTO, err := a.fetchVuln(ctx, alias)
			if err != nil || aliasDTO == nil {
				// Un alias que falle no invalida lo que ya tenemos del CVE.
				continue
			}

			// Deduplicamos al fusionar: dos avisos del mismo CVE (p. ej. GHSA y PYSEC)
			// suelen reportar la misma versión corregida, y cada llamada a toDomain
			// arrastra su propio control de duplicados.
			aliasInfo := a.toDomain(cveID, *aliasDTO)
			info.FixedVersions = append(info.FixedVersions, dedupeFixedVersions(info.FixedVersions, aliasInfo.FixedVersions)...)
			info.Patches = append(info.Patches, dedupePatchesByURL(info.Patches, aliasInfo.Patches)...)
		}
	}

	// Una referencia oficial puede estar en el registro CVE y la versión corregida
	// en uno de sus avisos enlazados. Se propaga la evidencia de versión al patch.
	for i := range info.Patches {
		if info.Patches[i].Official && strings.TrimSpace(info.Patches[i].FixedVersion) == "" {
			info.Patches[i].FixedVersion = fixedVersionText(info.FixedVersions)
		}
	}

	return info, nil
}

// fetchVuln consulta un registro de OSV por su ID. Devuelve (nil, nil) si no existe.
func (a *OSVAdapter) fetchVuln(ctx context.Context, id string) (*osvVulnerabilityDTO, error) {
	url := fmt.Sprintf("%s/v1/vulns/%s", a.baseURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error construyendo la petición a OSV: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error consultando OSV para %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// OSV no cubre este identificador: resultado válido sin datos.
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV devolvió estado %d para %s", resp.StatusCode, id)
	}

	var dto osvVulnerabilityDTO
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		return nil, fmt.Errorf("error decodificando la respuesta de OSV para %s: %w", id, err)
	}
	return &dto, nil
}

// toDomain traduce un registro de OSV a la entidad de dominio, normalizando fechas,
// deduplicando versiones corregidas y quedándose solo con las referencias de tipo FIX.
func (a *OSVAdapter) toDomain(cveID string, dto osvVulnerabilityDTO) *domain.PatchIntelligence {
	published := parseOSVTime(dto.Published)

	// Versiones corregidas: recorremos los paquetes afectados y sus rangos.
	// Se descartan los rangos de tipo GIT: sus eventos "fixed" son hashes de commit, que
	// no sirven para compararlos con la versión que hay instalada.
	fixedVersions := make([]domain.FixedVersion, 0)
	seenVersions := make(map[string]bool)
	for _, affected := range dto.Affected {
		for _, r := range affected.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			for _, event := range r.Events {
				if event.Fixed == "" {
					continue
				}
				fixed := domain.FixedVersion{
					Ecosystem: affected.Package.Ecosystem,
					Package:   affected.Package.Name,
					Version:   event.Fixed,
				}
				// La clave incluye el ecosistema: un mismo paquete@versión puede existir
				// en ecosistemas distintos y no son la misma corrección.
				key := fixed.Ecosystem + "|" + fixed.Package + "|" + fixed.Version
				if seenVersions[key] {
					continue
				}
				seenVersions[key] = true
				fixedVersions = append(fixedVersions, fixed)
			}
		}
	}

	// Parches: conservar FIX del upstream y advisories del fabricante identificables
	// por el repositorio o por el CNA del registro OSV.
	patches := make([]domain.Patch, 0)
	seenURLs := make(map[string]bool)
	upstreamRepos := make([]string, 0)
	for _, affected := range dto.Affected {
		for _, affectedRange := range affected.Ranges {
			if repo := strings.TrimSpace(affectedRange.Repo); repo != "" {
				upstreamRepos = append(upstreamRepos, repo)
			}
		}
	}

	for _, ref := range dto.References {
		referenceURL := strings.TrimSpace(ref.URL)
		referenceType := strings.ToUpper(strings.TrimSpace(ref.Type))
		if referenceURL == "" || seenURLs[referenceURL] {
			continue
		}
		if referenceType != "FIX" && referenceType != "ADVISORY" && referenceType != "WEB" {
			continue
		}
		if !isOfficialReference(
			referenceURL,
			referenceType,
			dto.DatabaseSpecific.CNAAssigner,
			upstreamRepos,
		) {
			continue
		}

		seenURLs[referenceURL] = true
		patches = append(patches, domain.Patch{
			Description: fmt.Sprintf("Corrección oficial del fabricante según OSV (%s)", cveID),
			URL:         referenceURL,
			ReleaseDate: published,
			Source:        "OSV",
			ReferenceType: referenceType,
			Official:      true,
			FixedVersion:  fixedVersionText(fixedVersions),
		})
	}

	return &domain.PatchIntelligence{
		CVEID:         cveID,
		Patches:       patches,
		FixedVersions: fixedVersions,
		Published:     published,
		Source:        "OSV",
	}
}

func fixedVersionText(fixedVersions []domain.FixedVersion) string {
	values := make([]string, 0, len(fixedVersions))
	for _, fixedVersion := range fixedVersions {
		values = append(values, fixedVersion.String())
	}
	return strings.Join(values, ", ")
}

// dedupeFixedVersions devuelve las versiones de candidates que no están ya en existing,
// comparando por ecosistema, paquete y versión.
func dedupeFixedVersions(existing, candidates []domain.FixedVersion) []domain.FixedVersion {
	key := func(f domain.FixedVersion) string {
		return f.Ecosystem + "|" + f.Package + "|" + f.Version
	}

	seen := make(map[string]bool, len(existing))
	for _, f := range existing {
		seen[key(f)] = true
	}

	result := make([]domain.FixedVersion, 0, len(candidates))
	for _, f := range candidates {
		if seen[key(f)] {
			continue
		}
		seen[key(f)] = true
		result = append(result, f)
	}
	return result
}

// dedupePatchesByURL devuelve los parches de candidates cuya URL no está ya en existing.
func dedupePatchesByURL(existing, candidates []domain.Patch) []domain.Patch {
	seen := make(map[string]bool, len(existing))
	for _, p := range existing {
		seen[p.URL] = true
	}

	result := make([]domain.Patch, 0, len(candidates))
	for _, p := range candidates {
		if seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		result = append(result, p)
	}
	return result
}

// parseOSVTime interpreta las marcas de tiempo RFC3339 de OSV. Devuelve nil si el campo
// viene vacío o con un formato inesperado, para no inventar una fecha.
func parseOSVTime(value string) *time.Time {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	utc := parsed.UTC()
	return &utc
}
