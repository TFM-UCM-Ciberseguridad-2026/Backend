package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

/*
CPEService implementa el servicio de aplicación dedicado a la resolución,
normalización y autocompletado de cadenas CPE (Common Platform Enumeration).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/service`, en la capa de servicios de aplicación del dominio.
2. Principio de Responsabilidad Única (SRP): Desacopla la lógica de resolución CPE del Orquestador general.
3. Orquestación de Resolutores: Coordina los resolutores externos (NIST NVD, CIRCL).
*/

type CPEService struct {
	cpeResolver ports.CPEResolverPort
	cpeGuesser  ports.CPEGuesserPort
}

// NewCPEService inicializa el servicio de resolución de CPEs
func NewCPEService(resolver ports.CPEResolverPort) *CPEService {
	return &CPEService{
		cpeResolver: resolver,
	}
}

func (s *CPEService) WithCPEGuesser(guesser ports.CPEGuesserPort) *CPEService {
	s.cpeGuesser = guesser
	return s
}

// SearchCPE busca candidatos a CPE utilizando el resolutor de candidatos y añade la opción de software personalizado interno.
func (s *CPEService) SearchCPE(ctx context.Context, vendor, product, version string) ([]domain.CPESuggestion, error) {
	suggestions := []domain.CPESuggestion{}

	// 1. Consultar NVD / External Resolver
	if s.cpeResolver != nil {
		nvdSuggestions, err := s.cpeResolver.SearchCPECandidates(ctx, vendor, product, version)
		if err == nil {
			suggestions = append(suggestions, nvdSuggestions...)
		}
	}

	// 2. Opción de software personalizado/interno
	customCPE := domain.GenerateCPE23("a", vendor, product, version)
	suggestions = append(suggestions, domain.CPESuggestion{
		CPE:                      customCPE,
		Vendor:                   vendor,
		Product:                  product,
		Title:                    fmt.Sprintf("%s %s (Software Interno / Personalizado)", vendor, product),
		MatchType:                "CUSTOM_INTERNAL",
		RequiresUserConfirmation: false,
	})

	return suggestions, nil
}

// ResolveSoftwareCPE resuelve el CPE adecuado para un software
func (s *CPEService) ResolveSoftwareCPE(ctx context.Context, software *domain.Software, saveAlias bool) (*domain.CPEMatchResult, error) {
	if software.CPEStatus == domain.CPEStatusNotInNVD {
		software.CPE = domain.GenerateCPE23(software.Type, software.Vendor, software.Name, software.Version)
		return &domain.CPEMatchResult{
			CPE:       software.CPE,
			CPEStatus: software.CPEStatus,
		}, nil
	}

	// Si ya viene un CPE especificado explícitamente (ej. seleccionado por el usuario desde la UI)
	if software.CPE != "" {
		if software.CPEStatus == "" {
			software.CPEStatus = domain.CPEStatusVerifiedManual
		}
		return &domain.CPEMatchResult{
			CPE:       software.CPE,
			CPEStatus: software.CPEStatus,
		}, nil
	}

	// Validación Exacta y Búsqueda en NVD
	syntheticCPE := domain.GenerateCPE23(software.Type, software.Vendor, software.Name, software.Version)
	if s.cpeResolver != nil {
		valid, err := s.cpeResolver.ValidateExactCPE(ctx, syntheticCPE)
		if err == nil && valid {
			software.CPE = syntheticCPE
			software.CPEStatus = domain.CPEStatusVerifiedAuto
			return &domain.CPEMatchResult{
				CPE:       syntheticCPE,
				CPEStatus: domain.CPEStatusVerifiedAuto,
			}, nil
		}

		// Búsqueda de candidatos
		candidates, err := s.cpeResolver.SearchCPECandidates(ctx, software.Vendor, software.Name, software.Version)
		if err == nil && len(candidates) > 0 {
			best := candidates[0]
			if best.MatchType == "EXACT_MATCH" || !best.RequiresUserConfirmation {
				software.CPE = best.CPE
				software.Vendor = best.Vendor
				software.Name = best.Product
				software.CPEStatus = domain.CPEStatusVerifiedAuto
				return &domain.CPEMatchResult{
					CPE:              best.CPE,
					CPEStatus:        domain.CPEStatusVerifiedAuto,
					CanonicalVendor:  best.Vendor,
					CanonicalProduct: best.Product,
				}, nil
			}

			// Coincidencia difusa: requiere confirmación del usuario y NO debe marcarse como VERIFIED_AUTO
			software.CPE = best.CPE
			software.CPEStatus = domain.CPEStatusPendingConfirmation
			return &domain.CPEMatchResult{
				CPE:              best.CPE,
				CPEStatus:        domain.CPEStatusPendingConfirmation,
				SuggestedCPE:     best.CPE,
				Suggestions:      candidates,
				CanonicalVendor:  best.Vendor,
				CanonicalProduct: best.Product,
			}, nil
		}
	}

	// Sin coincidencias externas: usar sintáctico y marcar como NOT_IN_NVD si no fue validado en NVD
	software.CPE = syntheticCPE
	software.CPEStatus = domain.CPEStatusNotInNVD
	return &domain.CPEMatchResult{
		CPE:       syntheticCPE,
		CPEStatus: domain.CPEStatusNotInNVD,
	}, nil
}

// ExecuteCPEPipeline ejecuta el pipeline completo de 5 fases para generar la lista final de sugerencias CPE.

func (s *CPEService) ExecuteCPEPipeline(ctx context.Context, rawInput string) ([]domain.CPEFinalItem, error) {
	// Fase 1: Sanitización y Tokenización del Input
	tokens, extractedVersion := domain.SanitizeAndTokenizeInput(rawInput)
	if len(tokens) == 0 {
		return []domain.CPEFinalItem{}, nil
	}

	// Fase 2: Búsqueda Difusa en CPE-Guesser
	baseCPEs := []string{}
	if s.cpeGuesser != nil {
		gResults, err := s.cpeGuesser.SearchBaseCPEs(ctx, tokens, 3)
		if err == nil {
			baseCPEs = gResults
		}
	}

	// Fallback si cpe-guesser no devuelve nada o no está inyectado
	if len(baseCPEs) == 0 {
		syntheticBase := fmt.Sprintf("cpe:2.3:a:%s", strings.Join(tokens, "_"))
		baseCPEs = append(baseCPEs, syntheticBase)
	}

	// Fase 3: Consulta y Validación en NVD CPE API v2.0 (Paralelizado)
	var wg sync.WaitGroup
	var mu sync.Mutex
	rawNVDItems := []domain.NVDProductItem{}

	// Si se extrajo una versión específica del input, priorizar consultas NVD con esa versión
	nvdQueries := []string{}
	for _, bCPE := range baseCPEs {
		if extractedVersion != "" {
			vCPEs := buildVersionedCPEs(bCPE, extractedVersion)
			nvdQueries = append(nvdQueries, vCPEs...)
		}
		nvdQueries = append(nvdQueries, bCPE)
	}

	if s.cpeResolver != nil {
		for _, qCPE := range nvdQueries {
			wg.Add(1)
			go func(cpeQuery string) {
				defer wg.Done()
				items, err := s.cpeResolver.FetchNVDProductsByCPEMatch(ctx, cpeQuery, 15)
				if err == nil && len(items) > 0 {
					mu.Lock()
					rawNVDItems = append(rawNVDItems, items...)
					mu.Unlock()
				}
			}(qCPE)
		}
		wg.Wait()
	}

	// Fase 4: Filtrado, Deduplicación y Normalización
	dedupMap := make(map[string]domain.NVDProductItem)
	for _, item := range rawNVDItems {
		if item.Deprecated {
			continue
		}
		key := item.CPENameID
		if key == "" {
			key = item.CPEName
		}
		if _, exists := dedupMap[key]; !exists {
			dedupMap[key] = item
		}
	}

	filteredItems := make([]domain.NVDProductItem, 0, len(dedupMap))
	for _, item := range dedupMap {
		filteredItems = append(filteredItems, item)
	}

	// Ordenamiento por coincidencia de versión y fecha de modificación
	sort.Slice(filteredItems, func(i, j int) bool {
		if extractedVersion != "" {
			vI := parseVersionFromCPE(filteredItems[i].CPEName)
			vJ := parseVersionFromCPE(filteredItems[j].CPEName)

			matchI := isVersionMatch(vI, extractedVersion)
			matchJ := isVersionMatch(vJ, extractedVersion)

			if matchI != matchJ {
				return matchI
			}
		}
		return filteredItems[i].LastModified.After(filteredItems[j].LastModified)
	})

	// Truncar sugerencias a un máximo de 20
	if len(filteredItems) > 20 {
		filteredItems = filteredItems[:20]
	}

	// Fase 5: Estructura de Respuesta Final
	finalList := make([]domain.CPEFinalItem, 0, len(filteredItems))
	for _, item := range filteredItems {
		cpeFormatted := item.CPEName
		if extractedVersion != "" && parseVersionFromCPE(item.CPEName) == "*" {
			// Si la entrada devuelta es comodín y el usuario especificó versión, formatearla
			parts := strings.Split(item.CPEName, ":")
			if len(parts) >= 6 {
				parts[5] = extractedVersion
				cpeFormatted = strings.Join(parts, ":")
			}
		}

		finalList = append(finalList, domain.CPEFinalItem{
			Title:        item.Title,
			CPE:          cpeFormatted,
			ID:           item.CPENameID,
			LastModified: item.LastModified,
			URL:          item.URL,
		})
	}

	return finalList, nil
}

func buildVersionedCPEs(bCPE string, version string) []string {
	parts := strings.Split(bCPE, ":")
	if len(parts) < 5 {
		return nil
	}
	part := parts[2]
	vendor := parts[3]
	product := parts[4]

	// Si el usuario introduce una versión corta tipo "1.10" (major.minor),
	// el estándar NVD CPE la almacena como "1.10.0" (semver).
	targetVersion := version
	if strings.Count(version, ".") == 1 {
		targetVersion = version + ".0"
	}

	return []string{
		fmt.Sprintf("cpe:2.3:%s:%s:%s:%s", part, vendor, product, targetVersion),
	}
}

func isVersionMatch(cpeVersion, inputVersion string) bool {
	if strings.EqualFold(cpeVersion, inputVersion) {
		return true
	}
	if strings.Count(inputVersion, ".") == 1 && strings.EqualFold(cpeVersion, inputVersion+".0") {
		return true
	}
	if strings.HasPrefix(cpeVersion, inputVersion+".") {
		return true
	}
	return false
}

func parseVersionFromCPE(cpeStr string) string {
	parts := strings.Split(cpeStr, ":")
	if len(parts) >= 6 {
		return parts[5]
	}
	return "*"
}
