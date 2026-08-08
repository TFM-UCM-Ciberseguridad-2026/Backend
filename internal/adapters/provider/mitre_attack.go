package provider

/*
Este archivo implementa el Adaptador de Salida (Outbound/Driven Adapter) para el catálogo STIX 2.1 de MITRE ATT&CK (Enterprise).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/provider`, implementando ports.MitreATTACKProvider.
2. Descarga y Parseo STIX 2.1: Consume el feed oficial de MITRE ATT&CK Enterprise, parsea los objetos STIX `attack-pattern` y extrae los nombres, tácticas y descripciones completas de cada técnica TTP.
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

const defaultMitreAttackURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

type mitreExternalRefDTO struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type mitreKillChainPhaseDTO struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type mitreObjectDTO struct {
	Type               string                   `json:"type"`
	ID                 string                   `json:"id"`
	Name               string                   `json:"name"`
	Description        string                   `json:"description"`
	ExternalReferences []mitreExternalRefDTO    `json:"external_references"`
	KillChainPhases    []mitreKillChainPhaseDTO `json:"kill_chain_phases"`
}

type mitreBundleDTO struct {
	Objects []mitreObjectDTO `json:"objects"`
}

type MitreAttackSTIXProvider struct {
	url        string
	httpClient *http.Client
}

func NewMitreAttackSTIXProvider(rawURL string, timeoutSeconds int) *MitreAttackSTIXProvider {
	if rawURL == "" {
		rawURL = defaultMitreAttackURL
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 90
	}
	return &MitreAttackSTIXProvider{
		url: rawURL,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// FetchATTACKBundle descarga y parsea las técnicas TTP de MITRE ATT&CK Enterprise.
func (p *MitreAttackSTIXProvider) FetchATTACKBundle(ctx context.Context) ([]domain.TTP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando solicitud HTTP para MITRE ATT&CK: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error ejecutando consulta HTTP a MITRE ATT&CK: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("la API de MITRE ATT&CK devolvió status code no válido: %d", resp.StatusCode)
	}

	var bundle mitreBundleDTO
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("error decodificando el bundle JSON de MITRE ATT&CK: %w", err)
	}

	var ttps []domain.TTP

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}

		var ttpID string
		for _, ref := range obj.ExternalReferences {
			if strings.ToLower(ref.SourceName) == "mitre-attack" && ref.ExternalID != "" {
				ttpID = strings.TrimSpace(ref.ExternalID)
				break
			}
		}

		if ttpID == "" {
			continue
		}

		var tactics []string
		for _, kc := range obj.KillChainPhases {
			if strings.TrimSpace(kc.PhaseName) != "" {
				tactics = append(tactics, strings.TrimSpace(kc.PhaseName))
			}
		}

		tacticStr := strings.Join(tactics, ", ")

		ttps = append(ttps, domain.TTP{
			TTPID:       ttpID,
			Name:        obj.Name,
			Tactic:      tacticStr,
			Description: obj.Description,
		})
	}

	return ttps, nil
}
