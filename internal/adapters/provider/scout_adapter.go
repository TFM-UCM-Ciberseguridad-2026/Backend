package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

// ScoutAdapter implementa la interfaz ContainerScannerPort utilizando el CLI de Docker Scout
type ScoutAdapter struct {
	mockData []byte // Usado para inyectar respuestas de prueba en ausencia del CLI real
}

func NewScoutAdapter() *ScoutAdapter {
	return &ScoutAdapter{}
}

// SetMockData permite inyectar un JSON de prueba para evitar ejecutar Docker en los tests
func (s *ScoutAdapter) SetMockData(data []byte) {
	s.mockData = data
}

// ScoutOutput representa un formato simplificado de salida.
// Nota: Dependiendo de la versión de Docker Scout y el formato (ej. --format sarif o gitlab),
// esta estructura debe ajustarse para coincidir con el schema exacto devuelto por el comando.
type ScoutOutput []ScoutVulnerability

type ScoutVulnerability struct {
	CVE         string `json:"cve"`
	Description string `json:"description"`
	CVSSVector  string `json:"cvss_vector"`
	Package     string `json:"package"`
	Version     string `json:"version"`
}

func (s *ScoutAdapter) ScanImage(ctx context.Context, imageName string) ([]domain.Vulnerability, error) {
	var outputBytes []byte
	var err error

	if s.mockData != nil {
		outputBytes = s.mockData
	} else {
		// Ejecutar el comando CLI real
		// NOTA: Se asume que el CLI devuelve un JSON simple de vulnerabilidades.
		// Si se usa SARIF, el comando sería --format sarif y el unmarshal debería parsear SARIF.
		cmd := exec.CommandContext(ctx, "docker", "scout", "cves", imageName, "--format", "json")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		
		err = cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("error ejecutando docker scout (stderr: %s): %w", stderr.String(), err)
		}
		outputBytes = out.Bytes()
	}

	var scoutVulns ScoutOutput
	err = json.Unmarshal(outputBytes, &scoutVulns)
	if err != nil {
		return nil, fmt.Errorf("error parseando el JSON de Docker Scout: %w", err)
	}

	// Mapear al modelo de dominio
	var domainVulns []domain.Vulnerability
	for _, sv := range scoutVulns {
		if sv.CVE == "" {
			continue
		}
		
		vuln := domain.Vulnerability{
			CVEID:       sv.CVE,
			Description: sv.Description,
			CVSSVector:  sv.CVSSVector,
			// Se pueden mapear otros campos relevantes como BaseScore dependiendo de los datos de Scout
		}
		domainVulns = append(domainVulns, vuln)
	}

	return domainVulns, nil
}
