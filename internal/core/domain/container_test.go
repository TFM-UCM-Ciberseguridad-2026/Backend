package domain

import (
	"testing"
)

func TestContainerRiskSummary(t *testing.T) {
	summary := ContainerRiskSummary{
		ContainerID:   "c-123",
		ContainerName: "test-container",
		State:         "running",
		RiskScore:     8.5,
		RiskTier:      "HIGH",
		PriorityScore: 9.0,
		PriorityTier:  "CRITICAL",
		TechnicalDriverType:      "CONTAINER_IMAGE_FINDING",
		TechnicalDriverAssetID:   "c-123",
		TechnicalDriverAssetName: "test-container",
		TechnicalDriverFindingID: 1001,
		TechnicalDriverCVEID:     "CVE-2023-1234",
		TechnicalDriverRiskScore: 8.5,
		RiskyAssetCount:          3,
	}

	if summary.ContainerID != "c-123" {
		t.Errorf("ContainerID esperado 'c-123', obtenido '%s'", summary.ContainerID)
	}
	if summary.RiskScore != 8.5 {
		t.Errorf("RiskScore esperado 8.5, obtenido %f", summary.RiskScore)
	}
	if summary.TechnicalDriverCVEID != "CVE-2023-1234" {
		t.Errorf("TechnicalDriverCVEID esperado 'CVE-2023-1234', obtenido '%s'", summary.TechnicalDriverCVEID)
	}
}

func TestFindingRiskContext_ContainerFields(t *testing.T) {
	ctx := FindingRiskContext{
		FindingID:     1,
		CVEID:         "CVE-2024-9999",
		AssetType:     "CONTAINER_IMAGE_FINDING",
		AssetID:       "c-456",
		AssetName:     "nginx-app",
		ContainerID:   "c-456",
		ContainerName: "nginx-app",
		ImageID:       "nginx:latest",
		InContainer:   true,
	}

	if !ctx.InContainer {
		t.Errorf("InContainer debería ser verdadero")
	}
	if ctx.AssetType != "CONTAINER_IMAGE_FINDING" {
		t.Errorf("AssetType esperado 'CONTAINER_IMAGE_FINDING', obtenido '%s'", ctx.AssetType)
	}
}
