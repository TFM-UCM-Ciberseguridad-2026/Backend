package service

import (
	"context"
	"testing"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

// Los stubs embeben la interfaz y solo implementan lo que usa resolvePatchLevel.

type stubPatchPort struct {
	ports.PatchPort
	patch *domain.Patch
}

func (s stubPatchPort) GetByID(_ context.Context, id int64) (*domain.Patch, error) {
	if s.patch != nil && s.patch.PatchID == id {
		return s.patch, nil
	}
	return nil, nil
}

func (s stubPatchPort) GetByVulnerability(_ context.Context, _ string) ([]domain.Patch, error) {
	if s.patch == nil {
		return nil, nil
	}
	return []domain.Patch{*s.patch}, nil
}

type stubSoftwareInstPort struct {
	ports.SoftwareInstallationPort
	installed string
}

func (s stubSoftwareInstPort) GetInstalledSoftware(_ context.Context, _ string) (*domain.Software, error) {
	return &domain.Software{Name: "log4j-core", Version: s.installed}, nil
}

func TestResolvePatchLevelMatriz(t *testing.T) {
	const cve = "CVE-TEST-0001"

	casos := []struct {
		nombre        string
		official      bool
		fixedVersion  string
		referenceType string
		targetVersion string
		instalada     string
		solicitado    domain.RemediationLevel
		esperado      domain.RemediationLevel
	}{
		{
			nombre: "oficial con version corregida", official: true, fixedVersion: "2.17.1",
			solicitado: domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelOfficialFix,
		},
		{
			nombre: "OSV sin aval pero la version verifica", official: false, fixedVersion: "2.17.1",
			targetVersion: "2.17.1",
			solicitado:    domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelOfficialFix,
		},
		{
			nombre: "OSV sin aval y la version se queda corta", official: false, fixedVersion: "2.17.1",
			targetVersion: "2.15.0",
			solicitado:    domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelOfficialFix,
		},
		{
			nombre: "OSV sin aval y sin version declarada", official: false, fixedVersion: "2.17.1",
			instalada:  "2.14.1",
			solicitado: domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelOfficialFix,
		},
		{
			nombre: "OSV sin aval, ya estaba instalada por encima", official: false, fixedVersion: "2.17.1",
			instalada:  "2.18.0",
			solicitado: domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelOfficialFix,
		},
		{
			nombre: "patch oficial sin version propuesta", official: true,
			referenceType: "PATCH",
			solicitado:    domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelTemporaryFix,
		},
		{
			nombre: "advisory oficial sin version, documenta mitigacion", official: true,
			referenceType: "MITIGATION",
			solicitado:    domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelWorkaround,
		},
		{
			nombre: "advisory oficial sin version ni mitigacion", official: true,
			referenceType: "ADVISORY",
			solicitado:    domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelTemporaryFix,
		},
		{
			nombre:     "sin evidencia de ningun tipo",
			solicitado: domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelUnavailable,
		},
		{
			nombre: "el operador declara menos de lo que sostiene la evidencia", official: true, fixedVersion: "2.17.1",
			solicitado: domain.RemediationLevelWorkaround, esperado: domain.RemediationLevelWorkaround,
		},
		{
			nombre: "el operador no puede subir por encima del techo (doc, seccion 6)", official: false, fixedVersion: "2.17.1",
			targetVersion: "2.15.0",
			solicitado:    domain.RemediationLevelOfficialFix, esperado: domain.RemediationLevelOfficialFix,
		},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			o := &Orchestrator{
				patchPort: stubPatchPort{patch: &domain.Patch{
					PatchID: 1, Official: c.official,
					FixedVersion: c.fixedVersion, ReferenceType: c.referenceType,
				}},
				softwareInstPort: stubSoftwareInstPort{installed: c.instalada},
			}

			got, err := o.resolvePatchLevel(context.Background(), "inst-1", cve, 1, c.targetVersion, c.solicitado)
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if got != c.esperado {
				t.Errorf("esperado %s, obtenido %s (factor %.2f)", c.esperado, got, RemediationFactorForLevel(got))
			}
		})
	}
}
