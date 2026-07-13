package service

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

/*
Este archivo contiene el Servicio de Aplicación (Application Service) u Orquestador de Casos de Uso.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/service`, actuando como el implementador de los puertos de entrada (inbound ports) y consumidor de los puertos de salida (outbound ports).
2. Núcleo Lógico de la Aplicación: Implementa los casos de uso principales de la lógica de negocio (como el análisis y correlación de vulnerabilidades de equipos mediante CPEs).
3. Coordinación de Dependencias: Recibe los puertos (CVEProvider, ExploitProvider, Database) a través del constructor (Inyección de Dependencias) y orquesta las llamadas necesarias en orden lógico para cumplir con el proceso de negocio.
4. Neutralidad Tecnológica: No expone tipos HTTP ni dependencias de frameworks web, garantizando que las reglas de negocio puedan ser llamadas por un servidor HTTP, un CLI de consola o un proceso de ejecución programada (cron).
*/

type Orchestrator struct {
	projectPort      ports.ProjectPort
	endpointPort     ports.EndpointPort
	hardwarePort     ports.HardwarePort
	networkPort      ports.NetworkPort
	softwareInstPort ports.SoftwareInstallationPort
	softwarePort     ports.SoftwarePort
	findingPort      ports.FindingPort
	vulnPort         ports.VulnerabilityPort
	remediationPort  ports.RemediationPort
	relationshipPort ports.RelationshipPort
	infraPort        ports.InfrastructurePort
}

func NewOrchestrator(
	projectPort ports.ProjectPort,
	endpointPort ports.EndpointPort,
	hardwarePort ports.HardwarePort,
	networkPort ports.NetworkPort,
	softwareInstPort ports.SoftwareInstallationPort,
	softwarePort ports.SoftwarePort,
	findingPort ports.FindingPort,
	vulnPort ports.VulnerabilityPort,
	remediationPort ports.RemediationPort,
	relationshipPort ports.RelationshipPort,
	infraPort ports.InfrastructurePort,
) *Orchestrator {
	return &Orchestrator{
		projectPort:      projectPort,
		endpointPort:     endpointPort,
		hardwarePort:     hardwarePort,
		networkPort:      networkPort,
		softwareInstPort: softwareInstPort,
		softwarePort:     softwarePort,
		findingPort:      findingPort,
		vulnPort:         vulnPort,
		remediationPort:  remediationPort,
		relationshipPort: relationshipPort,
		infraPort:        infraPort,
	}
}

// CreateProject guarda el proyecto principal.
func (o *Orchestrator) CreateProject(ctx context.Context, project *domain.Project) error {
	return o.projectPort.Save(ctx, project)
}

// AddEndpointToProject guarda un nuevo endpoint y lo vincula a un proyecto.
func (o *Orchestrator) AddEndpointToProject(ctx context.Context, projectID int64, endpoint *domain.Endpoint) error {
	if err := o.endpointPort.Save(ctx, endpoint); err != nil {
		return err
	}
	return o.relationshipPort.LinkProjectToEndpoint(ctx, projectID, endpoint.EndpointID)
}

// AssociateHardwareToEndpoint guarda componentes de hardware y los enlaza a un endpoint.
func (o *Orchestrator) AssociateHardwareToEndpoint(ctx context.Context, endpointID int64, hardware *domain.Hardware) error {
	if err := o.hardwarePort.Save(ctx, hardware); err != nil {
		return err
	}
	return o.relationshipPort.LinkEndpointToHardware(ctx, endpointID, hardware.HardwareID)
}

// AssociateNetworkToEndpoint guarda un segmento de red y lo asocia a un endpoint.
func (o *Orchestrator) AssociateNetworkToEndpoint(ctx context.Context, endpointID int64, network *domain.Network) error {
	if err := o.networkPort.Save(ctx, network); err != nil {
		return err
	}
	return o.relationshipPort.LinkEndpointToNetwork(ctx, endpointID, network.NetworkID)
}

// RegisterSoftwareInstallation guarda la definición del software, la instancia instalada,
// asocia la instancia al endpoint y el software genérico a la instancia instalada.
func (o *Orchestrator) RegisterSoftwareInstallation(ctx context.Context, endpointID int64, software *domain.Software, installation *domain.SoftwareInstallation) error {
	if err := o.softwarePort.Save(ctx, software); err != nil {
		return err
	}
	if err := o.softwareInstPort.Save(ctx, installation); err != nil {
		return err
	}
	if err := o.relationshipPort.LinkEndpointToInstallation(ctx, endpointID, installation.InstallationID); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToSoftware(ctx, installation.InstallationID, software.SoftwareID)
}

// GenerateFinding registra un hallazgo de vulnerabilidad (Finding) a una instalación específica.
func (o *Orchestrator) GenerateFinding(ctx context.Context, installationID string, finding *domain.Finding) error {
	if err := o.findingPort.Save(ctx, finding); err != nil {
		return err
	}
	return o.relationshipPort.LinkInstallationToFinding(ctx, installationID, finding.FindingID)
}

// AssociateVulnerabilitiesAndRemediations guarda la vulnerabilidad (CVE), el parche o mitigación,
// y relaciona ambas partes al finding detectado.
func (o *Orchestrator) AssociateVulnerabilitiesAndRemediations(ctx context.Context, findingID int64, vuln *domain.Vulnerability, rem *domain.Remediation) error {
	if err := o.vulnPort.Save(ctx, vuln); err != nil {
		return err
	}
	if err := o.remediationPort.Save(ctx, rem); err != nil {
		return err
	}
	if err := o.relationshipPort.LinkFindingToVulnerability(ctx, findingID, vuln.CVEID); err != nil {
		return err
	}
	return o.relationshipPort.LinkFindingToRemediation(ctx, findingID, rem.RemediationID)
}

// GetInfrastructure recupera el grafo actual de infraestructura del usuario.
// Si la base de datos está vacía (0 nodos), automáticamente la inicializa con el escenario de prueba.
func (o *Orchestrator) GetInfrastructure(ctx context.Context) (*domain.GraphData, error) {
	graph, err := o.infraPort.GetGraphData(ctx)
	if err != nil {
		return nil, err
	}

	return graph, nil
}



// GetTopAPTs obtiene la lista rankeada de Actores de Amenaza (APT) que más TTPs comparten
// con las vulnerabilidades detectadas en la infraestructura del usuario.
func (o *Orchestrator) GetTopAPTs(ctx context.Context) ([]domain.APTThreatResult, error) {
	return o.infraPort.GetTopAPTsByInfrastructureTTPs(ctx, 10)
}


