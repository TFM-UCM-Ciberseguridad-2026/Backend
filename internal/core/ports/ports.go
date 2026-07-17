package ports

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

/*
Este archivo define los Puertos (Ports) de entrada y salida para los servicios de la aplicación (vulnerabilidades, exploits y persistencia).

Propósito arquitectónico y teórico:
1. Puertos en Arquitectura Hexagonal: Define las interfaces formales (contratos lógicos) Inbound (de entrada, como handlers o casos de uso) y Outbound (de salida, como repositorios o clientes de APIs externas) que describen qué operaciones ofrece o requiere el núcleo de la aplicación, sin implementar cómo se realizan.
2. Principio de Inversión de Dependencias (DIP): Asegura que el núcleo del negocio (service y domain) dependa de abstracciones de esta capa (ports) y no de detalles concretos de infraestructura de red, HTTP o bases de datos (adapters).
3. Testabilidad mediante Mocks: Permite sustituir en tiempo de pruebas unitarias los componentes de persistencia o APIs externas por implementaciones simuladas que cumplan las firmas de las interfaces.
*/

type EndpointPort interface {
	Save(ctx context.Context, endpoint *domain.Endpoint) error       // Guarda en la DB
	GetByID(ctx context.Context, id int64) (*domain.Endpoint, error) // Te da con el id el objeto recuperado de la bd
	DeleteByID(ctx context.Context, id int64) error                  // Borra un nodo de la BD
}

type VulnerabilityPort interface {
	Save(ctx context.Context, vuln *domain.Vulnerability) error
	GetByID(ctx context.Context, cveID string) (*domain.Vulnerability, error)
	DeleteByID(ctx context.Context, cveID string) error
}

type SoftwarePort interface {
	Save(ctx context.Context, software *domain.Software) error
	GetByID(ctx context.Context, id int64) (*domain.Software, error)
	DeleteByID(ctx context.Context, id int64) error
}

type FindingPort interface {
	Save(ctx context.Context, finding *domain.Finding) error
	GetByID(ctx context.Context, id int64) (*domain.Finding, error)
	DeleteByID(ctx context.Context, id int64) error
}

type RemediationPort interface {
	Save(ctx context.Context, remediation *domain.Remediation) error
	GetByID(ctx context.Context, id int64) (*domain.Remediation, error)
	DeleteByID(ctx context.Context, id int64) error
}

type ExploitPort interface {
	Save(ctx context.Context, exploit *domain.Exploit) error
	GetByID(ctx context.Context, id int64) (*domain.Exploit, error)
	DeleteByID(ctx context.Context, id int64) error
}

type HardwarePort interface {
	Save(ctx context.Context, hardware *domain.Hardware) error
	GetByID(ctx context.Context, id int64) (*domain.Hardware, error)
	DeleteByID(ctx context.Context, id int64) error
}

type NetworkPort interface {
	Save(ctx context.Context, network *domain.Network) error
	GetByID(ctx context.Context, id int64) (*domain.Network, error)
	DeleteByID(ctx context.Context, id int64) error
}

type PatchPort interface {
	Save(ctx context.Context, patch *domain.Patch) error
	GetByID(ctx context.Context, id int64) (*domain.Patch, error)
	DeleteByID(ctx context.Context, id int64) error
}

type ProjectPort interface {
	Save(ctx context.Context, project *domain.Project) error
	GetByID(ctx context.Context, id int64) (*domain.Project, error)
	DeleteByID(ctx context.Context, id int64) error
}

type SoftwareInstallationPort interface {
	Save(ctx context.Context, installation *domain.SoftwareInstallation) error
	GetByID(ctx context.Context, id string) (*domain.SoftwareInstallation, error)
	DeleteByID(ctx context.Context, id string) error
}

// RelationshipPort abstrae la creación de relaciones entre entidades del dominio
type RelationshipPort interface {
	LinkProjectToEndpoint(ctx context.Context, projectID int64, endpointID int64) error
	LinkEndpointToHardware(ctx context.Context, endpointID int64, hardwareID int64) error
	LinkEndpointToNetwork(ctx context.Context, endpointID int64, networkID int64) error
	LinkEndpointToInstallation(ctx context.Context, endpointID int64, installationID string) error
	LinkInstallationToSoftware(ctx context.Context, installationID string, softwareID int64) error
	LinkInstallationToFinding(ctx context.Context, installationID string, findingID int64) error
	LinkFindingToVulnerability(ctx context.Context, findingID int64, cveID string) error
	LinkFindingToExploit(ctx context.Context, findingID int64, exploitID int64) error
	LinkFindingToRemediation(ctx context.Context, findingID int64, remediationID int64) error
	LinkRemediationToPatch(ctx context.Context, remediationID int64, patchID int64) error
	LinkPatchToVulnerability(ctx context.Context, patchID int64, cveID string) error
}

// DatabaseHelper es un puerto genérico para ejecutar consultas Cypher (Neo4j) que no están
// estrictamente ligadas a un único dominio, permitiendo ingestas dinámicas o consultas puras.
type DatabaseHelper interface {
	ExecuteWrite(ctx context.Context, query string, params map[string]any) error
	ExecuteRead(ctx context.Context, query string, params map[string]any) (any, error)
	GetNodeInfo(ctx context.Context, label string, propertyKey string, propertyValue any) (map[string]any, error)
}

// VulnerabilityAPIscanner escanea vuln de la api del nist (puerto de salida)
type VulnerabilityAPIscanner interface {
	// FetchVulnerabilities obtiene una lista de vulnerabilidades desde el API externa.
	FetchVulnerabilities(ctx context.Context, limit int, offset int) ([]domain.Vulnerability, error)
	// FetchByCPE obtiene las vulnerabilidades asociadas a un CPE específico.
	FetchByCPE(ctx context.Context, cpe string) ([]domain.Vulnerability, error)
}

//Los CRUDS para el mitre... consutarlo con Julve

type TTPPort interface {
	Save(ctx context.Context, ttp *domain.TTP) error
	GetByID(ctx context.Context, id string) (*domain.TTP, error)
	DeleteByID(ctx context.Context, id string) error
	RelateToVulnerability(ctx context.Context, cveID string, ttpID string) error
}

type ThreatActorPort interface {
	Save(ctx context.Context, actor *domain.ThreatActor) error
	GetByID(ctx context.Context, id string) (*domain.ThreatActor, error)
	DeleteByID(ctx context.Context, id string) error
	RelateToTTP(ctx context.Context, actorID string, ttpID string) error
	GetTopThreatActors(ctx context.Context, limit int) ([]domain.ThreatActorThreat, error)
}

type InfrastructurePort interface {
	GetGraphData(ctx context.Context) (*domain.GraphData, error)
	GetTopAPTsByInfrastructureTTPs(ctx context.Context, limit int) ([]domain.APTThreatResult, error)
}

// EPSSProvider obtiene scores de probabilidad de explotación desde la API FIRST/EPSS.
type EPSSProvider interface {
	FetchEPSS(ctx context.Context, cveIDs []string) (map[string]float64, error)
}

// KEVProvider obtiene el catálogo CISA Known Exploited Vulnerabilities.
type KEVProvider interface {
	FetchKEV(ctx context.Context) (map[string]bool, error)
}

// RiskPort agrupa las queries Neo4j específicas del motor de riesgo.
// Se separa de los puertos CRUD para no contaminar el contrato base de cada entidad.
type RiskPort interface {
	// GetFindingContextsByEndpoint recorre Endpoint→Installation→Finding→Vulnerability
	// y devuelve todo lo necesario para calcular el riesgo de cada finding.
	GetFindingContextsByEndpoint(ctx context.Context, endpointID int64) ([]domain.FindingRiskContext, error)

	// UpdateFindingScores persiste los scores calculados en el nodo Finding.
	UpdateFindingScores(ctx context.Context, findingID int64, impactScore, likelihood, exposureFactor, remediationFactor, riskScore, assetCriticality, urgencyBoost, priorityScore float64) error
	// UpdateEndpointRisk persiste el riesgo agregado en el nodo Endpoint.
	UpdateEndpointRisk(ctx context.Context, endpointID int64, riskScore float64, riskTier string) error

	// GetAllEndpointIDs devuelve los IDs de todos los endpoints para el recálculo diario.
	GetAllEndpointIDs(ctx context.Context) ([]int64, error)
}
