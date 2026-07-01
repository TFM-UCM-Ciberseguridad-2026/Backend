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
}
