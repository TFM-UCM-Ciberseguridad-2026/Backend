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

type EndpointPort interface { // funcionalidades para guardar un endpoint en la bd (es solo un boceto)
	Save(endpoint *domain.Endpoint) error        // Guarda en la DB
	GetByID(id string) (*domain.Endpoint, error) // Te da con el id el objeto recuperado de la bd
}

type VulnerabilityAPIscanner interface { // escanea vuln de la api del nist (puerto de salida)
	// FetchVulnerabilities obtiene una lista de vulnerabilidades desde el API externa.
	FetchVulnerabilities(ctx context.Context, limit int, offset int) ([]domain.Vulnerability, error)
}
