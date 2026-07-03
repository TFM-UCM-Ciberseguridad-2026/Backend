package neo4j

import (
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// NewRepository es el constructor del adaptador Neo4j.
// Retorna las interfaces de todos los puertos definidos en el core para asegurar el cumplimiento del contrato hexagonal.
func NewRepository(driver neo4j.DriverWithContext) (
	ports.EndpointPort,
	ports.VulnerabilityPort,
	ports.SoftwarePort,
	ports.SoftwareInstallationPort,
	ports.FindingPort,
	ports.RemediationPort,
	ports.ExploitPort,
	ports.HardwarePort,
	ports.NetworkPort,
	ports.PatchPort,
	ports.ProjectPort,
	ports.DatabaseHelper,
	ports.RelationshipPort,
) {
	return &endpointRepo{driver: driver},
		&vulnerabilityRepo{driver: driver},
		&softwareRepo{driver: driver},
		&softwareInstallationRepo{driver: driver},
		&findingRepo{driver: driver},
		&remediationRepo{driver: driver},
		&exploitRepo{driver: driver},
		&hardwareRepo{driver: driver},
		&networkRepo{driver: driver},
		&patchRepo{driver: driver},
		&projectRepo{driver: driver},
		&endpointRepo{driver: driver}, // DatabaseHelper
		&relationshipRepo{driver: driver} // RelationshipPort
}
