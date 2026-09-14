package neo4j

import (
	"context"
	"errors"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// schemaConstraints son las constraints de unicidad de las que depende la identidad de los
// nodos. Sin ellas, un MERGE que coincide con varios nodos (o dos MERGE concurrentes)
// duplicaba o fusionaba nodos distintos, y la importación de grafos mezclaba hallazgos,
// activos y catálogos entre sí.
var schemaConstraints = []struct {
	name      string
	statement string
}{
	// Un Finding es "un CVE en un activo": su identidad es finding_key y su id es la
	// referencia que usa la API.
	{"finding_key_unique", `CREATE CONSTRAINT finding_key_unique IF NOT EXISTS FOR (n:Finding) REQUIRE n.finding_key IS UNIQUE`},
	{"finding_id_unique", `CREATE CONSTRAINT finding_id_unique IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE`},

	// Catálogos compartidos entre proyectos, identificados por su clave pública.
	{"vulnerability_cve_id_unique", `CREATE CONSTRAINT vulnerability_cve_id_unique IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE`},
	{"ttp_ttp_id_unique", `CREATE CONSTRAINT ttp_ttp_id_unique IF NOT EXISTS FOR (n:TTP) REQUIRE n.ttp_id IS UNIQUE`},
	{"cwe_cwe_id_unique", `CREATE CONSTRAINT cwe_cwe_id_unique IF NOT EXISTS FOR (n:CWE) REQUIRE n.cwe_id IS UNIQUE`},
	{"capec_capec_id_unique", `CREATE CONSTRAINT capec_capec_id_unique IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.capec_id IS UNIQUE`},
	{"threat_actor_actor_id_unique", `CREATE CONSTRAINT threat_actor_actor_id_unique IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.actor_id IS UNIQUE`},

	// Software: el CPE es su clave natural (los vacíos se guardan como nulo).
	{"software_cpe_unique", `CREATE CONSTRAINT software_cpe_unique IF NOT EXISTS FOR (n:Software) REQUIRE n.cpe IS UNIQUE`},

	// Activos de proyecto sin clave natural: su id lo genera la aplicación y no puede
	// repetirse, porque las relaciones y la API los resuelven por id.
	{"project_id_unique", `CREATE CONSTRAINT project_id_unique IF NOT EXISTS FOR (n:Project) REQUIRE n.id IS UNIQUE`},
	{"endpoint_id_unique", `CREATE CONSTRAINT endpoint_id_unique IF NOT EXISTS FOR (n:Endpoint) REQUIRE n.id IS UNIQUE`},
	{"container_id_unique", `CREATE CONSTRAINT container_id_unique IF NOT EXISTS FOR (n:Container) REQUIRE n.id IS UNIQUE`},
	{"software_installation_id_unique", `CREATE CONSTRAINT software_installation_id_unique IF NOT EXISTS FOR (n:SoftwareInstallation) REQUIRE n.id IS UNIQUE`},
	{"hardware_id_unique", `CREATE CONSTRAINT hardware_id_unique IF NOT EXISTS FOR (n:Hardware) REQUIRE n.id IS UNIQUE`},
}

// EnsureSchema crea las constraints de unicidad que falten.
//
// Cada constraint se intenta por separado: si la base contiene duplicados de un tipo, esa
// creación falla pero no impide crear las demás. Se devuelven todos los errores juntos para
// que el arranque los registre sin tumbar el servicio.
func EnsureSchema(ctx context.Context, driver neo4j.DriverWithContext) error {
	var errs []error
	for _, constraint := range schemaConstraints {
		if err := executeWriteHelper(ctx, driver, constraint.statement, nil); err != nil {
			errs = append(errs, fmt.Errorf("constraint %s: %w", constraint.name, err))
		}
	}
	return errors.Join(errs...)
}
