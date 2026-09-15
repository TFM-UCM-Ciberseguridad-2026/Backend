package neo4j

import "strings"

/*
Ámbito canónico de las vulnerabilidades de un proyecto.

Hasta ahora cada consulta traía su propia lista de rutas y no coincidían: el
barrido de TTPs recorría 3, la matriz y el ranking de APTs 7, y las estadísticas
otras 7 distintas. El barrido de un proyecto podía dejar sin procesar CVEs que
la matriz de ese mismo proyecto sí mostraba.

La lista es la UNIÓN de todas. Algunas rutas no las escribe hoy la aplicación
(Endpoint/Container-[:HAS_VULNERABILITY], el contenedor colgando directamente
del proyecto), pero ImportGraphData crea relaciones del tipo que traiga el
fichero, así que pueden aparecer en datos importados. Una ruta sin datos solo
cuesta un EXISTS que no encuentra nada.
*/

// rutasAmbitoProyecto enumera cómo llega un proyecto a una vulnerabilidad. Cada
// patrón empieza en (p) y termina en (v), sin etiqueta en p, para poder componerlo
// tanto en el sentido proyecto→CVE como en el inverso.
var rutasAmbitoProyecto = []string{
	`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`,
	`(p)-[:HAS_ENDPOINT]->(:Container)-[:HAS_VULNERABILITY]->(v)`,
}

// condicionIdentidadProyecto reconoce al proyecto con la misma tolerancia que ya
// aplicaban las consultas de lectura: id numérico, id textual o nombre.
const condicionIdentidadProyecto = `p.id = $project_id OR toString(p.id) = toString($project_id) OR p.name = toString($project_id)`

// vulnEnAmbitoDeProyecto es una condición booleana sobre `v` que se cumple si la
// vulnerabilidad pertenece al proyecto `$project_id` por cualquiera de las rutas.
// Va entre paréntesis para poder combinarla con OR/AND sin sorpresas de precedencia.
var vulnEnAmbitoDeProyecto = construirCondicionAmbito()

// queryProyectosDeVulnerabilidad devuelve los ids de los proyectos que contienen
// una CVE. Se ancla en la CVE (constraint única sobre cve_id) y recorre cada ruta
// hacia atrás, así que su coste depende de los hallazgos que apuntan a esa CVE y
// no del número de proyectos. Medido sobre la base real: 145 CVE en 5-14 ms en total.
var queryProyectosDeVulnerabilidad = construirQueryProyectosDeVulnerabilidad()

func conEtiquetaProyecto(ruta string) string {
	return "(p:Project)" + strings.TrimPrefix(ruta, "(p)")
}

func construirCondicionAmbito() string {
	partes := make([]string, 0, len(rutasAmbitoProyecto))
	for _, ruta := range rutasAmbitoProyecto {
		partes = append(partes, "EXISTS { MATCH "+conEtiquetaProyecto(ruta)+" WHERE "+condicionIdentidadProyecto+" }")
	}
	return "(\n\t\t  " + strings.Join(partes, " OR\n\t\t  ") + "\n\t\t)"
}

func construirQueryProyectosDeVulnerabilidad() string {
	ramas := make([]string, 0, len(rutasAmbitoProyecto))
	for _, ruta := range rutasAmbitoProyecto {
		ramas = append(ramas, "WITH v MATCH "+conEtiquetaProyecto(ruta)+" RETURN p")
	}
	return `
		MATCH (v:Vulnerability {cve_id: $cve_id})
		CALL {
			` + strings.Join(ramas, "\n\t\t\tUNION\n\t\t\t") + `
		}
		WITH DISTINCT p WHERE p.id IS NOT NULL
		RETURN collect(DISTINCT toInteger(p.id)) AS ids
	`
}
