package neo4j

import (
	"strings"
	"testing"
)

// Rutas que usaba cada consulta antes de unificar el ámbito. La lista canónica
// debe contenerlas todas: si alguna se cae, la consulta de origen dejaría de ver
// CVEs que antes veía.
var rutasPrevias = map[string][]string{
	"barrido (GetUnmappedVulnerabilities)": {
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
	},
	"matriz y ranking de APTs": {
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`,
	},
	"estadísticas (GetTTPStats)": {
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:HAS_INSTALLATION]->(:SoftwareInstallation)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_FINDING]->(:Finding)-[:OF_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Container)-[:HAS_VULNERABILITY]->(v)`,
		`(p)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`,
	},
}

// Rutas que usaban las consultas previas y se retiraron a propósito: HAS_VULNERABILITY de
// una imagen es resultado del escaneo, no un hallazgo, y una imagen compartida con otro
// proyecto metía por aquí CVE sin finding.
var rutasRetiradas = map[string]bool{
	`(p)-[:HAS_ENDPOINT]->(:Endpoint)-[:HOSTS]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`: true,
	`(p)-[:HAS_ENDPOINT]->(:Container)-[:USES_IMAGE]->(:ContainerImage)-[:HAS_VULNERABILITY]->(v)`:                       true,
}

func TestAmbitoCanonicoContieneLasRutasDeTodasLasConsultas(t *testing.T) {
	canonicas := make(map[string]bool, len(rutasAmbitoProyecto))
	for _, r := range rutasAmbitoProyecto {
		if canonicas[r] {
			t.Errorf("ruta duplicada en el ámbito canónico: %s", r)
		}
		canonicas[r] = true
	}

	union := map[string]bool{}
	for consulta, rutas := range rutasPrevias {
		for _, r := range rutas {
			if rutasRetiradas[r] {
				continue
			}
			union[r] = true
			if !canonicas[r] {
				t.Errorf("la ruta de %s no está en el ámbito canónico: %s", consulta, r)
			}
		}
	}
	// Tampoco debe haber rutas que no usara ninguna consulta: el ámbito es la
	// unión, no una ampliación.
	if len(union) != len(canonicas) {
		t.Errorf("el ámbito canónico tiene %d rutas y la unión de las previas %d", len(canonicas), len(union))
	}
}

func TestAmbitoNoTomaCVEDeImagenSinFinding(t *testing.T) {
	for _, r := range rutasAmbitoProyecto {
		if rutasRetiradas[r] || strings.Contains(r, "(:ContainerImage)-[:HAS_VULNERABILITY]") {
			t.Errorf("el ámbito no debe tomar CVE de una imagen sin finding: %s", r)
		}
	}
}

func TestRutasAmbitoVanDeProyectoAVulnerabilidad(t *testing.T) {
	for _, r := range rutasAmbitoProyecto {
		if !strings.HasPrefix(r, "(p)-[:HAS_ENDPOINT]->") || !strings.HasSuffix(r, "->(v)") {
			t.Errorf("ruta mal formada (debe ir de (p) a (v)): %s", r)
		}
	}
}

func TestCondicionAmbitoUnExistsPorRuta(t *testing.T) {
	c := vulnEnAmbitoDeProyecto
	if got := strings.Count(c, "EXISTS {"); got != len(rutasAmbitoProyecto) {
		t.Errorf("EXISTS en la condición: %d, rutas: %d", got, len(rutasAmbitoProyecto))
	}
	if got := strings.Count(c, condicionIdentidadProyecto); got != len(rutasAmbitoProyecto) {
		t.Errorf("cada EXISTS debe filtrar por el proyecto: %d de %d", got, len(rutasAmbitoProyecto))
	}
	if strings.Count(c, "{") != strings.Count(c, "}") || strings.Count(c, "(") != strings.Count(c, ")") {
		t.Errorf("llaves o paréntesis desequilibrados en la condición:\n%s", c)
	}
	if !strings.HasPrefix(c, "(") || !strings.HasSuffix(c, ")") {
		t.Errorf("la condición debe ir entre paréntesis para combinarse con OR/AND")
	}
}

func TestQueryProyectosDeVulnerabilidadAnclaEnLaCVE(t *testing.T) {
	q := queryProyectosDeVulnerabilidad
	if !strings.Contains(q, "MATCH (v:Vulnerability {cve_id: $cve_id})") {
		t.Errorf("la consulta inversa debe anclarse en la CVE por cve_id")
	}
	if got := strings.Count(q, "UNION"); got != len(rutasAmbitoProyecto)-1 {
		t.Errorf("ramas UNION: %d, esperadas %d", got, len(rutasAmbitoProyecto)-1)
	}
	for _, r := range rutasAmbitoProyecto {
		if !strings.Contains(q, conEtiquetaProyecto(r)) {
			t.Errorf("falta la ruta en la consulta inversa: %s", r)
		}
	}
}
