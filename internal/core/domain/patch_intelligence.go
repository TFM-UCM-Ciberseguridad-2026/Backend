package domain

import "time"

/*
Este archivo define la entidad de dominio que transporta la información de remediación
obtenida de fuentes externas (OSV, MSRC, ...).
*/

// FixedVersion es una versión que corrige la vulnerabilidad, junto con el paquete al que
// aplica.
//
// El paquete es imprescindible: un mismo CVE puede corregirse en versiones distintas según
// el paquete afectado (Log4Shell se corrige en la 2.15.0 de log4j-core pero en la 1.9.2 de
// pax-logging-log4j2). Sin el paquete, comparar la versión instalada con la corregida daría
// resultados falsos.
type FixedVersion struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

// String representa la versión corregida en formato paquete@versión, o solo la versión
// cuando la fuente no informa del paquete.
func (f FixedVersion) String() string {
	if f.Package == "" {
		return f.Version
	}
	return f.Package + "@" + f.Version
}

// PatchIntelligence agrupa la información de remediación de un CVE recuperada de una
// fuente externa: los parches publicados y las versiones que corrigen la vulnerabilidad.
type PatchIntelligence struct {
	CVEID string `json:"cve_id"`

	// Patches son los parches publicados por el fabricante. La fuente los marca
	// explícitamente como correcciones (en OSV, referencias de tipo FIX).
	Patches []Patch `json:"patches"`

	// FixedVersions son las versiones que corrigen la vulnerabilidad. Un mismo CVE puede
	// tener varias si el proyecto mantiene ramas en paralelo (Log4Shell se corrige en
	// 2.3.1, 2.12.2 y 2.15.0, una por rama soportada) o si afecta a varios paquetes.
	FixedVersions []FixedVersion `json:"fixed_versions"`

	// Published es la fecha de publicación del aviso en la fuente. No es exactamente la
	// fecha de publicación del parche —ninguna fuente pública la expone de forma fiable—
	// pero es la mejor aproximación disponible y sirve como release_date de los parches.
	Published *time.Time `json:"published"`

	// Source identifica la fuente que produjo los datos (p. ej. "OSV").
	Source string `json:"source"`
}
