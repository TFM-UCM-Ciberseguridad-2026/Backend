package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type hardwareRepo struct {
	driver neo4j.DriverWithContext
}

// hardwareParams construye los parámetros comunes de Save y Update.
//
// La arquitectura se guarda en `architecture` y los núcleos en `cpu_cores`. Las propiedades
// antiguas `type` y `cpu` guardaban otra cosa (rol y texto libre), así que se dejan de
// escribir en vez de reinterpretarlas en la base: la lectura las traduce si hacen falta.
func hardwareParams(h *domain.Hardware) map[string]any {
	return map[string]any{
		"id":     h.HardwareID,
		"m":      h.Model,
		"arch":   h.Architecture,
		"mf":     h.Manufacturer,
		"serial": h.SerialNumber,
		"cores":  h.CPUCores,
		"ram":    h.RAMGB,
		"st":     h.StorageGB,
	}
}

func (r *hardwareRepo) Save(ctx context.Context, h *domain.Hardware) error {
	query := `
		MERGE (n:Hardware {id: $id})
		ON CREATE SET n.model = $m,
		    n.architecture = $arch,
		    n.manufacturer = $mf,
		    n.serial_number = $serial,
		    n.cpu_cores = $cores,
		    n.ram = $ram,
		    n.storage = $st
	`
	return executeWriteSaveHelper(ctx, r.driver, query, hardwareParams(h))
}

func (r *hardwareRepo) Update(ctx context.Context, h *domain.Hardware) error {
	// Los campos de texto que llegan vacíos conservan el valor previo. El modal de edición
	// no siempre envía todos (durante mucho tiempo no incluyó el número de serie) y un SET
	// incondicional borraba el dato sin dejar rastro en la auditoría.
	query := `
		MATCH (n:Hardware {id: $id})
		SET n.model = CASE WHEN $m = '' THEN n.model ELSE $m END,
		    n.architecture = CASE WHEN $arch = '' THEN n.architecture ELSE $arch END,
		    n.manufacturer = CASE WHEN $mf = '' THEN n.manufacturer ELSE $mf END,
		    n.serial_number = CASE WHEN $serial = '' THEN n.serial_number ELSE $serial END,
		    n.cpu_cores = CASE WHEN $cores = 0 THEN n.cpu_cores ELSE $cores END,
		    n.ram = CASE WHEN $ram = 0 THEN n.ram ELSE $ram END,
		    n.storage = CASE WHEN $st = 0 THEN n.storage ELSE $st END
	`
	return executeWriteUpdateHelper(ctx, r.driver, query, hardwareParams(h))
}

func (r *hardwareRepo) GetByID(ctx context.Context, id int64) (*domain.Hardware, error) {
	query := `MATCH (n:Hardware {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil {
		return nil, err
	}
	return &domain.Hardware{
		HardwareID:   getInt64(props, "id"),
		Model:        getString(props, "model"),
		Architecture: hardwareArchitecture(props),
		Manufacturer: getString(props, "manufacturer"),
		SerialNumber: getString(props, "serial_number"),
		CPUCores:     hardwareCPUCores(props),
		RAMGB:        int(getInt64(props, "ram")),
		StorageGB:    int(getInt64(props, "storage")),
	}, nil
}

// hardwareCPUCores lee los núcleos tolerando el formato antiguo: antes se guardaban como
// texto en `cpu` ("4 vCPU"). Si no se puede deducir un número se devuelve 0, que significa
// "sin dato": preferimos dejarlo vacío a inventar un valor.
func hardwareCPUCores(props map[string]any) int {
	if cores := int(getInt64(props, "cpu_cores")); cores > 0 {
		return cores
	}
	return domain.LegacyCPUCores(getString(props, "cpu"))
}

// hardwareArchitecture lee la arquitectura tolerando la propiedad antigua `type`, que
// mezclaba arquitecturas ("x86_64") con roles ("virtual-server"). Solo se acepta si
// pertenece al vocabulario actual; el resto queda vacío para que se corrija a mano.
func hardwareArchitecture(props map[string]any) string {
	if arch := getString(props, "architecture"); arch != "" {
		return arch
	}
	if legacy := getString(props, "type"); domain.IsValidArchitecture(legacy) {
		return legacy
	}
	return ""
}

func (r *hardwareRepo) DeleteByID(ctx context.Context, id int64) error {
	query := `
		MATCH (n:Hardware)
		WHERE toString(n.id) = toString($id) OR elementId(n) = toString($id)
		DETACH DELETE n
	`
	_ = executeWriteHelper(ctx, r.driver, query, map[string]any{"id": id})

	cleanupQuery := `
		MATCH (n)
		WHERE (n:Software OR n:Network OR n:Hardware OR n:IPAddress OR n:SoftwareInstallation OR n:Finding OR n:Remediation OR n:Exploit OR n:Patch OR n:Container OR n:ContainerImage OR n:Vulnerability)
		  AND NOT EXISTS((n)-[*1..5]-(:Endpoint)) AND NOT EXISTS((n)-[*1..5]-(:Project))
		DETACH DELETE n
	`
	return executeWriteHelper(ctx, r.driver, cleanupQuery, nil)
}
