package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type hardwareRepo struct {
	driver neo4j.DriverWithContext
}

func (r *hardwareRepo) Save(ctx context.Context, h *domain.Hardware) error {
	query := `
		MERGE (n:Hardware {id: $id})
		ON CREATE SET n.model = $m,
		    n.type = $t,
		    n.manufacturer = $mf,
		    n.serial_number = $serial,
		    n.cpu = $cpu,
		    n.ram = $ram,
		    n.storage = $st
	`
	params := map[string]any{
		"id":     h.HardwareID,
		"m":      h.Model,
		"t":      h.Type,
		"mf":     h.Manufacturer,
		"serial": h.SerialNumber,
		"cpu":    h.CPU,
		"ram":    h.RAMGB,
		"st":     h.StorageGB,
	}
	return executeWriteSaveHelper(ctx, r.driver, query, params)
}

func (r *hardwareRepo) Update(ctx context.Context, h *domain.Hardware) error {
	query := `
		MATCH (n:Hardware {id: $id})
		SET n.model = $m,
		    n.type = $t,
		    n.manufacturer = $mf,
		    n.serial_number = $serial,
		    n.cpu = $cpu,
		    n.ram = $ram,
		    n.storage = $st
	`
	params := map[string]any{
		"id":     h.HardwareID,
		"m":      h.Model,
		"t":      h.Type,
		"mf":     h.Manufacturer,
		"serial": h.SerialNumber,
		"cpu":    h.CPU,
		"ram":    h.RAMGB,
		"st":     h.StorageGB,
	}
	return executeWriteUpdateHelper(ctx, r.driver, query, params)
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
		Type:         getString(props, "type"),
		Manufacturer: getString(props, "manufacturer"),
		SerialNumber: getString(props, "serial_number"),
		CPU:          getString(props, "cpu"),
		RAMGB:        int(getInt64(props, "ram")),
		StorageGB:    int(getInt64(props, "storage")),
	}, nil
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