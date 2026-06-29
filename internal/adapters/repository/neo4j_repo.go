package repository

import (
	"context"
	"fmt"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

/*
Este archivo implementa el Adaptador de Repositorio (Driven Adapter) para Neo4j.

Propósito arquitectónico y teórico:
1. Implementación de Puertos: Satisface la interfaz EndpointPort y DatabaseHelper definida en core/ports.
2. Inversión de Dependencias: Permite que la capa de Dominio y Casos de Uso guarden y consulten nodos sin conocer Cypher ni la librería de Neo4j.
3. Consultas Genéricas vs Específicas: Ofrece métodos fuertemente tipados (SaveEndpoint) y métodos genéricos (ExecuteWrite) para dar flexibilidad en la ingesta.
*/

type neo4jRepo struct {
	driver neo4j.DriverWithContext
}

// NewNeo4jRepository es el constructor del adaptador Neo4j
// Retorna las interfaces de todos los puertos para asegurar que cumple los contratos.
func NewNeo4jRepository(driver neo4j.DriverWithContext) (
	ports.EndpointPort,
	ports.VulnerabilityPort,
	ports.SoftwarePort,
	ports.FindingPort,
	ports.RemediationPort,
	ports.ExploitPort,
	ports.HardwarePort,
	ports.NetworkPort,
	ports.PatchPort,
	ports.ProjectPort,
	ports.DatabaseHelper,
) {
	return &neo4jRepo{driver: driver},
		&neo4jVulnRepo{driver: driver},
		&neo4jSoftwareRepo{driver: driver},
		&neo4jFindingRepo{driver: driver},
		&neo4jRemediationRepo{driver: driver},
		&neo4jExploitRepo{driver: driver},
		&neo4jHardwareRepo{driver: driver},
		&neo4jNetworkRepo{driver: driver},
		&neo4jPatchRepo{driver: driver},
		&neo4jProjectRepo{driver: driver},
		&neo4jRepo{driver: driver} // DatabaseHelper
}

// ==========================================
// IMPLEMENTACIÓN DE EndpointPort
// ==========================================

// Save persiste un Endpoint en la base de datos de grafos Neo4j.
func (r *neo4jRepo) Save(ctx context.Context, endpoint *domain.Endpoint) error {
	query := `
		MERGE (e:Endpoint {id: $id})
		SET e.hostname = $hostname,
		    e.type = $type,
		    e.internet_exposed = $internet_exposed,
		    e.updated_at = timestamp()
	`
	params := map[string]any{
		"id":               endpoint.EndpointID,
		"hostname":         endpoint.Hostname,
		"type":             endpoint.Type,
		"internet_exposed": endpoint.InternetExposed,
	}

	return r.ExecuteWrite(ctx, query, params)
}

// GetByID recupera un Endpoint de Neo4j por su ID.
func (r *neo4jRepo) GetByID(ctx context.Context, id int64) (*domain.Endpoint, error) {
	query := `
		MATCH (e:Endpoint {id: $id})
		RETURN e.id AS id, e.hostname AS hostname, e.type AS type, e.internet_exposed AS internet_exposed
	`
	params := map[string]any{"id": id}

	res, err := r.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, nil // No encontrado
	}

	// Mapeo básico desde el mapa devuelto por ExecuteRead
	record := res.(map[string]any)
	endpoint := &domain.Endpoint{
		EndpointID:      record["id"].(int64),
		Hostname:        record["hostname"].(string),
		Type:            record["type"].(string),
		InternetExposed: record["internet_exposed"].(bool),
	}

	return endpoint, nil
}

// ==========================================
// IMPLEMENTACIÓN DE VulnerabilityPort
// ==========================================

type neo4jVulnRepo struct {
	driver neo4j.DriverWithContext
}

// Save persiste una Vulnerabilidad en la base de datos de grafos Neo4j.
func (r *neo4jVulnRepo) Save(ctx context.Context, vuln *domain.Vulnerability) error {
	query := `
		MERGE (v:Vulnerability {cve_id: $cve})
		SET v.description = $desc,
		    v.base_score = $score,
		    v.updated_at = timestamp()
	`
	params := map[string]any{
		"cve":   vuln.CVEID,
		"desc":  vuln.Description,
		"score": vuln.BaseScore,
	}

	// We can use a temporary helper instance or just re-implement ExecuteWrite
	// Better to use the same logic
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// GetByID recupera una Vulnerabilidad de Neo4j por su CVEID.
func (r *neo4jVulnRepo) GetByID(ctx context.Context, cveID string) (*domain.Vulnerability, error) {
	query := `
		MATCH (v:Vulnerability {cve_id: $cve})
		RETURN v.cve_id AS cve, v.description AS desc, v.base_score AS score
	`
	params := map[string]any{"cve": cveID}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		if res.Next(ctx) {
			return res.Record().AsMap(), nil
		}
		return nil, nil // No se encontraron registros
	})

	if err != nil || result == nil {
		return nil, err
	}

	record := result.(map[string]any)
	score, _ := record["score"].(float64)

	vuln := &domain.Vulnerability{
		CVEID:       record["cve"].(string),
		Description: record["desc"].(string),
		BaseScore:   score,
	}

	return vuln, nil
}

// ==========================================
// IMPLEMENTACIÓN DE SoftwarePort
// ==========================================
type neo4jSoftwareRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jSoftwareRepo) Save(ctx context.Context, s *domain.Software) error {
	query := `
		MERGE (n:Software {id: $id})
		SET n.name = $name, n.version = $version, n.type = $type, n.cpe = $cpe, n.purl = $purl, n.vendor = $vendor
	`
	params := map[string]any{"id": s.SoftwareID, "name": s.Name, "version": s.Version, "type": s.Type, "cpe": s.CPE, "purl": s.PURL, "vendor": s.Vendor}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jSoftwareRepo) GetByID(ctx context.Context, id int64) (*domain.Software, error) {
	query := `MATCH (n:Software {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Software{
		SoftwareID: getInt64(props, "id"), Name: getString(props, "name"), Version: getString(props, "version"),
		Type: getString(props, "type"), CPE: getString(props, "cpe"), PURL: getString(props, "purl"), Vendor: getString(props, "vendor"),
	}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE FindingPort
// ==========================================
type neo4jFindingRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jFindingRepo) Save(ctx context.Context, f *domain.Finding) error {
	query := `MERGE (n:Finding {id: $id}) SET n.risk_score = $risk, n.status = $status`
	params := map[string]any{"id": f.FindingID, "risk": f.RiskScore, "status": f.Status}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jFindingRepo) GetByID(ctx context.Context, id int64) (*domain.Finding, error) {
	query := `MATCH (n:Finding {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Finding{FindingID: getInt64(props, "id"), RiskScore: getFloat64(props, "risk_score"), Status: getString(props, "status")}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE RemediationPort
// ==========================================
type neo4jRemediationRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jRemediationRepo) Save(ctx context.Context, rem *domain.Remediation) error {
	query := `MERGE (n:Remediation {id: $id}) SET n.fixed_version = $fv, n.status = $status`
	params := map[string]any{"id": rem.RemediationID, "fv": rem.FixedVersion, "status": rem.Status}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jRemediationRepo) GetByID(ctx context.Context, id int64) (*domain.Remediation, error) {
	query := `MATCH (n:Remediation {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Remediation{RemediationID: getInt64(props, "id"), FixedVersion: getString(props, "fixed_version"), Status: getString(props, "status")}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE ExploitPort
// ==========================================
type neo4jExploitRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jExploitRepo) Save(ctx context.Context, e *domain.Exploit) error {
	query := `MERGE (n:Exploit {id: $id}) SET n.required_privilege = $rp, n.privilege_granted = $pg, n.technique = $t`
	params := map[string]any{"id": e.ExploitID, "rp": e.RequiredPrivilege, "pg": e.PrivilegeGranted, "t": e.Technique}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jExploitRepo) GetByID(ctx context.Context, id int64) (*domain.Exploit, error) {
	query := `MATCH (n:Exploit {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Exploit{ExploitID: getInt64(props, "id"), RequiredPrivilege: getString(props, "required_privilege"), PrivilegeGranted: getString(props, "privilege_granted"), Technique: getString(props, "technique")}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE HardwarePort
// ==========================================
type neo4jHardwareRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jHardwareRepo) Save(ctx context.Context, h *domain.Hardware) error {
	query := `MERGE (n:Hardware {id: $id}) SET n.model = $m, n.type = $t, n.manufacturer = $mf, n.cpu = $cpu, n.ram = $ram, n.storage = $st`
	params := map[string]any{"id": h.HardwareID, "m": h.Model, "t": h.Type, "mf": h.Manufacturer, "cpu": h.CPU, "ram": h.RAMGB, "st": h.StorageGB}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jHardwareRepo) GetByID(ctx context.Context, id int64) (*domain.Hardware, error) {
	query := `MATCH (n:Hardware {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Hardware{HardwareID: getInt64(props, "id"), Model: getString(props, "model"), Type: getString(props, "type"), Manufacturer: getString(props, "manufacturer"), CPU: getString(props, "cpu"), RAMGB: int(getInt64(props, "ram")), StorageGB: int(getInt64(props, "storage"))}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE NetworkPort
// ==========================================
type neo4jNetworkRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jNetworkRepo) Save(ctx context.Context, nw *domain.Network) error {
	query := `MERGE (n:Network {id: $id}) SET n.nombre = $name, n.cidr = $cidr, n.gateway = $gw, n.vlan_id = $vlan`
	params := map[string]any{"id": nw.NetworkID, "name": nw.Nombre, "cidr": nw.CIDR, "gw": nw.Gateway, "vlan": nw.VLANID}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jNetworkRepo) GetByID(ctx context.Context, id int64) (*domain.Network, error) {
	query := `MATCH (n:Network {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Network{NetworkID: getInt64(props, "id"), Nombre: getString(props, "nombre"), CIDR: getString(props, "cidr"), Gateway: getString(props, "gateway"), VLANID: getInt64(props, "vlan_id")}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE PatchPort
// ==========================================
type neo4jPatchRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jPatchRepo) Save(ctx context.Context, p *domain.Patch) error {
	query := `MERGE (n:Patch {id: $id}) SET n.description = $desc, n.url = $url`
	params := map[string]any{"id": p.PatchID, "desc": p.Description, "url": p.URL}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jPatchRepo) GetByID(ctx context.Context, id int64) (*domain.Patch, error) {
	query := `MATCH (n:Patch {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Patch{PatchID: getInt64(props, "id"), Description: getString(props, "description"), URL: getString(props, "url")}, nil
}

// ==========================================
// IMPLEMENTACIÓN DE ProjectPort
// ==========================================
type neo4jProjectRepo struct{ driver neo4j.DriverWithContext }

func (r *neo4jProjectRepo) Save(ctx context.Context, p *domain.Project) error {
	query := `MERGE (n:Project {id: $id}) SET n.nombre = $name`
	params := map[string]any{"id": p.ProjectID, "name": p.Nombre}
	return executeWriteHelper(ctx, r.driver, query, params)
}

func (r *neo4jProjectRepo) GetByID(ctx context.Context, id int64) (*domain.Project, error) {
	query := `MATCH (n:Project {id: $id}) RETURN properties(n) AS props`
	props, err := executeReadHelper(ctx, r.driver, query, map[string]any{"id": id})
	if err != nil || props == nil { return nil, err }
	return &domain.Project{ProjectID: getInt64(props, "id"), Nombre: getString(props, "nombre")}, nil
}

// ==========================================
// HELPERS INTERNOS PARA REDUCIR DUPLICACIÓN
// ==========================================

func executeWriteHelper(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]any) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})
	return err
}

func executeReadHelper(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]any) (map[string]any, error) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil { return nil, err }
		if res.Next(ctx) {
			record := res.Record().AsMap()
			if props, ok := record["props"].(map[string]any); ok { return props, nil }
		}
		return nil, nil
	})
	if err != nil || result == nil { return nil, err }
	return result.(map[string]any), nil
}

func getString(m map[string]any, k string) string { if v, ok := m[k].(string); ok { return v }; return "" }
func getInt64(m map[string]any, k string) int64 { if v, ok := m[k].(int64); ok { return v }; return 0 }
func getFloat64(m map[string]any, k string) float64 { if v, ok := m[k].(float64); ok { return v }; return 0.0 }

// ==========================================
// IMPLEMENTACIÓN DE DatabaseHelper (Genérico)
// ==========================================

// ExecuteWrite ejecuta una consulta Cypher de escritura (CREATE, MERGE, SET, DELETE)
func (r *neo4jRepo) ExecuteWrite(ctx context.Context, query string, params map[string]any) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// ExecuteRead ejecuta una consulta Cypher de lectura (MATCH, RETURN) y devuelve el primer registro como un mapa.
// Nota: Para TFM, esta es una implementación simplificada. Para múltiples registros, habría que devolver un slice.
func (r *neo4jRepo) ExecuteRead(ctx context.Context, query string, params map[string]any) (any, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		if res.Next(ctx) {
			return res.Record().AsMap(), nil
		}
		return nil, nil // No se encontraron registros
	})

	return result, err
}

// GetNodeInfo es un helper dinámico para obtener las propiedades de cualquier nodo dado su Label y un filtro.
// NOTA IMPORTANTE: Para evitar inyección Cypher, los Labels y PropertyKeys no se pueden parametrizar en Neo4j,
// por lo que deben inyectarse mediante fmt.Sprintf. Asegúrate de sanear 'label' y 'propertyKey' si vienen del usuario.
func (r *neo4jRepo) GetNodeInfo(ctx context.Context, label string, propertyKey string, propertyValue any) (map[string]any, error) {
	// Construimos la query dinámica segura (las variables de propiedad SÍ van parametrizadas)
	query := fmt.Sprintf("MATCH (n:%s { %s: $val }) RETURN properties(n) AS props", label, propertyKey)
	params := map[string]any{"val": propertyValue}

	res, err := r.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, nil // No encontrado
	}

	// Neo4j devuelve 'properties(n)' como un mapa
	record := res.(map[string]any)
	props := record["props"].(map[string]any)

	return props, nil
}
