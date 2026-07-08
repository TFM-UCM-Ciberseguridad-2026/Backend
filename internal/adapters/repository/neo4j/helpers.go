package neo4j

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// executeWriteHelper ejecuta una consulta Cypher de escritura en una sesión write temporal.
func executeWriteHelper(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]any) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})
	return err
}

// executeReadHelper ejecuta una consulta Cypher de lectura y devuelve las propiedades del nodo ("props").
func executeReadHelper(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]any) (map[string]any, error) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			record := res.Record().AsMap()
			if props, ok := record["props"].(map[string]any); ok {
				return props, nil
			}
		}
		return nil, nil
	})
	if err != nil || result == nil {
		return nil, err
	}
	return result.(map[string]any), nil
}

// Helpers de conversión de tipos seguros para Neo4j
func getString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func getInt64(m map[string]any, k string) int64 {
	if v, ok := m[k].(int64); ok {
		return v
	}
	return 0
}

func getFloat64(m map[string]any, k string) float64 {
	if v, ok := m[k].(float64); ok {
		return v
	}
	return 0.0
}

func getBool(m map[string]any, k string) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return false
}

func getTime(m map[string]any, k string) time.Time {
	if v, ok := m[k].(time.Time); ok {
		return v
	}
	return time.Time{}
}

func getTimePtr(m map[string]any, k string) *time.Time {
	if v, ok := m[k].(time.Time); ok {
		return &v
	}
	return nil
}
