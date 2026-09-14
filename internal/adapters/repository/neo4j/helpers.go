package neo4j

import (
	"context"
	"strings"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
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

// executeWriteSaveHelper ejecuta una consulta Cypher de creación/actualización con MERGE.
func executeWriteSaveHelper(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]any) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		_, err = res.Consume(ctx)
		return nil, err
	})
	return err
}

// executeWriteUpdateHelper ejecuta una consulta Cypher de actualización y devuelve error si el nodo no existe.
func executeWriteUpdateHelper(ctx context.Context, driver neo4j.DriverWithContext, query string, params map[string]any) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Añadimos RETURN 1 para forzar que res.Next() sea true si hizo match con algún nodo.
		res, err := tx.Run(ctx, query+"\nRETURN 1", params)
		if err != nil {
			return nil, err
		}
		if !res.Next(ctx) {
			return nil, domain.ErrNodeNotFound
		}
		return nil, nil
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

func getStringSlice(m map[string]any, k string) []string {
	if v, ok := m[k].([]any); ok {
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		if res != nil {
			return res
		}
	}
	if v, ok := m[k].([]string); ok {
		return v
	}
	if v, ok := m[k].(string); ok && v != "" && v != "N/A" {
		parts := strings.Split(v, ",")
		var res []string
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				res = append(res, trimmed)
			}
		}
		return res
	}
	return []string{}
}

func getInt64(m map[string]any, k string) int64 {
	if v, ok := m[k].(int64); ok {
		return v
	}
	return 0
}

func getFloat64(m map[string]any, key string) float64 {
        switch value := m[key].(type) {
        case float64:
                return value
        case float32:
                return float64(value)
        case int:
                return float64(value)
        case int32:
                return float64(value)
        case int64:
                return float64(value)
        default:
                return 0.0
        }
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

func timePtrValue(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
