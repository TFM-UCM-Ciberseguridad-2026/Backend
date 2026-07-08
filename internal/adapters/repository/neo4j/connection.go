package neo4j

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

/*
Este archivo gestiona el ciclo de vida de la conexión a la base de datos de grafos Neo4j.
*/

// NewDriver crea y verifica una conexión a la base de datos Neo4j.
func NewDriver(ctx context.Context, cfg *config.Config) (neo4j.DriverWithContext, error) {
	// Crear el driver con autenticación básica
	driver, err := neo4j.NewDriverWithContext(
		cfg.Neo4jURI,
		neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""),
	)
	if err != nil {
		return nil, err
	}

	// Verificar la conectividad antes de devolver el driver (ping)
	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		return nil, err
	}

	return driver, nil
}
