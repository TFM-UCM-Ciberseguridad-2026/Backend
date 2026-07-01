package repository

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

/*
Este archivo gestiona el Adaptador de Salida (Outbound/Driven Adapter) para la persistencia de datos en Neo4j.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/adapters/repository`, actuando como el puente de infraestructura.
2. Conexión e Infraestructura de Persistencia: Inicializa y expone el driver oficial de Neo4j usando la configuración cargada del entorno.
3. Aislamiento de Persistencia: Mantiene los detalles del protocolo Bolt y las credenciales encapsulados en la capa de adaptadores.
*/

// NewNeo4jDriver crea y verifica una conexión a la base de datos Neo4j.
func NewNeo4jDriver(ctx context.Context, cfg *config.Config) (neo4j.DriverWithContext, error) {
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
