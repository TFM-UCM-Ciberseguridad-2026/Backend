package domain

/*
Este archivo define la entidad de dominio para los Proyectos (Projects).

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Proyecto: Modela un proyecto organizativo o alcance de auditoría bajo el cual se agrupan los activos.
*/

// Project representa la entidad de dominio de un proyecto (nodo Project en Neo4j).
type Project struct {
	ProjectID int64  `json:"project_id"`
	Nombre    string `json:"nombre"`
}
