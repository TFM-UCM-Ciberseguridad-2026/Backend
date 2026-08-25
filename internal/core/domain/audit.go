package domain

import "time"

// AuditChange registra el estado anterior y posterior de un campo modificado.
type AuditChange struct {
	Antes   any `json:"antes,omitempty"`
	Despues any `json:"despues,omitempty"`
}

// AuditAction describe la operación y el activo sobre el que recae.
type AuditAction struct {
	Tipo         string `json:"tipo"`                    // "CREACION", "MODIFICACION", "ELIMINACION"
	TipoActivo   string `json:"tipo_activo"`             // "Endpoint", "Network", "Container", etc.
	IDActivo     string `json:"id_activo"`
	NombreActivo string `json:"nombre_activo,omitempty"`
	ProyectoID   string `json:"proyecto_id,omitempty"`
}

// AuditLogEntry es la estructura canónica que se emite en una sola línea JSON por stdout.
type AuditLogEntry struct {
	FechaHora         time.Time               `json:"fecha_hora"`
	Nivel             string                  `json:"nivel"` // "AUDIT"
	Accion            AuditAction             `json:"accion"`
	Justificacion     string                  `json:"justificacion,omitempty"`
	CambiosRealizados map[string]AuditChange `json:"cambios_realizados,omitempty"`
	Estado            string                  `json:"estado"` // "SUCCESS" | "ERROR"
	DetallesError     string                  `json:"detalles_error,omitempty"`
}