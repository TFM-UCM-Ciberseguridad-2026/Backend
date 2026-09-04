package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type auditChange struct {
	Antes   any `json:"antes,omitempty"`
	Despues any `json:"despues,omitempty"`
}

type auditAction struct {
	Tipo         string `json:"tipo"`
	TipoActivo   string `json:"tipo_activo"`
	IDActivo     string `json:"id_activo"`
	NombreActivo string `json:"nombre_activo,omitempty"`
	ProyectoID   string `json:"proyecto_id,omitempty"`
}

type auditLogEntry struct {
	FechaHora         string                 `json:"fecha_hora"`
	Nivel             string                 `json:"nivel"`
	Accion            auditAction            `json:"accion"`
	Justificacion     string                 `json:"justificacion,omitempty"`
	CambiosRealizados map[string]auditChange `json:"cambios_realizados,omitempty"`
	Estado            string                 `json:"estado"`
	DetallesError     string                 `json:"detalles_error,omitempty"`
}

var (
	auditWriter io.Writer = os.Stdout
	auditMu     sync.Mutex
)

func init() {
	logPath := os.Getenv("AUDIT_LOG_PATH")
	if logPath == "" {
		logPath = "logs/audit.log"
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}

	auditWriter = io.MultiWriter(os.Stdout, file)
}

func emitAuditLog(tipoAccion, tipoActivo, idActivo, nombreActivo, proyectoID, justificacion string, cambios map[string]auditChange, estado, errStr string) {
	entry := auditLogEntry{
		FechaHora: time.Now().UTC().Format(time.RFC3339Nano),
		Nivel:     "AUDIT",
		Accion: auditAction{
			Tipo:         tipoAccion,
			TipoActivo:   tipoActivo,
			IDActivo:     idActivo,
			NombreActivo: nombreActivo,
			ProyectoID:   proyectoID,
		},
		Justificacion:     justificacion,
		CambiosRealizados: cambios,
		Estado:            estado,
		DetallesError:     errStr,
	}

	payload, err := json.Marshal(entry)
	if err != nil {
		return
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	fmt.Fprintln(auditWriter, string(payload))
}
