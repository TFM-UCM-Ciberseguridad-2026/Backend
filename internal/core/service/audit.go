package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

// LogAudit imprime la entrada de auditoría en una única línea JSON a stdout para Docker.
func LogAudit(ctx context.Context, entry domain.AuditLogEntry) {
	entry.FechaHora = time.Now().UTC()
	entry.Nivel = "AUDIT"
	if entry.Estado == "" {
		entry.Estado = "SUCCESS"
	}

	payload, err := json.Marshal(entry)
	if err == nil {
		fmt.Fprintln(os.Stdout, string(payload))
	}
}
