package domain

import (
	"log"
	"time"
)

// ReviewWarningDays defines the days threshold for automatic review warning
const ReviewWarningDays = 30

// PolicyDocument represents a governance document
type PolicyDocument struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	Status         string `json:"status"`           // Calculated, not persisted
	StatusLabel    string `json:"status_label"`     // Calculated, not persisted
	Owner          string `json:"owner"`
	NextReviewDate string `json:"next_review_date"` // YYYY-MM-DD or empty
	DocumentURL    string `json:"document_url"`     // Optional external link
	UnderReview    bool   `json:"under_review"`
}

// CalculateStatus evaluates business logic to set Status and StatusLabel
func (p *PolicyDocument) CalculateStatus(now time.Time) {
	if p.UnderReview {
		p.Status = "in_review"
		p.StatusLabel = "En Revisión"
		return
	}

	if p.NextReviewDate == "" || p.NextReviewDate == "Pendiente" {
		p.Status = "pending"
		p.StatusLabel = "Pendiente"
		return
	}

	reviewDate, err := time.Parse("2006-01-02", p.NextReviewDate)
	if err != nil {
		// Fallback for legacy DD/MM/YYYY format
		reviewDate, err = time.Parse("02/01/2006", p.NextReviewDate)
		if err != nil {
			p.Status = "invalid"
			p.StatusLabel = "Fecha Inválida"
			return
		}
		log.Printf("[WARN] Política '%s' (ID: %s) parseada usando formato legacy DD/MM/YYYY: %s", p.Name, p.ID, p.NextReviewDate)
	}

	// Midnight in the server's real time zone
	hoy := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	if reviewDate.Before(hoy) {
		p.Status = "obsolete"
		p.StatusLabel = "Obsoleta"
		return
	}

	if reviewDate.Sub(hoy).Hours() <= float64(ReviewWarningDays*24) {
		p.Status = "in_review"
		p.StatusLabel = "En Revisión (Próxima a vencer)"
		return
	}

	p.Status = "active"
	p.StatusLabel = "Vigente"
}

// Procedure represents an operational procedure
type Procedure struct {
	ID    string   `json:"id"` // e.g., "PROC-01"
	Name  string   `json:"name"`
	Meta  string   `json:"meta"`
	Steps []string `json:"steps"`
}

// Role represents a role involved in the RACI matrix
type Role struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Contact string `json:"contact"` // e.g. email or department contact
}

// SLAConfig represents the SLA days for a specific severity within an asset category.
//
// El plazo depende de DOS ejes, no de uno: la severidad del CVE y el tipo de activo donde
// está. Una misma severidad no admite el mismo plazo en un servidor que en el puesto de un
// usuario, porque no comparten ni exposición ni ventana de mantenimiento.
type SLAConfig struct {
	Category EndpointCategory `json:"category"` // Server | Workstation | Container
	Severity string           `json:"severity"` // Critical, High, Medium, Low
	Days     int              `json:"days"`
}

// SLABreach represents a vulnerability and its SLA compliance status.
//
// Hay una fila por CVE y activo afectado, no una por CVE: la misma CVE en dos
// contenedores son dos filas, igual que en dos servidores. Agrupar por categoría
// obligaba a un contador «×N» que solo asomaba cuando un activo compartía imagen con
// otro, y que además no decía cuál de los dos había que reconstruir.
type SLABreach struct {
	CVEID           string  `json:"cve_id"`
	Severity        string  `json:"severity"`
	BaseScore       float64 `json:"base_score"`
	FirstDetectedAt int64   `json:"first_detected_at"`
	SLADays         int     `json:"sla_days"`
	DaysRemaining   int     `json:"days_remaining"` // Negative means breached

	// Category es el bucket de SLA aplicado. Vacía cuando el activo afectado no tiene un
	// tipo reconocido: en ese caso no hay plazo que exigir. Container cuando el hallazgo
	// vive dentro de un contenedor, sea en la imagen o en el software empaquetado en ella.
	Category EndpointCategory `json:"category"`

	// AssetID y AssetName identifican el activo de la fila: el endpoint en el software del
	// host, el contenedor en los hallazgos de contenedor. El nombre es lo que se enseña; el
	// id es lo que distingue dos activos que se llaman igual.
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name"`

	// FindingCount es el número de hallazgos que la fila agrupa: los de esa CVE en ese
	// activo. Normalmente uno, más de uno cuando la misma CVE afecta a varios paquetes
	// instalados en él. Sumarlo da el cumplimiento medido en hallazgos y no en CVE, que es
	// la unidad del resto del reporting.
	FindingCount int `json:"finding_count"`
}

// RACIActivity represents an activity in the RACI matrix and its associated roles
type RACIActivity struct {
	ID    string            `json:"id"`
	Name  string            `json:"name"`
	Order int               `json:"order"`
	Roles map[string]string `json:"roles"` // map of RoleID -> "R", "A", "C", "I"
}
