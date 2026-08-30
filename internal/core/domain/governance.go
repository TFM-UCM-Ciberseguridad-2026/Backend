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

// SLAConfig represents the SLA days for a specific severity
type SLAConfig struct {
	Severity string `json:"severity"` // Critical, High, Medium, Low
	Days     int    `json:"days"`
}

// SLABreach represents a vulnerability and its SLA compliance status
type SLABreach struct {
	CVEID           string  `json:"cve_id"`
	Severity        string  `json:"severity"`
	BaseScore       float64 `json:"base_score"`
	FirstDetectedAt int64   `json:"first_detected_at"`
	SLADays         int     `json:"sla_days"`
	DaysRemaining   int     `json:"days_remaining"` // Negative means breached
}

// RACIActivity represents an activity in the RACI matrix and its associated roles
type RACIActivity struct {
	ID    string            `json:"id"`
	Name  string            `json:"name"`
	Order int               `json:"order"`
	Roles map[string]string `json:"roles"` // map of RoleID -> "R", "A", "C", "I"
}
