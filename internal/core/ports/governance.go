package ports

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

type GovernanceRepository interface {
	// Policies
	SavePolicy(ctx context.Context, projectID int64, policy *domain.PolicyDocument) error
	GetPolicies(ctx context.Context, projectID int64) ([]domain.PolicyDocument, error)
	DeletePolicy(ctx context.Context, projectID int64, id string) error

	// Procedures
	SaveProcedure(ctx context.Context, projectID int64, procedure *domain.Procedure) error
	GetProcedures(ctx context.Context, projectID int64) ([]domain.Procedure, error)
	DeleteProcedure(ctx context.Context, projectID int64, id string) error

	// Roles
	SaveRole(ctx context.Context, projectID int64, role *domain.Role) error
	GetRoles(ctx context.Context, projectID int64) ([]domain.Role, error)
	DeleteRole(ctx context.Context, projectID int64, id string) error

	// RACI Activities
	SaveRACIActivity(ctx context.Context, projectID int64, activity *domain.RACIActivity) error
	GetRACIActivities(ctx context.Context, projectID int64) ([]domain.RACIActivity, error)
	DeleteRACIActivity(ctx context.Context, projectID int64, id string) error

	// Check if seeded
	IsSeeded(ctx context.Context, projectID int64) (bool, error)

	// ProjectsWithoutFramework devuelve los proyectos que todavía no tienen marco de
	// gobierno, para poder sembrarlos al arrancar sin recorrer los que ya lo tienen.
	ProjectsWithoutFramework(ctx context.Context) ([]int64, error)

	// SLA
	GetSLAConfigs(ctx context.Context, projectID int64) ([]domain.SLAConfig, error)
	SaveSLAConfigs(ctx context.Context, projectID int64, configs []domain.SLAConfig) error
	GetSLABreaches(ctx context.Context, projectID int64) ([]domain.SLABreach, error)
}

type GovernanceService interface {
	Seed(ctx context.Context, projectID int64) error

	// SeedPending siembra el marco de todos los proyectos que aún no lo tienen y devuelve
	// cuántos ha sembrado. Es idempotente: repetirlo no altera nada.
	SeedPending(ctx context.Context) (int, error)

	// Policies
	SavePolicy(ctx context.Context, projectID int64, policy *domain.PolicyDocument) error
	GetPolicies(ctx context.Context, projectID int64) ([]domain.PolicyDocument, error)
	DeletePolicy(ctx context.Context, projectID int64, id string) error

	// Procedures
	SaveProcedure(ctx context.Context, projectID int64, procedure *domain.Procedure) error
	GetProcedures(ctx context.Context, projectID int64) ([]domain.Procedure, error)
	DeleteProcedure(ctx context.Context, projectID int64, id string) error

	// Roles
	SaveRole(ctx context.Context, projectID int64, role *domain.Role) error
	GetRoles(ctx context.Context, projectID int64) ([]domain.Role, error)
	DeleteRole(ctx context.Context, projectID int64, id string) error

	// RACI Activities
	SaveRACIActivity(ctx context.Context, projectID int64, activity *domain.RACIActivity) error
	GetRACIActivities(ctx context.Context, projectID int64) ([]domain.RACIActivity, error)
	DeleteRACIActivity(ctx context.Context, projectID int64, id string) error

	// SLA
	GetSLAConfigs(ctx context.Context, projectID int64) ([]domain.SLAConfig, error)
	SaveSLAConfigs(ctx context.Context, projectID int64, configs []domain.SLAConfig) error
	GetSLABreaches(ctx context.Context, projectID int64) ([]domain.SLABreach, error)
}
