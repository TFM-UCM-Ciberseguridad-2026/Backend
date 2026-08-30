package ports

import (
	"context"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
)

type GovernanceRepository interface {
	// Policies
	SavePolicy(ctx context.Context, policy *domain.PolicyDocument) error
	GetPolicies(ctx context.Context) ([]domain.PolicyDocument, error)
	DeletePolicy(ctx context.Context, id string) error

	// Procedures
	SaveProcedure(ctx context.Context, procedure *domain.Procedure) error
	GetProcedures(ctx context.Context) ([]domain.Procedure, error)
	DeleteProcedure(ctx context.Context, id string) error

	// Roles
	SaveRole(ctx context.Context, role *domain.Role) error
	GetRoles(ctx context.Context) ([]domain.Role, error)
	DeleteRole(ctx context.Context, id string) error

	// RACI Activities
	SaveRACIActivity(ctx context.Context, activity *domain.RACIActivity) error
	GetRACIActivities(ctx context.Context) ([]domain.RACIActivity, error)
	DeleteRACIActivity(ctx context.Context, id string) error

	// Check if seeded
	IsSeeded(ctx context.Context) (bool, error)

	// SLA
	GetSLAConfigs(ctx context.Context) ([]domain.SLAConfig, error)
	SaveSLAConfigs(ctx context.Context, configs []domain.SLAConfig) error
	GetSLABreaches(ctx context.Context) ([]domain.SLABreach, error)
}

type GovernanceService interface {
	Seed(ctx context.Context) error

	// Policies
	SavePolicy(ctx context.Context, policy *domain.PolicyDocument) error
	GetPolicies(ctx context.Context) ([]domain.PolicyDocument, error)
	DeletePolicy(ctx context.Context, id string) error

	// Procedures
	SaveProcedure(ctx context.Context, procedure *domain.Procedure) error
	GetProcedures(ctx context.Context) ([]domain.Procedure, error)
	DeleteProcedure(ctx context.Context, id string) error

	// Roles
	SaveRole(ctx context.Context, role *domain.Role) error
	GetRoles(ctx context.Context) ([]domain.Role, error)
	DeleteRole(ctx context.Context, id string) error

	// RACI Activities
	SaveRACIActivity(ctx context.Context, activity *domain.RACIActivity) error
	GetRACIActivities(ctx context.Context) ([]domain.RACIActivity, error)
	DeleteRACIActivity(ctx context.Context, id string) error

	// SLA
	GetSLAConfigs(ctx context.Context) ([]domain.SLAConfig, error)
	SaveSLAConfigs(ctx context.Context, configs []domain.SLAConfig) error
	GetSLABreaches(ctx context.Context) ([]domain.SLABreach, error)
}
