package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/domain"
	"github.com/TFM-UCM-Ciberseguridad-2026/Backend/internal/core/ports"
)

type governanceService struct {
	repo ports.GovernanceRepository
}

func NewGovernanceService(repo ports.GovernanceRepository) ports.GovernanceService {
	return &governanceService{repo: repo}
}

// SeedPending siembra el marco de los proyectos que aún no lo tienen.
//
// Existe porque la siembra vivía en el arranque con un id de proyecto escrito a mano:
// los proyectos creados por cualquier otra vía se quedaban sin marco y su pestaña de
// Gobierno salía vacía sin explicación. Ahora los proyectos nuevos se siembran al
// crearse, y esto recupera a los que quedaron atrás.
func (s *governanceService) SeedPending(ctx context.Context) (int, error) {
	pendientes, err := s.repo.ProjectsWithoutFramework(ctx)
	if err != nil {
		return 0, err
	}

	sembrados := 0
	for _, projectID := range pendientes {
		if err := s.Seed(ctx, projectID); err != nil {
			// Un proyecto que falle no debe impedir sembrar los demás.
			return sembrados, fmt.Errorf("proyecto %d: %w", projectID, err)
		}
		sembrados++
	}
	return sembrados, nil
}

func (s *governanceService) Seed(ctx context.Context, projectID int64) error {
	seeded, err := s.repo.IsSeeded(ctx, projectID)
	if err != nil {
		return err
	}
	if seeded {
		return nil // Already seeded
	}

	// 1. Seed Roles
	roles := []domain.Role{
		{ID: "role-1", Name: "CISO", Contact: "ciso@company.local"},
		{ID: "role-2", Name: "Equipo SOC", Contact: "soc@company.local"},
		{ID: "role-3", Name: "Equipo Infraestructura", Contact: "infra@company.local"},
		{ID: "role-4", Name: "Dueño del Activo", Contact: "TBD"},
	}
	for _, r := range roles {
		if err := s.repo.SaveRole(ctx, projectID, &r); err != nil {
			return err
		}
	}

	// 2. Seed RACI Activities
	activities := []domain.RACIActivity{
		{ID: "act-1", Name: "Detección de CVE", Order: 1, Roles: map[string]string{"role-1": "I", "role-2": "A", "role-3": "C", "role-4": "I"}},
		{ID: "act-2", Name: "Priorización (risk-based)", Order: 2, Roles: map[string]string{"role-1": "A", "role-2": "R", "role-3": "C", "role-4": "I"}},
		{ID: "act-3", Name: "Aprobación de parcheo", Order: 3, Roles: map[string]string{"role-1": "I", "role-2": "C", "role-3": "A", "role-4": "R"}},
		{ID: "act-4", Name: "Pruebas en entorno controlado", Order: 4, Roles: map[string]string{"role-1": "I", "role-2": "C", "role-3": "A", "role-4": "R"}},
		{ID: "act-5", Name: "Ejecución de parcheo", Order: 5, Roles: map[string]string{"role-1": "I", "role-2": "C", "role-3": "R", "role-4": "A"}},
		{ID: "act-6", Name: "Verificación post-parcheo", Order: 6, Roles: map[string]string{"role-1": "I", "role-2": "R", "role-3": "C", "role-4": "A"}},
		{ID: "act-7", Name: "Gestión de excepciones", Order: 7, Roles: map[string]string{"role-1": "A", "role-2": "C", "role-3": "C", "role-4": "R"}},
		{ID: "act-8", Name: "Reporting a dirección", Order: 8, Roles: map[string]string{"role-1": "A", "role-2": "R", "role-3": "I", "role-4": "I"}},
	}
	for _, a := range activities {
		if err := s.repo.SaveRACIActivity(ctx, projectID, &a); err != nil {
			return err
		}
	}

	// 3. Seed Policies
	policies := []domain.PolicyDocument{
		{ID: "pol-1", Name: "Política de Gestión de Vulnerabilidades", Version: "v3.2", Owner: "CISO", NextReviewDate: "2027-06-15", UnderReview: false},
		{ID: "pol-2", Name: "Política de Parcheo en Producción", Version: "v1.5", Owner: "Equipo Infraestructura", NextReviewDate: "2027-03-02", UnderReview: false},
		{ID: "pol-3", Name: "Procedimiento de Excepciones", Version: "v2.0", Owner: "Equipo Infraestructura", NextReviewDate: "2024-01-01", UnderReview: true},
		{ID: "pol-4", Name: "Acuerdo de Nivel de Servicio (SLA) de Parcheo", Version: "v1.1", Owner: "CISO", NextReviewDate: "2027-08-10", UnderReview: false},
		{ID: "pol-5", Name: "Política de Hardening de Servidores", Version: "v2.3", Owner: "Equipo SOC", NextReviewDate: "2027-07-05", UnderReview: false},
		{ID: "pol-6", Name: "Política de Criptografía y Certificados", Version: "v1.0", Owner: "Equipo Infraestructura", NextReviewDate: "2023-12-10", UnderReview: false},
	}
	for _, p := range policies {
		if err := s.repo.SavePolicy(ctx, projectID, &p); err != nil {
			return err
		}
	}

	// 4. Seed Procedures
	procedures := []domain.Procedure{
		{ID: "PROC-01", Name: "Escaneo y Detección de CVE", Meta: "4 pasos · actualizado 12/07/2026", Steps: []string{"Ejecutar escaneo automático sobre el inventario de activos", "Correlacionar hallazgos con bases de datos CVE / NVD", "Enriquecer con EPSS y catálogo CISA KEV", "Registrar hallazgo en el grafo con first_detected_at"}},
		{ID: "PROC-02", Name: "Priorización basada en riesgo", Meta: "3 pasos · actualizado 02/03/2026", Steps: []string{"Calcular severidad efectiva (CVSS + exposición del activo)", "Asignar SLA de remediación según severidad", "Notificar al Dueño del Activo y al Equipo de Infraestructura"}},
		{ID: "PROC-03", Name: "Pruebas y validación de parches", Meta: "4 pasos · actualizado 18/05/2026", Steps: []string{"Desplegar el parche en entorno de pruebas aislado", "Ejecutar batería de regresión funcional", "Validar que no rompe dependencias críticas", "Aprobación formal de Infra antes del despliegue"}},
		{ID: "PROC-04", Name: "Despliegue por anillos", Meta: "3 pasos · actualizado 18/05/2026", Steps: []string{"Anillo piloto: subconjunto reducido y no crítico", "Anillo producción: resto de activos estándar", "Anillo crítico: solo tras verificación en anillos previos"}},
		{ID: "PROC-05", Name: "Gestión de excepciones", Meta: "3 pasos · actualizado 10/08/2026", Steps: []string{"Solicitud formal con justificación técnica del Dueño del Activo", "Definición de controles compensatorios obligatorios", "Revisión y renovación cada 30 días, nunca indefinida"}},
		{ID: "PROC-06", Name: "Escalado por incumplimiento", Meta: "4 pasos · actualizado 05/07/2026", Steps: []string{"Aviso automático al 80% del plazo consumido", "Escalado N1 a Responsable de Infraestructura al vencer", "Escalado N2 al CISO a los 15 días de vencido", "Aceptación formal del riesgo o priorización forzada"}},
	}
	for _, p := range procedures {
		if err := s.repo.SaveProcedure(ctx, projectID, &p); err != nil {
			return err
		}
	}

	return nil
}

// Policies
func (s *governanceService) SavePolicy(ctx context.Context, projectID int64, policy *domain.PolicyDocument) error {
	return s.repo.SavePolicy(ctx, projectID, policy)
}
func (s *governanceService) GetPolicies(ctx context.Context, projectID int64) ([]domain.PolicyDocument, error) {
	policies, err := s.repo.GetPolicies(ctx, projectID)
	if err != nil {
		return nil, err
	}
	
	now := time.Now()
	for i := range policies {
		policies[i].CalculateStatus(now)
	}
	return policies, nil
}
func (s *governanceService) DeletePolicy(ctx context.Context, projectID int64, id string) error {
	return s.repo.DeletePolicy(ctx, projectID, id)
}

// Procedures
func (s *governanceService) SaveProcedure(ctx context.Context, projectID int64, procedure *domain.Procedure) error {
	return s.repo.SaveProcedure(ctx, projectID, procedure)
}
func (s *governanceService) GetProcedures(ctx context.Context, projectID int64) ([]domain.Procedure, error) {
	return s.repo.GetProcedures(ctx, projectID)
}
func (s *governanceService) DeleteProcedure(ctx context.Context, projectID int64, id string) error {
	return s.repo.DeleteProcedure(ctx, projectID, id)
}

// Roles
func (s *governanceService) SaveRole(ctx context.Context, projectID int64, role *domain.Role) error {
	return s.repo.SaveRole(ctx, projectID, role)
}
func (s *governanceService) GetRoles(ctx context.Context, projectID int64) ([]domain.Role, error) {
	return s.repo.GetRoles(ctx, projectID)
}
func (s *governanceService) DeleteRole(ctx context.Context, projectID int64, id string) error {
	return s.repo.DeleteRole(ctx, projectID, id)
}

// RACI Activities
func (s *governanceService) SaveRACIActivity(ctx context.Context, projectID int64, activity *domain.RACIActivity) error {
	return s.repo.SaveRACIActivity(ctx, projectID, activity)
}
func (s *governanceService) GetRACIActivities(ctx context.Context, projectID int64) ([]domain.RACIActivity, error) {
	return s.repo.GetRACIActivities(ctx, projectID)
}
func (s *governanceService) DeleteRACIActivity(ctx context.Context, projectID int64, id string) error {
	return s.repo.DeleteRACIActivity(ctx, projectID, id)
}

func (s *governanceService) GetSLAConfigs(ctx context.Context, projectID int64) ([]domain.SLAConfig, error) {
	return s.repo.GetSLAConfigs(ctx, projectID)
}

func (s *governanceService) SaveSLAConfigs(ctx context.Context, projectID int64, configs []domain.SLAConfig) error {
	return s.repo.SaveSLAConfigs(ctx, projectID, configs)
}

func (s *governanceService) GetSLABreaches(ctx context.Context, projectID int64) ([]domain.SLABreach, error) {
	breaches, err := s.repo.GetSLABreaches(ctx, projectID)
	if err != nil {
		return nil, err
	}

	configs, err := s.repo.GetSLAConfigs(ctx, projectID)
	if err != nil {
		return nil, err
	}

	// La clave es el par (categoría, severidad): el plazo depende de los dos ejes.
	configMap := make(map[string]int, len(configs))
	for _, c := range configs {
		configMap[string(c.Category)+"|"+c.Severity] = c.Days
	}

	now := time.Now()
	nowUnix := now.UnixMilli()

	var finalBreaches []domain.SLABreach
	for _, b := range breaches {
		b.Severity = domain.ScoreToSeverity(b.BaseScore)

		// Excluir vulnerabilidades con CVSS 0.0 (severidad "None").
		// Un CVSS 0.0 no representa riesgo real y no debe forzarse a un SLA de remediación.
		if b.Severity == "None" {
			continue
		}

		// Sin categoría no hay compromiso que medir: el activo tiene un tipo que no es
		// ninguno de los reconocidos. Se devuelve con SLADays 0 para que la pantalla lo
		// muestre como "sin SLA" en vez de aplicarle un plazo que nadie ha acordado.
		days, ok := configMap[string(b.Category)+"|"+b.Severity]
		if !ok || b.Category == "" {
			b.SLADays = 0
			b.DaysRemaining = 0
			finalBreaches = append(finalBreaches, b)
			continue
		}

		b.SLADays = days

		limitTimeUnix := b.FirstDetectedAt + int64(b.SLADays*24*60*60*1000)
		daysRemaining := int((limitTimeUnix - nowUnix) / (1000 * 60 * 60 * 24))
		b.DaysRemaining = daysRemaining
		finalBreaches = append(finalBreaches, b)
	}

	// Order: breached first (DaysRemaining < 0) ascending by DaysRemaining (most negative first)
	// then non-breached ascending by DaysRemaining (closest to zero first).
	// Las entradas sin SLA se van al final: no tienen plazo, así que ordenarlas por días
	// restantes las colocaría en medio de la tabla fingiendo un compromiso que no existe.
	sort.Slice(finalBreaches, func(i, j int) bool {
		iSinSLA := finalBreaches[i].SLADays == 0
		jSinSLA := finalBreaches[j].SLADays == 0
		if iSinSLA != jSinSLA {
			return jSinSLA
		}
		return finalBreaches[i].DaysRemaining < finalBreaches[j].DaysRemaining
	})

	return finalBreaches, nil
}
