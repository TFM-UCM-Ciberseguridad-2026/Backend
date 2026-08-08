package domain

import (
	"strconv"
	"strings"
)

// Comparación de versiones y verificación de una declaración de parche contra la
// versión realmente instalada. Lógica de dominio pura, sin dependencias externas.

// CompareVersions compara dos versiones segmento a segmento: -1 si a < b, 0 si son
// equivalentes, 1 si a > b. El booleano indica si la comparación es concluyente.
//
// Los segmentos numéricos se comparan como números (2.10 > 2.9). Al llegar a un
// segmento no numérico sin haber decidido devuelve (0, false): sufijos como "beta" o
// "rc1" no tienen un orden universal. Las colas ausentes cuentan como cero, así que
// 2.15 == 2.15.0 pero 2.15 < 2.15.1.
func CompareVersions(a, b string) (int, bool) {
	segA := splitVersion(a)
	segB := splitVersion(b)

	if len(segA) == 0 || len(segB) == 0 {
		return 0, false
	}

	maxLen := len(segA)
	if len(segB) > maxLen {
		maxLen = len(segB)
	}

	for i := 0; i < maxLen; i++ {
		numA, okA := 0, true
		if i < len(segA) {
			numA, okA = parseVersionSegment(segA[i])
		}
		numB, okB := 0, true
		if i < len(segB) {
			numB, okB = parseVersionSegment(segB[i])
		}

		if !okA || !okB {
			return 0, false
		}
		if numA < numB {
			return -1, true
		}
		if numA > numB {
			return 1, true
		}
	}

	return 0, true
}

func splitVersion(version string) []string {
	normalized := strings.TrimSpace(version)
	normalized = strings.TrimPrefix(normalized, "v")
	normalized = strings.TrimPrefix(normalized, "V")
	if normalized == "" {
		return nil
	}

	return strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
}

func parseVersionSegment(segment string) (int, bool) {
	n, err := strconv.Atoi(segment)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Motivos de verificación de una declaración de parche.
const (
	VerificationVersionAtOrAboveFix = "La versión instalada alcanza o supera la versión corregida"
	VerificationVersionBelowFix     = "La versión instalada sigue por debajo de la versión corregida"
	VerificationNoFixedVersion      = "No consta la versión que corrige el CVE"
	VerificationNoInstalledVersion  = "No consta la versión instalada"
	VerificationNoPackageMatch      = "Ninguna versión corregida corresponde al software instalado"
	VerificationInconclusive        = "El formato de las versiones no permite compararlas"
	VerificationNotApplicable       = "La verificación por versión no aplica a este nivel de remediación"
)

// PatchVerification recoge el contraste entre una declaración de parche y la versión
// instalada. Conclusive distingue "comprobado y no cuadra" de "no se ha podido comprobar".
type PatchVerification struct {
	Verified   bool   `json:"verified"`
	Conclusive bool   `json:"conclusive"`
	Reason     string `json:"reason"`

	InstalledVersion string `json:"installed_version,omitempty"`
	ExpectedVersion  string `json:"expected_version,omitempty"`
	MatchedPackage   string `json:"matched_package,omitempty"`
}

// VerifyInstalledVersion contrasta la versión instalada con la que corrige el CVE.
//
// Nunca rechaza la declaración: hay parcheos legítimos que no cambian el número de
// versión, como los backports de las distribuciones.
func VerifyInstalledVersion(installedName, installedVersion string, fixedVersions []FixedVersion) PatchVerification {
	if installedVersion == "" {
		return PatchVerification{Reason: VerificationNoInstalledVersion}
	}
	if len(fixedVersions) == 0 {
		return PatchVerification{
			Reason:           VerificationNoFixedVersion,
			InstalledVersion: installedVersion,
		}
	}

	candidate, found := matchFixedVersion(installedName, fixedVersions)
	if !found {
		return PatchVerification{
			Reason:           VerificationNoPackageMatch,
			InstalledVersion: installedVersion,
		}
	}

	cmp, conclusive := CompareVersions(installedVersion, candidate.Version)
	if !conclusive {
		return PatchVerification{
			Reason:           VerificationInconclusive,
			InstalledVersion: installedVersion,
			ExpectedVersion:  candidate.Version,
			MatchedPackage:   candidate.Package,
		}
	}

	verification := PatchVerification{
		Conclusive:       true,
		InstalledVersion: installedVersion,
		ExpectedVersion:  candidate.Version,
		MatchedPackage:   candidate.Package,
	}

	if cmp >= 0 {
		verification.Verified = true
		verification.Reason = VerificationVersionAtOrAboveFix
	} else {
		verification.Reason = VerificationVersionBelowFix
	}
	return verification
}

// matchFixedVersion elige la versión corregida del paquete instalado. El nombre en OSV
// suele ser más específico que el del inventario ("org.apache...:log4j-core" frente a
// "log4j-core"), de ahí la comparación por contención. Entre varias del mismo paquete se
// queda con la más baja: exigir la más alta marcaría como vulnerable a quien parcheó por
// su rama de soporte.
func matchFixedVersion(installedName string, fixedVersions []FixedVersion) (FixedVersion, bool) {
	normalizedName := normalizePackageName(installedName)

	var best FixedVersion
	found := false

	for _, fv := range fixedVersions {
		if normalizedName != "" && fv.Package != "" {
			pkg := normalizePackageName(fv.Package)
			if !strings.Contains(pkg, normalizedName) && !strings.Contains(normalizedName, pkg) {
				continue
			}
		}

		if !found {
			best, found = fv, true
			continue
		}
		if cmp, ok := CompareVersions(fv.Version, best.Version); ok && cmp < 0 {
			best = fv
		}
	}

	return best, found
}

// normalizePackageName pasa a minúsculas y descarta el grupo Maven.
func normalizePackageName(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if idx := strings.LastIndex(normalized, ":"); idx >= 0 {
		normalized = normalized[idx+1:]
	}
	return normalized
}
