package domain

/*
Este archivo define la entidad de dominio para el Hardware.

Propósito arquitectónico y teórico:
1. Ubicación en Arquitectura Hexagonal: Se sitúa en `internal/core/domain`.
2. Definición de Hardware: Modela los componentes físicos o dispositivos de red.
*/

import (
	"fmt"
	"regexp"
	"strings"
)

// Arquitecturas admitidas. El campo describe el juego de instrucciones del componente,
// no su función en la red: el rol del equipo lo lleva el Endpoint (ver IsValidEndpointType),
// y duplicarlo aquí permitiría que ambos se contradijeran.
const (
	ArchX86_64  = "x86_64"
	ArchARM64   = "arm64"
	ArchAArch64 = "aarch64"
	ArchPPC64LE = "ppc64le"
	ArchRISCV64 = "riscv64"
	ArchS390X   = "s390x"
	ArchOtra    = "otro"
)

// ValidArchitectures es el vocabulario cerrado del campo Architecture.
var ValidArchitectures = []string{
	ArchX86_64, ArchARM64, ArchAArch64, ArchPPC64LE, ArchRISCV64, ArchS390X, ArchOtra,
}

// Límites de las magnitudes físicas. Son generosos a propósito: no pretenden adivinar el
// equipo real, solo descartar lo imposible (un componente con 222 petabytes de RAM).
const (
	MaxCPUCores    = 1024
	MaxRAMGB       = 65536   // 64 TB
	MaxStorageGB   = 1048576 // 1 PB
	MaxHardwareTxt = 120
	MaxSerialLen   = 100
)

// Hardware representa la entidad de dominio de un componente físico (nodo Hardware en Neo4j).
type Hardware struct {
	HardwareID   int64  `json:"hardware_id"`
	Model        string `json:"modelo"`
	Architecture string `json:"tipo"` // Arquitectura del componente (x86_64, arm64...)
	Manufacturer string `json:"manufacturer"`
	SerialNumber string `json:"serial_number"`
	CPUCores     int    `json:"cpu"` // Número de núcleos
	RAMGB        int    `json:"ram_gb"`
	StorageGB    int    `json:"storage_gb"`
}

// IsValidArchitecture indica si el valor pertenece al vocabulario cerrado.
func IsValidArchitecture(a string) bool {
	normalized := strings.ToLower(strings.TrimSpace(a))
	for _, valid := range ValidArchitectures {
		if normalized == valid {
			return true
		}
	}
	return false
}

// legacyCPUCores extrae el número de núcleos de los valores heredados que se guardaron como
// texto ("4 vCPU", "8 vCPU", "16"). Devuelve 0 si no se puede deducir, en cuyo caso el dato
// se deja vacío en vez de inventarlo.
var leadingDigits = regexp.MustCompile(`^\s*(\d+)`)

func LegacyCPUCores(raw string) int {
	match := leadingDigits.FindStringSubmatch(raw)
	if match == nil {
		return 0
	}
	cores := 0
	for _, c := range match[1] {
		cores = cores*10 + int(c-'0')
		if cores > MaxCPUCores {
			return 0
		}
	}
	return cores
}

// ValidateAndNormalizeHardware comprueba y normaliza un componente antes de persistirlo.
// Modifica el hardware in-place con los valores ya recortados.
//
// Se exige al menos un campo identificativo (fabricante o modelo): un componente sin
// ninguno de los dos no aporta nada al inventario y no hay forma de reconocerlo después.
func ValidateAndNormalizeHardware(hw *Hardware) error {
	if hw == nil {
		return fmt.Errorf("%w: componente no informado", ErrInvalidHardware)
	}

	hw.Manufacturer = strings.TrimSpace(hw.Manufacturer)
	hw.Model = strings.TrimSpace(hw.Model)
	hw.SerialNumber = strings.TrimSpace(hw.SerialNumber)

	if hw.Manufacturer == "" {
		return fmt.Errorf("%w: el fabricante del componente es obligatorio", ErrInvalidHardware)
	}
	if hw.Model == "" {
		return fmt.Errorf("%w: el modelo del componente es obligatorio", ErrInvalidHardware)
	}
	if len(hw.Manufacturer) > MaxHardwareTxt {
		return fmt.Errorf("%w: el fabricante no puede superar los %d caracteres", ErrInvalidHardware, MaxHardwareTxt)
	}
	if len(hw.Model) > MaxHardwareTxt {
		return fmt.Errorf("%w: el modelo no puede superar los %d caracteres", ErrInvalidHardware, MaxHardwareTxt)
	}
	if len(hw.SerialNumber) > MaxSerialLen {
		return fmt.Errorf("%w: el número de serie no puede superar los %d caracteres", ErrInvalidHardware, MaxSerialLen)
	}

	// La arquitectura es opcional; si viene, debe pertenecer al vocabulario cerrado.
	if hw.Architecture = strings.ToLower(strings.TrimSpace(hw.Architecture)); hw.Architecture != "" {
		if !IsValidArchitecture(hw.Architecture) {
			return fmt.Errorf("%w: la arquitectura '%s' no es válida (admitidas: %s)",
				ErrInvalidHardware, hw.Architecture, strings.Join(ValidArchitectures, ", "))
		}
	}

	// Las magnitudes son opcionales (0 = sin dato), pero si se informan deben ser posibles.
	if err := checkMagnitude("el número de núcleos", hw.CPUCores, MaxCPUCores); err != nil {
		return err
	}
	if err := checkMagnitude("la memoria RAM en GB", hw.RAMGB, MaxRAMGB); err != nil {
		return err
	}
	if err := checkMagnitude("el almacenamiento en GB", hw.StorageGB, MaxStorageGB); err != nil {
		return err
	}

	return nil
}

func checkMagnitude(etiqueta string, valor, maximo int) error {
	if valor < 0 {
		return fmt.Errorf("%w: %s no puede ser negativo", ErrInvalidHardware, etiqueta)
	}
	if valor > maximo {
		return fmt.Errorf("%w: %s no puede superar %d", ErrInvalidHardware, etiqueta, maximo)
	}
	return nil
}
