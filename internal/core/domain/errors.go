package domain

import "errors"

var (
	ErrNodeAlreadyExists = errors.New("node already exists, save ignored")
	ErrNodeNotFound      = errors.New("node not found, update ignored")

	// ErrInvalidNetwork indica que los datos de una red no superan la validación de dominio
	// (CIDR mal formado, gateway fuera de rango, VLAN inválida...). Se traduce a HTTP 400.
	ErrInvalidNetwork = errors.New("datos de red inválidos")

	// ErrDuplicateNetwork indica un conflicto con otra red ya existente del mismo proyecto
	// (mismo nombre, mismo CIDR o misma VLAN). Se traduce a HTTP 409.
	ErrDuplicateNetwork = errors.New("red duplicada")

	// ErrInvalidIP indica que una dirección IP de un activo no es válida o está repetida
	// dentro del propio activo. Se traduce a HTTP 400.
	ErrInvalidIP = errors.New("dirección IP inválida")

	// ErrDuplicateIP indica que la IP ya está asignada a otro activo del mismo proyecto.
	// Se traduce a HTTP 409.
	ErrDuplicateIP = errors.New("dirección IP duplicada")

	// ErrDuplicateAsset indica que ya existe un endpoint o un contenedor con ese nombre
	// en el mismo proyecto. Se traduce a HTTP 409.
	ErrDuplicateAsset = errors.New("activo duplicado")

	// ErrDuplicateProject indica que ya existe otro proyecto con ese nombre. Se traduce a
	// HTTP 409.
	ErrDuplicateProject = errors.New("proyecto duplicado")

	// ErrInvalidHardware indica que los datos de un componente físico no superan la
	// validación de dominio (magnitudes imposibles, arquitectura desconocida, sin
	// identificar). Se traduce a HTTP 400.
	ErrInvalidHardware = errors.New("datos de hardware inválidos")
)
