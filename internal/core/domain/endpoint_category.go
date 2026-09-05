package domain

/*
Este archivo define la categoría de negocio de un Endpoint dentro del proceso de gestión
de vulnerabilidades.

Propósito arquitectónico y teórico:
 1. Ubicación en Arquitectura Hexagonal: Se localiza en `internal/core/domain`, como lógica
    pura sin dependencias de persistencia ni de transporte.
 2. Segunda dimensión de clasificación: `Endpoint.Type` describe el rol técnico del activo en
    la red (Server, Workstation, Domain Controller, Firewall, Router) y no se toca. La
    categoría describe el bucket operativo con el que se gobierna el parcheo: SLA, criticidad
    y responsable. Son ejes distintos porque responden a preguntas distintas, y colapsarlos
    obligaría a reinterpretar el rol técnico cada vez que cambie la política de parcheo.
 3. Punto único de mapeo: la correspondencia tipo → categoría vive exclusivamente en
    `endpointTypeToCategory`. Ningún otro punto del sistema debe decidir si un activo es
    puesto o servidor comparando contra las constantes de tipo.
*/

// EndpointCategory es el bucket de negocio usado en la gestión de vulnerabilidades.
// Solo admite dos valores: los puestos de usuario y todo lo demás, que se gobierna como
// servidor.
type EndpointCategory string

const (
	CategoryWorkstation EndpointCategory = "Workstation"
	CategoryServer      EndpointCategory = "Server"
)

// endpointTypeToCategory es la ÚNICA fuente de verdad del mapeo rol técnico → categoría.
//
// Domain Controller, Firewall y Router se gobiernan hoy como servidores. Si en el futuro los
// dispositivos de red necesitan un SLA propio, se separan aquí y en ningún otro sitio.
var endpointTypeToCategory = map[string]EndpointCategory{
	EndpointTypeServer:           CategoryServer,
	EndpointTypeDomainController: CategoryServer,
	EndpointTypeFirewall:         CategoryServer,
	EndpointTypeRouter:           CategoryServer,
	EndpointTypeWorkstation:      CategoryWorkstation,
}

// CategoryForEndpointType traduce un rol técnico a su categoría de negocio.
//
// El segundo valor es false cuando el tipo no es uno de los cinco reconocidos, caso en el que
// la categoría devuelta es la cadena vacía. Quien llama decide qué hacer con un activo sin
// clasificar; esta función no inventa una categoría por defecto, porque asumir "servidor" ante
// un dato sucio inflaría el cumplimiento del SLA más exigente con activos que nadie ha
// clasificado.
//
// Nota de implementación: las constantes EndpointType* son constantes string sin tipo propio,
// así que el mapeo se expone como función de paquete en lugar de como método. Sobre un
// Endpoint concreto, usa Endpoint.ResolveCategory.
func CategoryForEndpointType(t string) (EndpointCategory, bool) {
	cat, ok := endpointTypeToCategory[t]
	return cat, ok
}

// ResolveCategory devuelve la categoría de negocio que corresponde al rol técnico del
// endpoint. Es el punto de llamada habitual: el resto del sistema pregunta al activo, no al
// mapa.
func (e *Endpoint) ResolveCategory() (EndpointCategory, bool) {
	if e == nil {
		return "", false
	}
	return CategoryForEndpointType(e.Type)
}

// ApplyCategory congela la categoría en el propio activo a partir de su rol técnico. Se invoca
// al crear y al actualizar el endpoint.
//
// La categoría se persiste en lugar de derivarse en cada lectura de forma deliberada: los
// plazos de parcheo y el reporting de cumplimiento son históricos, y un cambio futuro en
// endpointTypeToCategory no debe reescribir hacia atrás bajo qué SLA se midió un activo.
// Un tipo no reconocido deja la categoría vacía en vez de arrastrar la anterior, para que un
// dato sucio se vea en el inventario en lugar de esconderse.
func (e *Endpoint) ApplyCategory() {
	if e == nil {
		return
	}
	cat, _ := CategoryForEndpointType(e.Type)
	e.Category = string(cat)
}
