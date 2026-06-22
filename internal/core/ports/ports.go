package ports

/*
Este archivo define los Puertos (Ports) de entrada y salida para los servicios de la aplicación (vulnerabilidades, exploits y persistencia).

Propósito arquitectónico y teórico:
1. Puertos en Arquitectura Hexagonal: Define las interfaces formales (contratos lógicos) Inbound (de entrada, como handlers o casos de uso) y Outbound (de salida, como repositorios o clientes de APIs externas) que describen qué operaciones ofrece o requiere el núcleo de la aplicación, sin implementar cómo se realizan.
2. Principio de Inversión de Dependencias (DIP): Asegura que el núcleo del negocio (service y domain) dependa de abstracciones de esta capa (ports) y no de detalles concretos de infraestructura de red, HTTP o bases de datos (adapters).
3. Testabilidad mediante Mocks: Permite sustituir en tiempo de pruebas unitarias los componentes de persistencia o APIs externas por implementaciones simuladas que cumplan las firmas de las interfaces.
*/
