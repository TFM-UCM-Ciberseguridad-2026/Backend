package config

/*
Este archivo gestiona el subsistema de configuración estática y dinámica de la aplicación.

Propósito arquitectónico y teórico:
1. Carga de Variables de Entorno: Lee los parámetros del runtime del sistema operativo (u opcionalmente de un archivo .env en desarrollo).
2. Estructura de Configuración Tipada (Config): Define los tipos de datos requeridos por la aplicación (puertos, credenciales, URLs de APIs externas) para evitar dependencias directas de llamadas al sistema operativo (os.Getenv) a lo largo del código.
3. Desacoplamiento de Variables: Centraliza las constantes y configuraciones iniciales para que el resto de los componentes operen de manera agnóstica al entorno de despliegue (desarrollo, preproducción, producción).
*/
