package domain

// ContainerImage representa una imagen de contenedor.
type ContainerImage struct {
	ImageID    string  `json:"image_id"`
	Name       string  `json:"name"`
	Tag        string  `json:"tag"`
	Digest     string  `json:"digest"`
	RiskScore  float64 `json:"risk_score"`
}

// Container representa una instancia de un contenedor en ejecución.
type Container struct {
	ContainerID string  `json:"container_id"`
	Name        string  `json:"name"`
	State       string  `json:"state"`
	ImageID     string       `json:"image_id"`
	HostID      int64        `json:"host_id"` // ID del Endpoint donde corre
	RiskScore   float64      `json:"risk_score"`
	Privileged  bool         `json:"privileged"`
	InternetExposed bool         `json:"internet_exposed"`
	IPs         []EndpointIP `json:"ips,omitempty"` // IPs asociadas al contenedor (opcional)
}
