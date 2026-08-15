package ollama

import (
	"sync"
)

// TTPCache implementa una caché en memoria para los mapeos de CWE a TTPs.
// Los CWEs son finitos y estáticos (alrededor de 1000), por lo que es eficiente
// guardarlos en memoria para no saturar al LLM.
type TTPCache struct {
	mu    sync.RWMutex
	cache map[string][]string
}

// NewTTPCache inicializa una nueva caché en memoria.
func NewTTPCache() *TTPCache {
	return &TTPCache{
		cache: make(map[string][]string),
	}
}

// Get obtiene los TTPs cacheados para un CWE, si existe.
func (c *TTPCache) Get(cwe string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ttps, found := c.cache[cwe]
	return ttps, found
}

// Set guarda los TTPs para un CWE en la caché.
func (c *TTPCache) Set(cwe string, ttps []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[cwe] = ttps
}

// Invalidate elimina de la caché la entrada correspondiente a un CWE específico.
func (c *TTPCache) Invalidate(cwe string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, cwe)
}

// FlushAll limpia por completo todas las entradas de la caché.
func (c *TTPCache) FlushAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string][]string)
}
