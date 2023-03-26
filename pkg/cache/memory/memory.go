package memory

import (
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

const (
	expirationInterval = 12 * time.Hour
	purgeInterval      = 13 * time.Hour
	defaultExpiration  = cache.DefaultExpiration
)

// Cache is a wrapper around the go-cache library.
type Cache struct {
	c *cache.Cache
}

// New constructs a new in-memory cache.
func New() *Cache {
	c := cache.New(expirationInterval, purgeInterval)
	return &Cache{c: c}
}

// NewWithData constructs a new in-memory cache with existing data.
func NewWithData(data []string) *Cache {
	items := make(map[string]cache.Item, len(data))
	for _, d := range data {
		items[d] = cache.Item{Object: d, Expiration: int64(defaultExpiration)}
	}

	c := cache.NewFrom(expirationInterval, purgeInterval, items)
	return &Cache{c: c}
}

// Set adds a key-value pair to the cache.
func (c *Cache) Set(key, value string) {
	c.c.Set(key, value, defaultExpiration)
}

// Get returns the value for the given key.
func (c *Cache) Get(key string) (string, bool) {
	res, ok := c.c.Get(key)
	if !ok {
		return "", ok
	}
	return res.(string), ok
}

// Exists returns true if the given key exists in the cache.
func (c *Cache) Exists(key string) bool {
	_, ok := c.c.Get(key)
	return ok
}

// Delete removes the key-value pair from the cache.
func (c *Cache) Delete(key string) {
	c.c.Delete(key)
}

// Clear removes all key-value pairs from the cache.
func (c *Cache) Clear() {
	c.c.Flush()
}

// Count returns the number of key-value pairs in the cache.
func (c *Cache) Count() int {
	return c.c.ItemCount()
}

// Contents returns all key-value pairs in the cache encodes as a string.
func (c *Cache) Contents() string {
	items := c.c.Items()
	res := make([]string, 0, len(items))
	for k := range items {
		res = append(res, k)
	}
	return strings.Join(res, ",")
}
