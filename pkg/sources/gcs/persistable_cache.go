package gcs

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const defaultCachePersistIncrement = 2500

type persistibleCacheConfiguration func(c *persistableCache)

// persistableCache handles all cache operations with some additional bookkeeping.
// The threshold value is the percentage of objects that must be processed
// before the cache is persisted.
type persistableCache struct {
	persistIncrement int
	cache.Cache
	*sources.Progress
}

func newPersistableCache(p *sources.Progress, cfgs ...persistibleCacheConfiguration) *persistableCache {
	pc := &persistableCache{
		persistIncrement: defaultCachePersistIncrement,
		Progress:         p,
	}

	for _, cfg := range cfgs {
		cfg(pc)
	}
	return pc
}

// withMemoryPersistableCache configures the persistableCache to use an in-memory cache.
func withMemoryPersistableCache() persistibleCacheConfiguration {
	return func(pc *persistableCache) {
		pc.Cache = memory.New()
	}
}

// withMemoryLoadedPersistableCache configures the persistableCache to use an in-memory cache with the given contents.
func withMemoryLoadedPersistableCache(contents []string) persistibleCacheConfiguration {
	return func(pc *persistableCache) {
		pc.Cache = memory.NewWithData(contents)
	}
}

// withCustomIncrement configures the persistableCache to use the given increment.
func withCustomIncrement(increment int) persistibleCacheConfiguration {
	return func(pc *persistableCache) {
		pc.persistIncrement = increment
	}
}

// Set overrides the default Set method in order to persist the cache contents
// on each persistIncrement.
func (c *persistableCache) Set(key, value string) {
	c.Cache.Set(key, value)

	if ok, val := c.shouldPersist(); ok {
		c.EncodedResumeInfo = val
	}
}

func (c *persistableCache) shouldPersist() (bool, string) {
	if c.Count()%c.persistIncrement != 0 {
		return false, ""
	}
	return true, c.Contents()
}
