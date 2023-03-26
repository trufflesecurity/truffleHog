package gcs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestPersistableCache(t *testing.T) {
	// Create a new Progress object for testing.
	progress := sources.Progress{}

	tests := []struct {
		name string
		cfgs []persistibleCacheConfiguration
		fn   func(cache *persistableCache)
	}{
		{
			name: "withMemoryPersistableCache",
			cfgs: []persistibleCacheConfiguration{withMemoryPersistableCache()},
			fn: func(cache *persistableCache) {
				assert.NotNil(t, cache.Cache)
				assert.IsType(t, &memory.Cache{}, cache.Cache)
			},
		},
		{
			name: "withMemoryLoadedPersistableCache",
			cfgs: []persistibleCacheConfiguration{withMemoryLoadedPersistableCache([]string{"foo", "bar"})},
			fn: func(cache *persistableCache) {
				assert.NotNil(t, cache.Cache)
				assert.IsType(t, &memory.Cache{}, cache.Cache)
				assert.Contains(t, cache.Cache.Contents(), "foo,bar")
			},
		},
		{
			name: "withCustomIncrement",
			cfgs: []persistibleCacheConfiguration{withCustomIncrement(100)},
			fn: func(cache *persistableCache) {
				assert.Equal(t, 100, cache.persistIncrement)
			},
		},
		{
			name: "Set",
			cfgs: []persistibleCacheConfiguration{withMemoryPersistableCache(), withCustomIncrement(3)},
			fn: func(cache *persistableCache) {
				cache.Set("foo", "bar")
				assert.Equal(t, 1, cache.Count())

				cache.Set("baz", "qux")
				assert.Equal(t, 2, cache.Count())

				// The cache should not persist until the increment (3) is reached.
				assert.False(t, progress.EncodedResumeInfo != "")

				cache.Set("quux", "corge")
				assert.Equal(t, 3, cache.Count())

				// The cache should now persist.
				assert.True(t, progress.EncodedResumeInfo != "")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := newPersistableCache(&progress, test.cfgs...)
			assert.NotNil(t, cache)
			test.fn(cache)
		})
	}
}
