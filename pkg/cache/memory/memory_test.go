package memory

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCache(t *testing.T) {
	c := New()

	// Test set and get.
	c.Set("key1", "key1")
	v, ok := c.Get("key1")
	if !ok || v != "key1" {
		t.Fatalf("Unexpected value for key1: %v, %v", v, ok)
	}

	// Test exists.
	if !c.Exists("key1") {
		t.Fatalf("Expected key1 to exist")
	}

	// Test the count.
	if c.Count() != 1 {
		t.Fatalf("Unexpected count: %d", c.Count())
	}

	// Test delete.
	c.Delete("key1")
	v, ok = c.Get("key1")
	if ok || v != "" {
		t.Fatalf("Unexpected value for key1 after delete: %v, %v", v, ok)
	}

	// Test clear.
	c.Set("key10", "key10")
	c.Clear()
	v, ok = c.Get("key10")
	if ok || v != "" {
		t.Fatalf("Unexpected value for key10 after clear: %v, %v", v, ok)
	}

	// Test contents.
	keys := []string{"key1", "key2", "key3"}
	for _, k := range keys {
		c.Set(k, k)
	}

	items := c.Contents()
	sort.Strings(keys)
	res := strings.Split(items, ",")
	sort.Strings(res)

	if len(keys) != len(res) {
		t.Fatalf("Unexpected length of items: %d", len(res))
	}
	if !cmp.Equal(keys, res) {
		t.Fatalf("Unexpected items: %v", res)
	}
}

func TestCache_NewWithData(t *testing.T) {
	c := NewWithData([]string{"key1", "key2", "key3"})

	// Test the count.
	if c.Count() != 3 {
		t.Fatalf("Unexpected count: %d", c.Count())
	}

	// Test contents.
	keys := []string{"key1", "key2", "key3"}
	items := c.Contents()
	sort.Strings(keys)
	res := strings.Split(items, ",")
	sort.Strings(res)

	if len(keys) != len(res) {
		t.Fatalf("Unexpected length of items: %d", len(res))
	}
	if !cmp.Equal(keys, res) {
		t.Fatalf("Unexpected items: %v", res)
	}
}

func setupBenchmarks(b *testing.B) *Cache {
	b.Helper()

	c := New()

	for i := 0; i < 500_000; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Set(key, key)
	}

	return c
}

func BenchmarkSet(b *testing.B) {
	c := New()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Set(key, key)
	}
}

func BenchmarkGet(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Get(key)
	}
}

func BenchmarkDelete(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Delete(key)
	}
}

func BenchmarkCount(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Count()
	}
}

func BenchmarkContents(b *testing.B) {
	c := setupBenchmarks(b)
	b.ResetTimer()

	var s string

	for i := 0; i < b.N; i++ {
		s = c.Contents()
	}

	_ = s
}
