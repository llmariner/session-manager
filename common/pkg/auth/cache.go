package auth

import (
	"context"
	"sync"
	"time"
)

func newCacheWithCleaner(ctx context.Context, expiration, cleanup time.Duration) *cache {
	c := &cache{expiration: expiration}
	go func() {
		ticker := time.NewTicker(cleanup)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

type cacheItem struct {
	value      string
	expiration time.Time
}

type cache struct {
	expiration time.Duration
	items      sync.Map
}

func (c *cache) set(key string, value string) {
	exp := time.Now().Add(c.expiration)
	c.items.Store(key, cacheItem{value: value, expiration: exp})
}

func (c *cache) get(key string) (string, bool) {
	v, ok := c.items.Load(key)
	if !ok {
		return "", false
	}
	item, ok := v.(cacheItem)
	if !ok || time.Now().After(item.expiration) {
		c.items.Delete(key)
		return "", false
	}
	return item.value, true
}

func (c *cache) cleanup() {
	now := time.Now()
	c.items.Range(func(key, value any) bool {
		item, ok := value.(cacheItem)
		if !ok || now.After(item.expiration) {
			c.items.Delete(key)
		}
		return true
	})
}
