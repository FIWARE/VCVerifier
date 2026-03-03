package common

import (
	"time"

	"github.com/patrickmn/go-cache"
)

const CacheExpiry = 60

type Cache interface {
	Add(k string, x interface{}, d time.Duration) error
	Get(k string) (interface{}, bool)
	Set(k string, x interface{}, d time.Duration)
	GetWithExpiration(k string) (interface{}, time.Time, bool)
	Delete(k string)
}

type AllCaches struct {
	ServiceCache Cache
	TirEndpoints Cache
	IssuersCache Cache
	IssuerCache  Cache
}

func initCache() *AllCaches {
	return &AllCaches{
		ServiceCache: cache.New(CacheExpiry*time.Second, 2*CacheExpiry*time.Second),
		TirEndpoints: cache.New(CacheExpiry*time.Second, 2*CacheExpiry*time.Second),
		IssuersCache: cache.New(CacheExpiry*time.Second, 2*CacheExpiry*time.Second),
		IssuerCache:  cache.New(CacheExpiry*time.Second, 2*CacheExpiry*time.Second)}
}

var GlobalCache = initCache()

func ResetGlobalCache() {
	GlobalCache = initCache()
}
