package common

import (
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/piprate/json-gold/ld"
)

// Default cache TTL values for the CachingDocumentLoader.
const (
	// DefaultDocumentCacheTTL is the default time-to-live for cached
	// JSON-LD context documents (5 minutes).
	DefaultDocumentCacheTTL = 300 * time.Second

	// DefaultDocumentCacheCleanup is the default cleanup interval for
	// expired entries in the document cache (10 minutes).
	DefaultDocumentCacheCleanup = 600 * time.Second
)

// CachingDocumentLoader wraps an ld.DocumentLoader and caches fetched
// JSON-LD context documents in memory. Subsequent requests for the same
// URL return the cached result until the entry expires, avoiding
// redundant network round-trips for well-known @context URLs.
type CachingDocumentLoader struct {
	defaultLoader ld.DocumentLoader
	contextCache  Cache
}

// NewCachingDocumentLoader creates a CachingDocumentLoader that delegates
// to defaultLoader on cache misses. Cached documents expire after cacheTTL
// and the internal cleanup goroutine runs at cacheCleanup intervals.
//
// Pass DefaultDocumentCacheTTL and DefaultDocumentCacheCleanup for the
// standard configuration.
func NewCachingDocumentLoader(defaultLoader ld.DocumentLoader, cacheTTL, cacheCleanup time.Duration) ld.DocumentLoader {
	return &CachingDocumentLoader{
		defaultLoader: defaultLoader,
		contextCache:  cache.New(cacheTTL, cacheCleanup),
	}
}

// LoadDocument returns the cached document for the given URL, or fetches
// it via the underlying loader on a cache miss and stores the result.
func (cdl *CachingDocumentLoader) LoadDocument(u string) (document *ld.RemoteDocument, err error) {
	cachedDocument, hit := cdl.contextCache.Get(u)
	if hit {
		return cachedDocument.(*ld.RemoteDocument), nil
	}
	document, err = cdl.defaultLoader.LoadDocument(u)
	if err != nil {
		return document, err
	}
	cdl.contextCache.Set(u, document, cache.DefaultExpiration)
	return document, nil
}
