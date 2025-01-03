package verifier

import (
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"github.com/piprate/json-gold/ld"
)

type CachingDocumentLoader struct {
	defaultLoader ld.DocumentLoader
	contextCache  common.Cache
}

func NewCachingDocumentLoader(defaultLoader ld.DocumentLoader) ld.DocumentLoader {
	return CachingDocumentLoader{defaultLoader: defaultLoader,
		contextCache: cache.New(time.Duration(300)*time.Second, time.Duration(600)*time.Second)}
}

func (cdl CachingDocumentLoader) LoadDocument(u string) (document *ld.RemoteDocument, err error) {
	cachedDocument, hit := cdl.contextCache.Get(u)
	if hit {
		return cachedDocument.(*ld.RemoteDocument), err
	}
	document, err = cdl.defaultLoader.LoadDocument(u)
	if err != nil {
		logging.Log().Infof("Was not able to load %s", u)
		return document, err
	}
	cdl.contextCache.Set(u, document, cache.DefaultExpiration)
	return document, err
}
