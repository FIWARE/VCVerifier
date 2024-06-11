package openapi

import (
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/patrickmn/go-cache"
	"github.com/piprate/json-gold/ld"
)

type CachingDocumentLoader struct {
	defaultLoader ld.DocumentLoader
	contextCache  common.Cache
}

func NewCachingDocumentLoader(defaultLoader ld.DocumentLoader) ld.DocumentLoader {
	return CachingDocumentLoader{defaultLoader: defaultLoader,
		contextCache: cache.New(time.Duration(30)*time.Second, time.Duration(60)*time.Second)}
}

func (cdl CachingDocumentLoader) LoadDocument(u string) (doc *ld.RemoteDocument, err error) {
	document, hit := cdl.contextCache.Get(u)
	if hit {
		return document.(*ld.RemoteDocument), err
	}
	document, err = cdl.defaultLoader.LoadDocument(u)
	if err != nil {
		return doc, err
	}
	cdl.contextCache.Set(u, document, cache.DefaultExpiration)
	return doc, err
}
