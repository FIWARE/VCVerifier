package common

import (
	"errors"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDocumentLoader records calls and returns pre-configured results.
type mockDocumentLoader struct {
	// docs maps URL → document to return.
	docs map[string]*ld.RemoteDocument
	// errs maps URL → error to return.
	errs map[string]error
	// callCount tracks how many times LoadDocument was invoked per URL.
	callCount map[string]int
}

func newMockDocumentLoader() *mockDocumentLoader {
	return &mockDocumentLoader{
		docs:      make(map[string]*ld.RemoteDocument),
		errs:      make(map[string]error),
		callCount: make(map[string]int),
	}
}

func (m *mockDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	m.callCount[u]++
	if err, ok := m.errs[u]; ok {
		return nil, err
	}
	if doc, ok := m.docs[u]; ok {
		return doc, nil
	}
	return nil, errors.New("document not found: " + u)
}

func TestCachingDocumentLoader(t *testing.T) {
	type test struct {
		testName          string
		url               string
		mockDoc           *ld.RemoteDocument
		mockErr           error
		loadCount         int // how many times to call LoadDocument
		expectErr         bool
		expectDelegateCnt int // expected calls to the underlying loader
	}

	sampleDoc := &ld.RemoteDocument{
		DocumentURL: "https://www.w3.org/2018/credentials/v1",
		Document:    map[string]interface{}{"@context": "test"},
	}

	tests := []test{
		{
			testName:          "Cache miss delegates to underlying loader",
			url:               "https://www.w3.org/2018/credentials/v1",
			mockDoc:           sampleDoc,
			loadCount:         1,
			expectErr:         false,
			expectDelegateCnt: 1,
		},
		{
			testName:          "Cache hit returns cached document without delegating",
			url:               "https://www.w3.org/2018/credentials/v1",
			mockDoc:           sampleDoc,
			loadCount:         3,
			expectErr:         false,
			expectDelegateCnt: 1, // only the first call delegates
		},
		{
			testName:          "Error from underlying loader is propagated",
			url:               "https://example.com/bad-context",
			mockErr:           errors.New("network error"),
			loadCount:         1,
			expectErr:         true,
			expectDelegateCnt: 1,
		},
		{
			testName:          "Error is not cached — retry delegates again",
			url:               "https://example.com/transient-error",
			mockErr:           errors.New("transient failure"),
			loadCount:         2,
			expectErr:         true,
			expectDelegateCnt: 2, // each call delegates because errors are not cached
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mock := newMockDocumentLoader()
			if tc.mockDoc != nil {
				mock.docs[tc.url] = tc.mockDoc
			}
			if tc.mockErr != nil {
				mock.errs[tc.url] = tc.mockErr
			}

			loader := NewCachingDocumentLoader(mock, DefaultDocumentCacheTTL, DefaultDocumentCacheCleanup)

			var lastDoc *ld.RemoteDocument
			var lastErr error
			for i := 0; i < tc.loadCount; i++ {
				lastDoc, lastErr = loader.LoadDocument(tc.url)
			}

			if tc.expectErr {
				assert.Error(t, lastErr, "expected an error")
			} else {
				require.NoError(t, lastErr, "expected no error")
				assert.Equal(t, tc.mockDoc, lastDoc, "returned document should match")
			}

			assert.Equal(t, tc.expectDelegateCnt, mock.callCount[tc.url],
				"underlying loader should be called the expected number of times")
		})
	}
}

func TestCachingDocumentLoader_DifferentURLs(t *testing.T) {
	doc1 := &ld.RemoteDocument{
		DocumentURL: "https://example.com/ctx1",
		Document:    map[string]interface{}{"@context": "ctx1"},
	}
	doc2 := &ld.RemoteDocument{
		DocumentURL: "https://example.com/ctx2",
		Document:    map[string]interface{}{"@context": "ctx2"},
	}

	mock := newMockDocumentLoader()
	mock.docs["https://example.com/ctx1"] = doc1
	mock.docs["https://example.com/ctx2"] = doc2

	loader := NewCachingDocumentLoader(mock, DefaultDocumentCacheTTL, DefaultDocumentCacheCleanup)

	// Load both URLs
	result1, err := loader.LoadDocument("https://example.com/ctx1")
	require.NoError(t, err)
	assert.Equal(t, doc1, result1)

	result2, err := loader.LoadDocument("https://example.com/ctx2")
	require.NoError(t, err)
	assert.Equal(t, doc2, result2)

	// Load again — should be cached
	result1Again, err := loader.LoadDocument("https://example.com/ctx1")
	require.NoError(t, err)
	assert.Equal(t, doc1, result1Again)

	// Verify each URL was fetched exactly once from the underlying loader
	assert.Equal(t, 1, mock.callCount["https://example.com/ctx1"])
	assert.Equal(t, 1, mock.callCount["https://example.com/ctx2"])
}
