package findingsummary_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/utils/findingsummary"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

// --- MinimalFromLFMBytes ---

func TestMinimalFromLFMBytes_Fields(t *testing.T) {
	raw := loadFixture(t, "code-lfm.json")

	findings, counts := findingsummary.MinimalFromLFMBytes(raw, false)

	require.Len(t, findings, 3)

	assert.Equal(t, "javascript/DisablePoweredBy", findings[0].Rule)
	assert.Equal(t, "medium", findings[0].Severity)
	assert.Equal(t, "app.js", findings[0].File)
	assert.Equal(t, 27, findings[0].Line)
	assert.Empty(t, findings[0].Message, "message absent when full=false")

	assert.Equal(t, "javascript/HardcodedNonCryptoSecret", findings[1].Rule)
	assert.Equal(t, "high", findings[1].Severity)
	assert.Equal(t, "app.js", findings[1].File)
	assert.Equal(t, 73, findings[1].Line)

	assert.Equal(t, "javascript/NoSqli", findings[2].Rule)
	assert.Equal(t, "high", findings[2].Severity)
	assert.Equal(t, "routes/index.js", findings[2].File)
	assert.Equal(t, 39, findings[2].Line)

	assert.Equal(t, 2, counts["high"])
	assert.Equal(t, 1, counts["medium"])
}

func TestMinimalFromLFMBytes_FullMessage(t *testing.T) {
	raw := loadFixture(t, "code-lfm.json")

	findings, _ := findingsummary.MinimalFromLFMBytes(raw, true)

	require.NotEmpty(t, findings)
	assert.Equal(t, "Disable X-Powered-By header for your Express app (consider using Helmet middleware).", findings[0].Message)
}

func TestMinimalFromLFMBytes_Empty(t *testing.T) {
	empty := []byte(`{"findings":[],"outcome":{},"rules":[],"summary":{},"links":{}}`)

	findings, counts := findingsummary.MinimalFromLFMBytes(empty, false)

	assert.Empty(t, findings)
	assert.Empty(t, counts)
}

func TestMinimalFromLFMBytes_InvalidJSON(t *testing.T) {
	findings, counts := findingsummary.MinimalFromLFMBytes([]byte(`not json`), false)
	assert.Nil(t, findings)
	assert.Nil(t, counts)
}

// --- MinimalFromUFM ---

func TestMinimalFromUFM_Fields(t *testing.T) {
	raw := loadFixture(t, "secrets-ufm.json")

	// Deserialize the fixture as a serializable test result (same format the ufm package produces).
	results, err := ufm.NewSerializableTestResultFromBytes(raw)
	require.NoError(t, err)
	require.Len(t, results, 1)

	ctx := context.Background()
	findings, counts := findingsummary.MinimalFromUFM(ctx, results, false)

	require.Len(t, findings, 2)

	assert.Equal(t, "AWS Access Token", findings[0].Rule)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, "app.py", findings[0].File)
	assert.Equal(t, 1, findings[0].Line)
	assert.Empty(t, findings[0].Message, "message absent when full=false")

	assert.Equal(t, "Slack Bot Token", findings[1].Rule)
	assert.Equal(t, "high", findings[1].Severity)
	assert.Equal(t, "app.py", findings[1].File)
	assert.Equal(t, 5, findings[1].Line)

	assert.Equal(t, 1, counts["critical"])
	assert.Equal(t, 1, counts["high"])
}

func TestMinimalFromUFM_Empty(t *testing.T) {
	ctx := context.Background()
	findings, counts := findingsummary.MinimalFromUFM(ctx, nil, false)
	assert.Empty(t, findings)
	assert.Empty(t, counts)
}
