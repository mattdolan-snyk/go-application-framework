package output_workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func loadToonFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../utils/findingsummary/testdata/" + name)
	require.NoError(t, err)
	return data
}

func toonWriterEntry(buf *bytes.Buffer, renderEmpty bool) *WriterEntry {
	return &WriterEntry{
		writer:          &nopCloser{writer: buf},
		mimeType:        TOON_MIME_TYPE,
		renderEmptyData: renderEmpty,
		name:            "test",
	}
}

// --- LFM → TOON ---

func Test_renderLFMToTOON_ContainsKeyFields(t *testing.T) {
	raw := loadToonFixture(t, "code-lfm.json")

	var lf local_models.LocalFinding
	require.NoError(t, json.Unmarshal(raw, &lf))

	buf := &bytes.Buffer{}
	err := renderLFMToTOON(toonWriterEntry(buf, true), []*local_models.LocalFinding{&lf}, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "javascript/DisablePoweredBy", "rule id present")
	assert.Contains(t, out, "medium", "severity present")
	assert.Contains(t, out, "app.js", "file present")
	assert.NotContains(t, out, "Disable X-Powered-By", "message absent when full=false")
}

func Test_renderLFMToTOON_FullIncludesMessage(t *testing.T) {
	raw := loadToonFixture(t, "code-lfm.json")

	var lf local_models.LocalFinding
	require.NoError(t, json.Unmarshal(raw, &lf))

	buf := &bytes.Buffer{}
	err := renderLFMToTOON(toonWriterEntry(buf, true), []*local_models.LocalFinding{&lf}, true)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Disable X-Powered-By", "message present when full=true")
}

func Test_renderLFMToTOON_EmptySkipped(t *testing.T) {
	var lf local_models.LocalFinding

	buf := &bytes.Buffer{}
	err := renderLFMToTOON(toonWriterEntry(buf, false), []*local_models.LocalFinding{&lf}, false)
	require.NoError(t, err)
	assert.Empty(t, buf.String(), "empty findings not rendered when renderEmptyData=false")
}

func Test_renderLFMToTOON_EmptyRendered(t *testing.T) {
	var lf local_models.LocalFinding

	buf := &bytes.Buffer{}
	err := renderLFMToTOON(toonWriterEntry(buf, true), []*local_models.LocalFinding{&lf}, false)
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(buf.String()), "0", "zero count in output")
}

// --- UFM → TOON ---

func Test_renderUFMToTOON_ContainsKeyFields(t *testing.T) {
	raw := loadToonFixture(t, "secrets-ufm.json")

	results, err := ufm.NewSerializableTestResultFromBytes(raw)
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	err = renderUFMToTOON(context.Background(), toonWriterEntry(buf, true), results, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "AWS Access Token", "rule id present")
	assert.Contains(t, out, "critical", "severity present")
	assert.Contains(t, out, "app.py", "file present")
}

// --- summary helper ---

func Test_findingsSummary_NonEmpty(t *testing.T) {
	counts := map[string]int{"critical": 2, "high": 1}
	s := findingsSummary(3, counts)
	assert.Contains(t, s, "3")
	assert.Contains(t, s, "critical")
	assert.Contains(t, s, "high")
}

func Test_findingsSummary_Zero(t *testing.T) {
	s := findingsSummary(0, map[string]int{})
	assert.Contains(t, strings.ToLower(s), "0")
}
