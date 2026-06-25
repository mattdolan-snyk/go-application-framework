package findingsummary

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

const messageMaxLen = 200

// MinimalFinding is the scanner-agnostic summary of one finding for TOON output.
type MinimalFinding struct {
	Rule     string `toon:"rule"`
	Severity string `toon:"severity"`
	File     string `toon:"file"`
	Line     int    `toon:"line"`
	Message  string `toon:"message,omitempty"`
}

// MinimalFromLFMBytes parses a LocalFinding JSON payload and extracts minimal findings.
// Returns nil slices on parse error.
func MinimalFromLFMBytes(raw []byte, full bool) ([]MinimalFinding, map[string]int) {
	var lf local_models.LocalFinding
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, nil
	}
	return MinimalFromLocalFinding(lf, full)
}

// MinimalFromLocalFinding converts a LocalFinding to the minimal representation used by TOON rendering.
func MinimalFromLocalFinding(lf local_models.LocalFinding, full bool) ([]MinimalFinding, map[string]int) {
	counts := map[string]int{}
	findings := make([]MinimalFinding, 0, len(lf.Findings))

	for _, f := range lf.Findings {
		attr := f.Attributes

		severity := "low"
		if attr.Rating != nil {
			if v := strings.ToLower(string(attr.Rating.Severity.Value)); v != "" {
				severity = v
			}
		}
		counts[severity]++

		file := "unknown"
		line := 0
		if attr.Locations != nil && len(*attr.Locations) > 0 {
			if src := (*attr.Locations)[0].SourceLocations; src != nil {
				if src.Filepath != "" {
					file = src.Filepath
				}
				line = src.OriginalStartLine
			}
		}

		mf := MinimalFinding{
			Rule:     lfmRule(attr),
			Severity: severity,
			File:     file,
			Line:     line,
		}
		if full {
			mf.Message = truncate(lfmMessage(attr), messageMaxLen)
		}
		findings = append(findings, mf)
	}

	return findings, counts
}

// MinimalFromUFM converts TestResults to minimal findings. Calls Findings(ctx) on each result,
// which for deserialized results is a local cache hit (no network call).
func MinimalFromUFM(ctx context.Context, results []testapi.TestResult, full bool) ([]MinimalFinding, map[string]int) {
	if len(results) == 0 {
		return nil, nil
	}

	counts := map[string]int{}
	var findings []MinimalFinding

	for _, r := range results {
		data, _, err := r.Findings(ctx)
		if err != nil {
			continue
		}
		for _, fd := range data {
			if fd.Attributes == nil {
				continue
			}
			a := fd.Attributes

			severity := strings.ToLower(string(a.Rating.Severity))
			if severity == "" {
				severity = "low"
			}
			counts[severity]++

			file := "unknown"
			line := 0
			if len(a.Locations) > 0 {
				if src, err := a.Locations[0].AsSourceLocation(); err == nil {
					if src.FilePath != "" {
						file = src.FilePath
					}
					line = src.FromLine
				}
			}

			mf := MinimalFinding{
				Rule:     ufmRule(a),
				Severity: severity,
				File:     file,
				Line:     line,
			}
			if full {
				mf.Message = truncate(a.Description, messageMaxLen)
			}
			findings = append(findings, mf)
		}
	}

	return findings, counts
}

// lfmRule extracts the SAST rule identifier from LFM attributes.
// ReferenceId is canonical; component name is the fallback.
func lfmRule(attr local_models.TypesFindingAttributes) string {
	if attr.ReferenceId != nil && attr.ReferenceId.Identifier != "" {
		return attr.ReferenceId.Identifier
	}
	return attr.Component.Name
}

func lfmMessage(attr local_models.TypesFindingAttributes) string {
	if attr.Message.Text != "" {
		return attr.Message.Text
	}
	return attr.Message.Header
}

// ufmRule extracts the secret-type identifier from UFM finding attributes.
func ufmRule(a *testapi.FindingAttributes) string {
	if len(a.Problems) > 0 {
		if p, err := a.Problems[0].AsSecretsRuleProblem(); err == nil && p.Id != "" {
			return p.Id
		}
	}
	if a.Title != "" {
		return a.Title
	}
	return "secret"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…(+" + itoa(len(s)-max) + " chars)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
