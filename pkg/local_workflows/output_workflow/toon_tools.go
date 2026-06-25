package output_workflow

import (
	"context"
	"fmt"
	"strings"

	toon "github.com/toon-format/toon-go"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils/findingsummary"
)

var toonSeverityOrder = []string{"critical", "high", "medium", "low"}

// renderLFMToTOON renders LocalFinding data to the TOON format for the given writer.
// If renderEmptyData is false and there are no findings, nothing is written.
func renderLFMToTOON(w *WriterEntry, findings []*local_models.LocalFinding, full bool) error {
	defer w.writer.Close()

	var allFindings []findingsummary.MinimalFinding
	allCounts := map[string]int{}

	for _, lf := range findings {
		if lf == nil {
			continue
		}
		f, c := findingsummary.MinimalFromLocalFinding(*lf, full)
		allFindings = append(allFindings, f...)
		for k, v := range c {
			allCounts[k] += v
		}
	}

	total := len(allFindings)
	if !w.renderEmptyData && total == 0 {
		return nil
	}

	doc := toon.NewObject(
		toon.Field{Key: "findings", Value: allFindings},
		toon.Field{Key: "summary", Value: findingsSummary(total, allCounts)},
	)
	s, err := toon.MarshalString(doc)
	if err != nil {
		return fmt.Errorf("toon: marshal LFM findings: %w", err)
	}
	_, err = fmt.Fprintln(w.writer, s)
	return err
}

// renderUFMToTOON renders UFM TestResults to the TOON format for the given writer.
// If renderEmptyData is false and there are no findings, nothing is written.
func renderUFMToTOON(ctx context.Context, w *WriterEntry, results []testapi.TestResult, full bool) error {
	defer w.writer.Close()

	mf, counts := findingsummary.MinimalFromUFM(ctx, results, full)
	total := len(mf)

	if !w.renderEmptyData && total == 0 {
		return nil
	}

	if mf == nil {
		mf = []findingsummary.MinimalFinding{}
	}

	doc := toon.NewObject(
		toon.Field{Key: "findings", Value: mf},
		toon.Field{Key: "summary", Value: findingsSummary(total, counts)},
	)
	s, err := toon.MarshalString(doc)
	if err != nil {
		return fmt.Errorf("toon: marshal UFM findings: %w", err)
	}
	_, err = fmt.Fprintln(w.writer, s)
	return err
}

// findingsSummary builds a human-readable summary string: "N issues | X critical Y high …"
func findingsSummary(total int, counts map[string]int) string {
	if total == 0 {
		return "0 issues found"
	}
	var parts []string
	for _, s := range toonSeverityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d issues found", total)
	}
	return fmt.Sprintf("%d issues | %s", total, strings.Join(parts, " "))
}
