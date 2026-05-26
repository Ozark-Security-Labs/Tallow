package analyzers

import (
	"encoding/json"
	"fmt"
)

func ValidateInputJSON(data []byte) error {
	var input AnalyzerInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("invalid analyzer input json: %w", err)
	}
	if input.ContractVersion != ContractVersion || input.JobID == "" || input.AnalysisType == "" {
		return fmt.Errorf("analyzer input missing required contract fields")
	}
	if input.Subject.Ecosystem == "" || input.Subject.PackageName == "" {
		return fmt.Errorf("analyzer input missing subject")
	}
	return nil
}

func ValidateOutputJSON(data []byte) (*AnalyzerOutput, error) {
	var output AnalyzerOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid analyzer output json: %w", err)
	}
	if output.ContractVersion != ContractVersion || output.JobID == "" {
		return nil, fmt.Errorf("analyzer output missing required contract fields")
	}
	if output.Analyzer.ID == "" || output.Analyzer.Version == "" || output.Analyzer.RulesetVersion == "" {
		return nil, fmt.Errorf("analyzer output missing analyzer identity")
	}
	if output.Status != "ok" && output.Status != "failed" {
		return nil, fmt.Errorf("analyzer output has invalid status")
	}
	for _, finding := range output.Findings {
		if finding.ID == "" || finding.RuleID == "" || finding.AnalyzerID == "" {
			return nil, fmt.Errorf("analyzer output finding missing stable identity")
		}
		if len(finding.Evidence) == 0 {
			return nil, fmt.Errorf("analyzer output finding missing evidence")
		}
	}
	return &output, nil
}
