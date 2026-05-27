package analyzers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	contractschemas "github.com/Ozark-Security-Labs/Tallow/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaBaseURL = "https://tallow.osl.dev/schemas/"

var (
	schemaOnce      sync.Once
	schemaLoadErr   error
	inputSchema     *jsonschema.Schema
	outputSchema    *jsonschema.Schema
	findingSchema   *jsonschema.Schema
	schemaFilenames = []string{
		"analyzer-input.schema.json",
		"analyzer-output.schema.json",
		"finding.schema.json",
		"evidence/evidence-ref.v1.schema.json",
	}
)

func ValidateInputJSON(data []byte) error {
	if err := validateJSON(inputContractSchema, data); err != nil {
		return fmt.Errorf("invalid analyzer input schema: %w", err)
	}
	var input AnalyzerInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("invalid analyzer input json: %w", err)
	}
	return nil
}

func ValidateOutputJSON(data []byte) (*AnalyzerOutput, error) {
	if err := validateJSON(outputContractSchema, data); err != nil {
		return nil, fmt.Errorf("invalid analyzer output schema: %w", err)
	}
	var output AnalyzerOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("invalid analyzer output json: %w", err)
	}
	return &output, nil
}

func validateFindingJSON(data []byte) error {
	if err := validateJSON(findingContractSchema, data); err != nil {
		return fmt.Errorf("invalid finding schema: %w", err)
	}
	return nil
}

func validateJSON(schemaFn func() (*jsonschema.Schema, error), data []byte) error {
	schema, err := schemaFn()
	if err != nil {
		return err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return schema.Validate(instance)
}

func inputContractSchema() (*jsonschema.Schema, error) {
	if err := loadContractSchemas(); err != nil {
		return nil, err
	}
	return inputSchema, nil
}

func outputContractSchema() (*jsonschema.Schema, error) {
	if err := loadContractSchemas(); err != nil {
		return nil, err
	}
	return outputSchema, nil
}

func findingContractSchema() (*jsonschema.Schema, error) {
	if err := loadContractSchemas(); err != nil {
		return nil, err
	}
	return findingSchema, nil
}

func loadContractSchemas() error {
	schemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.AssertFormat()
		for _, name := range schemaFilenames {
			doc, err := readSchema(name)
			if err != nil {
				schemaLoadErr = err
				return
			}
			if err := compiler.AddResource(schemaBaseURL+name, doc); err != nil {
				schemaLoadErr = err
				return
			}
		}
		inputSchema, schemaLoadErr = compiler.Compile(schemaBaseURL + "analyzer-input.schema.json")
		if schemaLoadErr != nil {
			return
		}
		outputSchema, schemaLoadErr = compiler.Compile(schemaBaseURL + "analyzer-output.schema.json")
		if schemaLoadErr != nil {
			return
		}
		findingSchema, schemaLoadErr = compiler.Compile(schemaBaseURL + "finding.schema.json")
	})
	return schemaLoadErr
}

func readSchema(name string) (any, error) {
	data, err := contractschemas.Files.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(data))
}
