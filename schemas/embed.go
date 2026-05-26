package schemas

import "embed"

// Files contains the analyzer contract schemas used by Go-side validation.
//
//go:embed analyzer-input.schema.json analyzer-output.schema.json finding.schema.json evidence/evidence-ref.v1.schema.json
var Files embed.FS
