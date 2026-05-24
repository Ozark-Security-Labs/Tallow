package diff

import "encoding/json"

func Write(d Diff) ([]byte, error) { return json.MarshalIndent(d, "", "  ") }
