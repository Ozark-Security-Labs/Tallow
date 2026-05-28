package narrative

import (
	"context"
	"testing"
)

func TestNarrativeStoreSeparateRecord(t *testing.T) {
	s := &MemoryStore{}
	if err := s.Save(context.Background(), Record{ID: "N-1", FindingIDs: []string{"F-1"}, CanonicalSeverity: "high", ValidationStatus: "validated"}); err != nil {
		t.Fatal(err)
	}
	records, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].FindingIDs[0] != "F-1" {
		t.Fatalf("records=%+v", records)
	}
}
