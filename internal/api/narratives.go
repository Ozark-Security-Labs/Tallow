package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Ozark-Security-Labs/Tallow/internal/llm"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

func (s *Server) createNarrative(w http.ResponseWriter, r *http.Request) {
	if !s.Config.LLM.Enabled {
		writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "llm narrative enrichment is disabled"))
		return
	}
	if s.Narratives == nil {
		writeError(w, r, tallowerr.New(tallowerr.CodeInternal, "llm narrative service unavailable"))
		return
	}
	var input llm.GenerateInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "invalid narrative request"))
		return
	}
	narrative, err := s.Narratives.GenerateNarrative(r.Context(), input)
	if err != nil {
		if errors.Is(err, llm.ErrDisabled) {
			writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "llm narrative enrichment is disabled"))
			return
		}
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"narrative": narrative, "source": "llm_narrative"})
}
