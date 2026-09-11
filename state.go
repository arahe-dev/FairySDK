package fairy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// SurveyState is the full, JSON-serializable state of one survey.
// Observations accumulate across rounds; every completed experiment is
// immutable and the same experiment ID is never recorded twice.
type SurveyState = model.SurveyState

// ErrDuplicateExperiment is returned when an already-recorded experiment
// is added to a SurveyState again.
var ErrDuplicateExperiment = model.ErrDuplicateExperiment

// NewSurveyState starts a fresh survey state for a target.
func NewSurveyState(t Target) *SurveyState {
	return &model.SurveyState{
		SurveyID:  newSurveyID(),
		Target:    &t,
		StartedAt: time.Now(),
	}
}

// SaveState serializes a survey state for persistence.
func SaveState(s SurveyState) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("fairy: save state: %w", err)
	}
	return b, nil
}

// LoadState deserializes a persisted survey state.
func LoadState(b []byte) (SurveyState, error) {
	var s SurveyState
	if err := json.Unmarshal(b, &s); err != nil {
		return SurveyState{}, fmt.Errorf("fairy: load state: %w", err)
	}
	return s, nil
}

// newSurveyID returns a random survey identifier.
func newSurveyID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "survey-unknown"
	}
	return hex.EncodeToString(b[:])
}
