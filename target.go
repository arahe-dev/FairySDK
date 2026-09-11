package fairy

import (
	"github.com/arahe-dev/fairy/internal/model"
)

// Target is the subject of a survey: a parsed URL, host and port.
type Target = model.Target

// ParseTarget parses a raw URL into a Target. Only http and https are
// accepted; the port defaults to 443 (https) or 80 (http).
func ParseTarget(raw string) (Target, error) {
	return model.ParseTarget(raw)
}
