// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"strings"
)

// contextualError keeps application-owned guidance separate from its stable
// cause. Arguments must contain only the existing non-secret object metadata.
type contextualError struct {
	key   string
	cause error
	args  []any
}

func localError(key string, cause error, args ...any) error {
	return &contextualError{key: key, cause: cause, args: args}
}
func (e *contextualError) Unwrap() error { return e.cause }
func (e *contextualError) Error() string { return e.UserMessage() }
func (e *contextualError) UserMessage() string {
	args := append(append([]any(nil), e.args...), ErrorMessage(e.cause))
	return fmt.Sprintf(strings.ReplaceAll(i18n.T(e.key), "%w", "%s"), args...)
}
