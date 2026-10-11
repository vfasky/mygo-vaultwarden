// SPDX-License-Identifier: GPL-3.0-only
package i18n

// MessageError is an application-owned, safe display message. Its identity is
// independent of language; translation happens only when the error is displayed.
// Do not use it for server response bodies, secrets, or arbitrary error strings.
type MessageError struct{ key string }

func Error(key string) error                { return &MessageError{key: key} }
func (e *MessageError) Error() string       { return T(e.key) }
func (e *MessageError) UserMessage() string { return e.Error() }
