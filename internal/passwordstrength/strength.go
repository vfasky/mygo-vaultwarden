// SPDX-License-Identifier: GPL-3.0-only
// Package passwordstrength evaluates the fixed Bitwarden clients estimator.
// It returns no password, matched tokens, feedback, or user inputs.
package passwordstrength

import (
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
	"github.com/dop251/goja/parser"
	"github.com/vfasky/mygo-vaultwarden/third_party/zxcvbn"
)

// This wrapper mirrors PasswordStrengthService at the pinned clients commit.
// Keeping normalization in JS preserves UTF-16, trim and toLowerCase semantics.
const wrapper = `
function evaluateMyGoStrength(password, email, userInputs) {
 if (password == null || password.length === 0) return null;
 var inputs = ["bitwarden", "bit", "warden"].concat(userInputs || []);
 if (email != null && email.length !== 0) {
  var at = email.indexOf("@");
  if (at >= 0) inputs = inputs.concat(email.substring(0, at).trim().toLowerCase().split(/[^A-Za-z0-9]/));
 }
 var unique = [];
 for (var i = 0; i < inputs.length; i++) {
  if (unique.indexOf(inputs[i]) === -1) unique.push(inputs[i]);
 }
 var result = module.exports(password, unique);
 return {score: result.score, guessesLog10: result.guesses_log10};
}
`

var (
	ErrInput      = errors.New("invalid password strength input")
	ErrEvaluation = errors.New("password strength evaluation failed")
	compileOnce   sync.Once
	compiled      *goja.Program
	compileError  error
)

// Result exposes only the two numeric estimator outputs needed for policy and
// strength display. It is not proof of password secrecy or resistance to attack.
type Result struct {
	Score        int     `json:"score"`
	GuessesLog10 float64 `json:"guessesLog10"`
}

// CheckMinimum compares the official integer score with a type-1 policy's
// minComplexity. Empty passwords never satisfy a minimum, including zero.
// Callers still must enforce length and the other policy requirements separately.
func CheckMinimum(ctx context.Context, password, email string, userInputs []string, minimum int) (bool, error) {
	if minimum < 0 || minimum > 4 {
		return false, ErrInput
	}
	result, err := Evaluate(ctx, password, email, userInputs)
	if err != nil || result == nil {
		return false, err
	}
	return result.Score >= minimum, nil
}

// Evaluate preserves zxcvbn 4.4.2 scoring and Bitwarden's additional inputs.
// The bounds are application resource limits, not changes to scoring: input is
// never truncated. A caller must surface an error instead of treating it as a
// passing score. Empty password has no score, matching the official service.
// Each evaluation uses a fresh interpreter with no host IO bindings or runtime
// reuse. Go/JS managed strings cannot provide guaranteed memory zeroization.
func Evaluate(ctx context.Context, password, email string, userInputs []string) (*Result, error) {
	return evaluate(ctx, password, email, userInputs, time.Now)
}

func evaluate(ctx context.Context, password, email string, userInputs []string, clock func() time.Time) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !utf8.ValidString(password) || !utf8.ValidString(email) || len(password) > 1024 || len(email) > 1024 || len(userInputs) > 64 {
		return nil, ErrInput
	}
	total := len(password) + len(email)
	for _, input := range userInputs {
		if !utf8.ValidString(input) || len(input) > 1024 {
			return nil, ErrInput
		}
		total += len(input)
	}
	if total > 16384 {
		return nil, ErrInput
	}
	if password == "" {
		return nil, nil
	}
	compileOnce.Do(func() {
		// The original distribution retains its sourceMappingURL comment.
		// Disable source maps explicitly so compilation performs no file lookup.
		parsed, err := goja.Parse("zxcvbn-4.4.2", "var module = {exports: {}}; var exports = module.exports;\n"+zxcvbn.Script+"\n"+wrapper, parser.WithDisableSourceMaps)
		if err != nil {
			compileError = err
			return
		}
		compiled, compileError = goja.CompileAST(parsed, false)
	})
	if compileError != nil {
		return nil, ErrEvaluation
	}
	// Interrupt the interpreter, including dictionary initialization, on caller
	// cancellation or a fixed budget. Errors never expose interpreter exceptions,
	// stack traces, or secret arguments to callers.
	limited, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime := goja.New()
	runtime.SetTimeSource(clock)
	runtime.SetMaxCallStackSize(1024)
	stop := context.AfterFunc(limited, func() { runtime.Interrupt(ErrEvaluation) })
	defer stop()
	if _, err := runtime.RunProgram(compiled); err != nil {
		if limited.Err() != nil {
			return nil, limited.Err()
		}
		return nil, ErrEvaluation
	}
	call, ok := goja.AssertFunction(runtime.Get("evaluateMyGoStrength"))
	if !ok {
		return nil, ErrEvaluation
	}
	value, err := call(goja.Undefined(), runtime.ToValue(password), runtime.ToValue(email), runtime.ToValue(userInputs))
	if err != nil {
		if limited.Err() != nil {
			return nil, limited.Err()
		}
		return nil, ErrEvaluation
	}
	if limited.Err() != nil {
		return nil, limited.Err()
	}
	object := value.ToObject(runtime)
	score := object.Get("score").ToInteger()
	if score < 0 || score > 4 {
		return nil, ErrEvaluation
	}
	return &Result{Score: int(score), GuessesLog10: object.Get("guessesLog10").ToFloat()}, nil
}
