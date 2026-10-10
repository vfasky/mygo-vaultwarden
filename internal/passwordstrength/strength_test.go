// SPDX-License-Identifier: GPL-3.0-only
package passwordstrength

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOfficialNodeVectors(t *testing.T) {
	body, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Password, Email string
		UserInputs            []string
		Expected              *Result
	}
	if err = json.Unmarshal(body, &cases); err != nil {
		t.Fatal(err)
	}
	scores := map[int]bool{}
	clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := evaluate(context.Background(), tc.Password, tc.Email, tc.UserInputs, clock)
			if err != nil {
				t.Fatal(err)
			}
			if tc.Expected == nil {
				if got != nil {
					t.Fatal("empty password has score")
				}
				return
			}
			if got == nil || got.Score != tc.Expected.Score || math.Abs(got.GuessesLog10-tc.Expected.GuessesLog10) > 1e-10 {
				t.Fatalf("numeric result mismatch: got %+v want %+v", got, tc.Expected)
			}
			scores[got.Score] = true
		})
	}
	if len(scores) != 5 {
		t.Fatal("oracle does not cover every score", scores)
	}
}

func TestLimitsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		password, email string
		inputs          []string
	}{
		{password: strings.Repeat("x", 1025)},
		{password: "fixture", email: strings.Repeat("x", 1025)},
		{password: "fixture", inputs: make([]string, 65)},
		{password: "fixture", inputs: []string{strings.Repeat("x", 1025)}},
		{password: "fixture", inputs: strings.Split(strings.Repeat(strings.Repeat("x", 1024)+",", 17), ",")},
		{password: string([]byte{0xff})},
		{password: "fixture", email: string([]byte{0xff})},
		{password: "fixture", inputs: []string{string([]byte{0xff})}},
	} {
		if result, err := Evaluate(context.Background(), tc.password, tc.email, tc.inputs); !errors.Is(err, ErrInput) || result != nil {
			t.Fatal("invalid input accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := Evaluate(ctx, "fixture", "", nil); !errors.Is(err, context.Canceled) || result != nil {
		t.Fatal("cancelled work accepted", err)
	}
	// A completed fixed-program compile is shared, but runtimes and secrets are
	// never shared. Cancellation must interrupt expensive matching as well.
	if _, err := Evaluate(context.Background(), "fixture", "", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if result, err := Evaluate(ctx, strings.Repeat("abcdefghij", 100), "", nil); !errors.Is(err, context.DeadlineExceeded) || result != nil {
		t.Fatal("deadline ignored", err)
	}
}

func TestMinimumComplexity(t *testing.T) {
	// Scores from the independent Node oracle, chosen without year sensitivity.
	for _, tc := range []struct {
		password, email string
		score           int
	}{{"password", "", 0}, {"P@ssw0rd!", "", 1}, {"snowflake2025!", " SnowFlake.Manager+Dev@example.invalid", 2}, {"snowflake2025!", "different@snowflake.invalid", 3}, {"Tr0ub4dor&3", "", 4}} {
		for minimum := 0; minimum <= 4; minimum++ {
			got, err := CheckMinimum(context.Background(), tc.password, tc.email, nil, minimum)
			if err != nil || got != (tc.score >= minimum) {
				t.Fatalf("minimum %d score %d: %v %v", minimum, tc.score, got, err)
			}
		}
	}
	for minimum := -1; minimum <= 5; minimum++ {
		got, err := CheckMinimum(context.Background(), "", "", nil, minimum)
		if got || ((minimum < 0 || minimum > 4) != errors.Is(err, ErrInput)) {
			t.Fatal("empty or invalid minimum accepted", minimum, err)
		}
	}
}

func TestConcurrentRuntimeIsolation(t *testing.T) {
	for i := 0; i < 4; i++ {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			t.Parallel()
			with, err := Evaluate(context.Background(), "quasar12345", "", []string{"quasar"})
			if err != nil {
				t.Fatal(err)
			}
			without, err := Evaluate(context.Background(), "quasar12345", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if with.GuessesLog10 >= without.GuessesLog10 {
				t.Fatal("dictionary isolation not observable")
			}
		})
	}
}
