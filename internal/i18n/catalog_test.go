// SPDX-License-Identifier: GPL-3.0-only

package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

const importPath = "github.com/vfasky/mygo-vaultwarden/internal/i18n"

// I18N_SCOPE narrows the scan to a comma-separated list of files or
// directories relative to the module root; the unused-key check then only
// runs for the full scan.
var sourceRoots = []string{"internal"}

func hasHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func moduleRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

type use struct{ value, where string }

type scanResult struct {
	keys     []use           // literal keys passed to T or Tf
	chinese  []use           // Chinese passed to T or Tf instead of a key
	bare     []string        // Chinese literals outside them
	literals map[string]bool // every string literal, to find used keys
}

func scan(t *testing.T, root string, paths []string) scanResult {
	r := scanResult{literals: map[string]bool{}}
	for _, p := range paths {
		err := filepath.WalkDir(filepath.Join(root, p), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if d.IsDir() {
				if filepath.ToSlash(rel) == "internal/i18n" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ignored := map[int]bool{}
			for _, group := range file.Comments {
				for _, c := range group.List {
					if strings.Contains(c.Text, "i18n:ignore") {
						ignored[fset.Position(c.Pos()).Line] = true
					}
				}
			}
			local := ""
			for _, spec := range file.Imports {
				if p, _ := strconv.Unquote(spec.Path.Value); p == importPath {
					local = "i18n"
					if spec.Name != nil {
						local = spec.Name.Name
					}
				}
			}
			arg := map[*ast.BasicLit]string{} // literal -> function receiving it
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || local == "" || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != local {
					return true
				}
				if sel.Sel.Name != "T" && sel.Sel.Name != "Tf" {
					return true
				}
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					arg[lit] = sel.Sel.Name
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				r.literals[s] = true
				pos := fset.Position(lit.Pos())
				where := filepath.ToSlash(rel) + ":" + strconv.Itoa(pos.Line)
				_, wrapped := arg[lit]
				switch {
				case wrapped && !hasHan(s):
					r.keys = append(r.keys, use{s, where})
				case wrapped:
					r.chinese = append(r.chinese, use{s, where})
				case hasHan(s) && !ignored[pos.Line]:
					r.bare = append(r.bare, where+" "+strconv.Quote(s))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func report(t *testing.T, title string, lines []string) {
	if len(lines) > 0 {
		sort.Strings(lines)
		t.Errorf("%d %s:\n%s", len(lines), title, strings.Join(lines, "\n"))
	}
}

func TestCatalogCoverage(t *testing.T) {
	root := moduleRoot(t)
	paths, full := sourceRoots, true
	if scope := os.Getenv("I18N_SCOPE"); scope != "" {
		paths, full = strings.Split(scope, ","), false
	}
	r := scan(t, root, paths)
	report(t, "Chinese literals outside the i18n catalogs (use i18n.T with a key, or mark i18n:ignore)", r.bare)
	var unknown []string
	for _, k := range r.keys {
		if _, ok := messages[k.value]; !ok {
			unknown = append(unknown, k.where+" "+strconv.Quote(k.value))
		}
	}
	report(t, "keys passed to i18n.T/Tf are not defined", unknown)
	var chinese []string
	for _, c := range r.chinese {
		chinese = append(chinese, c.where+" "+strconv.Quote(c.value))
	}
	report(t, "Chinese text passed to i18n.T/Tf instead of a key", chinese)
	if full {
		var unused []string
		for key := range messages {
			if !r.literals[key] {
				unused = append(unused, key)
			}
		}
		report(t, "keys are not used by the code", unused)
	}
}

var verb = regexp.MustCompile(`%(\[\d+\])?[-+# 0]*(\d+|\*)?(\.(\d+|\*))?[a-zA-Z%]`)

// verbs returns the verbs of a format in argument order; explicit argument
// indexes let the languages place them differently.
func verbs(s string) []string {
	var out []string
	next := 1
	for _, v := range verb.FindAllString(s, -1) {
		if v == "%%" {
			continue
		}
		n := next
		if m := regexp.MustCompile(`^%\[(\d+)\]`).FindStringSubmatch(v); m != nil {
			n, _ = strconv.Atoi(m[1])
		}
		out = append(out, strconv.Itoa(n)+v[len(v)-1:])
		next = n + 1
	}
	sort.Strings(out)
	return out
}

func TestCatalogEntries(t *testing.T) {
	var problems []string
	for key, m := range messages {
		switch {
		case strings.TrimSpace(m.zh) == "" || strings.TrimSpace(m.en) == "":
			problems = append(problems, key+": empty text")
		case hasHan(m.en):
			problems = append(problems, key+": English contains Chinese: "+strconv.Quote(m.en))
		case !slices.Equal(verbs(m.zh), verbs(m.en)):
			problems = append(problems, key+": format verbs differ: "+strconv.Quote(m.zh)+" vs "+strconv.Quote(m.en))
		}
	}
	report(t, "catalog entries are invalid", problems)
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		tags []string
		want Lang
	}{
		{[]string{"zh-Hans-CN", "en-US"}, Chinese},
		{[]string{"zh-Hant-TW"}, Chinese},
		{[]string{"en-GB", "zh-Hans"}, English},
		{[]string{"ja-JP", "zh-Hans"}, Chinese},
		{[]string{"ja-JP", "fr-FR"}, English},
		{[]string{"zh_CN"}, Chinese},
		{nil, English},
	} {
		if got := Match(tc.tags); got != tc.want {
			t.Errorf("Match(%q) = %s, want %s", tc.tags, got, tc.want)
		}
	}
}

func TestTranslate(t *testing.T) {
	defer Set(Current())
	register("zztest", map[string]text{"zztest.items": {"测试：%[1]d 项，%[2]s", "Test %[2]s: %[1]d items"}})
	defer func() { delete(areas, "zztest"); delete(messages, "zztest.items") }()
	Set(Chinese)
	if got := Tf("zztest.items", 3, "x"); got != "测试：3 项，x" {
		t.Fatal(got)
	}
	Set(English)
	if got := Tf("zztest.items", 3, "x"); got != "Test x: 3 items" {
		t.Fatal(got)
	}
	if got := T("zztest.missing"); got != "zztest.missing" {
		t.Fatal(got)
	}
	if got := T("common.save"); got != "Save" {
		t.Fatal(got)
	}
	if !slices.Equal(verbs("%[1]d 项，%[2]s"), verbs("%[2]s: %[1]d")) || slices.Equal(verbs("%d %s"), verbs("%s %d")) {
		t.Fatal("verb comparison")
	}
}

func TestRegisterRejectsBadKeys(t *testing.T) {
	for _, key := range []string{"zzbad.Upper", "zzbad", "other.key", "zzbad.保存", "zzbad.trailing."} {
		func() {
			defer func() {
				delete(areas, "zzbad")
				if recover() == nil {
					t.Errorf("key %q was accepted", key)
				}
			}()
			register("zzbad", map[string]text{key: {"保存", "Save"}})
		}()
	}
}

func TestDefaultsToChineseInTests(t *testing.T) {
	if os.Getenv(EnvLanguage) == "" && detect() != Chinese {
		t.Fatal("tests must default to the Chinese text")
	}
}

func TestPreferredLanguagesReadable(t *testing.T) {
	tags := preferredLanguages()
	t.Logf("preferred languages: %q -> %s", tags, Match(tags))
}
