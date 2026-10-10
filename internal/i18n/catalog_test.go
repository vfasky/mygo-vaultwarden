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

// sourceRoots are scanned for user-visible Chinese text. I18N_SCOPE narrows
// the scan to a comma-separated list of directories relative to the module
// root; the unused-entry check then only runs for the full scan.
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

type use struct {
	source, where string
}

// scan returns the Chinese literals passed to T, Tf or Key, and the
// locations of Chinese literals outside them that are not marked
// "i18n:ignore" on their line.
func scan(t *testing.T, root string, dirs []string) (keys []use, bare []string) {
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
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
			wrapped := map[*ast.BasicLit]string{} // literal -> context prefix
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 || local == "" {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != local {
					return true
				}
				switch sel.Sel.Name {
				case "T", "Tf", "Key":
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						wrapped[lit] = ""
					}
				case "Tc":
					ctx, ok1 := call.Args[0].(*ast.BasicLit)
					if len(call.Args) == 2 && ok1 && ctx.Kind == token.STRING {
						if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							c, _ := strconv.Unquote(ctx.Value)
							wrapped[lit] = c + "\x04"
						}
					}
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !hasHan(s) {
					return true
				}
				pos := fset.Position(lit.Pos())
				where := filepath.ToSlash(rel) + ":" + strconv.Itoa(pos.Line)
				prefix, isWrapped := wrapped[lit]
				switch {
				case isWrapped:
					keys = append(keys, use{prefix + s, where})
				case !ignored[pos.Line]:
					bare = append(bare, where+" "+strconv.Quote(s))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return keys, bare
}

var verb = regexp.MustCompile(`%(\[\d+\])?[-+# 0]*(\d+|\*)?(\.(\d+|\*))?[a-zA-Z%]`)

func verbs(s string) []string {
	out := verb.FindAllString(s, -1)
	for i, v := range out {
		// Width and flags may differ between languages; the verb may not.
		out[i] = v[len(v)-1:]
		if m := regexp.MustCompile(`^%\[\d+\]`).FindString(v); m != "" {
			out[i] = m + out[i]
		}
	}
	return out
}

func TestCatalogCoverage(t *testing.T) {
	root := moduleRoot(t)
	dirs, full := sourceRoots, true
	if scope := os.Getenv("I18N_SCOPE"); scope != "" {
		dirs, full = strings.Split(scope, ","), false
	}
	keys, bare := scan(t, root, dirs)
	if len(bare) > 0 {
		sort.Strings(bare)
		t.Errorf("%d Chinese literals are not wrapped in i18n.T/Tf/Key (or marked i18n:ignore):\n%s", len(bare), strings.Join(bare, "\n"))
	}
	var missing []string
	used := map[string]bool{}
	for _, k := range keys {
		used[k.source] = true
		if _, ok := english[k.source]; !ok {
			missing = append(missing, k.where+" "+strconv.Quote(k.source))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d strings have no English translation:\n%s", len(missing), strings.Join(missing, "\n"))
	}
	if full {
		var unused []string
		for source := range english {
			if !used[source] {
				unused = append(unused, strconv.Quote(source))
			}
		}
		if len(unused) > 0 {
			sort.Strings(unused)
			t.Errorf("%d catalog entries are not used by the code:\n%s", len(unused), strings.Join(unused, "\n"))
		}
	}
}

func TestCatalogEntries(t *testing.T) {
	if len(conflicts) > 0 {
		t.Errorf("source strings translated differently by two catalogs:\n%s", strings.Join(conflicts, "\n"))
	}
	for name, entries := range catalogs {
		for source, translation := range entries {
			switch {
			case !hasHan(source):
				t.Errorf("%s: key %q is not Chinese source text", name, source)
			case strings.TrimSpace(translation) == "":
				t.Errorf("%s: %q has an empty translation", name, source)
			case hasHan(translation):
				t.Errorf("%s: translation of %q still contains Chinese: %q", name, source, translation)
			case !slices.Equal(verbs(source), verbs(translation)):
				t.Errorf("%s: format verbs differ: %q %v vs %q %v", name, source, verbs(source), translation, verbs(translation))
			}
		}
	}
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
	register("test", map[string]string{"测试：%d 项": "Test: %d items"})
	defer func() { delete(catalogs, "test"); delete(english, "测试：%d 项") }()
	Set(Chinese)
	if got := Tf("测试：%d 项", 3); got != "测试：3 项" {
		t.Fatal(got)
	}
	Set(English)
	if got := Tf("测试：%d 项", 3); got != "Test: 3 items" {
		t.Fatal(got)
	}
	if got := T("未翻译"); got != "未翻译" {
		t.Fatal(got)
	}
	register("test-context", map[string]string{"nav\x04测试": "Tests", "测试": "Test"})
	defer func() { delete(catalogs, "test-context"); delete(english, "nav\x04测试"); delete(english, "测试") }()
	if Tc("nav", "测试") != "Tests" || Tc("other", "测试") != "Test" {
		t.Fatal(Tc("nav", "测试"), Tc("other", "测试"))
	}
	Set(Chinese)
	if Tc("nav", "测试") != "测试" {
		t.Fatal("Tc must keep the Chinese source")
	}
	if Key("已核验") != "已核验" {
		t.Fatal("Key must not translate")
	}
}

func TestDefaultsToChineseInTests(t *testing.T) {
	if os.Getenv(EnvLanguage) == "" && detect() != Chinese {
		t.Fatal("tests must default to the Chinese source text")
	}
}

func TestPreferredLanguagesReadable(t *testing.T) {
	tags := preferredLanguages()
	t.Logf("preferred languages: %q -> %s", tags, Match(tags))
}
