// SPDX-License-Identifier: GPL-3.0-only
package kit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Widgets read hover and press while they are built. Keying the built
// element moves its identity past those lookups, so the hover and pressed
// looks never show: key the context instead, as in Action(c.Key(k), ...).
func TestElementsAreKeyedThroughTheContext(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Key" {
				if _, built := sel.X.(*ast.CallExpr); built {
					t.Errorf("%s: key the context, not the built element", fset.Position(call.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
