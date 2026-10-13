package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// constValues returns the string values of the constants declared in a file of
// the commands or notify package, read from source so that a constant added
// there is counted without a second list to keep.
func constValues(t *testing.T, path string) map[string]bool {
	t.Helper()

	return stringLiterals(t, path, func(n ast.Node) (ast.Expr, bool) {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 1 {
			return nil, false
		}

		return spec.Values[0], true
	})
}

// stringLiterals collects the string literals pick selects from a parsed file.
func stringLiterals(t *testing.T, path string, pick func(ast.Node) (ast.Expr, bool)) map[string]bool {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]bool{}

	ast.Inspect(file, func(n ast.Node) bool {
		expr, ok := pick(n)
		if !ok {
			return true
		}

		if lit, isLit := expr.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
			s, unquoteErr := strconv.Unquote(lit.Value)
			if unquoteErr == nil {
				out[s] = true
			}
		}

		return true
	})

	return out
}

// anyNotifyLiteral picks every string literal naming a notification.
func anyNotifyLiteral(n ast.Node) (ast.Expr, bool) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING || !strings.HasPrefix(lit.Value, `"notify`) {
		return nil, false
	}

	return lit, true
}

func TestResponseTableCommandsAreNamed(t *testing.T) {
	named := constValues(t, "../commands/names.go")

	for name := range responses {
		if !named[name] {
			t.Errorf("responses names command %q, which has no constant in package commands", name)
		}
	}
}

func TestNotificationsAreNamed(t *testing.T) {
	named := constValues(t, "../notify/notify.go")

	for _, file := range []string{"responses.go", "notifications.go"} {
		for name := range stringLiterals(t, file, anyNotifyLiteral) {
			if !named[name] {
				t.Errorf("%s uses notification %q, which has no constant in package notify", file, name)
			}
		}
	}
}
