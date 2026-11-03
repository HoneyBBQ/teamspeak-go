package teamspeak

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// handshakeCommands never pass through command middleware: a client sends them
// itself while it connects, before there is a session for the typed commands to
// run on, so package commands has no name for them.
var handshakeCommands = []string{"clientinit", "clientinitiv", "clientek"}

// notCommands are lines the WebQuery transport renders with the same builder
// but that are not commands: the "error" answer line it writes in a raw
// connection's format, and a bare property list, which has an empty name.
var notCommands = []string{"error", ""}

// TestEveryCommandTheModuleSendsHasANameInPackageCommands keeps package
// commands complete: the names a middleware matches on must include every
// command the module sends. It finds each command name written as a string in
// non-test code, either passed to one of the Commands helpers (exec, list and
// the like, which take a parameter named command) or as the first argument of
// wire.BuildCommand and wire.BuildCommandOrdered, and fails for one that is
// not a constant in package commands.
func TestEveryCommandTheModuleSendsHasANameInPackageCommands(t *testing.T) {
	known := commandConstants(t)
	sent := sentCommands(t)
	if len(sent) < 100 {
		t.Fatalf("found only %d command names in the source; the scan is broken", len(sent))
	}
	for name, where := range sent {
		if slices.Contains(handshakeCommands, name) || slices.Contains(notCommands, name) || known[name] {
			continue
		}
		t.Errorf("%q is sent at %s but is not a constant in package commands", name, where)
	}
}

// commandConstants returns the values of the string constants in package
// commands.
func commandConstants(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("commands", "names.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse commands/names.go: %v", err)
	}
	known := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, value := range spec.Values {
			if name, ok := stringLiteral(value); ok {
				known[name] = true
			}
		}

		return true
	})

	return known
}

// sentCommands returns each command name written as a string literal in the
// module's non-test code, with the position of one place that sends it.
func sentCommands(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	files := sourceFiles(t, fset)
	helpers := commandHelpers(files)

	sent := map[string]string{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			index, isHelper := helpers[calleeName(call)]
			if !isHelper || index >= len(call.Args) {
				return true
			}
			if name, ok := stringLiteral(call.Args[index]); ok {
				if _, seen := sent[name]; !seen {
					sent[name] = fset.Position(call.Pos()).String()
				}
			}

			return true
		})
	}

	return sent
}

// sourceFiles parses the module's non-test Go files.
func sourceFiles(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	var files []*ast.File
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		files = append(files, file)

		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	return files
}

// commandHelpers maps the name of each function that takes a command name to
// the position of that argument in a call: the builders in package wire, and
// every method with a parameter named command, which is where the literal goes
// in a call to it.
func commandHelpers(files []*ast.File) map[string]int {
	helpers := map[string]int{"BuildCommand": 0, "BuildCommandOrdered": 0}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}
			index := 0
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					if name.Name == "command" {
						helpers[fn.Name.Name] = index
					}
					index++
				}
			}
		}
	}

	return helpers
}

func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	}

	return ""
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)

	return value, err == nil
}
