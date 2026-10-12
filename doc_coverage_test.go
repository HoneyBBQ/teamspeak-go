package teamspeak

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryExportedFieldAndMethodIsDocumented keeps the public API documented:
// revive's exported rule checks types and functions, not struct fields, so a
// field or method added without a comment would otherwise go unnoticed. It
// covers every package outside internal/. Embedded fields are exempt: their
// type carries the documentation.
func TestEveryExportedFieldAndMethodIsDocumented(t *testing.T) {
	for _, dir := range publicPackageDirs(t) {
		for _, missing := range undocumented(t, dir) {
			t.Errorf("%s: %s has no doc comment", dir, missing)
		}
	}
}

func publicPackageDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != "." && (name == "internal" || name == "testdata" || strings.HasPrefix(name, ".")) {
			return filepath.SkipDir
		}
		matches, globErr := filepath.Glob(filepath.Join(path, "*.go"))
		if globErr != nil {
			return globErr
		}
		if len(matches) > 0 {
			dirs = append(dirs, path)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	return dirs
}

func undocumented(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		files = append(files, f)
	}
	docPkg, err := doc.NewFromFiles(fset, files, "example.com/"+dir)
	if err != nil {
		t.Fatalf("doc %s: %v", dir, err)
	}
	missing := make([]string, 0, len(docPkg.Types))
	for _, typ := range docPkg.Types {
		missing = append(missing, undocumentedMembers(typ)...)
	}

	return missing
}

func undocumentedMembers(typ *doc.Type) []string {
	var missing []string
	for _, spec := range typ.Decl.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		switch x := ts.Type.(type) {
		case *ast.StructType:
			missing = append(missing, undocumentedFields(typ.Name, x.Fields)...)
		case *ast.InterfaceType:
			missing = append(missing, undocumentedFields(typ.Name, x.Methods)...)
		}
	}
	for _, m := range typ.Methods {
		if ast.IsExported(m.Name) && strings.TrimSpace(m.Doc) == "" {
			missing = append(missing, "method "+typ.Name+"."+m.Name)
		}
	}

	return missing
}

func undocumentedFields(typeName string, fields *ast.FieldList) []string {
	var missing []string
	for _, f := range fields.List {
		if len(f.Names) == 0 || f.Doc != nil || f.Comment != nil {
			continue
		}
		for _, n := range f.Names {
			if n.IsExported() {
				missing = append(missing, typeName+"."+n.Name)
			}
		}
	}

	return missing
}
