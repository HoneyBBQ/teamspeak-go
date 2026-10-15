package versions

import (
	"crypto/ed25519"
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const publicKey = "UrN1jX0dBE1vulTNLCoYwrVpfITyo+NBuq/twbf9hLw="

var (
	platforms  = []string{"Windows", "Linux", "OS X", "macOS", "Android", "iOS"}
	versionRow = regexp.MustCompile(`^(.+) \[Build: (\d+)\]( [A-Z]+)?$`)
)

type entry struct {
	ClientVersion

	name string
}

// as is a type assertion that fails the test instead of panicking.
func as[T any](t *testing.T, v any) T {
	t.Helper()
	typed, ok := v.(T)
	if !ok {
		t.Fatalf("unexpected syntax %T in versions.go", v)
	}

	return typed
}

// table reads the package's own source, so names and values come in
// declaration order.
func table(t *testing.T) []entry {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "versions.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse versions.go: %v", err)
	}
	var out []entry
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs := as[*ast.ValueSpec](t, spec)
			lit := as[*ast.CompositeLit](t, vs.Values[0])
			e := entry{name: vs.Names[0].Name}
			for _, el := range lit.Elts {
				kv := as[*ast.KeyValueExpr](t, el)
				value, err := strconv.Unquote(as[*ast.BasicLit](t, kv.Value).Value)
				if err != nil {
					t.Fatalf("%s: %v", e.name, err)
				}
				switch as[*ast.Ident](t, kv.Key).Name {
				case "Platform":
					e.Platform = value
				case "Version":
					e.Version = value
				case "Sign":
					e.Sign = value
				default:
					t.Fatalf("%s: unexpected field %v", e.name, kv.Key)
				}
			}
			out = append(out, e)
		}
	}

	return out
}

// nameOf is the name a row takes: <Platform>_<version>_<build>[_<SUFFIX>],
// with a capital first letter on the platform so the name is exported.
func nameOf(t *testing.T, v ClientVersion) string {
	t.Helper()
	m := versionRow.FindStringSubmatch(v.Version)
	if m == nil {
		t.Fatalf("version %q does not match", v.Version)
	}
	platform := v.Platform
	switch platform {
	case "OS X":
		platform = "OSX"
	case "macOS":
		platform = "MacOS"
	case "iOS":
		platform = "IOS"
	}
	text := strings.NewReplacer(".", "_", "-", "_", "?", "X").Replace(m[1])
	name := platform + "_" + text + "_" + m[2]
	if suffix := strings.TrimSpace(m[3]); suffix != "" {
		name += "_" + suffix
	}

	return name
}

func TestTable_HoldsEntries(t *testing.T) {
	if n := len(table(t)); n < 1000 {
		t.Errorf("table has %d entries", n)
	}
}

func TestTable_EverySignatureVerifies(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.PublicKey(raw)
	for _, e := range table(t) {
		sig, err := base64.StdEncoding.DecodeString(e.Sign)
		if err != nil || len(sig) != ed25519.SignatureSize {
			t.Errorf("%s: sign is not the base64 of %d bytes", e.name, ed25519.SignatureSize)

			continue
		}
		if !ed25519.Verify(key, []byte(e.Platform+e.Version), sig) {
			t.Errorf("%s: signature does not verify", e.name)
		}
	}
}

func TestTable_RowsObeyTheRules(t *testing.T) {
	for _, e := range table(t) {
		if !slices.Contains(platforms, e.Platform) {
			t.Errorf("%s: platform %q is not allowed", e.name, e.Platform)
		}
		if !versionRow.MatchString(e.Version) {
			t.Errorf("%s: version %q does not match", e.name, e.Version)
		}
	}
}

func TestTable_NamesFollowFromRows(t *testing.T) {
	for _, e := range table(t) {
		if want := nameOf(t, e.ClientVersion); e.name != want {
			t.Errorf("%s should be named %s", e.name, want)
		}
	}
}

func TestTable_NoPlatformAndVersionTwice(t *testing.T) {
	seen := map[string]string{}
	for _, e := range table(t) {
		key := e.Platform + "\x00" + e.Version
		if first, dup := seen[key]; dup {
			t.Errorf("%s repeats %s", e.name, first)
		}
		seen[key] = e.name
	}
}

func TestTable_IsSorted(t *testing.T) {
	build := func(v ClientVersion) int {
		n, err := strconv.Atoi(versionRow.FindStringSubmatch(v.Version)[2])
		if err != nil {
			t.Fatal(err)
		}

		return n
	}
	rows := table(t)
	for i := 1; i < len(rows); i++ {
		a, b := rows[i-1], rows[i]
		order := build(a.ClientVersion) - build(b.ClientVersion)
		if order == 0 {
			order = slices.Index(platforms, a.Platform) - slices.Index(platforms, b.Platform)
		}
		if order == 0 {
			order = strings.Compare(a.Version, b.Version)
		}
		if order >= 0 {
			t.Errorf("%s must come before %s", a.name, b.name)
		}
	}
}
