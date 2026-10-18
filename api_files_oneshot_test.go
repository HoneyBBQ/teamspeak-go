package teamspeak

import (
	"errors"
	"reflect"
	"testing"

	"github.com/honeybbq/teamspeak-go/errcode"
)

// file is a row of a listing as both servers send it: type 0 is a directory.
func file(name, kind string) map[string]string {
	return map[string]string{"name": name, "type": kind, "size": "3", "datetime": "1792347698"}
}

func TestListFilesRecursive_WalksDirectoriesInOrder(t *testing.T) {
	s := &script{replies: []reply{
		{rows: []map[string]string{file("docs", "0"), file("a.txt", "1"), file("empty", "0")}},
		{rows: []map[string]string{file("inner", "0"), file("b.txt", "1")}},
		{rows: []map[string]string{file("c.txt", "1")}},
		// A directory with nothing in it is answered 1281, which is no files.
		{err: &ServerError{Code: errcode.DatabaseEmptyResult}},
		{err: &ServerError{Code: errcode.DatabaseEmptyResult}},
	}}
	got, err := NewCommands(s).ListFilesRecursive(t.Context(), 7, "", RecursiveFilesOptions{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}

	paths := make([]string, 0, len(got))
	for _, e := range got {
		paths = append(paths, e.Path)
	}
	want := []string{"/docs", "/docs/inner", "/docs/inner/c.txt", "/docs/b.txt", "/a.txt", "/empty"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if got[1].Name != "inner" || !got[1].IsDirectory || got[2].Size != 3 {
		t.Errorf("entries = %+v, want the listing's own fields kept", got)
	}
	wantSent := []string{
		`ftgetfilelist cid=7 path=\/ cpw=pw`,
		`ftgetfilelist cid=7 path=\/docs cpw=pw`,
		`ftgetfilelist cid=7 path=\/docs\/inner cpw=pw`,
		`ftgetfilelist cid=7 path=\/empty cpw=pw`,
	}
	if !reflect.DeepEqual(s.sent[:4], wantSent) {
		t.Errorf("sent %q, want %q first", s.sent, wantSent)
	}
}

// 1 is the path's own entries, as find's -maxdepth 1 is.
func TestListFilesRecursive_MaxDepth(t *testing.T) {
	for _, tc := range []struct {
		depth int
		sent  int
		paths []string
	}{
		{1, 1, []string{"/docs", "/a.txt"}},
		{2, 2, []string{"/docs", "/docs/inner", "/a.txt"}},
	} {
		s := &script{replies: []reply{
			{rows: []map[string]string{file("docs", "0"), file("a.txt", "1")}},
			{rows: []map[string]string{file("inner", "0")}},
			{rows: []map[string]string{file("deep.txt", "1")}},
		}}
		got, err := NewCommands(s).ListFilesRecursive(t.Context(), 7, "/", RecursiveFilesOptions{MaxDepth: tc.depth})
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, e := range got {
			paths = append(paths, e.Path)
		}
		if !reflect.DeepEqual(paths, tc.paths) || len(s.sent) != tc.sent {
			t.Errorf("depth %d: paths %v after %d listings, want %v after %d", tc.depth, paths, len(s.sent), tc.paths, tc.sent)
		}
	}
}

func TestListFilesRecursive_ErrorsAndEdges(t *testing.T) {
	refused(t, func(c *Commands) error {
		_, err := c.ListFilesRecursive(t.Context(), 1, "/", RecursiveFilesOptions{MaxDepth: -1})

		return err
	})

	// A path that is not there is the server's error.
	s := &script{replies: []reply{{err: &ServerError{Code: errcode.FileNotFound}}}}
	_, err := NewCommands(s).ListFilesRecursive(t.Context(), 1, "/nope", RecursiveFilesOptions{})
	if !errors.Is(err, errcode.FileNotFound) {
		t.Errorf("err = %v, want FileNotFound", err)
	}

	// A failure under the top ends the walk with that error.
	s = &script{replies: []reply{
		{rows: []map[string]string{file("docs", "0")}},
		{err: &ServerError{Code: errcode.FileNotFound}},
	}}
	got, err := NewCommands(s).ListFilesRecursive(t.Context(), 1, "/", RecursiveFilesOptions{})
	if !errors.Is(err, errcode.FileNotFound) || len(got) != 1 {
		t.Errorf("got %v, %v, want the error and what was listed before it", got, err)
	}

	// An empty top is no entries and no error.
	got, err = NewCommands(&script{replies: []reply{{err: &ServerError{Code: errcode.DatabaseEmptyResult}}}}).
		ListFilesRecursive(t.Context(), 1, "/", RecursiveFilesOptions{})
	if err != nil || len(got) != 0 {
		t.Errorf("empty top: %v, %v", got, err)
	}
}
