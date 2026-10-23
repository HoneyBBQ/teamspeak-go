package serverquery

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestReadBoundedLine(t *testing.T) {
	long := strings.Repeat("a", 100_000)
	for name, tc := range map[string]struct {
		err   error
		in    string
		want  []string
		limit int
	}{
		"lines":                   {in: "ab\ncd\n", limit: 10, want: []string{"ab\n", "cd\n"}},
		"line across the buffer":  {in: long + "\nx\n", limit: 200_000, want: []string{long + "\n", "x\n"}},
		"last line, no newline":   {in: "ab\ncd", limit: 10, want: []string{"ab\n", "cd"}},
		"exactly the limit":       {in: "abcd\n", limit: 5, want: []string{"abcd\n"}},
		"over the limit":          {in: "abcde\n", limit: 5, err: ErrLineTooLong},
		"over the limit, endless": {in: long, limit: 50_000, err: ErrLineTooLong},
	} {
		r := bufio.NewReader(iotest.OneByteReader(strings.NewReader(tc.in)))
		if len(tc.in) > 1000 {
			r = bufio.NewReader(strings.NewReader(tc.in))
		}
		var got []string
		var err error
		for {
			var line string
			line, err = readBoundedLine(r, tc.limit)
			if line != "" {
				got = append(got, line)
			}
			if err != nil {
				break
			}
		}
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: err = %v, want %v", name, err, tc.err)
			}

			continue
		}
		if !errors.Is(err, io.EOF) || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: got %q err %v, want %q", name, got, err, tc.want)
		}
	}
}

// A line past the limit ends the connection with ErrLineTooLong rather than
// growing without end, and reading it is not quadratic.
func TestStream_LineTooLongEndsTheConnection(t *testing.T) {
	pr, pw := io.Pipe()
	s := newStream(pr, streamOptions{maxLine: 1 << 20})
	go func() {
		chunk := []byte(strings.Repeat("x", 64<<10))
		for range 64 {
			_, err := pw.Write(chunk)
			if err != nil {
				return
			}
		}
		_ = pw.Close()
	}()
	start := time.Now()
	_, err := s.ReadLine()
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("ReadLine = %v, want ErrLineTooLong", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to refuse the line", elapsed)
	}
	_ = pr.Close()
}

// A big legitimate line below the limit is read whole and fast.
func TestStream_BigLineBelowTheLimit(t *testing.T) {
	big := strings.Repeat("client_nickname=abcdefgh ", 4<<20) // about 100 MB
	s := newStream(strings.NewReader("TS3\nWelcome\n"+big+"\n"), streamOptions{banner: 2})
	start := time.Now()
	line, err := s.ReadLine()
	if err != nil || len(line) != len(big) {
		t.Fatalf("ReadLine = %d bytes, %v; want %d", len(line), err, len(big))
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("a %d byte line took %v", len(line), elapsed)
	}
}

// FuzzReadBoundedLine checks that the bounded reader splits like a plain split
// on newlines for any input and any limit, and never returns a line past it.
func FuzzReadBoundedLine(f *testing.F) {
	f.Add("a=1 b=2\n\rerror id=0 msg=ok\n\r", 64)
	f.Add("no newline at all", 4)
	f.Add("\n\n\n", 1)
	f.Fuzz(func(t *testing.T, in string, limit int) {
		if limit < 1 || limit > 1<<16 {
			return
		}
		r := bufio.NewReaderSize(strings.NewReader(in), 16)
		var got strings.Builder
		for {
			line, err := readBoundedLine(r, limit)
			if len(line) > limit {
				t.Fatalf("returned %d bytes past the limit %d", len(line), limit)
			}
			got.WriteString(line)
			if errors.Is(err, ErrLineTooLong) {
				return
			}
			if err != nil {
				break
			}
		}
		if got.String() != in {
			t.Fatalf("lines joined = %q, want the input %q", got.String(), in)
		}
	})
}
