package client

import (
	"reflect"
	"slices"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

// fill sets v, and everything in it, to a value that is not the zero value:
// pointers get a pointee of their own and lists two elements, so a field a clone
// forgets cannot hide behind a zero.
func fill(t *testing.T, v reflect.Value, n int) {
	t.Helper()
	switch v.Kind() { //nolint:exhaustive // the kinds the records use
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, v.Elem(), n)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		fill(t, v.Index(0), n)
		fill(t, v.Index(1), n+1000)
	case reflect.String:
		v.SetString(v.Type().Name() + string(rune('a'+n%26)) + string(rune('a'+n/26)))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(n) + 1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(n) + 1)
	case reflect.Struct:
		if v.Type() != reflect.TypeFor[time.Time]() {
			t.Fatalf("fill: no value for a %s", v.Type())
		}
		v.Set(reflect.ValueOf(time.Unix(int64(n)+1, 0)))
	default:
		t.Fatalf("fill: no value for a %s", v.Type())
	}
}

func filled[T any](t *testing.T) T {
	t.Helper()
	var v T
	rv := reflect.ValueOf(&v).Elem()
	for i := range rv.NumField() {
		fill(t, rv.Field(i), i)
	}

	return v
}

// addrs lists the memory a field points into: the pointee of a pointer, and the
// backing array of a list, held directly or through a pointer.
func addrs(f reflect.Value) []uintptr {
	var out []uintptr
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return nil
		}
		out = append(out, f.Pointer())
		f = f.Elem()
	}
	if f.Kind() == reflect.Slice && f.Len() > 0 {
		out = append(out, f.Pointer())
	}

	return out
}

// sharedField names a field whose pointer or list a and b hold in common.
func sharedField(a, b any) string {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	for i := range av.NumField() {
		for _, x := range addrs(av.Field(i)) {
			if slices.Contains(addrs(bv.Field(i)), x) {
				return av.Type().Field(i).Name
			}
		}
	}

	return ""
}

// The changes clone holds every value and shares no pointer or list: a field
// added to the changes and left out of the clone fails here.
func TestEventClonesShareNothing(t *testing.T) {
	changes := filled[teamspeak.ClientChanges](t)
	if got := cloneChanges(changes); !reflect.DeepEqual(got, changes) {
		t.Errorf("cloneChanges = %+v, want %+v", got, changes)
	} else if shared := sharedField(changes, got); shared != "" {
		t.Errorf("cloneChanges shares %s", shared)
	}
}
