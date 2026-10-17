package teamspeak

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

// fill sets v, and everything in it, to a value that is not the zero value and
// differs from what fill gives other fields (n): pointers get a pointee of their
// own, lists two elements. It is how the tests below make every field of a record
// count, so a field the code forgets cannot hide behind a zero.
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

// filled returns a T with every field set by fill.
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
// backing array of a list, whether the list is held directly or through a pointer.
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

// sharesMemory reports a field, by name, whose pointer or list a and b hold in
// common, or "" when they share none. a and b may be of different types (a
// record and its changes) as long as the fields have the same names.
func sharesMemory(a, b reflect.Value) string {
	for i := range a.NumField() {
		name := a.Type().Field(i).Name
		other := b.FieldByName(name)
		if !other.IsValid() {
			continue
		}
		for _, x := range addrs(a.Field(i)) {
			if slices.Contains(addrs(other), x) {
				return name
			}
		}
	}

	return ""
}

// pointee returns what f points at, or f itself when it is not a pointer.
func pointee(f reflect.Value) reflect.Value {
	if f.Kind() == reflect.Pointer {
		return f.Elem()
	}

	return f
}

// Apply copies every field: with every change set to its own value, each field
// of the record that has a change ends up holding it. A field left out of Apply
// stays zero here and fails.
func TestApplyCopiesEveryField(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		changes := filled[ClientChanges](t)
		got := changes.Apply(ClientEntry{})
		assertApplied(t, reflect.ValueOf(changes), reflect.ValueOf(got))
		if shared := sharesMemory(reflect.ValueOf(changes), reflect.ValueOf(got)); shared != "" {
			t.Errorf("the result shares %s with the changes", shared)
		}
	})
	t.Run("channel", func(t *testing.T) {
		changes := filled[ChannelChanges](t)
		got := changes.Apply(Channel{})
		assertApplied(t, reflect.ValueOf(changes), reflect.ValueOf(got))
		if shared := sharesMemory(reflect.ValueOf(changes), reflect.ValueOf(got)); shared != "" {
			t.Errorf("the result shares %s with the changes", shared)
		}
	})
}

func assertApplied(t *testing.T, changes, record reflect.Value) {
	t.Helper()
	for i := range changes.NumField() {
		name := changes.Type().Field(i).Name
		want := changes.Field(i).Elem()
		got := pointee(record.FieldByName(name))
		if !got.IsValid() {
			t.Errorf("Apply left %s nil, want %v", name, want)

			continue
		}
		if !reflect.DeepEqual(got.Interface(), want.Interface()) {
			t.Errorf("Apply left %s as %v, want %v", name, got, want)
		}
	}
}

// Apply keeps what the changes do not name, and shares nothing with the record
// it was given.
func TestApplyKeepsTheRestAndSharesNothing(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		record := filled[ClientEntry](t)
		got := ClientChanges{}.Apply(record)
		if !reflect.DeepEqual(got, record) {
			t.Errorf("an empty Apply changed the record: %+v", got)
		}
		if shared := sharesMemory(reflect.ValueOf(record), reflect.ValueOf(got)); shared != "" {
			t.Errorf("the result shares %s with the record", shared)
		}
	})
	t.Run("channel", func(t *testing.T) {
		record := filled[Channel](t)
		got := ChannelChanges{}.Apply(record)
		if !reflect.DeepEqual(got, record) {
			t.Errorf("an empty Apply changed the record: %+v", got)
		}
		if shared := sharesMemory(reflect.ValueOf(record), reflect.ValueOf(got)); shared != "" {
			t.Errorf("the result shares %s with the record", shared)
		}
	})
}

// The clones hold every value and share no pointer or list.
func TestClonesShareNothing(t *testing.T) {
	entry := filled[ClientEntry](t)
	if got := entry.Clone(); !reflect.DeepEqual(got, entry) {
		t.Errorf("ClientEntry.Clone = %+v, want %+v", got, entry)
	} else if shared := sharesMemory(reflect.ValueOf(entry), reflect.ValueOf(got)); shared != "" {
		t.Errorf("ClientEntry.Clone shares %s", shared)
	}

	channel := filled[Channel](t)
	if got := channel.Clone(); !reflect.DeepEqual(got, channel) {
		t.Errorf("Channel.Clone = %+v, want %+v", got, channel)
	} else if shared := sharesMemory(reflect.ValueOf(channel), reflect.ValueOf(got)); shared != "" {
		t.Errorf("Channel.Clone shares %s", shared)
	}
}
