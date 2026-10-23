package teamspeak

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

// The changes struct of a record has a field for each of the record's, under the
// same name, as a pointer to the value, so a property cannot be added to one
// and forgotten in the other.
func TestChangesMirrorTheirRecords(t *testing.T) {
	for _, c := range []struct {
		record, changes reflect.Type
	}{
		{reflect.TypeFor[ClientEntry](), reflect.TypeFor[ClientChanges]()},
		{reflect.TypeFor[Channel](), reflect.TypeFor[ChannelChanges]()},
	} {
		for field := range c.record.Fields() {
			if field.Name == "ID" {
				if _, ok := c.changes.FieldByName("ID"); ok {
					t.Errorf("%s has an ID", c.changes)
				}

				continue
			}
			got, ok := c.changes.FieldByName(field.Name)
			if !ok {
				t.Errorf("%s lacks %s", c.changes, field.Name)

				continue
			}
			if want := reflect.PointerTo(derefType(field.Type)); got.Type != want {
				t.Errorf("%s.%s is %s, want %s", c.changes, field.Name, got.Type, want)
			}
		}
		if got, want := c.changes.NumField(), c.record.NumField()-1; got != want {
			t.Errorf("%s has %d fields, want %d", c.changes, got, want)
		}
	}
}

// What the SDK writes with is read back under the same name and type.
func TestChangesShareTheNamesOfTheOptions(t *testing.T) {
	for _, c := range []struct {
		changes, options reflect.Type
		skip             map[string]bool
	}{
		{reflect.TypeFor[ClientChanges](), reflect.TypeFor[ClientUpdateOptions](), nil},
		{reflect.TypeFor[ClientChanges](), reflect.TypeFor[ClientEditOptions](), nil},
		{reflect.TypeFor[ChannelChanges](), reflect.TypeFor[ChannelCreateOptions](), map[string]bool{"Password": true}},
		{reflect.TypeFor[ChannelChanges](), reflect.TypeFor[ChannelEditOptions](), map[string]bool{"Password": true}},
	} {
		for field := range c.options.Fields() {
			if c.skip[field.Name] {
				continue
			}
			got, ok := c.changes.FieldByName(field.Name)
			if !ok {
				t.Errorf("%s has %s, which %s lacks", c.options, field.Name, c.changes)

				continue
			}
			if got.Type != reflect.PointerTo(derefType(field.Type)) {
				t.Errorf("%s.%s is %s, %s.%s is %s", c.changes, field.Name, got.Type, c.options, field.Name, field.Type)
			}
		}
	}
}

func TestClientChangesApply_KeepsWhatIsNotNamed(t *testing.T) {
	entry := ClientEntry{
		ID: 7, Nickname: "Ann", IsAway: new(true), ServerGroups: []ServerGroupID{6},
		IsInputMuted: new(true), Description: new("d"),
	}
	got := ClientChanges{Nickname: new("Anna")}.Apply(entry)
	want := entry
	want.Nickname = "Anna"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Apply = %+v, want %+v", got, want)
	}
}

// A pointer to false or "" is a change; only nil is none.
func TestClientChangesApply_ZeroValuesAreChanges(t *testing.T) {
	entry := ClientEntry{IsAway: new(true), AwayMessage: new("lunch"), IsInputMuted: new(true), TalkPower: new(int32(5))}
	got := ClientChanges{
		IsAway: new(false), AwayMessage: new(""), IsInputMuted: new(false), TalkPower: new(int32(0)),
	}.Apply(entry)
	if got.IsAway == nil || *got.IsAway || got.AwayMessage == nil || *got.AwayMessage != "" ||
		got.IsInputMuted == nil || *got.IsInputMuted ||
		got.TalkPower == nil || *got.TalkPower != 0 {
		t.Errorf("Apply = %+v, want everything cleared", got)
	}
}

// A pointer to an empty list is a client that now holds no groups.
func TestClientChangesApply_AnEmptyListMeansNoGroups(t *testing.T) {
	got := ClientChanges{ServerGroups: new([]ServerGroupID{})}.Apply(ClientEntry{ServerGroups: []ServerGroupID{6, 7}})
	if got.ServerGroups == nil || len(got.ServerGroups) != 0 {
		t.Errorf("ServerGroups = %#v, want empty", got.ServerGroups)
	}
}

func TestChannelChangesApply(t *testing.T) {
	channel := Channel{ID: 5, Name: "Lobby", Topic: "t", TotalClients: new(int32(3)), DeleteDelay: new(time.Second)}
	got := ChannelChanges{Topic: new(""), IsPermanent: new(true), DeleteDelay: new(time.Minute)}.Apply(channel)
	want := channel
	want.Topic = ""
	want.IsPermanent = true
	want.DeleteDelay = new(time.Minute)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Apply = %+v, want %+v", got, want)
	}
	if channel.Topic != "t" || *channel.DeleteDelay != time.Second {
		t.Errorf("the channel changed: %+v", channel)
	}
	if !slices.Equal([]int32{*got.TotalClients}, []int32{3}) {
		t.Errorf("TotalClients = %d", *got.TotalClients)
	}
}
