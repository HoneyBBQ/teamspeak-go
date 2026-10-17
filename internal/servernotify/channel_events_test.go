package servernotify_test

import (
	"reflect"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
	"github.com/honeybbq/teamspeak-go/internal/servernotify"
	"github.com/honeybbq/teamspeak-go/internal/wire"
)

// The payloads below are the ones TeamSpeak 3 and TeamSpeak 6 sent.

func row(line string) map[string]string { return wire.ParseCommand(line).Params }

const admin = " invokerid=413 invokername=b2-adm invokeruid=serveradmin"

func TestChannelCreated_Temporary(t *testing.T) {
	evt, ok := servernotify.ChannelCreated(row(
		"notifychannelcreated cid=247 cpid=0 channel_name=b2m-tmp channel_order=246" + admin))
	if !ok {
		t.Fatal("not read")
	}
	if evt.ChannelID != 247 || evt.ParentID != 0 || evt.InvokerID != 413 || evt.InvokerName != "b2-adm" ||
		evt.InvokerUID != "serveradmin" {
		t.Errorf("event = %+v", evt)
	}
	ch := evt.Changes
	if ch.Name == nil || *ch.Name != "b2m-tmp" || ch.Order == nil || *ch.Order != 246 || ch.ParentID == nil {
		t.Errorf("changes = %+v", ch)
	}
	// Absent means the server default: nothing else is named.
	ch.Name, ch.Order, ch.ParentID = nil, nil, nil
	if !reflect.DeepEqual(ch, teamspeak.ChannelChanges{}) {
		t.Errorf("changes name more than the notification did: %+v", ch)
	}
}

func TestChannelCreated_FullTS6(t *testing.T) {
	evt, ok := servernotify.ChannelCreated(row("notifychannelcreated cid=9 cpid=2 channel_name=b2m-full channel_topic=tp" +
		" channel_codec_quality=7 channel_maxclients=5 channel_order=3 channel_flag_permanent=1" +
		" channel_unique_identifier=96fd8883-d846-4c13-88a8-680c2d4cad19" + admin))
	if !ok || evt.ParentID != 2 {
		t.Fatalf("event = %+v, %v", evt, ok)
	}
	ch := evt.Changes
	if ch.IsPermanent == nil || !*ch.IsPermanent || ch.MaxClients == nil || *ch.MaxClients != 5 ||
		ch.CodecQuality == nil || *ch.CodecQuality != 7 || ch.Topic == nil || *ch.Topic != "tp" ||
		ch.UID == nil || *ch.UID != "96fd8883-d846-4c13-88a8-680c2d4cad19" {
		t.Errorf("changes = %+v", ch)
	}
	if ch.Description != nil {
		t.Error("a new channel's description is never sent")
	}
	// Merging into a record keeps what the notification did not carry.
	base := teamspeak.Channel{ID: 9, Topic: "kept", HasPassword: true}
	got := ch.Apply(base)
	if got.Name != "b2m-full" || !got.IsPermanent || !got.HasPassword {
		t.Errorf("applied = %+v", got)
	}
}

func TestChannelCreated_WithoutAChannelIsDropped(t *testing.T) {
	for _, line := range []string{
		"notifychannelcreated cpid=0 channel_name=n", "notifychannelcreated cid=0 channel_name=n",
	} {
		if _, ok := servernotify.ChannelCreated(row(line)); ok {
			t.Errorf("%q was read", line)
		}
	}
}

func TestChannelEdited_NamesOnlyWhatChanged(t *testing.T) {
	evt, ok := servernotify.ChannelEdited(row("notifychanneledited cid=244 reasonid=10" + admin + " channel_topic=t2"))
	if !ok || evt.ChannelID != 244 || evt.Reason != teamspeak.ReasonChannelEdit || evt.InvokerName != "b2-adm" {
		t.Fatalf("event = %+v, %v", evt, ok)
	}
	want := teamspeak.ChannelChanges{Topic: new("t2")}
	if !reflect.DeepEqual(evt.Changes, want) {
		t.Errorf("changes = %+v", evt.Changes)
	}
}

func TestChannelEdited_DescriptionChangeNamesNoProperty(t *testing.T) {
	evt, ok := servernotify.ChannelEdited(row("notifychanneledited cid=244 reasonid=10" + admin))
	if !ok || !reflect.DeepEqual(evt.Changes, teamspeak.ChannelChanges{}) {
		t.Errorf("event = %+v, %v", evt, ok)
	}
}

func TestChannelEdited_PasswordFlagOnlyAsItFlips(t *testing.T) {
	evt, _ := servernotify.ChannelEdited(row(
		"notifychanneledited cid=244 reasonid=10" + admin + " channel_flag_password=0"))
	if evt.Changes.HasPassword == nil || *evt.Changes.HasPassword {
		t.Errorf("changes = %+v, want HasPassword pointing at false", evt.Changes)
	}
	limits, _ := servernotify.ChannelEdited(row("notifychanneledited cid=246 reasonid=10" + admin +
		" channel_codec_quality=5 channel_maxclients=8 channel_flag_maxclients_unlimited=0"))
	if limits.Changes.IsMaxClientsUnlimited == nil || *limits.Changes.IsMaxClientsUnlimited ||
		limits.Changes.MaxClients == nil || limits.Changes.CodecQuality == nil {
		t.Errorf("limits = %+v", limits.Changes)
	}
}

// Reason 9 without an invoker is the answer to channelgetdescription.
func TestChannelEdited_Reason9WithoutAnInvokerIsNotAnEdit(t *testing.T) {
	answer := "notifychanneledited cid=244 channel_description=initial\\sdesc reasonid=9"
	if _, ok := servernotify.ChannelEdited(row(answer)); ok {
		t.Error("the answer to a description fetch was read as an edit")
	}
	if _, ok := servernotify.ChannelEdited(row("notifychanneledited cid=244 channel_description= reasonid=9")); ok {
		t.Error("an empty description answer was read as an edit")
	}
	for name, line := range map[string]string{
		"with an invoker":  answer + admin,
		"another reason":   "notifychanneledited cid=244 channel_description=x reasonid=10",
		"no reason at all": "notifychanneledited cid=244 channel_topic=x",
		"invoker 0":        answer + " invokerid=0",
	} {
		if _, ok := servernotify.ChannelEdited(row(line)); !ok {
			t.Errorf("%s: read as no edit", name)
		}
	}
	if _, ok := servernotify.ChannelEdited(row("notifychanneledited reasonid=10 channel_topic=x")); ok {
		t.Error("an edit of no channel was read")
	}
}

func TestChannelMoved(t *testing.T) {
	evt, ok := servernotify.ChannelMoved(row("notifychannelmoved cid=244 cpid=2 order=0 reasonid=1" + admin))
	want := teamspeak.ChannelMovedEvent{
		ChannelID: 244, ParentID: 2, Order: 0, Reason: 1,
		InvokerID: 413, InvokerName: "b2-adm", InvokerUID: "serveradmin",
	}
	if !ok || evt != want {
		t.Errorf("event = %+v, %v", evt, ok)
	}
}

func TestChannelDeleted(t *testing.T) {
	evt, ok := servernotify.ChannelDeleted(row("notifychanneldeleted" + admin + " cid=246"))
	want := teamspeak.ChannelDeletedEvent{ChannelID: 246, InvokerID: 413, InvokerName: "b2-adm", InvokerUID: "serveradmin"}
	if !ok || evt != want {
		t.Errorf("event = %+v, %v", evt, ok)
	}
	// The server deleting an emptied temporary channel.
	evt, _ = servernotify.ChannelDeleted(row("notifychanneldeleted invokerid=0 invokername=Server cid=243"))
	if evt.InvokerID != 0 || evt.InvokerName != "Server" || evt.InvokerUID != "" {
		t.Errorf("event = %+v", evt)
	}
}

func TestServerEdited(t *testing.T) {
	// TeamSpeak 3 sends a reason; the properties kept are the server's own.
	evt := servernotify.ServerEdited(row("notifyserveredited reasonid=10" + admin +
		" virtualserver_name=b2\\sname virtualserver_hostbanner_url=http:\\/\\/x.invalid"))
	want := teamspeak.Properties{"virtualserver_name": "b2 name", "virtualserver_hostbanner_url": "http://x.invalid"}
	if !reflect.DeepEqual(evt.Changes, want) || evt.InvokerID != 413 || evt.InvokerName != "b2-adm" {
		t.Errorf("event = %+v", evt)
	}
	// TeamSpeak 6 sends none, and a welcome message change names no property.
	welcome := servernotify.ServerEdited(row("notifyserveredited" + admin))
	if welcome.Changes == nil || len(welcome.Changes) != 0 {
		t.Errorf("changes = %#v, want empty and not nil", welcome.Changes)
	}
}

func TestPluginCommand(t *testing.T) {
	evt := servernotify.PluginCommand(row(
		"notifyplugincmd name=b2\\splug data=a\\sb\\pc\\/d invokerid=414 invokername=b2-B invokeruid=3uq="))
	want := teamspeak.PluginCommandEvent{
		Name: "b2 plug", Data: "a b|c/d", InvokerID: 414, InvokerName: "b2-B", InvokerUID: "3uq=",
	}
	if evt != want {
		t.Errorf("event = %+v", evt)
	}
	if got := servernotify.PluginCommand(row("notifyplugincmd name=p data= invokerid=414")); got.Data != "" {
		t.Errorf("data = %q", got.Data)
	}
}

func TestClientChatComposing(t *testing.T) {
	evt, ok := servernotify.ClientChatComposing(row("notifyclientchatcomposing clid=414 cluid=3uq="))
	if !ok || evt.ClientID != 414 || evt.UID != "3uq=" {
		t.Errorf("event = %+v, %v", evt, ok)
	}
	if _, ok := servernotify.ClientChatComposing(row("notifyclientchatcomposing cluid=x")); ok {
		t.Error("a row naming no client was read")
	}
}

func TestChannelChanges_ReadsEveryRecordField(t *testing.T) {
	got := servernotify.ChannelChanges(row("x cid=1 pid=4 channel_unique_identifier=u channel_name=n" +
		" channel_topic= channel_description=d" +
		" channel_order=3 channel_icon_id=-2004712318 channel_codec=4 channel_codec_quality=6 channel_maxclients=-1" +
		" channel_maxfamilyclients=2 total_clients=1 total_clients_family=2 channel_needed_subscribe_power=3" +
		" channel_needed_talk_power=4 channel_flag_default=1 channel_flag_permanent=0 channel_flag_semi_permanent=1" +
		" channel_flag_password=1 channel_codec_latency_factor=2 channel_codec_is_unencrypted=1" +
		" channel_flag_maxclients_unlimited=1 channel_flag_maxfamilyclients_unlimited=0" +
		" channel_flag_maxfamilyclients_inherited=1" +
		" channel_delete_delay=30 channel_name_phonetic=p channel_forced_silence=1" +
		" channel_banner_gfx_url=u channel_banner_mode=2"))
	if got.Topic == nil || *got.Topic != "" {
		t.Error("an empty value is a change to empty")
	}
	if got.DeleteDelay == nil || *got.DeleteDelay != 30*time.Second || *got.IconID != 2290254978 || *got.MaxClients != -1 {
		t.Errorf("changes = %+v", got)
	}
	v := reflect.ValueOf(got)
	for i := range v.NumField() {
		if v.Field(i).IsNil() {
			t.Errorf("%s was not read", v.Type().Field(i).Name)
		}
	}
	cloned := servernotify.CloneChannelChanges(got)
	if !reflect.DeepEqual(cloned, got) {
		t.Error("the clone differs")
	}
	cv := reflect.ValueOf(cloned)
	for i := range v.NumField() {
		if cv.Field(i).Pointer() == v.Field(i).Pointer() {
			t.Errorf("the clone shares %s", v.Type().Field(i).Name)
		}
	}
}
