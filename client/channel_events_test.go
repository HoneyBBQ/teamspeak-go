package client

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

const adminInvoker = " invokerid=413 invokername=b2-adm invokeruid=serveradmin"

// Each notification becomes its event, in the order it arrived, and every one
// still reaches OnNotification after its typed event.
func TestChannelAndServerNotifications_BecomeEvents(t *testing.T) {
	c, events := collect(t)
	for _, line := range []string{
		"notifychannelcreated cid=247 cpid=0 channel_name=n channel_order=246" + adminInvoker,
		"notifychanneledited cid=247 reasonid=10" + adminInvoker + " channel_topic=t",
		"notifychannelmoved cid=247 cpid=2 order=0 reasonid=1" + adminInvoker,
		"notifychanneldescriptionchanged cid=247",
		"notifychannelpasswordchanged cid=247",
		"notifychanneldeleted cid=247 invokerid=0 invokername=Server",
		"notifyserveredited reasonid=10" + adminInvoker + " virtualserver_name=x",
		"notifychannelsubscribed cid=240 es=3",
		"notifychannelunsubscribed cid=240",
		"notifyplugincmd name=p data=d invokerid=414 invokername=B",
		"notifyclientchatcomposing clid=414 cluid=u",
	} {
		c.handleCommandLines(c.handler, line)
	}

	var names []string
	for _, e := range events() {
		name := reflect.TypeOf(e).Name()
		// Each typed event is followed by the notification it came from.
		if name == "NotificationEvent" {
			continue
		}
		names = append(names, name)
	}
	want := []string{
		"ChannelCreatedEvent", "ChannelEditedEvent", "ChannelMovedEvent", "ChannelDescriptionChangedEvent",
		"ChannelPasswordChangedEvent", "ChannelDeletedEvent", "ServerEditedEvent", "ChannelSubscribedEvent",
		"ChannelUnsubscribedEvent", "PluginCommandEvent", "ClientChatComposingEvent",
	}
	if !slices.Equal(names, want) {
		t.Errorf("events = %v\nwant     %v", names, want)
	}
}

func TestChannelEvents_HandlersGetTheirOwnChanges(t *testing.T) {
	c := newTestClient(t)
	first := make(chan ChannelEditedEvent, 1)
	second := make(chan ChannelEditedEvent, 1)
	c.OnChannelEdited(func(e ChannelEditedEvent) {
		*e.Changes.Topic = "edited by the first handler"
		first <- e
	})
	c.OnChannelEdited(func(e ChannelEditedEvent) { second <- e })
	c.handleCommandLines(c.handler, "notifychanneledited cid=5 reasonid=10"+adminInvoker+" channel_topic=t")

	<-first
	if got := *(<-second).Changes.Topic; got != "t" {
		t.Errorf("the second handler saw %q", got)
	}
}

func TestServerEdited_HandlersGetTheirOwnChanges(t *testing.T) {
	c := newTestClient(t)
	first := make(chan struct{}, 1)
	second := make(chan ServerEditedEvent, 1)
	c.OnServerEdited(func(e ServerEditedEvent) {
		e.Changes["virtualserver_name"] = "mine"
		first <- struct{}{}
	})
	c.OnServerEdited(func(e ServerEditedEvent) { second <- e })
	c.handleCommandLines(c.handler, "notifyserveredited"+adminInvoker+" virtualserver_name=x")

	<-first
	if got := (<-second).Changes["virtualserver_name"]; got != "x" {
		t.Errorf("the second handler saw %q", got)
	}
}

// The answer to a description fetch is not an edit: no event, but the catch-all
// has it.
func TestChannelEdited_Reason9AnswerIsNoEventButIsANotification(t *testing.T) {
	c, events := collect(t)
	notified := make(chan NotificationEvent, 2)
	c.OnNotification(func(n NotificationEvent) { notified <- n })

	c.handleCommandLines(c.handler, "notifychanneledited cid=5 channel_description=d reasonid=9")
	c.handleCommandLines(c.handler, "notifychanneledited cid=5 channel_description=d reasonid=9 invokerid=3 invokername=a")

	var edited int
	for _, e := range events() {
		if _, ok := e.(ChannelEditedEvent); ok {
			edited++
		}
	}
	if edited != 1 {
		t.Errorf("%d edits reported, want only the one with an invoker", edited)
	}
	if n := <-notified; n.Name != "notifychanneledited" {
		t.Errorf("notification = %q", n.Name)
	}
}

// The roster is not a writer for any of them.
func TestChannelEvents_LeaveWhatTheClientKnowsOfClients(t *testing.T) {
	c := newTestClient(t)
	before := teamspeak.ClientEntry{ID: 7, UID: "u7", Nickname: "A", ChannelID: 3}
	know(c, before)
	for _, line := range []string{
		"notifychannelcreated cid=3 cpid=0 channel_name=n",
		"notifychanneledited cid=3 reasonid=10 channel_topic=t",
		"notifychanneldeleted cid=3",
		"notifyserveredited virtualserver_name=n",
		"notifyplugincmd name=p data=d invokerid=7",
		"notifyclientchatcomposing clid=7",
	} {
		c.handleCommandLines(c.handler, line)
	}
	if got, _ := known(c, 7); !reflect.DeepEqual(got, before) {
		t.Errorf("entry = %+v", got)
	}
}

// A real edit that arrives while GetChannelDescription waits is collected as an
// answer row too; the description is the row for the channel that carries it.
func TestGetChannelDescription_SkipsAnEditThatArrivesMeanwhile(t *testing.T) {
	c, events := collect(t)

	type result struct {
		err  error
		desc string
	}
	done := make(chan result, 1)
	go func() {
		d, err := c.GetChannelDescription(context.Background(), 7)
		done <- result{err, d}
	}()
	var rc uint32
	deadline := time.Now().Add(5 * time.Second)
	for rc == 0 && time.Now().Before(deadline) {
		c.cmdTrack.mu.Lock()
		for k := range c.cmdTrack.pending {
			rc = k
		}
		c.cmdTrack.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	if rc == 0 {
		t.Fatal("the command was never sent")
	}

	c.handleCommandLines(c.handler, "notifychanneledited cid=7 reasonid=10"+adminInvoker+" channel_topic=other")
	c.handleCommandLines(c.handler, "notifychanneledited cid=9 reasonid=9 channel_description=elsewhere")
	c.handleCommandLines(c.handler, "notifychanneledited cid=7 reasonid=9 channel_description=the\\sdescription")
	c.handleCommandLines(c.handler, "error id=0 msg=ok return_code="+itoa(rc))

	got := <-done
	if got.err != nil || got.desc != "the description" {
		t.Errorf("GetChannelDescription = %q, %v", got.desc, got.err)
	}
	// The real edit is reported; the answers are not.
	var edits []ChannelEditedEvent
	for _, e := range events() {
		if edit, ok := e.(ChannelEditedEvent); ok {
			edits = append(edits, edit)
		}
	}
	if len(edits) != 1 || edits[0].Changes.Topic == nil || *edits[0].Changes.Topic != "other" {
		t.Errorf("edits = %+v", edits)
	}
}

func TestGetChannelDescription_AnEmptyDescriptionIsAnAnswer(t *testing.T) {
	c := newTestClient(t, WithCommandMiddleware(func(teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(context.Context, teamspeak.Request) ([]map[string]string, error) {
			return []map[string]string{{"cid": "7", "channel_description": ""}}, nil
		})
	}))
	desc, err := c.GetChannelDescription(t.Context(), 7)
	if err != nil || desc != "" {
		t.Errorf("GetChannelDescription = %q, %v", desc, err)
	}
}

func TestGetChannelDescription_OnlyAnotherChannelsRowIsNoData(t *testing.T) {
	c := newTestClient(t, WithCommandMiddleware(func(teamspeak.Executor) teamspeak.Executor {
		return teamspeak.ExecutorFunc(func(context.Context, teamspeak.Request) ([]map[string]string, error) {
			return []map[string]string{{"cid": "7", "channel_topic": "x"}, {"cid": "9", "channel_description": "d"}}, nil
		})
	}))
	_, err := c.GetChannelDescription(t.Context(), 7)
	if err == nil {
		t.Error("another channel's description was returned")
	}
}
