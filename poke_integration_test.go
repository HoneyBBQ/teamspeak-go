//go:build integration

package teamspeak_test

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	teamspeak "github.com/honeybbq/teamspeak-go"
)

func TestIntegration_PokeSendAndReceive(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	sender := newConnectedIntegrationClient(t, addr, "poke-tx", slog.Default())
	receiver := newConnectedIntegrationClient(t, addr, "poke-rx", slog.Default())

	pokeMsg := fmt.Sprintf("poke-test-%d", time.Now().UTC().UnixNano())

	poked := make(chan teamspeak.PokeEvent, 1)
	receiver.OnPoked(func(e teamspeak.PokeEvent) {
		select {
		case poked <- e:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	if err := sender.Poke(receiver.ClientID(), pokeMsg); err != nil {
		t.Fatalf("Poke: %v", err)
	}
	t.Logf("sent poke from clid=%d to clid=%d msg=%q", sender.ClientID(), receiver.ClientID(), pokeMsg)

	select {
	case evt := <-poked:
		t.Logf("poke received: invoker=%q uid=%q msg=%q", evt.InvokerName, evt.InvokerUID, evt.Message)
		if evt.InvokerID != sender.ClientID() {
			t.Errorf("InvokerID mismatch: got %d want %d", evt.InvokerID, sender.ClientID())
		}
		if evt.Message != pokeMsg {
			t.Errorf("Message mismatch: got %q want %q", evt.Message, pokeMsg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for poke notification")
	}
}

func TestIntegration_PokeEmptyMessage(t *testing.T) {
	addr := requireTeamSpeakAddr(t)

	sender := newConnectedIntegrationClient(t, addr, "poke-tx2", slog.Default())
	receiver := newConnectedIntegrationClient(t, addr, "poke-rx2", slog.Default())

	poked := make(chan teamspeak.PokeEvent, 1)
	receiver.OnPoked(func(e teamspeak.PokeEvent) {
		select {
		case poked <- e:
		default:
		}
	})

	time.Sleep(500 * time.Millisecond)

	if err := sender.Poke(receiver.ClientID(), ""); err != nil {
		t.Fatalf("Poke (empty): %v", err)
	}
	t.Logf("sent empty poke from clid=%d to clid=%d", sender.ClientID(), receiver.ClientID())

	select {
	case evt := <-poked:
		t.Logf("empty poke received: invoker=%q msg=%q", evt.InvokerName, evt.Message)
		if evt.Message != "" {
			t.Errorf("expected empty message, got %q", evt.Message)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for empty poke notification")
	}
}
