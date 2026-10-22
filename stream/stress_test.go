package stream

import (
	"context"
	"math/rand/v2"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/honeybbq/teamspeak-go/notify"
)

// TestStress_PublishFloodAndClose runs many Publish calls that are cancelled or
// time out at random against a server that answers after random delays, with
// notifications arriving from several goroutines, and closes the Streams in the
// middle of it. Run under the race detector, it holds the locking to account; the
// bubble fails it if any goroutine outlives its deadline.
func TestStress_PublishFloodAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newFakeHost()
		s := newStreams(h, Options{RememberDenied: true})
		s.OnError(func(error) {})
		var issued atomic.Int64
		h.reply = func(c sent) ([]map[string]string, error, bool) {
			if c.name != "setupstream" {
				return nil, nil, false
			}
			time.Sleep(time.Duration(rand.IntN(80)) * time.Millisecond)
			id := "s" + strconv.FormatInt(issued.Add(1), 10)
			row := announcement(id, 1)
			if rand.IntN(2) == 0 {
				h.notify(notify.StreamStarted, row)
			}

			return []map[string]string{row}, nil, true
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 20 {
					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1+rand.IntN(60))*time.Millisecond)
					p, err := s.Publish(ctx, PublishOptions{Name: "n"})
					cancel()
					if err == nil {
						p.OnRequest(func(r *JoinRequest) { _ = r.Deny(context.Background(), "") })
						if rand.IntN(3) == 0 {
							_ = p.Stop(context.Background(), 0)
						}
					}
				}
			})
		}
		for range 4 {
			wg.Go(func() {
				for i := range 200 {
					id := "s" + strconv.Itoa(1+rand.IntN(100))
					switch rand.IntN(5) {
					case 0:
						h.notify(notify.StreamStopped, map[string]string{"id": id})
					case 1:
						h.notify(notify.JoinStreamRequest, map[string]string{"id": id, "clid": strconv.Itoa(2 + i%5)})
					case 2:
						h.notify(notify.StreamInfo, map[string]string{"id": id, "clid": "1", "viewer": strconv.Itoa(i)})
					case 3:
						h.enter(2, new(rand.IntN(2) == 0))
					default:
						_ = s.List()
					}
					time.Sleep(time.Duration(rand.IntN(10)) * time.Millisecond)
				}
			})
		}
		wg.Go(func() {
			time.Sleep(700 * time.Millisecond)
			_ = s.Close(context.Background())
		})
		wg.Wait()
		time.Sleep(time.Minute)

		limit := issued.Load()
		for _, stop := range h.commands("stopstream") {
			n, _ := strconv.Atoi(stop.params["id"][1:])
			if int64(n) > limit {
				t.Errorf("stopstream for %s, but only %d streams were started", stop.params["id"], limit)
			}
		}
	})
}
