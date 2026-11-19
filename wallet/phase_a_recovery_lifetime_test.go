//go:build !slugtestpow

package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taytr-llc/slug/chaincfg/v2"
	"github.com/taytr-llc/slugwallet/walletdb"
)

func TestPhaseARecoveryBlockedStepCloseJoins(t *testing.T) {
	ctx := context.Background()
	bundle := phaseABundle(t, false)
	l, s := phaseABegin(t, bundle)
	for n := 0; n < 2; n++ {
		if _, e := s.Step(ctx, nil); e != nil {
			t.Fatal(e)
		}
	}
	before, e := s.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	source := &recoveryBlockingIdentity{entered: make(chan struct{})}
	finished := make(chan error, 1)
	go func() { _, e := s.Step(ctx, source); finished <- e }()
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("step did not reach source")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case e := <-finished:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("step did not join")
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not join")
	}
	resumed, e := l.OpenPhaseARecovery(ctx, retainedPubPass, bundle.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	defer resumed.Close()
	after, e := resumed.Status(ctx)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("canceled source advanced durable state", e)
	}
}

// Parent sends SIGKILL only after an explicit checkpoint. No deferred close
// executes, including when the child is killed inside an uncommitted write.
func TestPhaseARecoveryCrashChild(t *testing.T) {
	path := os.Getenv("SLUG_TEST_PHASE_A_CRASH_STATE")
	if path == "" {
		t.Skip("subprocess only")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var state reviewRecoveryCrashState
	if e = json.Unmarshal(raw, &state); e != nil {
		t.Fatal(e)
	}
	stop := func() {
		f, e := os.OpenFile(path+".ready", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(state.Stage)); e != nil {
			t.Fatal(e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		select {}
	}
	l := reviewRecoveryLoader(state.Directory)
	bundle := phaseABundle(t, false)
	var s *RecoverySession
	if state.Stage == "initialized" {
		l.recoveryCheckpoint = func(stage string) {
			if stage == state.Stage {
				stop()
			}
		}
		s, e = l.BeginPhaseARecovery(context.Background(), retainedPubPass, retainedPrivPass, bundle)
	} else {
		s, e = l.OpenPhaseARecovery(context.Background(), retainedPubPass, bundle.Manifest)
	}
	if e != nil {
		t.Fatal(e)
	}
	if state.Stage == "deriving-uncommitted" {
		real := s.update
		s.update = func(fn func(walletdb.ReadWriteTx) error) error {
			return real(func(tx walletdb.ReadWriteTx) error {
				if e := fn(tx); e != nil {
					return e
				}
				stop()
				return nil
			})
		}
	}
	s.checkpoint = func(stage string) {
		if stage == state.Stage {
			stop()
		}
	}
	source := &reviewRecoverySource{}
	source.set(reviewCopyBlock(chaincfg.MainNetParams.GenesisBlock))
	for n := 0; n < 10; n++ {
		p, e := s.Step(context.Background(), source)
		if e != nil {
			t.Fatal(e)
		}
		if p.Ready {
			break
		}
	}
	t.Fatal("requested crash checkpoint not reached")
}
func TestPhaseARecoveryProcessKillBoundaries(t *testing.T) {
	for _, stage := range []string{"initialized", "deriving-uncommitted", "ready"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			state := reviewRecoveryCrashState{Directory: filepath.Join(dir, "wallet"), Stage: stage}
			bundle := phaseABundle(t, false)
			if stage != "initialized" {
				l := reviewRecoveryLoader(state.Directory)
				s, e := l.BeginPhaseARecovery(context.Background(), retainedPubPass, retainedPrivPass, bundle)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.Close(); e != nil {
					t.Fatal(e)
				}
			}
			path := filepath.Join(dir, "public-crash-state.json")
			raw, _ := json.Marshal(state)
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPhaseARecoveryCrashChild$", "-test.timeout=45s")
			cmd.Env = append(os.Environ(), "SLUG_TEST_PHASE_A_CRASH_STATE="+path)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			timer := time.NewTimer(40 * time.Second)
			defer timer.Stop()
		wait:
			for {
				select {
				case e := <-done:
					t.Fatalf("child stopped before checkpoint %v %s", e, output.String())
				case <-timer.C:
					_ = cmd.Process.Kill()
					<-done
					t.Fatalf("checkpoint deadline %s", output.String())
				case <-tick.C:
					if _, e := os.Stat(path + ".ready"); e == nil {
						break wait
					} else if !errors.Is(e, os.ErrNotExist) {
						_ = cmd.Process.Kill()
						<-done
						t.Fatal(e)
					}
				}
			}
			if e := cmd.Process.Kill(); e != nil {
				<-done
				t.Fatal(e)
			}
			if e := <-done; e == nil {
				t.Fatal("child exited normally")
			}
			if bytes.Contains(output.Bytes(), []byte("DATA RACE")) {
				t.Fatalf("child race %s", output.String())
			}
			l := reviewRecoveryLoader(state.Directory)
			s, e := l.OpenPhaseARecovery(context.Background(), retainedPubPass, bundle.Manifest)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			p, e := s.Status(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if stage == "ready" {
				if !p.Ready || p.Derived != 160 || p.ScannedHeight != 0 {
					t.Fatal("ready commit lost", p)
				}
			} else if p.Ready || p.Derived != 0 || p.ScannedHeight != -1 {
				t.Fatal("uncommitted work survived", p)
			}
		})
	}
}
