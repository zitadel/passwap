package passwap

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

// stubHasher is a Hasher that performs no real hashing.
// It counts calls and tracks how many are in flight at once.
// If block is non-nil, every call waits until it is closed.
// If sleep is non-zero, every call sleeps for that duration.
// If onWork is non-nil, it is called at the start of every call.
type stubHasher struct {
	verifyResult verifier.Result
	block        chan struct{}
	sleep        time.Duration
	onWork       func()

	calls       atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

func (h *stubHasher) work() {
	if h.onWork != nil {
		h.onWork()
	}
	h.calls.Add(1)
	n := h.inFlight.Add(1)
	defer h.inFlight.Add(-1)

	for {
		cur := h.maxInFlight.Load()
		if n <= cur || h.maxInFlight.CompareAndSwap(cur, n) {
			break
		}
	}

	if h.block != nil {
		<-h.block
	}
	if h.sleep > 0 {
		time.Sleep(h.sleep)
	}
}

func (h *stubHasher) Validate(string) (verifier.Result, error) {
	return verifier.OK, nil
}

func (h *stubHasher) Verify(string, string) (verifier.Result, error) {
	h.work()
	return h.verifyResult, nil
}

func (h *stubHasher) Hash(string) (string, error) {
	h.work()
	return "$stub$hash", nil
}

func TestNewSemaphore(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("NewSemaphore(%d) did not panic", n)
				}
			}()
			NewSemaphore(testSwapper, n)
		}()
	}

	if got := NewSemaphore(testSwapper, 1); got == nil {
		t.Error("NewSemaphore(1) returned nil")
	}
}

func TestSemaphore_Validate(t *testing.T) {
	sem := NewSemaphore(testSwapper, 1)
	for _, encoded := range []string{tv.Argon2idEncoded, tv.ScryptEncoded, "foobar", "$argon2id$foo"} {
		want := testSwapper.Validate(encoded)
		got := sem.Validate(encoded)
		if (got == nil) != (want == nil) {
			t.Errorf("Semaphore.Validate(%q) error = %v, Swapper.Validate error = %v", encoded, got, want)
		}
	}
}

func TestSemaphore_Verify(t *testing.T) {
	sem := NewSemaphore(testSwapper, 1)

	t.Run("match", func(t *testing.T) {
		updated, err := sem.Verify(t.Context(), tv.Argon2idEncoded, tv.Password)
		if err != nil {
			t.Fatalf("Semaphore.Verify() error = %v", err)
		}
		if updated != "" {
			t.Errorf("Semaphore.Verify() updated = %q, want empty", updated)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		updated, err := sem.Verify(t.Context(), tv.Argon2idEncoded, "wrong")
		if !errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("Semaphore.Verify() error = %v, want %v", err, ErrPasswordMismatch)
		}
		if updated != "" {
			t.Errorf("Semaphore.Verify() updated = %q, want empty", updated)
		}
	})

	t.Run("needs update", func(t *testing.T) {
		updated, err := sem.Verify(t.Context(), tv.ScryptEncoded, tv.Password)
		if err != nil {
			t.Fatalf("Semaphore.Verify() error = %v", err)
		}
		if updated == "" {
			t.Fatal("Semaphore.Verify() did not return updated")
		}
		// The updated hash must be accepted by the Swapper without further update.
		again, err := testSwapper.Verify(updated, tv.Password)
		if err != nil {
			t.Fatalf("Swapper.Verify(updated) error = %v", err)
		}
		if again != "" {
			t.Errorf("Swapper.Verify(updated) = %q, want empty", again)
		}
	})
}

func TestSemaphore_VerifyAndUpdate(t *testing.T) {
	sem := NewSemaphore(testSwapper, 1)

	t.Run("no change", func(t *testing.T) {
		updated, err := sem.VerifyAndUpdate(t.Context(), tv.Argon2idEncoded, tv.Password, tv.Password)
		if !errors.Is(err, ErrPasswordNoChange) {
			t.Errorf("Semaphore.VerifyAndUpdate() error = %v, want %v", err, ErrPasswordNoChange)
		}
		if updated != "" {
			t.Errorf("Semaphore.VerifyAndUpdate() updated = %q, want empty", updated)
		}
	})

	t.Run("update", func(t *testing.T) {
		const newPassword = "newpassword"
		updated, err := sem.VerifyAndUpdate(t.Context(), tv.Argon2idEncoded, tv.Password, newPassword)
		if err != nil {
			t.Fatalf("Semaphore.VerifyAndUpdate() error = %v", err)
		}
		if updated == "" {
			t.Fatal("Semaphore.VerifyAndUpdate() did not return updated")
		}
		if _, err := testSwapper.Verify(updated, newPassword); err != nil {
			t.Errorf("Swapper.Verify(updated, newPassword) error = %v", err)
		}
	})
}

func TestSemaphore_Hash(t *testing.T) {
	sem := NewSemaphore(testSwapper, 1)

	encoded, err := sem.Hash(t.Context(), tv.Password)
	if err != nil {
		t.Fatalf("Semaphore.Hash() error = %v", err)
	}
	if encoded == "" {
		t.Fatal("Semaphore.Hash() returned empty")
	}
	updated, err := testSwapper.Verify(encoded, tv.Password)
	if err != nil {
		t.Fatalf("Swapper.Verify(encoded) error = %v", err)
	}
	if updated != "" {
		t.Errorf("Swapper.Verify(encoded) = %q, want empty", updated)
	}
}

func TestSemaphore_concurrencyBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			n     = 2
			calls = 50
		)
		stub := &stubHasher{verifyResult: verifier.OK, sleep: time.Millisecond}
		sem := NewSemaphore(NewSwapper(stub), n)

		var wg sync.WaitGroup
		for i := range calls {
			wg.Go(func() {
				var err error
				if i%2 == 0 {
					_, err = sem.Hash(t.Context(), tv.Password)
				} else {
					_, err = sem.Verify(t.Context(), "$stub$hash", tv.Password)
				}
				if err != nil {
					t.Errorf("call %d error = %v", i, err)
				}
			})
		}
		wg.Wait()

		if got := stub.calls.Load(); got != calls {
			t.Errorf("stub calls = %d, want %d", got, calls)
		}
		if got := stub.maxInFlight.Load(); got != n {
			t.Errorf("max in flight = %d, want %d", got, n)
		}
		if got := stub.inFlight.Load(); got != 0 {
			t.Errorf("in flight after completion = %d, want 0", got)
		}
	})
}

func TestSemaphore_oneSlotPerVerifyWithRehash(t *testing.T) {
	stub := &stubHasher{verifyResult: verifier.NeedUpdate}
	var sem *Semaphore
	// Record how many slots are held on every stub call.
	var held []int
	stub.onWork = func() {
		held = append(held, len(sem.slots))
	}
	sem = NewSemaphore(NewSwapper(stub), 1)

	updated, err := sem.Verify(t.Context(), "$stub$old", tv.Password)
	if err != nil {
		t.Fatalf("Semaphore.Verify() error = %v", err)
	}
	if updated == "" {
		t.Fatal("Semaphore.Verify() did not return updated")
	}
	// Verify and the subsequent Hash must both have run inside the single slot.
	if got := stub.calls.Load(); got != 2 {
		t.Errorf("stub calls = %d, want 2", got)
	}
	if want := []int{1, 1}; !slices.Equal(held, want) {
		t.Errorf("slots held per call = %v, want %v", held, want)
	}
	if got := stub.maxInFlight.Load(); got != 1 {
		t.Errorf("max in flight = %d, want 1", got)
	}
}

func TestSemaphore_context(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		stub := &stubHasher{verifyResult: verifier.OK}
		sem := NewSemaphore(NewSwapper(stub), 1)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Repeat: without the ctx.Err() pre-check in acquire, select would
		// pick the free slot over the done context some of the time.
		for range 100 {
			if _, err := sem.Hash(ctx, tv.Password); !errors.Is(err, context.Canceled) {
				t.Errorf("Semaphore.Hash() error = %v, want %v", err, context.Canceled)
			}
			if _, err := sem.Verify(ctx, "$stub$hash", tv.Password); !errors.Is(err, context.Canceled) {
				t.Errorf("Semaphore.Verify() error = %v, want %v", err, context.Canceled)
			}
			if _, err := sem.VerifyAndUpdate(ctx, "$stub$hash", tv.Password, "newpassword"); !errors.Is(err, context.Canceled) {
				t.Errorf("Semaphore.VerifyAndUpdate() error = %v, want %v", err, context.Canceled)
			}
		}
		if got := stub.calls.Load(); got != 0 {
			t.Errorf("stub calls = %d, want 0", got)
		}
	})

	t.Run("cancelled while waiting", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stub := &stubHasher{verifyResult: verifier.OK, block: make(chan struct{})}
			sem := NewSemaphore(NewSwapper(stub), 1)

			var wg sync.WaitGroup
			// Hold the only slot.
			wg.Go(func() {
				if _, err := sem.Hash(t.Context(), tv.Password); err != nil {
					t.Errorf("holder Semaphore.Hash() error = %v", err)
				}
			})
			synctest.Wait()
			if got := stub.calls.Load(); got != 1 {
				t.Fatalf("stub calls = %d, want 1", got)
			}

			ctx, cancel := context.WithCancel(t.Context())
			errs := make(chan error, 1)
			wg.Go(func() {
				_, err := sem.Verify(ctx, "$stub$hash", tv.Password)
				errs <- err
			})
			// The waiter must be blocked on the slot, not have started hashing.
			synctest.Wait()
			if got := stub.calls.Load(); got != 1 {
				t.Fatalf("stub calls = %d, want 1", got)
			}

			cancel()
			if err := <-errs; !errors.Is(err, context.Canceled) {
				t.Errorf("waiter Semaphore.Verify() error = %v, want %v", err, context.Canceled)
			}
			if got := stub.calls.Load(); got != 1 {
				t.Errorf("stub calls = %d, want 1", got)
			}

			close(stub.block)
			wg.Wait()
		})
	})

	t.Run("deadline while waiting", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stub := &stubHasher{verifyResult: verifier.OK, block: make(chan struct{})}
			sem := NewSemaphore(NewSwapper(stub), 1)

			var wg sync.WaitGroup
			// Hold the only slot.
			wg.Go(func() {
				if _, err := sem.Hash(t.Context(), tv.Password); err != nil {
					t.Errorf("holder Semaphore.Hash() error = %v", err)
				}
			})
			synctest.Wait()

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()

			if _, err := sem.Hash(ctx, tv.Password); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("waiter Semaphore.Hash() error = %v, want %v", err, context.DeadlineExceeded)
			}
			if got := stub.calls.Load(); got != 1 {
				t.Errorf("stub calls = %d, want 1", got)
			}

			close(stub.block)
			wg.Wait()
		})
	})
}
