package passwap

import (
	"context"
	"fmt"
)

// Semaphore wraps a [Swapper] and bounds the number of
// password hash operations that may run concurrently.
// Password hashing is deliberately expensive in CPU and,
// for algorithms like argon2, memory. Without a bound,
// a burst of requests can exhaust the resources of a host.
// Semaphore limits the damage by letting at most n operations
// run at the same time and making all others wait for a free slot.
//
// Each slot covers one full call of [Semaphore.Verify],
// [Semaphore.VerifyAndUpdate] or [Semaphore.Hash],
// including any re-hash the wrapped Swapper performs
// when an updated encoded string is required.
// [Semaphore.Validate] only parses encoded strings and
// never hashes, so it takes no slot.
//
// Waiting for a slot is bounded by the passed context:
// when the context is done before a slot is obtained,
// the call returns without hashing and the error wraps
// the context's error, so [errors.Is] can match it against
// [context.Canceled] or [context.DeadlineExceeded].
//
// Sizing: Verify hashes with the cost parameters found in the
// stored encoded string, which can be anything the configured
// verifiers accept, not only the parameters of the Hasher.
// Peak memory used by hashing is therefore about n × the largest
// memory cost any configured hasher or verifier will accept,
// on top of the usual process memory. For argon2 that is the
// larger of Params.Memory and ValidationOpts.MaxMemory (in KiB),
// so bound MaxMemory accordingly and choose n with the available
// memory and CPU cores in mind.
//
// A Semaphore is safe for concurrent use.
type Semaphore struct {
	s     *Swapper
	slots chan struct{}
}

// NewSemaphore wraps s, allowing at most n concurrent
// hash operations. NewSemaphore panics if n is less than 1.
func NewSemaphore(s *Swapper, n int) *Semaphore {
	if n < 1 {
		panic("passwap: NewSemaphore n must be positive")
	}
	return &Semaphore{
		s:     s,
		slots: make(chan struct{}, n),
	}
}

// acquire a slot, waiting until one is free or ctx is done.
// A context that is already done never obtains a slot,
// even when one is free.
func (s *Semaphore) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("passwap: %w", err)
	}
	select {
	case s.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("passwap: %w", ctx.Err())
	}
}

// release a slot obtained by acquire.
func (s *Semaphore) release() {
	<-s.slots
}

// Validate operates like [Swapper.Validate].
// It only parses the encoded string and does not take a slot.
func (s *Semaphore) Validate(encoded string) error {
	return s.s.Validate(encoded)
}

// Verify operates like [Swapper.Verify], after obtaining a slot.
// The slot is held for the complete call, including the re-hash
// that produces updated when needed.
// If ctx is done before a slot is obtained, the wrapped
// context error is returned and no hashing takes place.
func (s *Semaphore) Verify(ctx context.Context, encoded, password string) (updated string, err error) {
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()

	return s.s.Verify(encoded, password)
}

// VerifyAndUpdate operates like [Swapper.VerifyAndUpdate], after obtaining a slot.
// [ErrPasswordNoChange] is returned without taking a slot
// when newPassword equals oldPassword.
// If ctx is done before a slot is obtained, the wrapped
// context error is returned and no hashing takes place.
func (s *Semaphore) VerifyAndUpdate(ctx context.Context, encoded, oldPassword, newPassword string) (updated string, err error) {
	if oldPassword == newPassword {
		return "", ErrPasswordNoChange
	}
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()

	return s.s.VerifyAndUpdate(encoded, oldPassword, newPassword)
}

// Hash operates like [Swapper.Hash], after obtaining a slot.
// If ctx is done before a slot is obtained, the wrapped
// context error is returned and no hashing takes place.
func (s *Semaphore) Hash(ctx context.Context, password string) (encoded string, err error) {
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()

	return s.s.Hash(password)
}
