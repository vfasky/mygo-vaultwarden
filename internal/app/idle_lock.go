// SPDX-License-Identifier: GPL-3.0-only
package app

import "time"

const vaultIdleTimeout = 15 * time.Minute

// idleLockController owns the inactivity deadline. Only real keyboard/mouse
// activity reported by idle may extend it; rendering and sync never do. All
// state is confined to the UI dispatcher, including timer completions.
type idleLockController struct {
	now        func() time.Time
	idle       func() time.Duration
	after      func(time.Duration, func()) func()
	dispatch   func(func())
	lock       func()
	started    time.Time
	active     bool
	generation uint64
	cancel     func()
}

func (c *idleLockController) start() {
	if c == nil || c.active {
		return
	}
	c.active = true
	c.generation++
	c.started = c.now()
	c.schedule(c.generation)
}

func (c *idleLockController) stop() {
	if c == nil {
		return
	}
	c.active = false
	c.generation++
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
}

func (c *idleLockController) schedule(generation uint64) {
	c.cancel = c.after(time.Second, func() {
		c.dispatch(func() {
			if !c.active || c.generation != generation {
				return
			}
			// Grant a fresh authenticated unlock its own interval even if the
			// system's last input was earlier (e.g. a biometric unlock).
			if c.now().Sub(c.started) >= vaultIdleTimeout && c.idle() >= vaultIdleTimeout {
				c.stop()
				c.lock()
				return
			}
			c.schedule(generation)
		})
	})
}

func idleAfter(delay time.Duration, f func()) func() {
	timer := time.AfterFunc(delay, f)
	return func() { timer.Stop() }
}
