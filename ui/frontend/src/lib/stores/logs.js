import { writable } from 'svelte/store';
import { Events, Call } from '@wailsio/runtime';

const MAX_LOGS = 1000;

function createLogStore() {
  const { subscribe, update, set } = writable([]);
  let buffer = [];
  let rafId = null;

  function flush() {
    rafId = null;
    if (buffer.length === 0) return;
    const batch = buffer;
    buffer = [];
    update(current => {
      const updated = [...current, ...batch];
      return updated.length > MAX_LOGS ? updated.slice(updated.length - MAX_LOGS) : updated;
    });
  }

  // Subscribe to log events FIRST, before starting the stream,
  // so no events are lost between stream start and subscription.
  // Events are buffered and flushed via requestAnimationFrame to
  // prevent UI freezes during event bursts (max ~60 updates/sec).
  Events.On('log-entry', (event) => {
    const entry = event.data;
    if (!entry) return;
    buffer.push(entry);
    if (rafId === null) {
      rafId = requestAnimationFrame(flush);
    }
  });

  // Now start the gRPC log stream on the backend.
  // This is safe to call multiple times (guarded by sync.Once in Go).
  Call.ByName("main.BindingService.StartLogStream");

  return {
    subscribe,
    clear: () => { buffer = []; set([]); },
  };
}

export const logStore = createLogStore();
