import { writable } from 'svelte/store';
import { Events, Call } from '@wailsio/runtime';

const MAX_LOGS = 1000;

function createLogStore() {
  const { subscribe, update, set } = writable([]);

  // Subscribe to log events FIRST, before starting the stream,
  // so no events are lost between stream start and subscription.
  Events.On('log-entry', (event) => {
    const entry = event.data;
    if (!entry) return;
    update(current => {
      const updated = [...current, entry];
      return updated.length > MAX_LOGS ? updated.slice(updated.length - MAX_LOGS) : updated;
    });
  });

  // Now start the gRPC log stream on the backend.
  // This is safe to call multiple times (guarded by sync.Once in Go).
  Call.ByName("main.BindingService.StartLogStream");

  return {
    subscribe,
    clear: () => set([]),
  };
}

export const logStore = createLogStore();
