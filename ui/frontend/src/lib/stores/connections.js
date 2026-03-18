import { writable } from 'svelte/store';
import { Events, Call } from '@wailsio/runtime';

function createConnectionStore() {
  const { subscribe, set, update } = writable([]);
  let isPaused = false;

  // Subscribe to pause state changes
  pausedStore.subscribe(v => isPaused = v);

  // Listen for connection snapshots from the backend
  Events.On('connection-snapshot', (event) => {
    if (!isPaused) {
      const snapshot = event.data;
      if (snapshot) {
        set(snapshot);
      }
    }
  });

  // Start the connection monitor stream on the backend
  Call.ByName("main.BindingService.StartConnectionMonitorStream");

  return {
    subscribe,
    clear: () => set([]),
    pause: () => pausedStore.set(true),
    resume: () => pausedStore.set(false),
  };
}

/** @type {import('svelte/store').Writable<boolean>} */
export const pausedStore = writable(false);

/** @type {import('svelte/store').Writable<Array>} */
export const connections = createConnectionStore();
