import { writable } from 'svelte/store';
import { Events, Call } from '@wailsio/runtime';

/** @type {import('svelte/store').Writable<boolean>} */
export const pausedStore = writable(false);

/** @type {import('svelte/store').Writable<boolean>} */
export const monitorEnabled = writable(false);

function createConnectionStore() {
  const { subscribe, set } = writable([]);
  let isPaused = false;
  let isEnabled = false;
  let streamStarted = false;

  pausedStore.subscribe(v => isPaused = v);

  monitorEnabled.subscribe(v => {
    isEnabled = v;
    if (v && !streamStarted) {
      streamStarted = true;
      Call.ByName("main.BindingService.StartConnectionMonitorStream");
    }
    if (!v) {
      set([]);
      streamStarted = false;
      Call.ByName("main.BindingService.StopConnectionMonitorStream");
    }
  });

  Events.On('connection-snapshot', (event) => {
    if (!isPaused && isEnabled) {
      const snapshot = event.data;
      if (snapshot) {
        set(snapshot);
      }
    }
  });

  return {
    subscribe,
    clear: () => set([]),
  };
}

/** @type {import('svelte/store').Writable<Array>} */
export const connections = createConnectionStore();
