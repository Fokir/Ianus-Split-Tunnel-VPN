import { writable, get } from 'svelte/store';
import { Events, Call } from '@wailsio/runtime';

const STORAGE_KEY = 'awg-log-max-entries';
const DEFAULT_MAX = 1000;
const ALLOWED_LIMITS = [500, 1000, 2000, 5000, 10000];

function loadMaxLogs() {
  try {
    const v = parseInt(localStorage.getItem(STORAGE_KEY), 10);
    if (ALLOWED_LIMITS.includes(v)) return v;
  } catch {}
  return DEFAULT_MAX;
}

export const maxLogsStore = writable(loadMaxLogs());

maxLogsStore.subscribe(v => {
  try { localStorage.setItem(STORAGE_KEY, String(v)); } catch {}
});

function createLogStore() {
  const { subscribe, update, set } = writable([]);
  let buffer = [];
  let rafId = null;

  function flush() {
    rafId = null;
    if (buffer.length === 0) return;
    const batch = buffer;
    buffer = [];
    const maxLogs = get(maxLogsStore);
    update(current => {
      // Avoid full copy when possible
      if (current.length + batch.length <= maxLogs) {
        current.push(...batch);
        return current;
      }
      const combined = current.concat(batch);
      return combined.slice(combined.length - maxLogs);
    });
  }

  Events.On('log-entry', (event) => {
    const entry = event.data;
    if (!entry) return;
    buffer.push(entry);
    if (rafId === null) {
      rafId = requestAnimationFrame(flush);
    }
  });

  Call.ByName("main.BindingService.StartLogStream");

  return {
    subscribe,
    clear: () => { buffer = []; set([]); },
    trimToMax: (newMax) => {
      update(current => {
        return current.length > newMax ? current.slice(current.length - newMax) : current;
      });
    },
  };
}

export const logStore = createLogStore();
export { ALLOWED_LIMITS };
