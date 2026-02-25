import { writable } from 'svelte/store';

/** Whether the currently active tab has unsaved changes. */
export const tabDirty = writable(false);
