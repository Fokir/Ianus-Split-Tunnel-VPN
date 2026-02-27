import { writable } from 'svelte/store';
import * as api from '../api.js';

/** Current OS: "windows" | "darwin" | "linux". Loaded once on app start. */
export const platform = writable('windows');

/** Whether the current OS is macOS. */
export const isMac = writable(false);

/** Detect OS from browser userAgent when Go binding is unavailable. */
function detectPlatformFromUA() {
  const ua = navigator.userAgent || '';
  if (ua.includes('Macintosh') || ua.includes('Mac OS')) return 'darwin';
  if (ua.includes('Linux')) return 'linux';
  return 'windows';
}

/** Initialize platform detection — call once from App.svelte or main. */
export async function initPlatform() {
  let os;
  try {
    os = await api.getPlatform();
  } catch (_) {
    // Binding not generated yet — detect from userAgent.
    os = detectPlatformFromUA();
  }
  platform.set(os);
  isMac.set(os === 'darwin');
}
