/**
 * Frontend utility functions for formatting and display.
 */

/**
 * Debounce a function call.
 * @param {Function} fn
 * @param {number} ms - Delay in milliseconds
 * @returns {Function}
 */
export function debounce(fn, ms = 300) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/**
 * Sort tunnels by sortIndex with stable tiebreak by id.
 * Returns a new sorted array (does not mutate the input).
 * @param {Array<{id: string, sortIndex?: number}>} tunnels
 * @returns {Array}
 */
export function sortTunnels(tunnels) {
  return [...tunnels].sort((a, b) => {
    const diff = (a.sortIndex || 0) - (b.sortIndex || 0);
    if (diff !== 0) return diff;
    return a.id.localeCompare(b.id);
  });
}

/**
 * Get a flag image URL for a 2-letter country code.
 * Uses flagcdn.com for SVG flag icons (works on Windows where emoji flags don't render).
 * @param {string} code - ISO 3166-1 alpha-2 country code
 * @returns {string} URL to flag image, or empty string
 */
export function countryFlagUrl(code) {
  if (!code || code.length !== 2) return '';
  return `https://flagcdn.com/20x15/${code.toLowerCase()}.png`;
}

/**
 * Format bytes per second into a human-readable speed string.
 * @param {number} bytesPerSec
 * @returns {string}
 */
export function formatSpeed(bytesPerSec) {
  if (bytesPerSec < 1024) return `${bytesPerSec} B/s`;
  if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`;
}

/**
 * Format total bytes into a human-readable size string.
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}
