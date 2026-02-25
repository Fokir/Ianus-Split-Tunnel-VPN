/**
 * Lightweight i18n system for Svelte 4.
 *
 * Usage:
 *   import { t, locale, availableLocales } from './i18n';
 *   {$t('tabs.connections')}
 *   {$t('about.updateAvailable', { version: '1.2.3' })}
 */
import { writable, derived } from 'svelte/store';
import ru from './ru.json';
import en from './en.json';

const locales = { ru, en };

/** Available locale codes. */
export const availableLocales = [
  { code: 'ru', label: 'Русский' },
  { code: 'en', label: 'English' },
];

/** Current locale — persisted in localStorage. */
export const locale = writable(localStorage.getItem('locale') || 'en');
locale.subscribe(val => localStorage.setItem('locale', val));

/**
 * Translation function store.
 * $t('key')           → translated string
 * $t('key', {n: 42})  → replaces {n} with 42
 * Falls back to Russian, then returns the key itself.
 */
export const t = derived(locale, ($locale) => {
  const msgs = locales[$locale] || locales.ru;
  return (key, params = {}) => {
    let msg = key.split('.').reduce((o, k) => o?.[k], msgs);
    // Fallback to Russian if key not found in current locale.
    if (msg === undefined) {
      msg = key.split('.').reduce((o, k) => o?.[k], locales.ru);
    }
    // Return key itself if still not found.
    if (msg === undefined) return key;
    // Replace {param} placeholders.
    return msg.replace(/\{(\w+)\}/g, (_, k) => params[k] ?? `{${k}}`);
  };
});
