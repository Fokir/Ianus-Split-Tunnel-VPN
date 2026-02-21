<script>
  import { onMount } from 'svelte';
  import * as api from '../api.js';

  let version = '';
  let uptime = '';

  onMount(async () => {
    try {
      const status = await api.getStatus();
      version = status.version || 'неизвестно';
      uptime = formatUptime(status.uptimeSeconds);
    } catch (e) {
      version = 'н/д';
    }
  });

  function formatUptime(seconds) {
    if (!seconds) return '0с';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const parts = [];
    if (h > 0) parts.push(`${h}ч`);
    if (m > 0) parts.push(`${m}м`);
    parts.push(`${s}с`);
    return parts.join(' ');
  }
</script>

<div class="p-6 max-w-lg mx-auto space-y-8">
  <!-- Logo & Title -->
  <div class="text-center space-y-2">
    <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-violet-600 shadow-lg">
      <svg class="w-8 h-8 text-white" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
      </svg>
    </div>
    <h1 class="text-xl font-bold text-zinc-100">AWG Split Tunnel</h1>
    <p class="text-sm text-zinc-500">Многотуннельный VPN-клиент с per-process split tunneling</p>
  </div>

  <!-- Info cards -->
  <div class="space-y-2">
    <div class="flex items-center justify-between px-4 py-3 bg-zinc-800/40 border border-zinc-700/40 rounded-lg">
      <span class="text-sm text-zinc-400">Версия</span>
      <span class="text-sm text-zinc-200 font-mono">{version}</span>
    </div>
    <div class="flex items-center justify-between px-4 py-3 bg-zinc-800/40 border border-zinc-700/40 rounded-lg">
      <span class="text-sm text-zinc-400">Время работы</span>
      <span class="text-sm text-zinc-200 font-mono">{uptime}</span>
    </div>
    <div class="flex items-center justify-between px-4 py-3 bg-zinc-800/40 border border-zinc-700/40 rounded-lg">
      <span class="text-sm text-zinc-400">Платформа</span>
      <span class="text-sm text-zinc-200">Windows</span>
    </div>
  </div>

  <!-- Developer -->
  <section class="space-y-2">
    <h3 class="text-xs font-medium text-zinc-500 uppercase tracking-wider">Разработчик</h3>
    <div class="px-4 py-3 bg-zinc-800/40 border border-zinc-700/40 rounded-lg space-y-1">
      <div class="text-sm text-zinc-200">Соколов Андрей</div>
      <div class="text-xs text-zinc-500">
        <a href="mailto:sokol.fokir@gmail.com" class="hover:text-blue-400 transition-colors" data-wml-openURL="mailto:sokol.fokir@gmail.com">
          sokol.fokir@gmail.com
        </a>
      </div>
    </div>
  </section>

  <!-- License -->
  <section class="space-y-2">
    <h3 class="text-xs font-medium text-zinc-500 uppercase tracking-wider">Лицензия</h3>
    <div class="px-4 py-3 bg-zinc-800/40 border border-zinc-700/40 rounded-lg">
      <div class="text-sm text-zinc-200">CC BY-NC-SA 4.0</div>
      <div class="text-xs text-zinc-500 mt-1">
        Creative Commons Attribution-NonCommercial-ShareAlike 4.0
      </div>
    </div>
  </section>
</div>
