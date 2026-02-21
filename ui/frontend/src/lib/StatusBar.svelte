<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import * as api from './api.js';

  let tunnels = [];
  let unsubscribe;

  onMount(async () => {
    // Initial load
    try {
      const list = await api.listTunnels();
      tunnels = (list || []).map(t => ({
        ...t,
        txSpeed: 0,
        rxSpeed: 0,
      }));
    } catch (e) {
      // ignore
    }

    // Listen for stats updates
    unsubscribe = Events.On('stats-update', (event) => {
      const snap = event.data;
      if (!snap || !snap.tunnels) return;

      tunnels = tunnels.map(t => {
        const stat = snap.tunnels.find(s => s.tunnelId === t.id);
        if (stat) {
          return {
            ...t,
            state: stat.state || t.state,
            txSpeed: stat.txBytesPerSec || 0,
            rxSpeed: stat.rxBytesPerSec || 0,
          };
        }
        return t;
      });
    });
  });

  onDestroy(() => {
    if (unsubscribe) unsubscribe();
  });

  function formatSpeed(bytesPerSec) {
    if (bytesPerSec < 1024) return `${bytesPerSec} B/s`;
    if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
    return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`;
  }

</script>

<footer class="flex items-center gap-1 px-2 py-1 bg-zinc-800/60 border-t border-zinc-700/40 shrink-0 overflow-x-auto">
  {#if tunnels.length === 0}
    <span class="text-xs text-zinc-600 px-2">Нет туннелей</span>
  {:else}
    {#each tunnels as tunnel}
      <div class="flex items-center gap-1.5 px-2 py-0.5 rounded text-xs shrink-0">
        <!-- State dot -->
        <span class="w-1.5 h-1.5 rounded-full {tunnel.state === 'up' ? 'bg-green-400' : tunnel.state === 'connecting' ? 'bg-yellow-400 animate-pulse' : tunnel.state === 'error' ? 'bg-red-400' : 'bg-zinc-600'}"></span>

        <!-- Name -->
        <span class="text-zinc-400 font-medium">{tunnel.name || tunnel.id}</span>

        <!-- Speed (only if up) -->
        {#if tunnel.state === 'up'}
          <span class="text-zinc-600 font-mono tabular-nums">
            <span class="text-green-400/60" title="Upload">&uarr;{formatSpeed(tunnel.txSpeed)}</span>
            <span class="text-blue-400/60 ml-0.5" title="Download">&darr;{formatSpeed(tunnel.rxSpeed)}</span>
          </span>
        {/if}

      </div>

      <!-- Separator between tunnels -->
      {#if tunnel !== tunnels[tunnels.length - 1]}
        <span class="text-zinc-700/50">|</span>
      {/if}
    {/each}
  {/if}
</footer>
