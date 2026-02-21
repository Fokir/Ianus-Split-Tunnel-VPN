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

  function stateIcon(state) {
    switch (state) {
      case 'up': return 'text-green-400';
      case 'connecting': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      default: return 'text-zinc-600';
    }
  }

  async function toggleTunnel(tunnel) {
    try {
      if (tunnel.state === 'up') {
        await api.disconnectTunnel(tunnel.id);
      } else {
        await api.connectTunnel(tunnel.id);
      }
    } catch (e) {
      // ignore
    }
  }

  async function restartTunnel(tunnel) {
    try {
      await api.restartTunnel(tunnel.id);
    } catch (e) {
      // ignore
    }
  }
</script>

<footer class="flex items-center gap-1 px-2 py-1 bg-zinc-800/60 border-t border-zinc-700/40 shrink-0 overflow-x-auto">
  {#if tunnels.length === 0}
    <span class="text-xs text-zinc-600 px-2">Нет туннелей</span>
  {:else}
    {#each tunnels as tunnel}
      <div class="flex items-center gap-1.5 px-2 py-0.5 rounded text-xs shrink-0 group">
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

        <!-- Actions (visible on hover) -->
        <div class="hidden group-hover:flex items-center gap-0.5 ml-0.5">
          <button
            class="p-0.5 rounded {stateIcon(tunnel.state)} hover:bg-zinc-700/50"
            title={tunnel.state === 'up' ? 'Отключить' : 'Подключить'}
            on:click={() => toggleTunnel(tunnel)}
          >
            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
              {#if tunnel.state === 'up'}
                <path d="M6 6h12v12H6z"/>
              {:else}
                <path d="M8 5v14l11-7z"/>
              {/if}
            </svg>
          </button>
          {#if tunnel.state === 'up'}
            <button
              class="p-0.5 rounded text-zinc-500 hover:text-yellow-400 hover:bg-zinc-700/50"
              title="Перезапустить"
              on:click={() => restartTunnel(tunnel)}
            >
              <svg class="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                <path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
              </svg>
            </button>
          {/if}
        </div>
      </div>

      <!-- Separator between tunnels -->
      {#if tunnel !== tunnels[tunnels.length - 1]}
        <span class="text-zinc-700/50">|</span>
      {/if}
    {/each}
  {/if}
</footer>
