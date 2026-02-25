<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import * as api from './api.js';
  import { t } from './i18n';

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
        packetLoss: 0,
        latencyMs: 0,
        jitterMs: 0,
      }));
    } catch (e) {
      // ignore
    }

    // Start stats stream (safe to call multiple times)
    api.startStatsStream();

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
            txSpeed: stat.speedTx || 0,
            rxSpeed: stat.speedRx || 0,
            packetLoss: stat.packetLoss || 0,
            latencyMs: stat.latencyMs || 0,
            jitterMs: stat.jitterMs || 0,
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
    if (bytesPerSec < 1024) return `${bytesPerSec}B/s`;
    if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)}KB/s`;
    return `${(bytesPerSec / 1048576).toFixed(1)}MB/s`;
  }

  function formatLoss(loss) {
    return `${(loss * 100).toFixed(1)}%`;
  }

  function lossColor(loss) {
    if (loss >= 0.10) return 'text-red-400';
    if (loss >= 0.03) return 'text-yellow-400';
    return 'text-zinc-600';
  }

  function hasWarning(tunnel) {
    if (tunnel.state !== 'up') return false;
    return tunnel.packetLoss >= 0.03 || tunnel.jitterMs >= 30;
  }

  function warningColor(tunnel) {
    if (tunnel.packetLoss >= 0.10 || tunnel.jitterMs >= 80) return 'text-red-400';
    return 'text-yellow-400';
  }

  function qualityTooltip(tunnel) {
    const parts = [];
    parts.push(`${$t('statusbar.latency')}: ${tunnel.latencyMs}ms`);
    parts.push(`${$t('statusbar.jitter')}: ${tunnel.jitterMs}ms`);
    parts.push(`${$t('statusbar.loss')}: ${formatLoss(tunnel.packetLoss)}`);
    if (tunnel.packetLoss >= 0.10) {
      parts.push($t('statusbar.highLoss'));
    } else if (tunnel.jitterMs >= 80) {
      parts.push($t('statusbar.highJitter'));
    } else if (tunnel.packetLoss >= 0.03) {
      parts.push($t('statusbar.elevatedLoss'));
    } else if (tunnel.jitterMs >= 30) {
      parts.push($t('statusbar.elevatedJitter'));
    }
    return parts.join('\n');
  }

  // Sort: Direct (__direct__) always first, then alphabetical by name.
  $: sortedTunnels = [...tunnels].sort((a, b) => {
    const aIsDirect = a.id === '__direct__';
    const bIsDirect = b.id === '__direct__';
    if (aIsDirect && !bIsDirect) return -1;
    if (!aIsDirect && bIsDirect) return 1;
    const nameA = (a.name || a.id).toLowerCase();
    const nameB = (b.name || b.id).toLowerCase();
    return nameA.localeCompare(nameB);
  });

</script>

<footer class="flex flex-wrap items-center gap-x-1 gap-y-0.5 px-2 py-1 bg-zinc-800/60 border-t border-zinc-700/40 shrink-0">
  {#if sortedTunnels.length === 0}
    <span class="text-xs text-zinc-600 px-2">{$t('statusbar.noTunnels')}</span>
  {:else}
    {#each sortedTunnels as tunnel}
      <div class="flex items-center gap-1.5 px-1.5 py-0.5 rounded text-xs min-w-0"
           style="flex: {sortedTunnels.length <= 4 ? '1 1 0' : '0 0 calc(25% - 3px)'}">
        <!-- State indicator -->
        {#if tunnel.state === 'up' && hasWarning(tunnel)}
          <span class="flex items-center shrink-0 {warningColor(tunnel)}" title={qualityTooltip(tunnel)}>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="w-3 h-3">
              <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.168 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
            </svg>
          </span>
        {:else}
          <span class="w-1.5 h-1.5 rounded-full shrink-0 {tunnel.state === 'up' ? 'bg-green-400' : tunnel.state === 'connecting' ? 'bg-yellow-400 animate-pulse' : tunnel.state === 'error' ? 'bg-red-400' : 'bg-zinc-600'}"></span>
        {/if}

        <!-- Name (truncated with ellipsis on overflow) -->
        <span class="text-zinc-400 font-medium leading-none truncate min-w-[3rem]">{tunnel.name || tunnel.id}</span>

        <!-- Speed + quality (only if up) -->
        {#if tunnel.state === 'up'}
          {@const txText = formatSpeed(tunnel.txSpeed)}
          {@const rxText = formatSpeed(tunnel.rxSpeed)}
          <span class="text-zinc-600 font-mono tabular-nums inline-flex items-center gap-0.5 shrink-0">
            <span class="text-green-400/60 inline-block w-[4rem] overflow-hidden whitespace-nowrap leading-none {txText.length > 7 ? 'text-[0.625rem]' : ''}" title="Upload">&uarr;{txText}</span>
            <span class="text-blue-400/60 inline-block w-[4rem] overflow-hidden whitespace-nowrap leading-none {rxText.length > 7 ? 'text-[0.625rem]' : ''}" title="Download">&darr;{rxText}</span>
          </span>

          <!-- Packet loss -->
          <span class="font-mono tabular-nums inline-flex items-center w-[3rem] overflow-hidden whitespace-nowrap leading-none shrink-0 {lossColor(tunnel.packetLoss)}" title={qualityTooltip(tunnel)}>
            {formatLoss(tunnel.packetLoss)}
          </span>
        {/if}
      </div>
    {/each}
  {/if}
</footer>
