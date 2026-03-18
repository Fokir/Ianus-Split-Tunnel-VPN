<script>
  import { connections, pausedStore } from '../stores/connections.js';
  import { t } from '../i18n';

  let processFilter = '';
  let tunnelFilter = '';
  let sortKey = 'lastActivity';
  let sortAsc = false;

  $: filteredConnections = ($connections || [])
    .filter(c => {
      if (processFilter && !c.processName?.toLowerCase().includes(processFilter.toLowerCase())) return false;
      if (tunnelFilter && c.tunnelId !== tunnelFilter) return false;
      return true;
    })
    .sort((a, b) => {
      let va = a[sortKey], vb = b[sortKey];
      if (typeof va === 'string') { va = va.toLowerCase(); vb = (vb || '').toLowerCase(); }
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });

  $: tunnelIds = [...new Set(($connections || []).map(c => c.tunnelId).filter(Boolean))].sort();

  function toggleSort(key) {
    if (sortKey === key) { sortAsc = !sortAsc; }
    else { sortKey = key; sortAsc = true; }
  }

  function formatTime(unix) {
    if (!unix) return '';
    return new Date(unix * 1000).toLocaleTimeString();
  }

  function sortIndicator(key) {
    if (sortKey !== key) return '';
    return sortAsc ? ' \u25B2' : ' \u25BC';
  }
</script>

<div class="flex flex-col h-full">
  <div class="flex items-center gap-3 p-3 border-b border-zinc-700/40 shrink-0 flex-wrap">
    <input type="text" bind:value={processFilter}
      placeholder={$t('monitor.filterProcess')}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 placeholder-zinc-600 focus:outline-none w-48" />
    <select bind:value={tunnelFilter}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 focus:outline-none w-40">
      <option value="">{$t('monitor.allTunnels')}</option>
      {#each tunnelIds as tid}
        <option value={tid}>{tid}</option>
      {/each}
    </select>

    <div class="flex-1"></div>

    <span class="text-xs text-zinc-500">{filteredConnections.length} {$t('monitor.connections')}</span>

    <button on:click={() => $pausedStore = !$pausedStore}
      class="px-2 py-1 text-xs rounded transition-colors {$pausedStore ? 'bg-yellow-600/20 text-yellow-400 hover:bg-yellow-600/30' : 'bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700'}">
      {$pausedStore ? $t('monitor.resume') : $t('monitor.pause')}
    </button>
  </div>

  <div class="flex-1 overflow-auto">
    <table class="w-full text-xs">
      <thead class="sticky top-0 bg-zinc-900 z-10">
        <tr class="text-zinc-500 uppercase tracking-wider">
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('processName')}>
            {$t('monitor.process')}{sortIndicator('processName')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('protocol')}>
            {$t('monitor.proto')}{sortIndicator('protocol')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('dstIp')}>
            {$t('monitor.destination')}{sortIndicator('dstIp')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('domain')}>
            {$t('monitor.domain')}{sortIndicator('domain')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('tunnelId')}>
            {$t('monitor.tunnel')}{sortIndicator('tunnelId')}
          </th>
          <th class="px-3 py-2 text-center cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('country')}>
            {$t('monitor.country')}{sortIndicator('country')}
          </th>
          <th class="px-3 py-2 text-center cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('state')}>
            {$t('monitor.state')}{sortIndicator('state')}
          </th>
          <th class="px-3 py-2 text-right cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('lastActivity')}>
            {$t('monitor.lastSeen')}{sortIndicator('lastActivity')}
          </th>
        </tr>
      </thead>
      <tbody>
        {#each filteredConnections as conn (conn.dstIp + ':' + conn.dstPort + ':' + conn.protocol + ':' + conn.processName)}
          <tr class="border-b border-zinc-700/20 hover:bg-zinc-800/30 transition-colors">
            <td class="px-3 py-1.5 text-zinc-300 truncate max-w-[200px]" title={conn.processPath || conn.processName}>
              {conn.processName || '\u2014'}
            </td>
            <td class="px-3 py-1.5">
              <span class="px-1.5 py-0.5 rounded text-[0.625rem] font-medium leading-none
                {conn.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-400' : conn.protocol === 'UDP' ? 'bg-green-500/20 text-green-400' : 'bg-zinc-700/60 text-zinc-400'}">
                {conn.protocol}
              </span>
            </td>
            <td class="px-3 py-1.5 text-zinc-500 font-mono">{conn.dstIp}:{conn.dstPort}</td>
            <td class="px-3 py-1.5 text-zinc-400 truncate max-w-[180px]" title={conn.domain}>{conn.domain || '\u2014'}</td>
            <td class="px-3 py-1.5">
              <span class="px-1.5 py-0.5 rounded text-[0.625rem] font-medium leading-none bg-violet-500/20 text-violet-400">{conn.tunnelId}</span>
            </td>
            <td class="px-3 py-1.5 text-center text-zinc-500">{conn.country || '\u2014'}</td>
            <td class="px-3 py-1.5 text-center">
              <span class="inline-block w-2 h-2 rounded-full {conn.state === 'active' ? 'bg-green-400' : 'bg-zinc-500'}"></span>
            </td>
            <td class="px-3 py-1.5 text-right text-zinc-600">{formatTime(conn.lastActivity)}</td>
          </tr>
        {/each}
        {#if filteredConnections.length === 0}
          <tr>
            <td colspan="8" class="px-3 py-8 text-center text-zinc-600">{$t('monitor.noConnections')}</td>
          </tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>
