<script>
  import { connections, pausedStore, monitorEnabled } from '../stores/connections.js';
  import { CountryIcon } from '../components';
  import { t } from '../i18n';
  import * as api from '../api.js';

  function revealProcess(path) {
    if (path) {
      api.revealInExplorer(path).catch(err => console.error('RevealInExplorer failed:', err, 'path:', path));
    }
  }

  let searchFilter = '';
  let tunnelFilter = '';
  let sortKey = 'lastActivity';
  let sortAsc = false;

  function groupConnections(conns) {
    const groups = new Map();
    for (const c of conns) {
      const target = c.domain || c.dstIp;
      const key = `${c.processName || ''}\0${target}\0${c.tunnelId || ''}`;
      if (!groups.has(key)) {
        groups.set(key, {
          processName: c.processName,
          processPath: c.processPath,
          target,
          domain: c.domain,
          tunnelId: c.tunnelId,
          country: c.country,
          protocols: new Set(),
          ports: new Set(),
          states: new Set(),
          lastActivity: c.lastActivity,
          times: new Set(),
          count: 0,
        });
      }
      const g = groups.get(key);
      if (c.protocol) g.protocols.add(c.protocol);
      if (c.dstPort) g.ports.add(c.dstPort);
      if (c.state) g.states.add(c.state);
      if (c.lastActivity > g.lastActivity) g.lastActivity = c.lastActivity;
      if (c.lastActivity) g.times.add(c.lastActivity);
      if (c.country && !g.country) g.country = c.country;
      if (c.processPath && !g.processPath) g.processPath = c.processPath;
      g.count++;
    }
    return [...groups.values()].map(g => ({
      ...g,
      protocols: [...g.protocols].sort(),
      ports: [...g.ports].sort((a, b) => a - b),
      states: [...g.states],
      times: [...g.times].sort((a, b) => b - a),
      hasActive: g.states.has('active'),
    }));
  }

  $: filteredConns = ($connections || []).filter(c => {
    if (searchFilter) {
      const q = searchFilter.toLowerCase();
      const haystack = [c.processName, c.domain, c.dstIp, c.dstPort != null ? String(c.dstPort) : ''].join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    if (tunnelFilter && c.tunnelId !== tunnelFilter) return false;
    return true;
  });

  $: grouped = groupConnections(filteredConns);

  $: filteredGrouped = [...grouped].sort((a, b) => {
    let va = a[sortKey], vb = b[sortKey];
    if (sortKey === 'protocols') { va = a.protocols.join(','); vb = b.protocols.join(','); }
    if (sortKey === 'dstIp') { va = a.target; vb = b.target; }
    if (sortKey === 'domain') { va = a.domain || a.target; vb = b.domain || b.target; }
    if (sortKey === 'state') { va = a.hasActive ? 'active' : 'fin'; vb = b.hasActive ? 'active' : 'fin'; }
    if (sortKey === 'count') { va = a.count; vb = b.count; }
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

  $: arrow = sortAsc ? ' ▲' : ' ▼';
  $: si = (key) => sortKey === key ? arrow : '';

  function formatPorts(ports) {
    if (ports.length <= 3) return ports.join(', ');
    return ports.slice(0, 3).join(', ') + ` +${ports.length - 3}`;
  }

</script>

<div class="flex flex-col h-full">
  <div class="flex items-center gap-3 p-3 border-b border-zinc-700/40 shrink-0 flex-wrap">
    <input type="text" bind:value={searchFilter}
      placeholder={$t('monitor.filterSearch')}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 placeholder-zinc-600 focus:outline-none w-56" />
    <select bind:value={tunnelFilter}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 focus:outline-none w-40">
      <option value="">{$t('monitor.allTunnels')}</option>
      {#each tunnelIds as tid}
        <option value={tid}>{tid}</option>
      {/each}
    </select>

    <div class="flex-1"></div>

    {#if $monitorEnabled}
      <span class="text-xs text-zinc-500">{filteredGrouped.length} {$t('monitor.groups')}</span>

      <button on:click={() => $pausedStore = !$pausedStore}
        class="px-2 py-1 text-xs rounded transition-colors {$pausedStore ? 'bg-yellow-600/20 text-yellow-400 hover:bg-yellow-600/30' : 'bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700'}">
        {$pausedStore ? $t('monitor.resume') : $t('monitor.pause')}
      </button>
    {/if}

    <button on:click={() => $monitorEnabled = !$monitorEnabled}
      class="px-2 py-1 text-xs rounded transition-colors {$monitorEnabled ? 'bg-green-600/20 text-green-400 hover:bg-green-600/30' : 'bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700'}">
      {$monitorEnabled ? $t('monitor.stop') : $t('monitor.start')}
    </button>
  </div>

  {#if !$monitorEnabled}
    <div class="flex-1 flex items-center justify-center">
      <div class="text-center">
        <p class="text-zinc-500 text-sm">{$t('monitor.disabled')}</p>
        <button on:click={() => $monitorEnabled = true}
          class="mt-3 px-4 py-2 text-sm rounded-lg bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors">
          {$t('monitor.start')}
        </button>
      </div>
    </div>
  {:else}
  <div class="flex-1 overflow-auto">
    <table class="w-full text-xs">
      <thead class="sticky top-0 bg-zinc-900 z-10">
        <tr class="text-zinc-500 uppercase tracking-wider">
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('processName')}>
            {$t('monitor.process')}{si('processName')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('protocols')}>
            {$t('monitor.proto')}{si('protocols')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('domain')}>
            {$t('monitor.domain')}{si('domain')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('dstIp')}>
            {$t('monitor.destination')}{si('dstIp')}
          </th>
          <th class="px-3 py-2 text-left cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('tunnelId')}>
            {$t('monitor.tunnel')}{si('tunnelId')}
          </th>
          <th class="px-3 py-2 text-center cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('country')}>
            {$t('monitor.country')}{si('country')}
          </th>
          <th class="px-3 py-2 text-center cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('state')}>
            {$t('monitor.state')}{si('state')}
          </th>
          <th class="px-3 py-2 text-right cursor-pointer hover:text-zinc-300 transition-colors" on:click={() => toggleSort('lastActivity')}>
            {$t('monitor.lastSeen')}{si('lastActivity')}
          </th>
        </tr>
      </thead>
      <tbody>
        {#each filteredGrouped as g (g.processName + '\0' + g.target + '\0' + g.tunnelId)}
          <tr class="border-b border-zinc-700/20 hover:bg-zinc-800/30 transition-colors">
            <td class="px-3 py-1.5 text-zinc-300 max-w-[220px]">
              <div class="flex items-center gap-1 min-w-0">
                <span class="truncate" title={g.processPath || g.processName}>{g.processName || '—'}</span>
                {#if g.count > 1}
                  <span class="text-[0.6rem] text-zinc-600 shrink-0">×{g.count}</span>
                {/if}
                {#if g.processPath}
                  <button on:click|stopPropagation={() => revealProcess(g.processPath)}
                    class="shrink-0 p-0.5 rounded hover:bg-zinc-700/60 text-zinc-600 hover:text-zinc-400 transition-colors" title={$t('monitor.openFolder')}>
                    <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                    </svg>
                  </button>
                {/if}
              </div>
            </td>
            <td class="px-3 py-1.5">
              <div class="flex gap-1 flex-wrap">
                {#each g.protocols as proto}
                  <span class="px-1.5 py-0.5 rounded text-[0.625rem] font-medium leading-none
                    {proto === 'TCP' ? 'bg-blue-500/20 text-blue-400' : proto === 'UDP' ? 'bg-green-500/20 text-green-400' : 'bg-zinc-700/60 text-zinc-400'}">
                    {proto}
                  </span>
                {/each}
              </div>
            </td>
            <td class="px-3 py-1.5 text-zinc-400 truncate max-w-[180px]" title={g.domain}>{g.domain || '—'}</td>
            <td class="px-3 py-1.5 text-zinc-500 font-mono text-[0.65rem]" title={g.ports.join(', ')}>
              {g.target}{#if g.ports.length > 0}<span class="text-zinc-600">:{formatPorts(g.ports)}</span>{/if}
            </td>
            <td class="px-3 py-1.5">
              {#if g.tunnelId === '__direct__'}
                <span class="px-1.5 py-0.5 rounded text-[0.625rem] font-medium leading-none bg-amber-500/20 text-amber-400">Direct</span>
              {:else}
                <span class="px-1.5 py-0.5 rounded text-[0.625rem] font-medium leading-none bg-violet-500/20 text-violet-400">{g.tunnelId}</span>
              {/if}
            </td>
            <td class="px-3 py-1.5 text-center">
              <span class="inline-flex items-center gap-1">
                <CountryIcon code={g.country} domain={g.domain} size={16} showCode={true} />
              </span>
            </td>
            <td class="px-3 py-1.5 text-center">
              <span class="inline-block w-2 h-2 rounded-full {g.hasActive ? 'bg-green-400' : 'bg-zinc-500'}"></span>
            </td>
            <td class="px-3 py-1.5 text-right">
              <div class="flex flex-col items-end gap-0.5">
                {#each g.times.slice(0, 3) as t}
                  <span class="text-zinc-600">{formatTime(t)}</span>
                {/each}
                {#if g.times.length > 3}
                  <span class="text-zinc-700 text-[0.6rem]">+{g.times.length - 3}</span>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
        {#if filteredGrouped.length === 0}
          <tr>
            <td colspan="8" class="px-3 py-8 text-center text-zinc-600">{$t('monitor.noConnections')}</td>
          </tr>
        {/if}
      </tbody>
    </table>
  </div>
  {/if}
</div>
