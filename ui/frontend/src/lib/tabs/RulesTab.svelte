<script>
  import { onMount, onDestroy, tick } from 'svelte';
  import * as api from '../api.js';
  import { sortTunnels } from '../utils.js';
  import ErrorAlert from '../ErrorAlert.svelte';
  import ProcessPicker from '../ProcessPicker.svelte';
  import { t } from '../i18n';
  import { tabDirty } from '../stores/dirty.js';
  import { isMac } from '../stores/platform.js';

  $: $tabDirty = dirty || ipsDirty || appsDirty;

  // Platform-aware placeholder examples.
  $: appExclusionPlaceholder = $isMac ? 'chrome, /Applications/Games/*' : 'chrome.exe, C:\\Games\\*';
  $: rulePatternPlaceholder = $isMac
    ? 'chrome, firefox*, regex:^.*/games/.*$'
    : 'chrome.exe, firefox*, regex:^.*\\\\games\\\\.*$';
  onDestroy(() => tabDirty.set(false));

  let rules = [];
  let tunnels = [];
  let loading = true;
  let error = '';
  let dirty = false;

  // Disallowed IPs state
  let config = null;
  let disallowedIps = [];
  let ipsDirty = false;
  let ipsError = '';

  // Disallowed Apps state
  let disallowedApps = [];
  let appsDirty = false;
  let appsError = '';
  let showAppProcessPicker = false;
  let appPickerIndex = -1;

  // Rule edit modal
  let showModal = false;
  let editIndex = -1;
  let modalRule = { pattern: '', tunnelId: '', fallback: 'allow_direct', priority: 'auto' };

  // Process picker (rule modal)
  let showProcessPicker = false;

  // Drag & drop (grouped)
  let dragGroupIdx = -1;
  let dragRuleIdx = -1;
  let dragOverGroupIdx = -1;
  let dragOverRuleIdx = -1;

  // Inline group rename
  let renamingGroupPattern = '';
  let renameGroupValue = '';
  let renameGroupInput;

  // ─── Quick Rule Wizard ────────────────────────────────────────────
  let showQuickWizard = false;
  let wizardStep = 1;
  let wizardSelectedProcess = null;
  let wizardSelectedTunnels = [];

  $: wizardAvailableTunnels = tunnels.filter(t => !wizardSelectedTunnels.some(s => s.id === t.id));

  // ─── Rule Grouping ────────────────────────────────────────────────
  $: groups = computeGroups(rules);

  function computeGroups(rulesList) {
    const map = new Map();
    const result = [];
    for (let i = 0; i < rulesList.length; i++) {
      const rule = rulesList[i];
      let group = map.get(rule.pattern);
      if (!group) {
        group = { pattern: rule.pattern, rules: [] };
        map.set(rule.pattern, group);
        result.push(group);
      }
      group.rules.push({ ...rule, realIndex: i });
    }
    return result;
  }

  // ─── Pattern Icons ───────────────────────────────────────────────

  let patternIcons = {};
  let iconLoadTimer;

  async function loadPatternIcons() {
    try {
      const procs = await api.listProcesses('') || [];
      const iconMap = {};
      for (const group of groups) {
        const pat = group.pattern.toLowerCase();
        // 1. Exact match by process name
        let match = procs.find(p => p.name.toLowerCase() === pat && p.icon);
        // 2. If pattern is path/*, find process in that folder
        if (!match && (pat.endsWith('/*') || pat.endsWith('\\*'))) {
          const dir = pat.slice(0, -2);
          match = procs.find(p => p.path && p.path.toLowerCase().startsWith(dir) && p.icon);
        }
        // 3. Substring match (e.g. "chrome", "firefox")
        if (!match) {
          match = procs.find(p => p.name.toLowerCase().includes(pat) && p.icon);
        }
        if (match) iconMap[group.pattern] = match.icon;
      }
      patternIcons = iconMap;
    } catch {
      // Icons are optional — don't break on failure
    }
  }

  $: if (groups.length > 0) {
    clearTimeout(iconLoadTimer);
    iconLoadTimer = setTimeout(loadPatternIcons, 300);
  }

  // ─── Lifecycle ────────────────────────────────────────────────────

  onMount(async () => {
    await loadData();
  });

  async function loadData() {
    loading = true;
    error = '';
    try {
      const [r, t, cfg] = await Promise.all([api.listRules(), api.listTunnels(), api.getConfig()]);
      rules = r || [];
      tunnels = sortTunnels(t || []);
      config = cfg || {};
      if (!config.global) config.global = {};
      buildDisallowedIpsList();
      buildDisallowedAppsList();
    } catch (e) {
      error = e.message || $t('rules.failedToLoad');
    } finally {
      loading = false;
    }
  }

  // ─── Disallowed IPs ──────────────────────────────────────────────

  function buildDisallowedIpsList() {
    const list = [];
    if (config.global && config.global.disallowed_ips) {
      for (const cidr of config.global.disallowed_ips) {
        list.push({ cidr, scope: '__global__' });
      }
    }
    if (config.tunnels) {
      for (const t of config.tunnels) {
        if (t.disallowed_ips) {
          for (const cidr of t.disallowed_ips) {
            list.push({ cidr, scope: t.id });
          }
        }
      }
    }
    disallowedIps = list;
    ipsDirty = false;
    ipsError = '';
  }

  function addDisallowedIp() {
    disallowedIps = [...disallowedIps, { cidr: '', scope: '__global__' }];
    ipsDirty = true;
  }

  function removeDisallowedIp(index) {
    disallowedIps = disallowedIps.filter((_, i) => i !== index);
    ipsDirty = true;
  }

  function handleCidrInput(e, index) {
    const filtered = e.target.value.replace(/[^0-9./]/g, '');
    e.target.value = filtered;
    disallowedIps[index].cidr = filtered;
    disallowedIps = disallowedIps;
    ipsDirty = true;
  }

  function isValidCidr(value) {
    if (!value) return true;
    const parts = value.split('/');
    if (parts.length > 2) return false;
    const ip = parts[0];
    const octets = ip.split('.');
    if (octets.length !== 4) return false;
    for (const o of octets) {
      if (!o || o.length > 3) return false;
      const n = parseInt(o, 10);
      if (isNaN(n) || n < 0 || n > 255) return false;
      if (o.length > 1 && o[0] === '0') return false;
    }
    if (parts.length === 2) {
      const prefix = parts[1];
      if (!prefix) return false;
      const p = parseInt(prefix, 10);
      if (isNaN(p) || p < 0 || p > 32) return false;
    }
    return true;
  }

  async function saveIps() {
    ipsError = '';
    try {
      const globalIps = [];
      const tunnelIpsMap = {};
      for (const entry of disallowedIps) {
        const cidr = entry.cidr.trim();
        if (!cidr) continue;
        if (entry.scope === '__global__') {
          globalIps.push(cidr);
        } else {
          if (!tunnelIpsMap[entry.scope]) tunnelIpsMap[entry.scope] = [];
          tunnelIpsMap[entry.scope].push(cidr);
        }
      }
      config.global.disallowed_ips = globalIps;
      if (config.tunnels) {
        for (const t of config.tunnels) {
          t.disallowed_ips = tunnelIpsMap[t.id] || [];
        }
      }
      await api.saveConfig(config, true);
      ipsDirty = false;
    } catch (e) {
      ipsError = e.message || $t('rules.failedToSave');
    }
  }

  function cancelIps() { buildDisallowedIpsList(); }

  // ─── Disallowed Apps ─────────────────────────────────────────────

  function buildDisallowedAppsList() {
    const list = [];
    if (config.global && config.global.disallowed_apps) {
      for (const pattern of config.global.disallowed_apps) {
        list.push({ pattern, scope: '__global__' });
      }
    }
    if (config.tunnels) {
      for (const t of config.tunnels) {
        if (t.disallowed_apps) {
          for (const pattern of t.disallowed_apps) {
            list.push({ pattern, scope: t.id });
          }
        }
      }
    }
    disallowedApps = list;
    appsDirty = false;
    appsError = '';
  }

  function addDisallowedApp() {
    disallowedApps = [...disallowedApps, { pattern: '', scope: '__global__' }];
    appsDirty = true;
  }

  function removeDisallowedApp(index) {
    disallowedApps = disallowedApps.filter((_, i) => i !== index);
    appsDirty = true;
  }

  function markAppsDirty() { appsDirty = true; }

  async function saveApps() {
    appsError = '';
    try {
      const globalApps = [];
      const tunnelAppsMap = {};
      for (const entry of disallowedApps) {
        const pattern = entry.pattern.trim();
        if (!pattern) continue;
        if (entry.scope === '__global__') {
          globalApps.push(pattern);
        } else {
          if (!tunnelAppsMap[entry.scope]) tunnelAppsMap[entry.scope] = [];
          tunnelAppsMap[entry.scope].push(pattern);
        }
      }
      config.global.disallowed_apps = globalApps;
      if (config.tunnels) {
        for (const t of config.tunnels) {
          t.disallowed_apps = tunnelAppsMap[t.id] || [];
        }
      }
      await api.saveConfig(config, true);
      appsDirty = false;
    } catch (e) {
      appsError = e.message || $t('rules.failedToSave');
    }
  }

  function cancelApps() { buildDisallowedAppsList(); }

  function openAppProcessPicker(index) {
    appPickerIndex = index;
    showAppProcessPicker = true;
  }

  function selectAppProcess(proc) {
    if (appPickerIndex >= 0 && appPickerIndex < disallowedApps.length) {
      disallowedApps[appPickerIndex].pattern = proc.name;
      disallowedApps = [...disallowedApps];
      appsDirty = true;
    }
    showAppProcessPicker = false;
    appPickerIndex = -1;
  }

  function closeAppProcessPicker() {
    showAppProcessPicker = false;
    appPickerIndex = -1;
  }

  // ─── Rule Edit Modal ─────────────────────────────────────────────

  function openAddModal() {
    editIndex = -1;
    modalRule = { pattern: '', tunnelId: '', fallback: 'allow_direct', priority: 'auto' };
    showModal = true;
  }

  function openEditModal(index) {
    editIndex = index;
    modalRule = { ...rules[index] };
    showModal = true;
  }

  function closeModal() {
    showModal = false;
  }

  function saveModalRule() {
    if (!modalRule.pattern.trim()) return;
    if (editIndex >= 0) {
      rules[editIndex] = { ...modalRule };
    } else {
      rules = [...rules, { ...modalRule }];
    }
    dirty = true;
    closeModal();
  }

  function removeRule(index) {
    rules = rules.filter((_, i) => i !== index);
    dirty = true;
  }

  async function save() {
    error = '';
    try {
      await api.saveRules(rules);
      dirty = false;
    } catch (e) {
      error = e.message;
    }
  }

  function cancel() {
    loadData();
    dirty = false;
  }

  function openProcessPicker() {
    showProcessPicker = true;
  }

  function selectProcess(proc) {
    modalRule.pattern = proc.name;
    showProcessPicker = false;
  }

  function selectFolderProcess(detail) {
    modalRule.pattern = detail.pattern;
    showProcessPicker = false;
  }

  function wizardSelectFolder(detail) {
    wizardSelectedProcess = { name: detail.pattern, path: detail.folder, icon: null };
    wizardStep = 2;
  }

  function selectAppFolder(detail) {
    if (appPickerIndex >= 0 && appPickerIndex < disallowedApps.length) {
      disallowedApps[appPickerIndex].pattern = detail.pattern;
      disallowedApps = [...disallowedApps];
      appsDirty = true;
    }
    showAppProcessPicker = false;
    appPickerIndex = -1;
  }

  // ─── Drag & Drop (grouped) ───────────────────────────────────────

  function handleGroupDragStart(e, gi, ri) {
    dragGroupIdx = gi;
    dragRuleIdx = ri;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', `${gi}:${ri}`);
    e.currentTarget.closest('tr').style.opacity = '0.4';
  }

  function handleGroupDragEnd(e) {
    e.currentTarget.closest('tr').style.opacity = '';
    dragGroupIdx = -1;
    dragRuleIdx = -1;
    dragOverGroupIdx = -1;
    dragOverRuleIdx = -1;
  }

  function handleGroupDragOver(e, gi, ri) {
    if (gi !== dragGroupIdx) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    dragOverGroupIdx = gi;
    dragOverRuleIdx = ri;
  }

  function handleGroupDragLeave() {
    dragOverGroupIdx = -1;
    dragOverRuleIdx = -1;
  }

  function handleGroupDrop(e, gi, ri) {
    e.preventDefault();
    if (gi !== dragGroupIdx || dragRuleIdx === ri) {
      dragGroupIdx = -1;
      dragRuleIdx = -1;
      dragOverGroupIdx = -1;
      dragOverRuleIdx = -1;
      return;
    }
    const g = groups[gi];
    const fromReal = g.rules[dragRuleIdx].realIndex;
    const toReal = g.rules[ri].realIndex;
    const reordered = [...rules];
    const [moved] = reordered.splice(fromReal, 1);
    reordered.splice(toReal, 0, moved);
    rules = reordered;
    dirty = true;
    dragGroupIdx = -1;
    dragRuleIdx = -1;
    dragOverGroupIdx = -1;
    dragOverRuleIdx = -1;
  }

  // ─── Inline Group Rename ─────────────────────────────────────────

  async function startGroupRename(group) {
    renamingGroupPattern = group.pattern;
    renameGroupValue = group.pattern;
    await tick();
    if (renameGroupInput) { renameGroupInput.focus(); renameGroupInput.select(); }
  }

  function saveGroupRename() {
    if (!renamingGroupPattern) return;
    const trimmed = renameGroupValue.trim();
    if (trimmed && trimmed !== renamingGroupPattern) {
      rules = rules.map(r => r.pattern === renamingGroupPattern ? { ...r, pattern: trimmed } : r);
      dirty = true;
    }
    renamingGroupPattern = '';
    renameGroupValue = '';
  }

  function cancelGroupRename() { renamingGroupPattern = ''; renameGroupValue = ''; }

  function handleGroupRenameKeydown(e) {
    if (e.key === 'Enter') { e.preventDefault(); saveGroupRename(); }
    else if (e.key === 'Escape') { e.preventDefault(); cancelGroupRename(); }
  }

  // ─── Quick Rule Wizard ────────────────────────────────────────────

  function openQuickWizard() {
    showQuickWizard = true;
    wizardStep = 1;
    wizardSelectedProcess = null;
    wizardSelectedTunnels = [];
  }

  function closeQuickWizard() {
    showQuickWizard = false;
    wizardStep = 1;
    wizardSelectedProcess = null;
    wizardSelectedTunnels = [];
  }

  function wizardSelectProcess(proc) {
    wizardSelectedProcess = proc;
    wizardStep = 2;
  }

  function wizardAddTunnel(tunnel) {
    wizardSelectedTunnels = [...wizardSelectedTunnels, tunnel];
  }

  function wizardRemoveTunnel(index) {
    wizardSelectedTunnels = wizardSelectedTunnels.filter((_, i) => i !== index);
  }

  function wizardMoveTunnel(index, dir) {
    const newIdx = index + dir;
    if (newIdx < 0 || newIdx >= wizardSelectedTunnels.length) return;
    const arr = [...wizardSelectedTunnels];
    [arr[index], arr[newIdx]] = [arr[newIdx], arr[index]];
    wizardSelectedTunnels = arr;
  }

  function wizardConfirm() {
    const pattern = wizardSelectedProcess.name;

    const newRules = [];
    for (let i = 0; i < wizardSelectedTunnels.length; i++) {
      const isLast = i === wizardSelectedTunnels.length - 1;
      newRules.push({
        pattern,
        tunnelId: wizardSelectedTunnels[i].id,
        fallback: isLast ? 'allow_direct' : 'failover',
        priority: 'auto',
      });
    }

    // Insert after last existing rule with same pattern, or append
    let insertAt = rules.length;
    for (let i = rules.length - 1; i >= 0; i--) {
      if (rules[i].pattern.toLowerCase() === pattern.toLowerCase()) {
        insertAt = i + 1;
        break;
      }
    }
    rules = [...rules.slice(0, insertAt), ...newRules, ...rules.slice(insertAt)];
    dirty = true;
    closeQuickWizard();
  }

  // ─── Helpers ──────────────────────────────────────────────────────

  function tunnelName(id) {
    if (!id) return $t('rules.notAssigned');
    const tun = tunnels.find(tun => tun.id === id);
    return tun ? (tun.name || tun.id) : id;
  }

  function fallbackLabel(fb) {
    switch (fb) {
      case 'block': return $t('rules.fallbackBlock');
      case 'drop': return $t('rules.fallbackDrop');
      case 'failover': return $t('rules.fallbackFailover');
      default: return $t('rules.fallbackDirect');
    }
  }

  function priorityLabel(p) {
    switch (p) {
      case 'realtime': return 'Realtime';
      case 'normal': return 'Normal';
      case 'low': return 'Low';
      default: return 'Auto';
    }
  }

  function priorityColor(p) {
    switch (p) {
      case 'realtime': return 'text-orange-400 bg-orange-400/10';
      case 'normal': return 'text-blue-400 bg-blue-400/10';
      case 'low': return 'text-zinc-400 bg-zinc-400/10';
      default: return 'text-green-400 bg-green-400/10';
    }
  }
</script>

<!-- ─── Sticky save bar ──────────────────────────────────────────── -->
{#if dirty || ipsDirty || appsDirty}
  <div class="sticky top-0 z-10 flex justify-end gap-2 py-2 px-4 bg-zinc-900/95 backdrop-blur-sm border-b border-zinc-700/40">
    {#if dirty}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={cancel}
      >
        {$t('rules.cancel')}
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
        on:click={save}
      >
        {$t('rules.save')}
      </button>
    {/if}
    {#if ipsDirty}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={cancelIps}
      >
        {$t('rules.cancel')} (IP)
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
        on:click={saveIps}
      >
        {$t('rules.save')} (IP)
      </button>
    {/if}
    {#if appsDirty}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={cancelApps}
      >
        {$t('rules.cancel')} (Apps)
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
        on:click={saveApps}
      >
        {$t('rules.save')} (Apps)
      </button>
    {/if}
  </div>
{/if}

<!-- ─── Routing Rules Header ─────────────────────────────────────── -->
<div class="p-4 space-y-4">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">{$t('rules.title')}</h2>
    <div class="flex items-center gap-2">
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 transition-colors"
        on:click={openQuickWizard}
      >
        <svg class="w-3.5 h-3.5 inline mr-1 -mt-0.5" viewBox="0 0 24 24" fill="currentColor">
          <path d="M7 2v11h3v9l7-12h-4l4-8z"/>
        </svg>
        {$t('rules.quickRule')}
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
        on:click={openAddModal}
      >
        {$t('rules.addRule')}
      </button>
    </div>
  </div>

  {#if error}
    <ErrorAlert message={error} />
  {/if}

  {#if loading}
    <div class="flex items-center justify-center py-12 text-zinc-500">
      <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24" fill="none">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
      </svg>
      {$t('rules.loading')}
    </div>
  {:else if rules.length === 0}
    <div class="flex flex-col items-center justify-center py-16 text-zinc-500">
      <svg class="w-12 h-12 mb-3 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
        <path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/>
      </svg>
      <p class="text-sm">{$t('rules.noRules')}</p>
      <p class="text-xs text-zinc-600 mt-1">{$t('rules.noRulesHint')}</p>
    </div>
  {:else}
    <!-- Grouped Rules -->
    <div class="space-y-3">
      {#each groups as group, gi (group.pattern + '-' + gi)}
        <div class="border border-zinc-700/40 rounded-lg overflow-hidden">
          <!-- Group header -->
          <div class="bg-zinc-800/60 px-4 py-2 flex items-center gap-2">
            {#if patternIcons[group.pattern]}
              <img src={patternIcons[group.pattern]} alt="" class="w-4 h-4 shrink-0 rounded" />
            {:else}
              <svg class="w-3.5 h-3.5 text-zinc-500 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                <path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/>
              </svg>
            {/if}
            {#if renamingGroupPattern === group.pattern}
              <input bind:this={renameGroupInput} bind:value={renameGroupValue}
                on:blur={saveGroupRename} on:keydown={handleGroupRenameKeydown}
                class="font-mono text-xs text-zinc-200 bg-zinc-700 border border-blue-500 rounded px-1.5 py-0.5 outline-none min-w-[80px] max-w-[300px]" />
            {:else}
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <span class="font-mono text-xs text-zinc-200 cursor-default"
                on:dblclick={() => startGroupRename(group)}
                title={$t('rules.clickToRenameGroup')}>
                {group.pattern}
              </span>
            {/if}
            <span class="text-[10px] text-zinc-500">
              {group.rules.length} {group.rules.length === 1 ? $t('rules.oneRule') : $t('rules.nRules')}
            </span>
          </div>
          <!-- Group rules -->
          <table class="w-full text-sm" style="table-layout:fixed">
            <colgroup>
              <col style="width:32px" />
              <col />
              <col style="width:140px" />
              <col style="width:100px" />
              <col style="width:96px" />
            </colgroup>
            <tbody>
              {#each group.rules as rule, ri (rule.realIndex)}
                <tr
                  class="border-t border-zinc-700/30 hover:bg-zinc-800/30 transition-colors {rule.active === false ? 'opacity-50' : ''} {dragOverGroupIdx === gi && dragOverRuleIdx === ri ? 'border-t-2 !border-t-blue-500' : ''}"
                  on:dragover={e => handleGroupDragOver(e, gi, ri)}
                  on:dragleave={handleGroupDragLeave}
                  on:drop={e => handleGroupDrop(e, gi, ri)}
                >
                  <!-- Drag handle -->
                  <td class="w-8 px-0 py-2.5 text-center">
                    {#if group.rules.length > 1}
                      <!-- svelte-ignore a11y-no-static-element-interactions -->
                      <div
                        class="inline-flex items-center justify-center w-6 h-6 cursor-grab active:cursor-grabbing text-zinc-600 hover:text-zinc-400 transition-colors"
                        draggable="true"
                        on:dragstart={e => handleGroupDragStart(e, gi, ri)}
                        on:dragend={handleGroupDragEnd}
                      >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                          <circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/>
                          <circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/>
                          <circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/>
                        </svg>
                      </div>
                    {:else}
                      <div class="w-6 h-6"></div>
                    {/if}
                  </td>
                  <td class="px-4 py-2.5 truncate {rule.active === false ? 'text-zinc-500' : 'text-zinc-300'}" title="{tunnelName(rule.tunnelId)}">
                    {tunnelName(rule.tunnelId)}
                    {#if rule.active === false}
                      <span class="ml-1.5 inline-block px-1.5 py-0.5 text-[10px] rounded bg-zinc-700/50 text-zinc-500 font-sans">offline</span>
                    {/if}
                  </td>
                  <td class="px-4 py-2.5 {rule.active === false ? 'text-zinc-500' : 'text-zinc-400'}">{fallbackLabel(rule.fallback)}</td>
                  <td class="px-4 py-2.5">
                    <span class="inline-block px-1.5 py-0.5 text-xs rounded {priorityColor(rule.priority)}">
                      {priorityLabel(rule.priority)}
                    </span>
                  </td>
                  <td class="px-4 py-2.5 text-right w-24">
                    <button
                      class="text-zinc-500 hover:text-zinc-200 transition-colors mr-2"
                      on:click={() => openEditModal(rule.realIndex)}
                    >
                      <svg class="w-3.5 h-3.5 inline" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.003 1.003 0 000-1.42l-2.34-2.34a1.003 1.003 0 00-1.42 0l-1.83 1.83 3.75 3.75 1.84-1.82z"/>
                      </svg>
                    </button>
                    <button
                      class="text-zinc-500 hover:text-red-400 transition-colors"
                      on:click={() => removeRule(rule.realIndex)}
                    >
                      <svg class="w-3.5 h-3.5 inline" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                      </svg>
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Disallowed IPs section -->
{#if !loading}
  <div class="p-4 space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-lg font-semibold text-zinc-100">{$t('rules.ipExclusions')}</h2>
        <p class="text-xs text-zinc-500 mt-0.5">{$t('rules.ipExclusionsHint')}</p>
      </div>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
        on:click={addDisallowedIp}
      >
        {$t('rules.addBtn')}
      </button>
    </div>

    {#if ipsError}
      <ErrorAlert message={ipsError} />
    {/if}

    {#if disallowedIps.length === 0}
      <div class="flex flex-col items-center justify-center py-8 text-zinc-500">
        <svg class="w-10 h-10 mb-2 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9A7.902 7.902 0 014 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1A7.902 7.902 0 0120 12c0 4.42-3.58 8-8 8z"/>
        </svg>
        <p class="text-sm">{$t('rules.noIpExclusions')}</p>
        <p class="text-xs text-zinc-600 mt-1">{$t('rules.noIpExclusionsHint')}</p>
      </div>
    {:else}
      <div class="space-y-2">
        {#each disallowedIps as entry, i}
          <div class="flex items-center gap-2">
            <input
              type="text"
              value={entry.cidr}
              on:input={e => handleCidrInput(e, i)}
              placeholder="192.168.1.0/24"
              class="flex-1 px-3 py-2 text-sm bg-zinc-900 border rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none font-mono {entry.cidr && !isValidCidr(entry.cidr) ? 'border-red-500/60 focus:border-red-500/80' : 'border-zinc-700 focus:border-blue-500/50'}"
            />
            <select
              bind:value={entry.scope}
              on:change={() => { ipsDirty = true; }}
              class="w-44 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
            >
              <option value="__global__">{$t('rules.global')}</option>
              {#each tunnels as t}
                <option value={t.id}>{t.name || t.id}</option>
              {/each}
            </select>
            <button
              class="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
              on:click={() => removeDisallowedIp(i)}
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
              </svg>
            </button>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- Disallowed Apps section -->
{#if !loading}
  <div class="p-4 space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-lg font-semibold text-zinc-100">{$t('rules.appExclusions')}</h2>
        <p class="text-xs text-zinc-500 mt-0.5">{$t('rules.appExclusionsHint')}</p>
      </div>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
        on:click={addDisallowedApp}
      >
        {$t('rules.addBtn')}
      </button>
    </div>

    {#if appsError}
      <ErrorAlert message={appsError} />
    {/if}

    {#if disallowedApps.length === 0}
      <div class="flex flex-col items-center justify-center py-8 text-zinc-500">
        <svg class="w-10 h-10 mb-2 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
          <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
        </svg>
        <p class="text-sm">{$t('rules.noAppExclusions')}</p>
        <p class="text-xs text-zinc-600 mt-1">{$t('rules.noAppExclusionsHint')}</p>
      </div>
    {:else}
      <div class="space-y-2">
        {#each disallowedApps as entry, i}
          <div class="flex items-center gap-2">
            <div class="flex-1 flex gap-1.5">
              <input
                type="text"
                bind:value={entry.pattern}
                on:input={markAppsDirty}
                placeholder={appExclusionPlaceholder}
                class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 font-mono"
              />
              <button
                class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
                title={$t('rules.selectProcess')}
                on:click={() => openAppProcessPicker(i)}
              >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
                </svg>
              </button>
            </div>
            <select
              bind:value={entry.scope}
              on:change={markAppsDirty}
              class="w-44 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
            >
              <option value="__global__">{$t('rules.global')}</option>
              {#each tunnels as t}
                <option value={t.id}>{t.name || t.id}</option>
              {/each}
            </select>
            <button
              class="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
              on:click={() => removeDisallowedApp(i)}
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
              </svg>
            </button>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- ─── App process picker modal ─────────────────────────────────── -->
{#if showAppProcessPicker}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="fixed inset-0 bg-black/60 z-40 flex items-center justify-center"
       on:click|self={closeAppProcessPicker}
       on:keydown={e => e.key === 'Escape' && closeAppProcessPicker()}
       role="dialog"
       tabindex="-1"
  >
    <div class="bg-zinc-800 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-4 space-y-3 max-h-[70vh] flex flex-col">
      <h3 class="text-sm font-semibold text-zinc-100 shrink-0">{$t('rules.selectProcess')}</h3>
      <div class="flex-1 overflow-y-auto min-h-0">
        <ProcessPicker groupByFolder on:select={e => selectAppProcess(e.detail)} on:selectFolder={e => selectAppFolder(e.detail)} />
      </div>
      <div class="flex justify-end pt-1 shrink-0">
        <button
          class="px-3 py-1.5 text-xs rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
          on:click={closeAppProcessPicker}
        >
          {$t('rules.close')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ─── Rule edit modal ──────────────────────────────────────────── -->
{#if showModal}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="fixed inset-0 bg-black/60 z-40 flex items-center justify-center"
       on:click|self={closeModal}
       on:keydown={e => e.key === 'Escape' && closeModal()}
       role="dialog"
       tabindex="-1"
  >
    <div class="bg-zinc-800 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-5 space-y-4">
      <h3 class="text-base font-semibold text-zinc-100">
        {editIndex >= 0 ? $t('rules.editRule') : $t('rules.newRule')}
      </h3>

      <div class="space-y-3">
        <!-- Pattern -->
        <div>
          <label for="rule-pattern" class="block text-xs font-medium text-zinc-400 mb-1">{$t('rules.processPattern')}</label>
          <div class="flex gap-2">
            <input
              id="rule-pattern"
              type="text"
              bind:value={modalRule.pattern}
              placeholder={rulePatternPlaceholder}
              class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
            />
            <button
              class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
              title={$t('rules.selectProcess')}
              on:click={openProcessPicker}
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
              </svg>
            </button>
          </div>
          <p class="text-[10px] text-zinc-500 mt-1">{$t('rules.patternHint')}</p>
        </div>

        <!-- Process picker inline -->
        {#if showProcessPicker}
          <div class="bg-zinc-900 border border-zinc-700 rounded-lg p-2">
            <ProcessPicker compact groupByFolder on:select={e => selectProcess(e.detail)} on:selectFolder={e => selectFolderProcess(e.detail)} />
          </div>
        {/if}

        <!-- Tunnel -->
        <div>
          <label for="rule-tunnel" class="block text-xs font-medium text-zinc-400 mb-1">{$t('rules.tunnelLabel')}</label>
          <select
            id="rule-tunnel"
            bind:value={modalRule.tunnelId}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="">{$t('rules.notAssigned')}</option>
            {#each tunnels as t}
              <option value={t.id}>{t.name || t.id} ({t.protocol})</option>
            {/each}
            <option value="__block__">{$t('rules.blockAction')}</option>
            <option value="__drop__">{$t('rules.dropAction')}</option>
          </select>
        </div>

        <!-- Fallback -->
        <div>
          <label for="rule-fallback" class="block text-xs font-medium text-zinc-400 mb-1">{$t('rules.fallbackLabel')}</label>
          <select
            id="rule-fallback"
            bind:value={modalRule.fallback}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="allow_direct">{$t('rules.fallbackDirect')}</option>
            <option value="block">{$t('rules.fallbackBlock')}</option>
            <option value="drop">{$t('rules.fallbackDrop')}</option>
            <option value="failover">{$t('rules.fallbackFailover')}</option>
          </select>
        </div>

        <!-- Priority -->
        <div>
          <label for="rule-priority" class="block text-xs font-medium text-zinc-400 mb-1">{$t('rules.priorityQos')}</label>
          <select
            id="rule-priority"
            bind:value={modalRule.priority}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="auto">{$t('rules.priorityAuto')}</option>
            <option value="realtime">{$t('rules.priorityRealtime')}</option>
            <option value="normal">{$t('rules.priorityNormal')}</option>
            <option value="low">{$t('rules.priorityLow')}</option>
          </select>
        </div>
      </div>

      <div class="flex justify-end gap-2 pt-2">
        <button
          class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
          on:click={closeModal}
        >
          {$t('rules.cancel')}
        </button>
        <button
          class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
          disabled={!modalRule.pattern.trim()}
          on:click={saveModalRule}
        >
          {editIndex >= 0 ? $t('rules.save') : $t('common.add')}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ─── Quick Rule Wizard ────────────────────────────────────────── -->
{#if showQuickWizard}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="fixed inset-0 bg-black/60 z-50 flex items-center justify-center"
       on:click|self={closeQuickWizard}
       on:keydown={e => e.key === 'Escape' && closeQuickWizard()}
       role="dialog"
       tabindex="-1"
  >
    <div class="bg-zinc-800 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4 p-5 space-y-4 max-h-[85vh] flex flex-col">
      <!-- Title -->
      <h3 class="text-base font-semibold text-zinc-100 shrink-0">{$t('rules.quickRuleTitle')}</h3>

      <!-- Stepper -->
      <div class="flex items-center justify-center gap-1.5 shrink-0">
        {#each [{ n: 1, l: 'stepProcess' }, { n: 2, l: 'stepTunnels' }, { n: 3, l: 'stepConfirm' }] as step}
          <div class="flex items-center gap-1.5">
            <div class="w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium {
              wizardStep > step.n ? 'bg-emerald-500/20 text-emerald-400' :
              wizardStep === step.n ? 'bg-blue-500/20 text-blue-400 ring-1 ring-blue-500/50' :
              'bg-zinc-700/50 text-zinc-500'
            }">
              {#if wizardStep > step.n}
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
              {:else}
                {step.n}
              {/if}
            </div>
            <span class="text-xs {wizardStep >= step.n ? 'text-zinc-200' : 'text-zinc-500'}">{$t(`rules.${step.l}`)}</span>
          </div>
          {#if step.n < 3}
            <div class="w-6 h-px bg-zinc-700 mx-1"></div>
          {/if}
        {/each}
      </div>

      <!-- Step content -->
      <div class="flex-1 overflow-y-auto min-h-0">
        <!-- ── Step 1: Select Process ── -->
        {#if wizardStep === 1}
          <ProcessPicker groupByFolder on:select={e => wizardSelectProcess(e.detail)} on:selectFolder={e => wizardSelectFolder(e.detail)} />

        <!-- ── Step 2: Select Tunnels ── -->
        {:else if wizardStep === 2}
          <div class="space-y-4">
            <p class="text-xs text-zinc-400">{$t('rules.selectTunnelsHint')}</p>

            <!-- Selected tunnels (ordered) -->
            {#if wizardSelectedTunnels.length > 0}
              <div>
                <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.selectedTunnels')}</div>
                <div class="space-y-1">
                  {#each wizardSelectedTunnels as tun, i}
                    <div class="flex items-center gap-2 px-3 py-2 bg-zinc-700/30 rounded-lg border border-zinc-700/50">
                      <span class="text-xs font-mono text-zinc-500 w-5 shrink-0">{i + 1}.</span>
                      <span class="text-sm text-zinc-200 flex-1 truncate">{tun.name || tun.id}</span>
                      <span class="text-[10px] text-zinc-500">{tun.protocol}</span>
                      <!-- Move up -->
                      <button
                        class="p-1 text-zinc-500 hover:text-zinc-300 transition-colors disabled:opacity-30"
                        disabled={i === 0}
                        on:click={() => wizardMoveTunnel(i, -1)}
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M7.41 15.41L12 10.83l4.59 4.58L18 14l-6-6-6 6z"/></svg>
                      </button>
                      <!-- Move down -->
                      <button
                        class="p-1 text-zinc-500 hover:text-zinc-300 transition-colors disabled:opacity-30"
                        disabled={i === wizardSelectedTunnels.length - 1}
                        on:click={() => wizardMoveTunnel(i, 1)}
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6z"/></svg>
                      </button>
                      <!-- Remove -->
                      <button
                        class="p-1 text-zinc-500 hover:text-red-400 transition-colors"
                        on:click={() => wizardRemoveTunnel(i)}
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                      </button>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <!-- Available tunnels -->
            <div>
              <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.availableTunnels')}</div>
              {#if wizardAvailableTunnels.length === 0 && wizardSelectedTunnels.length === 0}
                <div class="text-xs text-zinc-500 py-4 text-center">{$t('rules.noTunnelsAvailable')}</div>
              {:else if wizardAvailableTunnels.length === 0}
                <div class="text-xs text-zinc-600 py-2 text-center">-</div>
              {:else}
                <div class="space-y-0.5">
                  {#each wizardAvailableTunnels as tun}
                    <button
                      class="w-full flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-zinc-700/50 transition-colors text-left"
                      on:click={() => wizardAddTunnel(tun)}
                    >
                      <svg class="w-4 h-4 text-blue-400 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
                      </svg>
                      <span class="text-sm text-zinc-300 flex-1 truncate">{tun.name || tun.id}</span>
                      <span class="text-[10px] text-zinc-500">{tun.protocol}</span>
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
          </div>

        <!-- ── Step 3: Confirm ── -->
        {:else if wizardStep === 3}
          <div class="space-y-4">
            <!-- Selected process -->
            <div>
              <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.processLabel')}</div>
              <div class="flex items-center gap-3 px-3 py-2.5 bg-zinc-700/30 rounded-lg border border-zinc-700/50">
                <div class="w-8 h-8 shrink-0 flex items-center justify-center rounded bg-zinc-700/50">
                  {#if wizardSelectedProcess?.icon}
                    <img src={wizardSelectedProcess.icon} alt="" class="w-7 h-7" />
                  {:else}
                    <svg class="w-5 h-5 text-zinc-500" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                    </svg>
                  {/if}
                </div>
                <div class="min-w-0 flex-1">
                  <div class="text-sm font-medium text-zinc-100">{wizardSelectedProcess?.name}</div>
                  {#if wizardSelectedProcess?.path}
                    <div class="text-[10px] text-zinc-500 truncate">{wizardSelectedProcess.path}</div>
                  {/if}
                </div>
              </div>
            </div>

            <!-- Rules preview -->
            <div>
              <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.rulesPreview')}</div>
              <div class="border border-zinc-700/50 rounded-lg overflow-hidden">
                {#each wizardSelectedTunnels as tun, i}
                  {@const isLast = i === wizardSelectedTunnels.length - 1}
                  <div class="flex items-center gap-3 px-3 py-2 {i > 0 ? 'border-t border-zinc-700/30' : ''} {isLast ? 'bg-zinc-800/40' : ''}">
                    <span class="text-xs font-mono text-zinc-500 w-5 shrink-0">{i + 1}.</span>
                    <div class="flex-1 min-w-0">
                      <span class="text-sm text-zinc-200">{wizardSelectedProcess?.name}</span>
                      <svg class="w-3.5 h-3.5 inline mx-1.5 text-zinc-600" viewBox="0 0 24 24" fill="currentColor"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>
                      <span class="text-sm text-blue-400">{tun.name || tun.id}</span>
                    </div>
                    {#if isLast}
                      <span class="text-[10px] text-emerald-400 shrink-0">{$t('rules.fallbackDirect')}</span>
                    {:else}
                      <span class="text-[10px] text-zinc-500 shrink-0">{$t('rules.fallbackFailover')}</span>
                    {/if}
                  </div>
                {/each}
              </div>
            </div>
          </div>
        {/if}
      </div>

      <!-- Footer buttons -->
      <div class="flex justify-between pt-2 shrink-0">
        <div>
          {#if wizardStep > 1}
            <button
              class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
              on:click={() => { wizardStep -= 1; }}
            >
              {$t('rules.back')}
            </button>
          {/if}
        </div>
        <div class="flex gap-2">
          <button
            class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
            on:click={closeQuickWizard}
          >
            {$t('rules.cancel')}
          </button>
          {#if wizardStep === 2}
            <button
              class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
              disabled={wizardSelectedTunnels.length === 0}
              on:click={() => { wizardStep = 3; }}
            >
              {$t('rules.next')}
            </button>
          {:else if wizardStep === 3}
            <button
              class="px-4 py-2 text-sm rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors"
              on:click={wizardConfirm}
            >
              {$t('rules.create')}
            </button>
          {/if}
        </div>
      </div>
    </div>
  </div>
{/if}
