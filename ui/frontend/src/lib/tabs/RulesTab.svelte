<script>
  import { onMount, onDestroy } from 'svelte';
  import * as api from '../api.js';
  import { sortTunnels } from '../utils.js';
  import { t } from '../i18n';
  import { tabDirty } from '../stores/dirty.js';

  import RoutingRulesSection from './rules/RoutingRulesSection.svelte';
  import DisallowedIpsSection from './rules/DisallowedIpsSection.svelte';
  import DisallowedAppsSection from './rules/DisallowedAppsSection.svelte';
  import AutoBypassSection from './rules/AutoBypassSection.svelte';
  import RuleEditModal from './rules/RuleEditModal.svelte';
  import QuickRuleWizard from './rules/QuickRuleWizard.svelte';

  $: $tabDirty = dirty || ipsDirty || appsDirty || autoBypassDirty;
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

  // Auto Bypass state
  let autoBypassEnabled = false;
  let autoBypassExtraPatterns = [];
  let autoBypassExtraBypass = [];
  let autoBypassNeverBypass = [];
  let autoBypassDirty = false;

  // Rule edit modal
  let showModal = false;
  let editIndex = -1;
  let modalRule = { pattern: '', tunnelId: '', fallback: 'allow_direct', priority: 'auto' };

  // Quick wizard
  let showQuickWizard = false;

  // Pattern icons
  let patternIcons = {};
  let iconLoadTimer;

  $: groups = computeGroups(rules);

  $: if (groups.length > 0) {
    clearTimeout(iconLoadTimer);
    iconLoadTimer = setTimeout(loadPatternIcons, 300);
  }

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

  async function loadPatternIcons() {
    try {
      const procs = await api.listProcesses('') || [];
      const iconMap = {};
      for (const group of groups) {
        const pat = group.pattern.toLowerCase();
        let match = procs.find(p => p.name.toLowerCase() === pat && p.icon);
        if (!match && (pat.endsWith('/*') || pat.endsWith('\\*'))) {
          const dir = pat.slice(0, -2);
          match = procs.find(p => p.path && p.path.toLowerCase().startsWith(dir) && p.icon);
        }
        if (!match) {
          match = procs.find(p => p.name.toLowerCase().includes(pat) && p.icon);
        }
        if (match) iconMap[group.pattern] = match.icon;
      }
      patternIcons = iconMap;
    } catch {
      // Icons are optional
    }
  }

  // ─── Lifecycle ──────────────────────────────────────────────────

  onMount(async () => { await loadData(); });

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
      buildAutoBypass();
    } catch (e) {
      error = e.message || $t('rules.failedToLoad');
    } finally {
      loading = false;
    }
  }

  // ─── Routing Rules ─────────────────────────────────────────────

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

  function handleSaveRule(e) {
    const { rule, editIndex: idx } = e.detail;
    if (idx >= 0) {
      // Preserve enabled state when editing via modal
      rules[idx] = { ...rule, enabled: rules[idx].enabled !== false };
    } else {
      rules = [...rules, { ...rule, enabled: true }];
    }
    dirty = true;
    showModal = false;
  }

  function removeRule(index) {
    rules = rules.filter((_, i) => i !== index);
    dirty = true;
  }

  function toggleRule(index) {
    rules[index] = { ...rules[index], enabled: rules[index].enabled === false ? true : false };
    rules = rules;
    dirty = true;
  }

  function handleReorder(e) {
    rules = e.detail;
    dirty = true;
  }

  function handleRename(e) {
    const { oldPattern, newPattern } = e.detail;
    rules = rules.map(r => r.pattern === oldPattern ? { ...r, pattern: newPattern } : r);
    dirty = true;
  }

  function handleWizardConfirm(e) {
    const { rules: newRules, pattern } = e.detail;
    let insertAt = rules.length;
    for (let i = rules.length - 1; i >= 0; i--) {
      if (rules[i].pattern.toLowerCase() === pattern.toLowerCase()) {
        insertAt = i + 1;
        break;
      }
    }
    rules = [...rules.slice(0, insertAt), ...newRules, ...rules.slice(insertAt)];
    dirty = true;
    showQuickWizard = false;
  }

  async function saveRules() {
    error = '';
    try {
      await api.saveRules(rules);
      dirty = false;
    } catch (e) {
      error = e.message;
    }
  }

  function cancelRules() {
    loadData();
    dirty = false;
  }

  // ─── Disallowed IPs ──────────────────────────────────────────

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

  function addIp() {
    disallowedIps = [...disallowedIps, { cidr: '', scope: '__global__' }];
    ipsDirty = true;
  }

  function removeIp(e) {
    disallowedIps = disallowedIps.filter((_, i) => i !== e.detail);
    ipsDirty = true;
  }

  function handleCidrInput(e) {
    const { index, value } = e.detail;
    disallowedIps[index].cidr = value;
    disallowedIps = disallowedIps;
    ipsDirty = true;
  }

  function markIpsDirty() { ipsDirty = true; }

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

  // ─── Disallowed Apps ─────────────────────────────────────────

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

  function addApp() {
    disallowedApps = [...disallowedApps, { pattern: '', scope: '__global__' }];
    appsDirty = true;
  }

  function removeApp(e) {
    disallowedApps = disallowedApps.filter((_, i) => i !== e.detail);
    appsDirty = true;
  }

  function handleUpdateAppPattern(e) {
    const { index, pattern } = e.detail;
    disallowedApps[index].pattern = pattern;
    disallowedApps = [...disallowedApps];
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

  // ─── Auto Bypass ──────────────────────────────────────────

  function buildAutoBypass() {
    const ab = config.auto_bypass || {};
    autoBypassEnabled = !!ab.enabled;
    autoBypassExtraPatterns = ab.extra_patterns ? [...ab.extra_patterns] : [];
    autoBypassExtraBypass = ab.extra_bypass ? [...ab.extra_bypass] : [];
    autoBypassNeverBypass = ab.never_bypass ? [...ab.never_bypass] : [];
    autoBypassDirty = false;
  }

  function handleAutoBypassChange(e) {
    const { enabled, extraPatterns, extraBypass, neverBypass } = e.detail;
    autoBypassEnabled = enabled;
    autoBypassExtraPatterns = extraPatterns;
    autoBypassExtraBypass = extraBypass;
    autoBypassNeverBypass = neverBypass;
    autoBypassDirty = true;
  }

  async function saveAutoBypass() {
    try {
      if (!config.auto_bypass) config.auto_bypass = {};
      config.auto_bypass.enabled = autoBypassEnabled;
      config.auto_bypass.extra_patterns = autoBypassExtraPatterns.filter(s => s.trim());
      config.auto_bypass.extra_bypass = autoBypassExtraBypass.filter(s => s.trim());
      config.auto_bypass.never_bypass = autoBypassNeverBypass.filter(s => s.trim());
      await api.saveConfig(config, false);
      autoBypassDirty = false;
    } catch (e) {
      error = e.message || 'Failed to save auto-bypass settings';
    }
  }

  function cancelAutoBypass() { buildAutoBypass(); }
</script>

<!-- Sticky save bar -->
{#if dirty || ipsDirty || appsDirty || autoBypassDirty}
  <div class="sticky top-0 z-10 flex justify-end gap-2 py-2 px-4 bg-zinc-900/95 backdrop-blur-sm border-b border-zinc-700/40">
    {#if dirty}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={cancelRules}
      >
        {$t('rules.cancel')}
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
        on:click={saveRules}
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
    {#if autoBypassDirty}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={cancelAutoBypass}
      >
        {$t('rules.cancel')} (Auto Bypass)
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
        on:click={saveAutoBypass}
      >
        {$t('rules.save')} (Auto Bypass)
      </button>
    {/if}
  </div>
{/if}

<!-- Auto Bypass -->
{#if !loading}
  <AutoBypassSection
    enabled={autoBypassEnabled}
    extraPatterns={autoBypassExtraPatterns}
    extraBypass={autoBypassExtraBypass}
    neverBypass={autoBypassNeverBypass}
    {rules}
    on:change={handleAutoBypassChange}
  />
{/if}

<!-- Routing Rules -->
<RoutingRulesSection
  {rules} {tunnels} {loading} {error} {patternIcons}
  on:addRule={openAddModal}
  on:editRule={e => openEditModal(e.detail)}
  on:removeRule={e => removeRule(e.detail)}
  on:toggleRule={e => toggleRule(e.detail)}
  on:reorder={handleReorder}
  on:rename={handleRename}
  on:quickWizard={() => showQuickWizard = true}
/>

<!-- Disallowed IPs -->
{#if !loading}
  <DisallowedIpsSection
    {disallowedIps} {tunnels} error={ipsError}
    on:add={addIp}
    on:remove={removeIp}
    on:cidrInput={handleCidrInput}
    on:dirty={markIpsDirty}
  />
{/if}

<!-- Disallowed Apps -->
{#if !loading}
  <DisallowedAppsSection
    {disallowedApps} {tunnels} error={appsError}
    on:add={addApp}
    on:remove={removeApp}
    on:updatePattern={handleUpdateAppPattern}
    on:dirty={markAppsDirty}
  />
{/if}

<!-- Rule edit modal -->
<RuleEditModal
  open={showModal} {editIndex} rule={modalRule} {tunnels}
  on:close={() => showModal = false}
  on:save={handleSaveRule}
/>

<!-- Quick rule wizard -->
<QuickRuleWizard
  open={showQuickWizard} {tunnels}
  on:close={() => showQuickWizard = false}
  on:confirm={handleWizardConfirm}
/>
