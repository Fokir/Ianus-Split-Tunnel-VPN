<script>
  import { createEventDispatcher, tick } from 'svelte';
  import * as api from '../../api.js';
  import ErrorAlert from '../../ErrorAlert.svelte';
  import { Spinner, EmptyState } from '../../components';
  import { t } from '../../i18n';

  export let rules = [];
  export let tunnels = [];
  export let loading = false;
  export let error = '';
  export let patternIcons = {};

  const dispatch = createEventDispatcher();

  // Drag & drop
  let dragGroupIdx = -1;
  let dragRuleIdx = -1;
  let dragOverGroupIdx = -1;
  let dragOverRuleIdx = -1;

  // Inline group rename
  let renamingGroupPattern = '';
  let renameGroupValue = '';
  let renameGroupInput;

  // Grouping
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

  // Helpers
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

  // Drag & drop
  function handleGroupDragStart(e, gi, ri) {
    dragGroupIdx = gi;
    dragRuleIdx = ri;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', `${gi}:${ri}`);
    e.currentTarget.closest('tr').style.opacity = '0.4';
  }

  function handleGroupDragEnd(e) {
    e.currentTarget.closest('tr').style.opacity = '';
    dragGroupIdx = -1; dragRuleIdx = -1;
    dragOverGroupIdx = -1; dragOverRuleIdx = -1;
  }

  function handleGroupDragOver(e, gi, ri) {
    if (gi !== dragGroupIdx) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    dragOverGroupIdx = gi;
    dragOverRuleIdx = ri;
  }

  function handleGroupDragLeave() {
    dragOverGroupIdx = -1; dragOverRuleIdx = -1;
  }

  function handleGroupDrop(e, gi, ri) {
    e.preventDefault();
    if (gi !== dragGroupIdx || dragRuleIdx === ri) {
      dragGroupIdx = -1; dragRuleIdx = -1;
      dragOverGroupIdx = -1; dragOverRuleIdx = -1;
      return;
    }
    const g = groups[gi];
    const fromReal = g.rules[dragRuleIdx].realIndex;
    const toReal = g.rules[ri].realIndex;
    const reordered = [...rules];
    const [moved] = reordered.splice(fromReal, 1);
    reordered.splice(toReal, 0, moved);
    dispatch('reorder', reordered);
    dragGroupIdx = -1; dragRuleIdx = -1;
    dragOverGroupIdx = -1; dragOverRuleIdx = -1;
  }

  // Inline rename
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
      dispatch('rename', { oldPattern: renamingGroupPattern, newPattern: trimmed });
    }
    renamingGroupPattern = '';
    renameGroupValue = '';
  }

  function cancelGroupRename() { renamingGroupPattern = ''; renameGroupValue = ''; }

  function handleGroupRenameKeydown(e) {
    if (e.key === 'Enter') { e.preventDefault(); saveGroupRename(); }
    else if (e.key === 'Escape') { e.preventDefault(); cancelGroupRename(); }
  }
</script>

<div class="p-4 space-y-4">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">{$t('rules.title')}</h2>
    <div class="flex items-center gap-2">
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 transition-colors"
        on:click={() => dispatch('quickWizard')}
      >
        <svg class="w-3.5 h-3.5 inline mr-1 -mt-0.5" viewBox="0 0 24 24" fill="currentColor">
          <path d="M7 2v11h3v9l7-12h-4l4-8z"/>
        </svg>
        {$t('rules.quickRule')}
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
        on:click={() => dispatch('addRule')}
      >
        {$t('rules.addRule')}
      </button>
    </div>
  </div>

  {#if error}
    <ErrorAlert message={error} />
  {/if}

  {#if loading}
    <Spinner text={$t('rules.loading')} />
  {:else if rules.length === 0}
    <EmptyState title={$t('rules.noRules')} description={$t('rules.noRulesHint')}>
      <svelte:fragment slot="icon">
        <svg class="w-12 h-12 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
          <path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/>
        </svg>
      </svelte:fragment>
    </EmptyState>
  {:else}
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
          <!-- Group rules table -->
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
                      on:click={() => dispatch('editRule', rule.realIndex)}
                    >
                      <svg class="w-3.5 h-3.5 inline" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.003 1.003 0 000-1.42l-2.34-2.34a1.003 1.003 0 00-1.42 0l-1.83 1.83 3.75 3.75 1.84-1.82z"/>
                      </svg>
                    </button>
                    <button
                      class="text-zinc-500 hover:text-red-400 transition-colors"
                      on:click={() => dispatch('removeRule', rule.realIndex)}
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
