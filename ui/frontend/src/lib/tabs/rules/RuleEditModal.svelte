<script>
  import { createEventDispatcher } from 'svelte';
  import ProcessPicker from '../../ProcessPicker.svelte';
  import { Modal } from '../../components';
  import { t } from '../../i18n';
  import { isMac } from '../../stores/platform.js';

  export let open = false;
  export let editIndex = -1;
  export let rule = { pattern: '', tunnelId: '', fallback: 'allow_direct', priority: 'auto' };
  export let tunnels = [];

  const dispatch = createEventDispatcher();

  let showProcessPicker = false;

  $: rulePatternPlaceholder = $isMac
    ? 'chrome, firefox*, regex:^.*/games/.*$'
    : 'chrome.exe, firefox*, regex:^.*\\\\games\\\\.*$';

  $: if (open) showProcessPicker = false;

  function close() { dispatch('close'); }

  function save() {
    if (!rule.pattern.trim()) return;
    dispatch('save', { rule: { ...rule }, editIndex });
  }

  function selectProcess(proc) {
    rule.pattern = proc.name;
    showProcessPicker = false;
  }

  function selectFolderProcess(detail) {
    rule.pattern = detail.pattern;
    showProcessPicker = false;
  }
</script>

<Modal {open} title={editIndex >= 0 ? $t('rules.editRule') : $t('rules.newRule')} on:close={close}>
  <div class="space-y-3">
    <!-- Pattern -->
    <div>
      <label for="rule-pattern" class="block text-xs font-medium text-zinc-400 mb-1">{$t('rules.processPattern')}</label>
      <div class="flex gap-2">
        <input
          id="rule-pattern"
          type="text"
          bind:value={rule.pattern}
          placeholder={rulePatternPlaceholder}
          class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
        />
        <button
          class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
          title={$t('rules.selectProcess')}
          on:click={() => showProcessPicker = !showProcessPicker}
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
        bind:value={rule.tunnelId}
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
        bind:value={rule.fallback}
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
        bind:value={rule.priority}
        class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
      >
        <option value="auto">{$t('rules.priorityAuto')}</option>
        <option value="realtime">{$t('rules.priorityRealtime')}</option>
        <option value="normal">{$t('rules.priorityNormal')}</option>
        <option value="low">{$t('rules.priorityLow')}</option>
      </select>
    </div>
  </div>

  <svelte:fragment slot="footer">
    <button
      class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
      on:click={close}
    >
      {$t('rules.cancel')}
    </button>
    <button
      class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
      disabled={!rule.pattern.trim()}
      on:click={save}
    >
      {editIndex >= 0 ? $t('rules.save') : $t('common.add')}
    </button>
  </svelte:fragment>
</Modal>
