<script>
  import { createEventDispatcher } from 'svelte';
  import ProcessPicker from '../../ProcessPicker.svelte';
  import { Modal } from '../../components';
  import { t } from '../../i18n';

  export let enabled = false;
  export let extraPatterns = [];
  export let extraBypass = [];
  export let neverBypass = [];
  export let rules = [];

  const dispatch = createEventDispatcher();

  let showProcessPicker = false;
  let pickerTarget = null; // { list: 'extraBypass' | 'neverBypass', index: number }

  // Conflict detection: exe names that already have routing rules
  $: rulePatterns = new Set(rules.map(r => r.pattern.toLowerCase()));
  $: conflicts = extraBypass.filter(e => rulePatterns.has(e.toLowerCase()));

  function emitChange() {
    dispatch('change', { enabled, extraPatterns, extraBypass, neverBypass });
  }

  function toggleEnabled() {
    enabled = !enabled;
    emitChange();
  }

  // ─── Extra Bypass (exe names) ───────────────────────────────
  function addExtraBypass() {
    extraBypass = [...extraBypass, ''];
    emitChange();
  }

  function removeExtraBypass(index) {
    extraBypass = extraBypass.filter((_, i) => i !== index);
    emitChange();
  }

  function updateExtraBypass(index, value) {
    extraBypass[index] = value;
    extraBypass = extraBypass;
    emitChange();
  }

  // ─── Extra Patterns (directories) ──────────────────────────
  function addExtraPattern() {
    extraPatterns = [...extraPatterns, ''];
    emitChange();
  }

  function removeExtraPattern(index) {
    extraPatterns = extraPatterns.filter((_, i) => i !== index);
    emitChange();
  }

  function updateExtraPattern(index, value) {
    extraPatterns[index] = value;
    extraPatterns = extraPatterns;
    emitChange();
  }

  // ─── Never Bypass ──────────────────────────────────────────
  function addNeverBypass() {
    neverBypass = [...neverBypass, ''];
    emitChange();
  }

  function removeNeverBypass(index) {
    neverBypass = neverBypass.filter((_, i) => i !== index);
    emitChange();
  }

  function updateNeverBypass(index, value) {
    neverBypass[index] = value;
    neverBypass = neverBypass;
    emitChange();
  }

  // ─── Process Picker ────────────────────────────────────────
  function openProcessPicker(list, index) {
    pickerTarget = { list, index };
    showProcessPicker = true;
  }

  function selectProcess(proc) {
    if (!pickerTarget) return;
    if (pickerTarget.list === 'extraBypass') {
      updateExtraBypass(pickerTarget.index, proc.name);
    } else if (pickerTarget.list === 'neverBypass') {
      updateNeverBypass(pickerTarget.index, proc.name);
    }
    closeProcessPicker();
  }

  function selectFolder(detail) {
    if (!pickerTarget) return;
    if (pickerTarget.list === 'extraPatterns') {
      updateExtraPattern(pickerTarget.index, detail.pattern);
    }
    closeProcessPicker();
  }

  function closeProcessPicker() {
    showProcessPicker = false;
    pickerTarget = null;
  }
</script>

<div class="p-4 space-y-4">
  <!-- Header with toggle -->
  <div class="flex items-center justify-between">
    <div>
      <h2 class="text-lg font-semibold text-zinc-100">Auto Bypass</h2>
      <p class="text-xs text-zinc-500 mt-0.5">Automatically bypass VPN for system and well-known apps</p>
    </div>
    <label class="flex items-center gap-2 cursor-pointer">
      <span class="text-xs text-zinc-400">{enabled ? 'Enabled' : 'Disabled'}</span>
      <input
        type="checkbox"
        checked={enabled}
        on:change={toggleEnabled}
        class="w-9 h-5 bg-zinc-700 rounded-full appearance-none relative cursor-pointer
               checked:bg-blue-600 transition-colors
               after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4
               after:bg-white after:rounded-full after:transition-transform
               checked:after:translate-x-4"
      />
    </label>
  </div>

  {#if conflicts.length > 0}
    <div class="flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-900/20 border border-amber-700/30">
      <svg class="w-4 h-4 text-amber-400 mt-0.5 shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
      </svg>
      <div class="text-xs text-amber-300">
        <span class="font-medium">Conflict:</span> the following apps already have routing rules and may not be auto-bypassed:
        <span class="font-mono">{conflicts.join(', ')}</span>
      </div>
    </div>
  {/if}

  {#if enabled}
    <!-- Extra Bypass (exe names) -->
    <div class="space-y-2">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-sm font-medium text-zinc-200">Extra Bypass Apps</h3>
          <p class="text-xs text-zinc-500 mt-0.5">Additional exe names to always bypass VPN</p>
        </div>
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
          on:click={addExtraBypass}
        >
          Add
        </button>
      </div>
      {#each extraBypass as entry, i}
        <div class="flex items-center gap-2">
          <input
            type="text"
            value={entry}
            on:input={e => updateExtraBypass(i, e.target.value)}
            placeholder="app.exe"
            class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 font-mono"
          />
          <button
            class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
            title="Select process"
            on:click={() => openProcessPicker('extraBypass', i)}
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
            </svg>
          </button>
          <button
            class="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
            on:click={() => removeExtraBypass(i)}
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
            </svg>
          </button>
        </div>
      {/each}
    </div>

    <!-- Extra Patterns (directories) -->
    <div class="space-y-2">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-sm font-medium text-zinc-200">Extra Bypass Directories</h3>
          <p class="text-xs text-zinc-500 mt-0.5">Directory patterns to bypass (e.g. C:\Windows\*)</p>
        </div>
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
          on:click={addExtraPattern}
        >
          Add
        </button>
      </div>
      {#each extraPatterns as entry, i}
        <div class="flex items-center gap-2">
          <input
            type="text"
            value={entry}
            on:input={e => updateExtraPattern(i, e.target.value)}
            placeholder="C:\Program Files\MyApp\*"
            class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 font-mono"
          />
          <button
            class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
            title="Select folder"
            on:click={() => openProcessPicker('extraPatterns', i)}
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/>
            </svg>
          </button>
          <button
            class="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
            on:click={() => removeExtraPattern(i)}
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
            </svg>
          </button>
        </div>
      {/each}
    </div>

    <!-- Never Bypass -->
    <div class="space-y-2">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-sm font-medium text-zinc-200">Never Bypass</h3>
          <p class="text-xs text-zinc-500 mt-0.5">Apps that should never be bypassed, even if matched by auto-bypass</p>
        </div>
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
          on:click={addNeverBypass}
        >
          Add
        </button>
      </div>
      {#each neverBypass as entry, i}
        <div class="flex items-center gap-2">
          <input
            type="text"
            value={entry}
            on:input={e => updateNeverBypass(i, e.target.value)}
            placeholder="app.exe"
            class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 font-mono"
          />
          <button
            class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
            title="Select process"
            on:click={() => openProcessPicker('neverBypass', i)}
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
            </svg>
          </button>
          <button
            class="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
            on:click={() => removeNeverBypass(i)}
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

<!-- Process picker modal -->
<Modal open={showProcessPicker} title="Select Process" on:close={closeProcessPicker}>
  <div class="max-h-[50vh] overflow-y-auto">
    <ProcessPicker
      groupByFolder
      on:select={e => selectProcess(e.detail)}
      on:selectFolder={e => selectFolder(e.detail)}
    />
  </div>
  <svelte:fragment slot="footer">
    <button
      class="px-3 py-1.5 text-xs rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
      on:click={closeProcessPicker}
    >
      Close
    </button>
  </svelte:fragment>
</Modal>
