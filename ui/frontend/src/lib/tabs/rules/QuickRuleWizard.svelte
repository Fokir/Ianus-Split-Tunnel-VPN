<script>
  import { createEventDispatcher } from 'svelte';
  import ProcessPicker from '../../ProcessPicker.svelte';
  import { Modal } from '../../components';
  import { t } from '../../i18n';

  export let open = false;
  export let tunnels = [];

  const dispatch = createEventDispatcher();

  let wizardStep = 1;
  let selectedProcess = null;
  let selectedTunnels = [];

  $: availableTunnels = tunnels.filter(t => !selectedTunnels.some(s => s.id === t.id));

  $: if (open) {
    wizardStep = 1;
    selectedProcess = null;
    selectedTunnels = [];
  }

  function close() { dispatch('close'); }

  function selectProcess(proc) {
    selectedProcess = proc;
    wizardStep = 2;
  }

  function selectFolder(detail) {
    selectedProcess = { name: detail.pattern, path: detail.folder, icon: null };
    wizardStep = 2;
  }

  function addTunnel(tunnel) {
    selectedTunnels = [...selectedTunnels, tunnel];
  }

  function removeTunnel(index) {
    selectedTunnels = selectedTunnels.filter((_, i) => i !== index);
  }

  function moveTunnel(index, dir) {
    const newIdx = index + dir;
    if (newIdx < 0 || newIdx >= selectedTunnels.length) return;
    const arr = [...selectedTunnels];
    [arr[index], arr[newIdx]] = [arr[newIdx], arr[index]];
    selectedTunnels = arr;
  }

  function confirm() {
    const pattern = selectedProcess.name;
    const newRules = [];
    for (let i = 0; i < selectedTunnels.length; i++) {
      const isLast = i === selectedTunnels.length - 1;
      newRules.push({
        pattern,
        tunnelId: selectedTunnels[i].id,
        fallback: isLast ? 'allow_direct' : 'failover',
        priority: 'auto',
      });
    }
    dispatch('confirm', { rules: newRules, pattern });
  }
</script>

<Modal {open} title={$t('rules.quickRuleTitle')} width="max-w-lg" on:close={close}>
  <!-- Stepper -->
  <div class="flex items-center justify-center gap-1.5 mb-4">
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
  <div class="max-h-[50vh] overflow-y-auto">
    <!-- Step 1: Select Process -->
    {#if wizardStep === 1}
      <ProcessPicker groupByFolder on:select={e => selectProcess(e.detail)} on:selectFolder={e => selectFolder(e.detail)} />

    <!-- Step 2: Select Tunnels -->
    {:else if wizardStep === 2}
      <div class="space-y-4">
        <p class="text-xs text-zinc-400">{$t('rules.selectTunnelsHint')}</p>

        <!-- Selected tunnels (ordered) -->
        {#if selectedTunnels.length > 0}
          <div>
            <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.selectedTunnels')}</div>
            <div class="space-y-1">
              {#each selectedTunnels as tun, i}
                <div class="flex items-center gap-2 px-3 py-2 bg-zinc-700/30 rounded-lg border border-zinc-700/50">
                  <span class="text-xs font-mono text-zinc-500 w-5 shrink-0">{i + 1}.</span>
                  <span class="text-sm text-zinc-200 flex-1 truncate">{tun.name || tun.id}</span>
                  <span class="text-[10px] text-zinc-500">{tun.protocol}</span>
                  <button
                    class="p-1 text-zinc-500 hover:text-zinc-300 transition-colors disabled:opacity-30"
                    disabled={i === 0}
                    on:click={() => moveTunnel(i, -1)}
                  >
                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M7.41 15.41L12 10.83l4.59 4.58L18 14l-6-6-6 6z"/></svg>
                  </button>
                  <button
                    class="p-1 text-zinc-500 hover:text-zinc-300 transition-colors disabled:opacity-30"
                    disabled={i === selectedTunnels.length - 1}
                    on:click={() => moveTunnel(i, 1)}
                  >
                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6z"/></svg>
                  </button>
                  <button
                    class="p-1 text-zinc-500 hover:text-red-400 transition-colors"
                    on:click={() => removeTunnel(i)}
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
          {#if availableTunnels.length === 0 && selectedTunnels.length === 0}
            <div class="text-xs text-zinc-500 py-4 text-center">{$t('rules.noTunnelsAvailable')}</div>
          {:else if availableTunnels.length === 0}
            <div class="text-xs text-zinc-600 py-2 text-center">-</div>
          {:else}
            <div class="space-y-0.5">
              {#each availableTunnels as tun}
                <button
                  class="w-full flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-zinc-700/50 transition-colors text-left"
                  on:click={() => addTunnel(tun)}
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

    <!-- Step 3: Confirm -->
    {:else if wizardStep === 3}
      <div class="space-y-4">
        <div>
          <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.processLabel')}</div>
          <div class="flex items-center gap-3 px-3 py-2.5 bg-zinc-700/30 rounded-lg border border-zinc-700/50">
            <div class="w-8 h-8 shrink-0 flex items-center justify-center rounded bg-zinc-700/50">
              {#if selectedProcess?.icon}
                <img src={selectedProcess.icon} alt="" class="w-7 h-7" />
              {:else}
                <svg class="w-5 h-5 text-zinc-500" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                </svg>
              {/if}
            </div>
            <div class="min-w-0 flex-1">
              <div class="text-sm font-medium text-zinc-100">{selectedProcess?.name}</div>
              {#if selectedProcess?.path}
                <div class="text-[10px] text-zinc-500 truncate">{selectedProcess.path}</div>
              {/if}
            </div>
          </div>
        </div>

        <div>
          <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">{$t('rules.rulesPreview')}</div>
          <div class="border border-zinc-700/50 rounded-lg overflow-hidden">
            {#each selectedTunnels as tun, i}
              {@const isLast = i === selectedTunnels.length - 1}
              <div class="flex items-center gap-3 px-3 py-2 {i > 0 ? 'border-t border-zinc-700/30' : ''} {isLast ? 'bg-zinc-800/40' : ''}">
                <span class="text-xs font-mono text-zinc-500 w-5 shrink-0">{i + 1}.</span>
                <div class="flex-1 min-w-0">
                  <span class="text-sm text-zinc-200">{selectedProcess?.name}</span>
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

  <svelte:fragment slot="footer">
    <div class="flex justify-between w-full">
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
          on:click={close}
        >
          {$t('rules.cancel')}
        </button>
        {#if wizardStep === 2}
          <button
            class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
            disabled={selectedTunnels.length === 0}
            on:click={() => { wizardStep = 3; }}
          >
            {$t('rules.next')}
          </button>
        {:else if wizardStep === 3}
          <button
            class="px-4 py-2 text-sm rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors"
            on:click={confirm}
          >
            {$t('rules.create')}
          </button>
        {/if}
      </div>
    </div>
  </svelte:fragment>
</Modal>
