<script>
  import { createEventDispatcher } from 'svelte';
  import { Modal } from '../../components';
  import { t } from '../../i18n';

  export let open = false;
  export let tunnelName = '';

  const dispatch = createEventDispatcher();

  let otpCode = '';
  let connecting = false;

  $: if (open) { otpCode = ''; connecting = false; }

  function handleKeydown(e) {
    if (e.key === 'Enter' && otpCode.trim()) {
      e.preventDefault();
      submit();
    } else if (e.key === 'Escape') {
      dispatch('cancel');
    }
  }

  function submit() {
    connecting = true;
    dispatch('connect', { otpCode: otpCode.trim() });
  }

  function skip() {
    connecting = true;
    dispatch('connect', { otpCode: '' });
  }
</script>

<Modal {open} title="{tunnelName} — {$t('connections.otpTitle')}" width="max-w-sm" on:close={() => dispatch('cancel')}>
  <div class="space-y-3">
    <p class="text-sm text-zinc-400">{$t('connections.otpDescription')}</p>
    <div>
      <label for="otp-input" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.otpLabel')}</label>
      <!-- svelte-ignore a11y-autofocus -->
      <input
        id="otp-input"
        type="text"
        bind:value={otpCode}
        on:keydown={handleKeydown}
        placeholder="123456"
        autofocus
        autocomplete="one-time-code"
        inputmode="numeric"
        maxlength="8"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200
               focus:border-blue-500 focus:outline-none text-center text-lg tracking-widest font-mono"
      />
    </div>
  </div>

  <svelte:fragment slot="footer">
    <button
      class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
      on:click={() => dispatch('cancel')}
      disabled={connecting}
    >
      {$t('connections.cancel')}
    </button>
    <button
      class="px-4 py-2 text-sm rounded-lg bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700 transition-colors"
      on:click={skip}
      disabled={connecting}
    >
      {$t('connections.otpSkip')}
    </button>
    <button
      class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
      disabled={connecting || !otpCode.trim()}
      on:click={submit}
    >
      {connecting ? $t('connections.connecting') : $t('connections.connect')}
    </button>
  </svelte:fragment>
</Modal>
