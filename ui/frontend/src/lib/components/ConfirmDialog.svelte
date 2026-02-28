<script>
  import { createEventDispatcher } from 'svelte';
  import Modal from './Modal.svelte';
  import { t } from '../i18n';

  export let open = false;
  export let title = '';
  export let message = '';
  export let confirmText = '';
  export let cancelText = '';
  /** Red destructive styling for confirm button */
  export let destructive = false;
  export let loading = false;

  const dispatch = createEventDispatcher();

  $: confirmLabel = confirmText || $t('common.confirm');
  $: cancelLabel = cancelText || $t('common.cancel');
</script>

<Modal {open} {title} width="max-w-sm" on:close={() => dispatch('cancel')}>
  <p class="text-sm text-zinc-400">{message}</p>

  <svelte:fragment slot="footer">
    <button
      class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
      on:click={() => dispatch('cancel')}
      disabled={loading}
    >
      {cancelLabel}
    </button>
    <button
      class="px-4 py-2 text-sm rounded-lg text-white transition-colors disabled:opacity-40
             {destructive ? 'bg-red-600 hover:bg-red-500' : 'bg-blue-600 hover:bg-blue-500'}"
      on:click={() => dispatch('confirm')}
      disabled={loading}
    >
      {confirmLabel}
    </button>
  </svelte:fragment>
</Modal>
