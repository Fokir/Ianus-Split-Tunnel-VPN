<script>
  import { createEventDispatcher } from 'svelte';

  /** Whether the modal is visible */
  export let open = false;
  /** Optional title shown in the header */
  export let title = '';
  /** Width class for the card */
  export let width = 'max-w-md';
  /** Whether to show close (X) button and react to Escape */
  export let closeable = true;

  const dispatch = createEventDispatcher();

  function handleBackdropClick() {
    if (closeable) dispatch('close');
  }

  function handleKeydown(e) {
    if (e.key === 'Escape' && closeable) dispatch('close');
  }
</script>

{#if open}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div
    class="fixed inset-0 bg-black/60 z-50 flex items-center justify-center"
    on:click|self={handleBackdropClick}
    on:keydown={handleKeydown}
    role="dialog"
    tabindex="-1"
  >
    <div class="bg-zinc-800 border border-zinc-700 rounded-xl shadow-2xl w-full {width} mx-4 max-h-[85vh] overflow-y-auto">
      {#if title || closeable}
        <div class="flex items-center justify-between px-5 py-4 border-b border-zinc-700">
          {#if title}
            <h3 class="text-base font-semibold text-zinc-100">{title}</h3>
          {:else}
            <div></div>
          {/if}
          {#if closeable}
            <button class="text-zinc-400 hover:text-zinc-200 transition-colors" on:click={() => dispatch('close')}>
              <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
              </svg>
            </button>
          {/if}
        </div>
      {/if}

      <div class="px-5 py-4">
        <slot />
      </div>

      {#if $$slots.footer}
        <div class="flex justify-end gap-2 px-5 py-4 border-t border-zinc-700">
          <slot name="footer" />
        </div>
      {/if}
    </div>
  </div>
{/if}
