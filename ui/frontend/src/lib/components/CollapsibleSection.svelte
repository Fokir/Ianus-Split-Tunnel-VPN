<script>
  /** Section heading text */
  export let title = '';
  /** Whether the section is expanded */
  export let open = false;

  function toggle() {
    open = !open;
  }
</script>

<section class="space-y-3">
  <button
    class="flex items-center gap-2 text-sm font-medium text-zinc-400 uppercase tracking-wider hover:text-zinc-300 transition-colors"
    on:click={toggle}
  >
    <svg class="w-3.5 h-3.5 transition-transform {open ? 'rotate-90' : ''}" viewBox="0 0 24 24" fill="currentColor">
      <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/>
    </svg>
    {title}
    {#if $$slots['header-extra']}
      <slot name="header-extra" />
    {/if}
  </button>
  {#if open}
    <slot />
  {/if}
</section>
