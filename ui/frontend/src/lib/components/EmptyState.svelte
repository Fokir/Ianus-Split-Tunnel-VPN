<script>
  /** Main message */
  export let title = '';
  /** Smaller hint text below the title */
  export let description = '';
</script>

<div class="flex flex-col items-center justify-center py-16 text-zinc-500">
  {#if $$slots.icon}
    <div class="mb-3 text-zinc-600">
      <slot name="icon" />
    </div>
  {/if}
  {#if title}
    <p class="text-sm">{title}</p>
  {/if}
  {#if description}
    <p class="text-xs text-zinc-600 mt-1">{description}</p>
  {/if}
  {#if $$slots.action}
    <div class="mt-3">
      <slot name="action" />
    </div>
  {/if}
</div>
