<script>
  import { Window } from '@wailsio/runtime';

  let hovered = false;

  function minimize() {
    Window.Minimise();
  }

  function toggleMaximize() {
    Window.ToggleMaximise();
  }

  function close() {
    Window.Close();
  }
</script>

<!-- svelte-ignore a11y-no-static-element-interactions -->
<header
  class="titlebar"
  style="--wails-draggable: drag"
  on:dblclick={toggleMaximize}
>
  <span class="title">AWG Split Tunnel</span>

  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div
    class="controls"
    style="--wails-draggable: no-drag"
    on:mouseenter={() => hovered = true}
    on:mouseleave={() => hovered = false}
  >
    <button class="btn minimize" on:click={minimize} title="Свернуть">
      {#if hovered}
        <svg viewBox="0 0 12 12" fill="none">
          <rect x="2" y="5.25" width="8" height="1.5" rx="0.5" fill="rgba(0,0,0,0.55)"/>
        </svg>
      {/if}
    </button>
    <button class="btn maximize" on:click={toggleMaximize} title="Развернуть">
      {#if hovered}
        <svg viewBox="0 0 12 12" fill="none">
          <path d="M3.5 7.5L3.5 4.5L6.5 4.5" stroke="rgba(0,0,0,0.55)" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M8.5 4.5L8.5 7.5L5.5 7.5" stroke="rgba(0,0,0,0.55)" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      {/if}
    </button>
    <button class="btn close" on:click={close} title="Закрыть">
      {#if hovered}
        <svg viewBox="0 0 12 12" fill="none">
          <path d="M3.5 3.5L8.5 8.5M8.5 3.5L3.5 8.5" stroke="rgba(0,0,0,0.55)" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
      {/if}
    </button>
  </div>
</header>

<style>
  .titlebar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 38px;
    padding: 0 16px;
    background: rgb(24 24 27);
    flex-shrink: 0;
  }

  .title {
    font-size: 12px;
    color: rgb(113 113 122); /* zinc-500 */
    font-weight: 500;
    letter-spacing: 0.02em;
    pointer-events: none;
  }

  .controls {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .btn {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    border: none;
    padding: 0;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: filter 0.15s;
  }

  .btn svg {
    width: 10px;
    height: 10px;
  }

  .btn:active {
    filter: brightness(0.85);
  }

  .minimize {
    background: #FEBC2E;
  }
  .minimize:hover {
    background: #F0A500;
  }

  .maximize {
    background: #28C840;
  }
  .maximize:hover {
    background: #1DAD2B;
  }

  .close {
    background: #FF5F57;
  }
  .close:hover {
    background: #E0443E;
  }
</style>
