/**
 * Drag-and-drop reorder helpers for Svelte components.
 *
 * Usage:
 *   const dnd = createDndState();
 *   // In template: use dnd.handlers(index) on each draggable row
 *   // On drop: items = dnd.reorder(items)
 */

/**
 * Create reactive drag-and-drop state for a flat list.
 * @returns {{ dragIndex, dragOverIndex, handlers, reorder, reset }}
 */
export function createDndState() {
  let dragIndex = -1;
  let dragOverIndex = -1;

  function handleDragStart(e, index) {
    dragIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(index));
    const row = e.currentTarget.closest('tr') || e.currentTarget;
    row.style.opacity = '0.4';
  }

  function handleDragEnd(e) {
    const row = e.currentTarget.closest('tr') || e.currentTarget;
    row.style.opacity = '';
    dragIndex = -1;
    dragOverIndex = -1;
  }

  function handleDragOver(e, index) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    dragOverIndex = index;
  }

  function handleDragLeave() {
    dragOverIndex = -1;
  }

  /**
   * Reorder an array based on current drag state.
   * @template T
   * @param {T[]} items
   * @returns {{ items: T[], changed: boolean }}
   */
  function reorder(items) {
    if (dragIndex < 0 || dragIndex === dragOverIndex) {
      dragIndex = -1;
      dragOverIndex = -1;
      return { items, changed: false };
    }
    const reordered = [...items];
    const [moved] = reordered.splice(dragIndex, 1);
    reordered.splice(dragOverIndex, 0, moved);
    dragIndex = -1;
    dragOverIndex = -1;
    return { items: reordered, changed: true };
  }

  function reset() {
    dragIndex = -1;
    dragOverIndex = -1;
  }

  return {
    get dragIndex() { return dragIndex; },
    get dragOverIndex() { return dragOverIndex; },
    handleDragStart,
    handleDragEnd,
    handleDragOver,
    handleDragLeave,
    reorder,
    reset,
  };
}

/**
 * Helper: debounce a function.
 * @param {Function} fn
 * @param {number} ms
 * @returns {Function}
 */
export function debounce(fn, ms = 300) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
