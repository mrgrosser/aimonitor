(() => {
  'use strict';
  const modes = ['system', 'light', 'dark'];
  const media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  let preference = 'system';
  function readPreference() {
    try { const saved = localStorage.getItem('jo-theme'); return modes.includes(saved) ? saved : 'system'; }
    catch { return 'system'; }
  }
  function apply(value, persist = false) {
    preference = modes.includes(value) ? value : 'system';
    const resolved = preference === 'system' ? (media?.matches ? 'dark' : 'light') : preference;
    document.documentElement.dataset.theme = resolved;
    document.documentElement.dataset.themePreference = preference;
    document.documentElement.style.colorScheme = resolved;
    if (persist) { try { localStorage.setItem('jo-theme', preference); } catch {} }
    document.querySelectorAll('[data-theme-select]').forEach(select => { select.value = preference; });
  }
  apply(readPreference());
  const systemChanged = () => { if (preference === 'system') apply('system'); };
  if (media?.addEventListener) media.addEventListener('change', systemChanged);
  else if (media?.addListener) media.addListener(systemChanged);
  window.addEventListener('storage', event => { if (event.key === 'jo-theme' || event.key === null) apply(readPreference()); });
  window.JOTheme = {
    attach() {
      document.querySelectorAll('[data-theme-select]').forEach(select => {
        select.value = preference;
        select.onchange = () => apply(select.value, true);
      });
    }
  };
})();
