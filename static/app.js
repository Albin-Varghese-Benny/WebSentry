// Keep countdowns accurate between page refreshes; server-side expiry is enforced by the proxy.
document.querySelectorAll('[data-seconds]').forEach((node) => {
  let remaining = Number(node.dataset.seconds || 0);
  const render = () => {
    if (remaining <= 0) { node.textContent = 'Expiring…'; return; }
    const m = Math.floor(remaining / 60), s = remaining % 60;
    node.textContent = `${m}m ${s}s left`;
    remaining -= 1;
  };
  render();
  window.setInterval(render, 1000);
});

// Account menu: opens on hover (CSS) and on click/tap/keyboard (this), closes on outside click or Escape.
(() => {
  const menu = document.getElementById('user-menu');
  if (!menu) return;
  const trigger = menu.querySelector('.user-trigger');
  const setOpen = (open) => { menu.classList.toggle('open', open); trigger.setAttribute('aria-expanded', String(open)); };
  trigger.addEventListener('click', (e) => { e.stopPropagation(); setOpen(!menu.classList.contains('open')); });
  document.addEventListener('click', (e) => { if (!menu.contains(e.target)) setOpen(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { setOpen(false); trigger.blur(); } });
})();
