// Injects the Rakshak guardian SVG into every sidebar's foot area.
(async () => {
  const slot = document.querySelector('.sidebar .foot');
  if (!slot || document.querySelector('.guardian-slot')) return;
  try {
    const html = await fetch('/guardian.html').then(r => r.text());
    const wrap = document.createElement('div');
    wrap.innerHTML = html;
    const node = wrap.querySelector('.guardian-slot');
    if (node) slot.parentNode.insertBefore(node, slot);
  } catch (e) { /* non-fatal */ }
})();
