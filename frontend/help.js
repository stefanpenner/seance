// Keyboard shortcuts help dialog — include on any page via <script src="./help.js"></script>
(function() {
  // Inject CSS
  var style = document.createElement('style');
  style.textContent = [
    '.help-dialog { border:none; background:transparent; padding:0; max-width:420px; width:90vw; }',
    '.help-dialog::backdrop { background:rgba(0,0,0,0.6); }',
    '.help-panel { background:#1a1b26; border:1px solid #29334d; border-radius:10px; overflow:hidden; font-family:system-ui,-apple-system,sans-serif; color:#a9b1d6; font-size:13px; }',
    '.help-header { display:flex; align-items:center; justify-content:space-between; padding:12px 16px; border-bottom:1px solid #29334d; }',
    '.help-title { font-weight:600; color:#c0caf5; font-size:14px; }',
    '.help-close { background:none; border:none; color:#565f89; font-size:18px; cursor:pointer; padding:0 4px; line-height:1; }',
    '.help-close:hover { color:#c0caf5; }',
    '.help-body { padding:8px 0; max-height:70vh; overflow-y:auto; }',
    '.help-section { padding:4px 16px 8px; }',
    '.help-section-title { font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:#565f89; padding:6px 0 4px; }',
    '.help-row { display:flex; align-items:center; justify-content:space-between; padding:4px 0; }',
    '.help-row kbd { background:#29334d; color:#7aa2f7; padding:2px 8px; border-radius:4px; font-family:inherit; font-size:12px; white-space:nowrap; }',
    '.help-row span { color:#a9b1d6; }'
  ].join('\n');
  document.head.appendChild(style);

  // Inject dialog HTML
  var dialog = document.createElement('dialog');
  dialog.id = 'helpDialog';
  dialog.className = 'help-dialog';
  dialog.innerHTML =
    '<div class="help-panel">' +
      '<div class="help-header">' +
        '<span class="help-title">Keyboard Shortcuts</span>' +
        '<button class="help-close" aria-label="Close">&times;</button>' +
      '</div>' +
      '<div class="help-body">' +
        '<div class="help-section">' +
          '<div class="help-section-title">General</div>' +
          '<div class="help-row"><kbd>Ctrl+Shift+?</kbd><span>Show this help</span></div>' +
          '<div class="help-row"><kbd>Ctrl+Shift+K</kbd><span>Session switcher</span></div>' +
          '<div class="help-row"><kbd>Ctrl+Shift+N</kbd><span>New session</span></div>' +
          '<div class="help-row"><kbd>Ctrl+Shift+W</kbd><span>Close focused pane</span></div>' +
        '</div>' +
        '<div class="help-section">' +
          '<div class="help-section-title">Splits</div>' +
          '<div class="help-row"><kbd>Cmd/Ctrl+D</kbd><span>Split right</span></div>' +
          '<div class="help-row"><kbd>Cmd/Ctrl+Shift+D</kbd><span>Split down</span></div>' +
        '</div>' +
        '<div class="help-section">' +
          '<div class="help-section-title">Session Switcher</div>' +
          '<div class="help-row"><kbd>j / k</kbd><span>Navigate up/down</span></div>' +
          '<div class="help-row"><kbd>Enter</kbd><span>Switch to session</span></div>' +
          '<div class="help-row"><kbd>n</kbd><span>New session</span></div>' +
          '<div class="help-row"><kbd>r</kbd><span>Rename session</span></div>' +
          '<div class="help-row"><kbd>x</kbd><span>Kill session</span></div>' +
          '<div class="help-row"><kbd>Esc</kbd><span>Close switcher</span></div>' +
        '</div>' +
        '<div class="help-section">' +
          '<div class="help-section-title">Terminal</div>' +
          '<div class="help-row"><kbd>Right-click</kbd><span>Context menu</span></div>' +
        '</div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(dialog);

  // Close button
  dialog.querySelector('.help-close').addEventListener('click', function() {
    dialog.close();
  });

  // Click backdrop to close
  dialog.addEventListener('click', function(e) {
    if (e.target === dialog) dialog.close();
  });

  // Cancel event (Esc inside dialog)
  dialog.addEventListener('cancel', function(e) {
    e.preventDefault();
    dialog.close();
  });

  // Ctrl+Shift+N for new session (works on all pages)
  function createNewSession() {
    fetch('/api/sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      .then(function(r) { return r.json(); })
      .then(function(s) { location.href = '/terminal?session=' + s.id; });
  }

  window.addEventListener('keydown', function(e) {
    // Ctrl+Shift+? to toggle help
    if (e.ctrlKey && e.shiftKey && (e.key === '?' || e.key === '/')) {
      e.preventDefault();
      e.stopImmediatePropagation();
      if (dialog.open) dialog.close(); else dialog.showModal();
      return;
    }
    // Ctrl+Shift+N for new session
    if (e.ctrlKey && e.shiftKey && e.key === 'N') {
      e.preventDefault();
      e.stopImmediatePropagation();
      createNewSession();
    }
  }, true);
})();
