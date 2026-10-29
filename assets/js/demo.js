// Quick self-check: ping the admin API to see if env vars are configured
(async () => {
  try {
    const res = await fetch('/api/admin', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ action: 'send-code', addr: 'probe@demo.internal' })
    });
    const data = await res.json().catch(() => ({}));
    const banner = document.getElementById('env-status');
    if (res.status === 500 && data.error && data.error.includes('not set')) {
      // env vars missing - keep warning
      document.getElementById('blockers-label').textContent = 'env vars needed';
      document.getElementById('blockers-bar').style.width = '100%';
    } else if (res.status === 400 || res.status === 429 || res.status === 500) {
      // API is responding - env vars likely set
      banner.className = 'alert alert-ok';
      banner.innerHTML = '<span class="alert-icon">✅</span><div><div class="alert-title">API is responding — environment variables appear to be set</div><div class="alert-body">The server replied to a test request. You can now walk through the features below.</div></div>';
      document.getElementById('blockers-label').textContent = 'none detected';
      document.getElementById('blockers-bar').style.width = '0%';
    }
  } catch(e) {
    // network error or first load - neutral
  }
})();
