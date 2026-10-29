// Runs in <head> before anything else: picks up the tokens a sign-in link puts after "#" and removes them from the
// address bar at once, so they are never bookmarked, shared or sent anywhere.
(() => { const p = new URLSearchParams(location.hash.slice(1));
    if (p.has('access_token') || p.has('error_description')) {
        window.NPS_AUTH_CALLBACK = { access: p.get('access_token'), refresh: p.get('refresh_token'), error: p.get('error_description') };
        history.replaceState(null, '', location.pathname);
    }
})();
