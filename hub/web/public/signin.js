// Sign-in page: lists the forges this deployment was configured with.
'use strict';

const LABELS = { github: 'Continue with GitHub', gitlab: 'Continue with GitLab' };

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const failure = params.get('error');
  if (failure) {
    const box = document.getElementById('error');
    box.textContent = failure;
    box.classList.remove('hidden');
  }

  const holder = document.getElementById('providers');
  try {
    const response = await fetch('/api/me', { credentials: 'same-origin' });
    const me = await response.json();
    if (me.authenticated) {
      window.location.replace('/app.html');
      return;
    }
    holder.textContent = '';
    const forges = (me.forges || []).slice().sort();
    if (forges.length === 0) {
      holder.textContent = 'No forge is configured on this deployment.';
      return;
    }
    for (const kind of forges) {
      const link = document.createElement('a');
      link.href = '/auth/' + encodeURIComponent(kind) + '/start';
      link.textContent = LABELS[kind] || 'Continue with ' + kind;
      link.rel = 'nofollow';
      holder.appendChild(link);
    }
  } catch (err) {
    holder.textContent = 'The service is unreachable. Try again in a moment.';
  }
});
