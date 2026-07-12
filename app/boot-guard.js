// app/boot-guard.js — the app must never lie "booting…" forever.
//
// A CLASSIC script (not a module) loaded BEFORE the module entry point, for one reason: when an ES
// module graph fails to load, NOTHING in that graph runs. app.js's own try/catch (which would have
// said "failed to start") never gets a chance, so the page sits on the status text index.html shipped
// — "booting…" — with no error anywhere but the console. That is what a phone showed us: a totally
// dead app that still looks like it is working. (Real instance: GitHub Pages' Jekyll silently drops
// every `_`-prefixed file, so the vendored noble `_arx.js`/`_md.js`/… 404'd and the whole graph died.
// A `.nojekyll` at the repo root fixes THAT bug; this file makes the CLASS of bug speak up.)
//
// It cannot import anything (a bad import is exactly the failure we are catching), and it must not
// depend on app.js either — so the boot signal it watches is the one thing every successful boot
// changes: the status line stops saying "booting…".
//
// CSP: an EXTERNAL same-origin script, so `script-src 'self'` already allows it — no inline hash, and
// the import-map hash in index.html is untouched.
(function () {
  var BOOT_MS = 8000 // if the app has not moved off "booting…" by now, something is wrong — say what.
  var BOOTING = 'booting…' // must match the initial #statusText in index.html
  // A file deep in the module graph. If the deployment drops files, this is the kind of URL that 404s.
  var PROBE = '/src/browser/vendor/ciphers/_arx.js'
  var loadError = null // a <script>/module in the graph could not be FETCHED — a deployment bug, ours
  var lastError = null // something in the boot chain THREW — a code/runtime bug

  function statusEl() { return document.getElementById('statusText') }

  // Booted = the app took over the status line (app.js writes 'going online…' the moment it lives).
  function booted() {
    var el = statusEl()
    return !!window.__p2pBooted || !el || el.textContent !== BOOTING
  }

  function show(msg) {
    if (booted()) return // the app is alive and owns the status line — never speak over it
    statusEl().textContent = msg
    var dot = document.getElementById('dot')
    if (dot) dot.classList.remove('on')
  }

  // Import maps: iOS/iPadOS Safari 16.4+, Chrome 89+, Firefox 108+, Samsung 15+. Without them the
  // bare `node:crypto` specifier cannot resolve and the app can never start on this browser — there
  // is no zero-build fallback, so the honest thing is to say so plainly.
  function importMapsSupported() {
    return !!(window.HTMLScriptElement && HTMLScriptElement.supports && HTMLScriptElement.supports('importmap'))
  }

  // Any uncaught error/rejection in the boot chain — remembered, and surfaced instead of "booting…".
  // A module graph that fails to fetch reports on the ROOT <script> element (the browser will not name
  // the file deep in the graph that 404'd) — so this tells us THAT the load died, and the probe below
  // tells us WHY.
  window.addEventListener('error', function (e) {
    if (e && e.target && e.target.tagName === 'SCRIPT') loadError = e.target.src || 'a script'
    else if (e && e.message) lastError = e.message
  }, true) // capture: a script element's error event does not bubble
  window.addEventListener('unhandledrejection', function (e) {
    var r = e && e.reason
    lastError = (r && r.message) || String(r || 'unknown error')
  })

  // Everything we know, in order of how specific (and how actionable) it is.
  function diagnose(probeStatus) {
    if (probeStatus && probeStatus >= 400) {
      return 'The app is broken: a file it needs is missing from the server (HTTP ' + probeStatus + ' on '
        + PROBE + '). This is a bug on our side, not your browser.'
    }
    if (loadError) {
      return 'The app is broken: it could not load ' + loadError + ' (or something it imports). '
        + 'This is a bug on our side, not your browser.'
    }
    if (lastError) return 'The app failed to start: ' + lastError
    // Everything loaded, nothing threw, and it still has not come up. The remaining suspect is browser
    // storage — IndexedDB holds the identity, and private mode / blocked site-data can stall or refuse
    // it. Say the true thing, not a guess dressed as a fact.
    return 'Still starting — this browser may be blocking storage (private mode, or cookies/site-data blocked). Try a normal window, or use the CLI.'
  }

  setTimeout(function () {
    if (booted()) return

    // Import maps are the one hard requirement we cannot work around without a build step.
    if (!importMapsSupported()) {
      show('This browser is too old to run the app — it needs import maps (iOS/iPadOS 16.4+, Chrome 89+, Firefox 108+). Open this page in a newer browser, or use the CLI.')
      return
    }

    // The browser CAN run the app, so ask the network what actually broke. A 404 on a file the app
    // imports means the DEPLOYMENT dropped it — our bug, and the user deserves to be told it is ours.
    // The probe is a bonus, not a dependency: if it is blocked (CSP, offline, a proxy), diagnose()
    // still speaks from the error listeners above.
    fetch(PROBE, { cache: 'no-store' })
      .then(function (res) { show(diagnose(res.status)) })
      .catch(function () { show(diagnose(null)) })
  }, BOOT_MS)
})()
