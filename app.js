/* p2p.akeyo.io — landing + /init/KEY deep-link SPA.
   Zero deps, no build step, no network calls. Plain script (not a module) so it works
   from file:// too. Pure helpers are exported for the node-based test at the bottom. */
(function (root) {
  'use strict'

  // ── key parsing (mirrors src/key.js canonicalize()) ────────────────────────
  // Crockford base32, 26 chars. I/L → 1, O → 0, case-insensitive. U is NOT a symbol.
  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

  /** Canonicalize a candidate key, or return null if it isn't a well-formed 26-char key. */
  function normalizeKey(s) {
    if (typeof s !== 'string') return null
    s = s.trim()
    if (s.length !== 26) return null
    var out = ''
    for (var i = 0; i < 26; i++) {
      var ch = s[i].toUpperCase()
      if (ch === 'I' || ch === 'L') ch = '1'
      else if (ch === 'O') ch = '0'
      if (ALPHABET.indexOf(ch) === -1) return null
      out += ch
    }
    return out
  }

  /** The install/connect command strings. key === null → plain install. */
  function commands(key) {
    if (key) {
      return {
        unix: 'curl -fsSL https://p2p.akeyo.io/init | sh -s -- ' + key,
        // PowerShell can't pass args through `| iex`; install first, then run the CLI.
        win: 'irm https://p2p.akeyo.io/init.ps1 | iex\np2p ' + key,
        already: 'p2p ' + key
      }
    }
    return {
      unix: 'curl -fsSL https://p2p.akeyo.io/init | sh',
      win: 'irm https://p2p.akeyo.io/init.ps1 | iex',
      already: 'p2p'
    }
  }

  /** Pull the intended path: `?p=/init/KEY` (from 404.html) or a real path. */
  function intendedPath(loc) {
    var m = /[?&]p=([^&]*)/.exec(loc.search || '')
    if (m) { try { return decodeURIComponent(m[1]) } catch (e) { return m[1] } }
    return loc.pathname || '/'
  }

  /** Route a path → { key, bad }. bad = "looked like a deep link but the key was invalid". */
  function route(path) {
    var m = /^\/?init\/([^/?#]+)\/?$/i.exec(path || '')
    if (!m) return { key: null, bad: false }
    var key = normalizeKey(decodeURIComponent(m[1]))
    return key ? { key: key, bad: false } : { key: null, bad: true }
  }

  function isWindows(nav) {
    var s = ((nav && (nav.userAgentData && nav.userAgentData.platform)) || (nav && nav.platform) || '') + ' ' +
      ((nav && nav.userAgent) || '')
    return /win/i.test(s) && !/darwin|mac/i.test(s)
  }

  var api = { normalizeKey: normalizeKey, commands: commands, route: route, intendedPath: intendedPath, isWindows: isWindows }

  // ── DOM (browser only) ─────────────────────────────────────────────────────
  if (typeof document === 'undefined') {
    if (typeof module !== 'undefined' && module.exports) module.exports = api
    root.p2pSite = api
    return
  }
  root.p2pSite = api

  var $ = function (id) { return document.getElementById(id) }

  function boot() {
    var path = intendedPath(window.location)
    var r = route(path)
    var cmds = commands(r.key)
    var win = isWindows(navigator)

    // clean the ?p= redirect out of the address bar, keeping the pretty URL
    if (/[?&]p=/.test(window.location.search) && window.history && window.history.replaceState) {
      try { window.history.replaceState(null, '', path) } catch (e) { /* file:// */ }
    }

    if (r.key) {
      $('invite').hidden = false
      $('pitch').hidden = true
      $('shortid').textContent = r.key.slice(0, 6)
      $('fullkey').textContent = r.key
      $('cmd-already').textContent = cmds.already
      $('alt-already').hidden = false
      document.title = 'p2p — ' + r.key.slice(0, 6) + ' shared their key with you'
    }
    if (r.bad) $('badkey').hidden = false

    $('cmd-unix').textContent = cmds.unix
    $('cmd-win').textContent = cmds.win
    setOS(win ? 'win' : 'unix')

    Array.prototype.forEach.call(document.querySelectorAll('[data-os]'), function (b) {
      b.addEventListener('click', function () { setOS(b.getAttribute('data-os')) })
    })
    Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (b) {
      b.addEventListener('click', function () { copy(b) })
    })
  }

  function setOS(os) {
    Array.prototype.forEach.call(document.querySelectorAll('[data-os]'), function (b) {
      var on = b.getAttribute('data-os') === os
      b.classList.toggle('on', on)
      b.setAttribute('aria-selected', on ? 'true' : 'false')
    })
    Array.prototype.forEach.call(document.querySelectorAll('[data-osblock]'), function (el) {
      el.hidden = el.getAttribute('data-osblock') !== os
    })
  }

  function copy(btn) {
    var target = $(btn.getAttribute('data-copy'))
    var text = target ? target.textContent : ''
    var done = function (ok) {
      btn.classList.add(ok ? 'copied' : 'failed')
      var was = btn.getAttribute('data-label') || btn.textContent
      btn.setAttribute('data-label', was)
      btn.textContent = ok ? 'copied!' : 'copy failed'
      setTimeout(function () {
        btn.classList.remove('copied', 'failed')
        btn.textContent = was
      }, 1600)
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true) }, function () { done(legacyCopy(text)) })
    } else {
      done(legacyCopy(text))
    }
  }

  function legacyCopy(text) {
    try {
      var ta = document.createElement('textarea')
      ta.value = text
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      var ok = document.execCommand('copy')
      document.body.removeChild(ta)
      return ok
    } catch (e) { return false }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot)
  else boot()
})(typeof globalThis !== 'undefined' ? globalThis : this)
