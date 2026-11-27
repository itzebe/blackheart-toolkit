"""Probe pages for the Chrome VRP engagement.

Each probe is a self-contained HTML document that exercises one security
invariant in a real Chromium build and writes its observation as JSON into
``<pre id="result">``. The harness loads the page headlessly and reads that JSON;
it never scrapes prose out of the DOM.

A probe reports ``violations`` -- a non-empty list means the invariant did *not*
hold, which is the only thing worth escalating. The pages are deliberately
small: one invariant each, so a violation is unambiguous and reproducible.

These probes run against local loopback origins we control. They test the
browser's *enforcement* of its own boundaries; they never touch a third-party
system.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# H1 -- Same-Origin Policy read boundary
# --------------------------------------------------------------------------- #

SOP_READ = """<!doctype html><meta charset="utf-8">
<pre id="result">{"_state":"running"}</pre>
<script>
const R = { probe: "sop-read", violations: [], details: {} };
const out = document.getElementById('result');
function done() { out.textContent = JSON.stringify(R); }
const params = new URLSearchParams(location.search);
const cross = params.get('cross');
R.details.top_origin = location.origin;
R.details.cross = cross;
function inspect(win) {
  // 1. contentDocument must be null for a cross-origin frame.
  let cd = null;
  try { cd = win.contentDocument; } catch (e) { R.details.contentDocument_threw = e.name; }
  if (cd !== null && cd !== undefined) {
    R.violations.push('contentDocument readable across origins: ' + (cd.URL || ''));
  }
  R.details.contentDocument = cd === null ? 'null' : String(cd);
  // 2. Cross-origin Location access must throw a SecurityError.
  try {
    const href = win.contentWindow.location.href;
    R.violations.push('location.href readable across origins: ' + href);
  } catch (e) {
    R.details.location_threw = e.name;
    if (e.name !== 'SecurityError') R.details.location_unexpected_error = e.name;
  }
  // 3. A cross-origin window must not expose its document via the WindowProxy.
  try {
    const d = win.contentWindow.document;
    R.violations.push('window.document readable across origins: ' + (d && d.URL));
  } catch (e) { R.details.window_document_threw = e.name; }
}
if (!cross) { R.details.error = 'no cross origin supplied'; done(); }
else {
  const f = document.createElement('iframe');
  f.src = cross;
  f.onload = () => { try { inspect(f); } catch (e) { R.details.inspect_error = String(e); } done(); };
  document.body.appendChild(f);
  setTimeout(done, 3000);
}
</script>
"""

# --------------------------------------------------------------------------- #
# H2 -- Cross-origin isolation gates powerful APIs (COOP + COEP)
# --------------------------------------------------------------------------- #

#: Served WITH ``Cross-Origin-Opener-Policy: same-origin`` and
#: ``Cross-Origin-Embedder-Policy: require-corp`` (see ISOLATED_HEADERS).
ISOLATED_POSITIVE = """<!doctype html><meta charset="utf-8">
<pre id="result">{"_state":"running"}</pre>
<script>
const R = { probe: "cross-origin-isolated", violations: [], details: {} };
R.details.crossOriginIsolated = window.crossOriginIsolated;
R.details.shared_array_buffer = (typeof SharedArrayBuffer === 'function');
R.details.origin = location.origin;
// With COOP+COEP the document must be isolated and SAB must be available.
if (window.crossOriginIsolated !== true)
  R.violations.push('crossOriginIsolated false despite COOP+COEP headers');
if (typeof SharedArrayBuffer !== 'function')
  R.violations.push('SharedArrayBuffer unavailable in an isolated document');
document.getElementById('result').textContent = JSON.stringify(R);
</script>
"""

#: Served WITHOUT the isolation headers: SAB must NOT be available.
ISOLATED_NEGATIVE = """<!doctype html><meta charset="utf-8">
<pre id="result">{"_state":"running"}</pre>
<script>
const R = { probe: "not-cross-origin-isolated", violations: [], details: {} };
R.details.crossOriginIsolated = window.crossOriginIsolated;
R.details.shared_array_buffer = (typeof SharedArrayBuffer === 'function');
R.details.origin = location.origin;
// Without COOP+COEP the document must not be isolated, and a plain page must
// not be able to allocate a SharedArrayBuffer (it would be a spectre-enabling
// capability leak).
if (window.crossOriginIsolated !== false)
  R.violations.push('crossOriginIsolated true without COOP+COEP headers');
if (typeof SharedArrayBuffer === 'function')
  R.violations.push('SharedArrayBuffer available without cross-origin isolation');
document.getElementById('result').textContent = JSON.stringify(R);
</script>
"""

ISOLATED_HEADERS = (
    "Cross-Origin-Opener-Policy: same-origin\n"
    "Cross-Origin-Embedder-Policy: require-corp\n"
)

# --------------------------------------------------------------------------- #
# H3 -- postMessage origin integrity
# --------------------------------------------------------------------------- #

#: The top document; embeds a cross-origin child that posts back.
POSTMESSAGE_TOP = """<!doctype html><meta charset="utf-8">
<pre id="result">{"_state":"running"}</pre>
<script>
const R = { probe: "postmessage-origin", violations: [], details: {} };
const out = document.getElementById('result');
function done() { out.textContent = JSON.stringify(R); }
const params = new URLSearchParams(location.search);
const childOrigin = params.get('child_origin');
R.details.child_origin = childOrigin;
const seen = [];
window.addEventListener('message', (ev) => {
  seen.push({ origin: ev.origin, data: String(ev.data).slice(0, 64) });
  // The reported origin must be the sender's real origin, never spoofable.
  if (ev.origin !== childOrigin)
    R.violations.push('postMessage origin mismatch: got ' + ev.origin +
                      ' expected ' + childOrigin);
  R.details.messages = seen;
  done();
});
const f = document.createElement('iframe');
f.src = params.get('child');
document.body.appendChild(f);
setTimeout(done, 3000);
</script>
"""

#: The cross-origin child; posts a message to its parent.
POSTMESSAGE_CHILD = """<!doctype html><meta charset="utf-8">
<h1>child</h1>
<script>
try { parent.postMessage('hello-from-child', '*'); } catch (e) {}
</script>
"""

__all__ = [
    "ISOLATED_HEADERS",
    "ISOLATED_NEGATIVE",
    "ISOLATED_POSITIVE",
    "POSTMESSAGE_CHILD",
    "POSTMESSAGE_TOP",
    "SOP_READ",
]
