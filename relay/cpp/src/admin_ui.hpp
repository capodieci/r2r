// R2R relay -- the embedded /admin console page.
//
// A self-contained JS-over-WSS client for the admin_* frames: the operator
// unlocks it with their identity seed, the page signs the same hello proof a
// wallet sends, and every action is owner-gated server-side exactly like the
// wallet's owner panel. The key never leaves the browser. Served only in
// builds with R2R_WITH_ADMIN_UI.
#pragma once

namespace r2r::admin_ui {

// The console page; contains {{BASE}} sentinels to substitute at serve time.
const char* html();
// tweetnacl (from the wallet project), served at /admin/nacl.js.
const char* nacl_js();

}  // namespace r2r::admin_ui
