<?php
// Shared topbar — used by index.php, profile.php, settings.php. Renders
// brand mark, language selector, and either the avatar+menu (signed-in)
// or login/register pills (signed-out).
//
// Inputs expected in scope (set by including page):
//   $state    : sippis_session_state() result
//   $user     : $state['user']
//   $h        : html-escape closure
//   $lang_code: active language code

if (!isset($state) || !isset($h)) {
    return; // not includable directly — included from a controller
}

$user_name  = $h($user['fullName']     ?? '');
$user_email = $h($user['email']        ?? '');
$first_name = $h(explode(' ', $user['fullName'] ?? 'there')[0]);
$pic_url    = $user['profilePictureUrl'] ?? null;  // may be null today; v1 will populate when uploaded

// Monogram fallback. First grapheme of fullName, uppercased.
$mono = '?';
if (!empty($user['fullName'])) {
    $first_char = mb_substr(trim($user['fullName']), 0, 1, 'UTF-8');
    if ($first_char !== '') $mono = mb_strtoupper($first_char, 'UTF-8');
}
?>
<header class="topbar">
  <?php
    $tb_b    = sippis_branding();
    $tb_acc  = rtrim(sippis_config()['account_url'], '/');
    $tb_name = $tb_b['appName'] ?? '';
    $tb_logo = !empty($tb_b['logoUrl']) ? $tb_acc . $tb_b['logoUrl'] : '';
  ?>
  <a class="brand r2r-brand" href="/" aria-label="R2Я home">
    <?php include __DIR__ . '/../lib/_mesh.php'; ?>
  </a>

  <?php
    // Site-wide navigation. Highlights the active page based on the request path.
    // "Downloads" and "Houses" open in a new tab (external assets/portal domains).
    $cur = strtolower(strtok($_SERVER['REQUEST_URI'] ?? '/', '?'));
    $nav_items = [
      ['label' => 'Home',       'href' => '/',                'match' => ['/', '/index.php']],
      ['label' => 'Redeem',     'href' => '/redeem.php',      'match' => ['/redeem.php']],
      ['label' => 'Downloads',  'href' => '/downloads.php',   'match' => ['/downloads.php']],
      ['label' => 'Your Relay', 'href' => '/run-a-relay.php', 'match' => ['/run-a-relay.php']],
      ['label' => 'Network',    'href' => '/network.php',     'match' => ['/network.php']],
      ['label' => 'Privacy',    'href' => '/privacy.php',     'match' => ['/privacy.php']],
      ['label' => 'Homes',      'href' => '/homes.php',       'match' => ['/homes.php']],
      ['label' => 'FAQ',        'href' => '/faq.php',         'match' => ['/faq.php']],
    ];
  ?>
  <nav class="site-nav" aria-label="Site sections">
    <?php foreach ($nav_items as $it):
      $active = in_array($cur, $it['match'] ?? [], true);
      $ext    = !empty($it['ext']);
    ?>
      <a href="<?= $h($it['href']) ?>"
         class="site-nav-item<?= $active ? ' active' : '' ?>"
         <?= $ext ? 'target="_blank" rel="noopener"' : '' ?>><?= $h($it['label']) ?></a>
    <?php endforeach; ?>
  </nav>

  <nav class="topbar-actions">
    <form class="lang-form" method="get" action="">
      <label class="visually-hidden" for="sippis-lang"><?= $h(t('topbar.lang_label')) ?></label>
      <select id="sippis-lang" name="lang" class="lang-select" onchange="this.form.submit()">
        <?php foreach (sippis_supported_languages() as $L): ?>
          <option value="<?= $h($L['code']) ?>"<?= strcasecmp($L['code'], $lang_code) === 0 ? ' selected' : '' ?>><?= $h($L['native']) ?></option>
        <?php endforeach; ?>
      </select>
      <noscript><button type="submit" class="lang-apply">&#x2713;</button></noscript>
    </form>

    <?php if ($state['signed_in']): ?>
      <div class="user-menu">
        <button type="button" class="user-avatar" id="sippis-user-trigger"
                aria-haspopup="menu" aria-expanded="false"
                aria-label="<?= $h(t('topbar.howdy', ['NAME' => $first_name])) ?>">
          <?php if ($pic_url): ?>
            <img class="user-avatar-img" src="<?= $h($pic_url) ?>" alt="">
          <?php else: ?>
            <span class="user-avatar-monogram"><?= $h($mono) ?></span>
          <?php endif; ?>
        </button>
        <div class="user-menu-dropdown" role="menu" hidden id="sippis-user-menu">
          <div class="user-menu-header">
            <div class="user-menu-name"><?= $user_name ?></div>
            <?php if ($user_email): ?>
              <div class="user-menu-email"><?= $user_email ?></div>
            <?php endif; ?>
          </div>
          <hr>
          <a class="user-menu-item" role="menuitem" href="/auth/profile.php">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
              <circle cx="12" cy="7" r="4"></circle>
            </svg>
            <span><?= $h(t('topbar.profile')) ?></span>
          </a>
          <a class="user-menu-item" role="menuitem" href="/auth/settings.php">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
            <span><?= $h(t('topbar.settings')) ?></span>
          </a>
          <?php if (sippis_is_app_owner($state)): ?>
          <a class="user-menu-item" role="menuitem" href="/admin.php">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 2 L4 6 v6 c0 5 4 9 8 10 4-1 8-5 8-10 V6 z"></path>
              <path d="M9 12 l2 2 4-4"></path>
            </svg>
            <span>Open admin console</span>
          </a>
          <?php endif; ?>
          <hr>
          <a class="user-menu-item" role="menuitem" href="/auth/logout.php">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
              <polyline points="16 17 21 12 16 7"></polyline>
              <line x1="21" y1="12" x2="9" y2="12"></line>
            </svg>
            <span><?= $h(t('topbar.signout')) ?></span>
          </a>
        </div>
      </div>
    <?php else: ?>
      <?php $intent_active = (($_GET['intent'] ?? '') === 'login') ? 'login' : 'register'; ?>
      <div class="topbar-intent-pills">
        <a class="intent-pill<?= $intent_active === 'register' ? ' active' : '' ?>" href="/auth/login.php?intent=register"><?= $h(t('topbar.register')) ?></a>
        <a class="intent-pill<?= $intent_active === 'login' ? ' active' : '' ?>" href="/auth/login.php?intent=login"><?= $h(t('topbar.login')) ?></a>
      </div>
    <?php endif; ?>
  </nav>
</header>

<?php if ($state['signed_in']): ?>
<script>
(function() {
  var t = document.getElementById('sippis-user-trigger');
  var d = document.getElementById('sippis-user-menu');
  if (!t || !d) return;
  function close() { d.hidden = true; t.setAttribute('aria-expanded', 'false'); }
  function open()  { d.hidden = false; t.setAttribute('aria-expanded', 'true'); }
  t.addEventListener('click', function(e) {
    e.stopPropagation();
    if (d.hidden) open(); else close();
  });
  document.addEventListener('click', function(e) {
    if (!d.hidden && !d.contains(e.target) && e.target !== t) close();
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') close();
  });
})();
</script>
<?php endif; ?>
