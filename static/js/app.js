/* Sèmè Kids — comportements communs (sans dépendance). */
(function () {
  'use strict';
  document.documentElement.classList.add('js');

  // Application installable + lecture hors ligne
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(function () {}); });
  }

  // Apparition douce au défilement
  var rev = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { threshold: 0.12 });
    rev.forEach(function (el, i) { el.style.setProperty('--d', (i % 4) * 80 + 'ms'); io.observe(el); });
  } else {
    rev.forEach(function (el) { el.classList.add('in'); });
  }

  // Compte à rebours
  document.querySelectorAll('[data-countdown]').forEach(function (box) {
    var target = new Date(box.getAttribute('data-countdown')).getTime();
    var parts = {}; box.querySelectorAll('[data-cd]').forEach(function (b) { parts[b.getAttribute('data-cd')] = b; });
    function upd() {
      var diff = target - Date.now();
      if (isNaN(target)) return;
      if (diff <= 0) {
        var g = box.querySelector('.cd-grid'); if (g) g.hidden = true;
        var l = box.querySelector('.cd-live'); if (l) l.hidden = false;
        return;
      }
      var s = Math.floor(diff / 1000);
      var v = { d: Math.floor(s / 86400), h: Math.floor(s % 86400 / 3600), m: Math.floor(s % 3600 / 60), s: s % 60 };
      Object.keys(parts).forEach(function (k) { parts[k].textContent = String(v[k]).padStart(2, '0'); });
      setTimeout(upd, 1000);
    }
    upd();
  });

  // Copier dans le presse-papiers
  document.querySelectorAll('[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var input = document.querySelector(b.getAttribute('data-copy'));
      if (!input) return;
      input.select();
      var done = function () { var t = b.innerHTML; b.textContent = 'Copié ✓'; setTimeout(function () { b.innerHTML = t; }, 1800); };
      if (navigator.clipboard) navigator.clipboard.writeText(input.value).then(done, function () { document.execCommand('copy'); done(); });
      else { document.execCommand('copy'); done(); }
    });
  });

  // Lecture vocale (pour les personnes qui ne lisent pas)
  document.querySelectorAll('[data-speak]').forEach(function (b) {
    if (!window.speechSynthesis) { b.hidden = true; return; }
    b.addEventListener('click', function () {
      if (speechSynthesis.speaking) { speechSynthesis.cancel(); return; }
      var u = new SpeechSynthesisUtterance(b.getAttribute('data-speak'));
      u.lang = 'fr-FR'; u.rate = 0.95;
      speechSynthesis.speak(u);
    });
  });

  // Confirmation avant les actions sensibles
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) { if (!confirm(f.getAttribute('data-confirm'))) e.preventDefault(); });
  });

  // Dernière confirmation avant l'effacement total
  var rb = document.querySelector('[data-confirm-reset]');
  if (rb) rb.form.addEventListener('submit', function (e) {
    if (!confirm('DERNIÈRE CONFIRMATION\n\nTout effacer définitivement ? Cette action est irréversible.')) e.preventDefault();
  });

  // Installer l'application sur le téléphone (plus besoin de chercher le lien)
  var standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone;
  var installCard = document.querySelector('[data-install-card]');
  var deferred = null;
  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault(); deferred = e;
    if (installCard && !standalone) installCard.hidden = false;
  });
  var ib = document.querySelector('[data-install]');
  if (ib) ib.addEventListener('click', function () {
    if (!deferred) return;
    deferred.prompt();
    deferred.userChoice.then(function () { deferred = null; installCard.hidden = true; });
  });
  var ios = document.querySelector('[data-install-ios]');
  if (ios && !standalone && /iphone|ipad|ipod/i.test(navigator.userAgent)) ios.hidden = false;

  // Indicateur « prêt sans internet » : la page de lecture et le scanner sont-ils en mémoire ?
  var off = document.querySelector('[data-offline-status]');
  if (off) {
    var txt = off.querySelector('[data-offline-text]');
    var show = function (ok, msg) { off.hidden = false; off.classList.toggle('ok', ok); off.classList.toggle('ko', !ok); txt.innerHTML = msg; };
    if (!('serviceWorker' in navigator) || !window.caches) {
      show(false, '<b>Ce navigateur ne permet pas la lecture sans internet.</b> Utilisez Chrome (Android) ou Safari (iPhone).');
    } else {
      var check = function () {
        caches.keys().then(function (ks) {
          return Promise.all(ks.filter(function (k) { return k.indexOf('kidlink-') === 0; }).map(function (k) {
            return caches.open(k).then(function (c) { return Promise.all([c.match('/v/_/'), c.match('/scanner/')]); });
          }));
        }).then(function (all) {
          var ready = all.some(function (pair) { return pair[0] && pair[1]; });
          if (ready) show(true, '<b>Prêt sans internet ✓</b> Ce téléphone peut lire les bracelets même sans connexion.');
          else show(false, '<b>Pas encore prêt sans internet.</b> Gardez cette page ouverte quelques secondes avec internet.');
          return ready;
        }).catch(function () {});
      };
      check();
      navigator.serviceWorker.ready.then(function () { setTimeout(check, 1500); });
    }
  }

  // Menu mobile
  document.querySelectorAll('[data-toggle-menu]').forEach(function (b) {
    b.addEventListener('click', function () { document.body.classList.toggle('menu-open'); });
  });

  // Messages qui disparaissent
  document.querySelectorAll('.toast').forEach(function (t) { setTimeout(function () { t.classList.add('out'); }, 6000); });

  // Création d'un lien : récapitulatif en direct + double confirmation
  var lf = document.getElementById('link-form');
  if (lf) {
    var prices = {}; try { prices = JSON.parse(document.getElementById('prices').textContent); } catch (e) {}
    var f = function (n) { return lf.querySelector('[name="' + n + '"]'); };
    var fmt = function (n) { return n.toLocaleString('fr-FR') + ' F'; };
    var warn = document.getElementById('recap-warn');
    var upd = function () {
      var q = parseInt(f('quota').value, 10) || 0, q2 = parseInt(f('quota_confirm').value, 10) || 0;
      var price = prices[f('event').value] || 0, amount = parseInt(f('amount_received').value, 10) || 0;
      lf.querySelector('[data-r="quota"]').textContent = q || '—';
      lf.querySelector('[data-r="expected"]').textContent = price && q ? fmt(price * q) : '—';
      lf.querySelector('[data-r="amount"]').textContent = f('amount_received').value ? fmt(amount) : '—';
      var msgs = [];
      if (q && q2 && q !== q2) msgs.push('Les deux nombres d\'enfants sont différents (' + q + ' et ' + q2 + ').');
      if (price && q && amount && amount < price * q) msgs.push('Le montant encaissé est inférieur au prix normal de ' + fmt(price * q) + '.');
      warn.hidden = !msgs.length; warn.textContent = msgs.join(' ');
    };
    lf.addEventListener('input', upd); lf.addEventListener('change', upd); upd();
    lf.addEventListener('submit', function (e) {
      var q = parseInt(f('quota').value, 10) || 0;
      if (q >= 30 && !confirm('Vous allez créer un lien pour ' + q + ' enfants.\n\nAvez-vous bien encaissé le paiement de ' + q + ' enfants ?')) e.preventDefault();
    });
  }
})();
