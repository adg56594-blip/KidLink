/* Sèmè Kids — lecture et vérification d'un bracelet.
 * 1) Vérifie la signature ECDSA DANS le téléphone (marche sans internet).
 * 2) Si internet est disponible, confirme auprès du serveur (bracelet désactivé, expiré…).
 * Aucune donnée n'est envoyée au serveur en dehors de l'identifiant et du code signé déjà présents dans le QR.
 */
(function () {
  'use strict';
  var root = document.querySelector('[data-pk]');
  if (!root) return;
  var $ = function (id) { return document.getElementById(id); };
  // v1 : sans le nom du chargé ; v2 : nom du chargé à la fin. Les deux restent valides.
  var FIELDS_BY_VERSION = {
    '1': ['expiry', 'nom', 'prenom', 'parent_name', 'parent_phone', 'parent_phone2', 'paroisse', 'charge_phone', 'ref'],
    '2': ['expiry', 'nom', 'prenom', 'parent_name', 'parent_phone', 'parent_phone2', 'paroisse', 'charge_phone', 'ref', 'charge_name']
  };

  // Horloge en direct dans le sceau : une capture d'écran ou une fausse page figée se repère.
  function tick() {
    var d = new Date();
    $('seal-clock').textContent = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  tick(); setInterval(tick, 1000);

  function b64uBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64Bytes(s) { return b64uBytes(s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')); }

  function seal(state, title, sub) {
    var el = $('seal');
    el.className = 'seal seal-' + state;
    $('seal-title').textContent = title;
    $('seal-sub').textContent = sub || '';
    var use = el.querySelector('use');
    use.setAttribute('href', state === 'bad' ? '#i-alert' : (state === 'checking' ? '#i-shield' : '#i-check'));
  }

  function bad(title, text) {
    seal('bad', title, 'Ne faites pas confiance à ce code');
    $('child').hidden = true;
    $('bad').hidden = false;
    $('bad-title').textContent = title;
    if (text) $('bad-text').textContent = text;
  }

  function telHref(p) { return 'tel:' + p.replace(/[^\d+]/g, ''); }
  function pretty(p) {
    if (/^\+229\d{8,10}$/.test(p)) return '+229 ' + p.slice(4).replace(/(\d{2})(?=\d)/g, '$1 ');
    return p;
  }

  var data = null;

  function showChild(d, code) {
    data = d;
    var name = (d.prenom + ' ' + d.nom).trim();
    document.title = name + ' · Sèmè Kids';
    $('c-name').textContent = name;
    $('c-paroisse').textContent = d.paroisse || '—';
    $('c-parent').textContent = d.parent_name || '—';
    $('c-ref').textContent = d.ref || '—';
    $('c-code').textContent = code.slice(0, 4) + '-' + code.slice(4, 8) + '-' + code.slice(8);
    $('b-call').href = telHref(d.parent_phone);
    $('b-call-num').textContent = pretty(d.parent_phone);
    var wa = $('b-wa');
    wa.href = waUrl(null);
    wa.addEventListener('click', function (e) {
      if (!navigator.geolocation) return;
      e.preventDefault();
      var done = false;
      var go = function (pos) { if (done) return; done = true; window.location.href = waUrl(pos); };
      setTimeout(function () { go(null); }, 6000);
      navigator.geolocation.getCurrentPosition(go, function () { go(null); }, { enableHighAccuracy: true, timeout: 5000, maximumAge: 60000 });
    });
    if (d.parent_phone2) { $('b-call2').hidden = false; $('b-call2').href = telHref(d.parent_phone2); $('b-call2-num').textContent = pretty(d.parent_phone2); }
    if (d.charge_name || d.charge_phone) {
      $('c-charge-row').hidden = false;
      $('c-charge').textContent = d.charge_name || pretty(d.charge_phone);
    }
    if (d.charge_phone) {
      $('b-charge').hidden = false; $('b-charge').href = telHref(d.charge_phone); $('b-charge-num').textContent = pretty(d.charge_phone);
      $('b-charge-name').textContent = d.charge_name ? d.charge_name + ' (chargé)' : 'le chargé';
    }
    $('child').hidden = false;
    $('bad').hidden = true;
  }

  function waUrl(pos) {
    var name = (data.prenom + ' ' + data.nom).trim();
    var msg = 'Bonjour, j\'ai trouvé votre enfant ' + name + ' grâce à son bracelet Sèmè Kids. Il est avec moi.';
    if (pos && pos.coords) {
      msg += ' Je suis ici : https://maps.google.com/?q=' + pos.coords.latitude.toFixed(5) + ',' + pos.coords.longitude.toFixed(5);
    }
    return 'https://wa.me/' + data.parent_phone.replace(/\D/g, '') + '?text=' + encodeURIComponent(msg);
  }

  $('speak-child').addEventListener('click', function () {
    if (!data || !window.speechSynthesis) return;
    var u = new SpeechSynthesisUtterance('Cet enfant s\'appelle ' + data.prenom + ' ' + data.nom +
      '. Restez avec lui. Appuyez sur le gros bouton vert pour appeler sa famille.');
    u.lang = 'fr-FR'; u.rate = 0.95;
    speechSynthesis.cancel(); speechSynthesis.speak(u);
  });

  async function verifyLocal(id, payload, sig) {
    if (!(window.crypto && crypto.subtle)) return null; // impossible de vérifier (ancien navigateur)
    // Signature « low-S » obligatoire (anti-malléabilité) : s <= n/2
    var sHex = Array.prototype.map.call(sig.slice(32), function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
    if (sHex > '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8') return false;
    try {
      var key = await crypto.subtle.importKey('spki', b64Bytes(root.dataset.pk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      var msg = new TextEncoder().encode('KL1|' + id + '|' + payload);
      return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, msg);
    } catch (e) { return null; }
  }

  async function verifyOnline(id, frag) {
    var ctrl = window.AbortController ? new AbortController() : null;
    var t = setTimeout(function () { if (ctrl) ctrl.abort(); }, 7000);
    try {
      var r = await fetch('/api/verify/', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit', cache: 'no-store',
        body: JSON.stringify({ id: id, f: frag }), signal: ctrl ? ctrl.signal : undefined
      });
      if (!r.ok && r.status !== 429) return null;
      return await r.json();
    } catch (e) { return null; } finally { clearTimeout(t); }
  }

  async function run() {
    var parts = location.pathname.split('/').filter(Boolean);
    var id = (parts[1] || '').toUpperCase();
    var frag = decodeURIComponent((location.hash || '').slice(1));
    if (!/^[A-Z0-9]{12}$/.test(id) || frag.indexOf('.') < 1) {
      return bad('Bracelet non reconnu', 'Ce code est incomplet ou n\'a pas été produit par Sèmè Kids.');
    }
    var payload, sig, fields;
    try {
      var bits = frag.split('.');
      payload = new TextDecoder('utf-8', { fatal: true }).decode(b64uBytes(bits[0]));
      sig = b64uBytes(bits[1]);
      fields = payload.split('|');
    } catch (e) { return bad('Bracelet non reconnu'); }
    var FIELDS = FIELDS_BY_VERSION[fields[0]];
    if (!FIELDS || fields.length !== FIELDS.length + 1 || sig.length !== 64) return bad('Bracelet non reconnu');

    var local = await verifyLocal(id, payload, sig);
    if (local === false) {
      return bad('Bracelet FALSIFIÉ', 'Ce code a été modifié : la signature Sèmè Kids ne correspond pas. Les numéros affichés pourraient être faux. Appelez l\'administration.');
    }
    var d = {};
    FIELDS.forEach(function (f, i) { d[f] = fields[i + 1] || ''; });
    var exp = d.expiry;
    var today = new Date(); var ymd = String(today.getFullYear()) + String(today.getMonth() + 1).padStart(2, '0') + String(today.getDate()).padStart(2, '0');
    if (exp && ymd > exp) return bad('Bracelet expiré', 'L\'événement de ce bracelet est terminé depuis longtemps. Si un enfant est perdu, appelez l\'administration.');

    showChild(d, id);
    if (local === true) seal('offline', 'Bracelet authentique', 'Signature vérifiée dans ce téléphone');
    else seal('checking', 'Vérification en ligne…', 'Un instant');

    var res = await verifyOnline(id, frag);
    if (!res) {
      if (local === true) seal('offline', 'Bracelet authentique', 'Vérifié sans internet · signature valide');
      else seal('warn', 'Vérification impossible', 'Pas d\'internet : soyez prudent');
      return;
    }
    if (res.status === 'valid') {
      if (res.charge_name && !data.charge_name) {  // ancien bracelet : nom du chargé fourni par le serveur
        data.charge_name = res.charge_name;
        $('c-charge-row').hidden = false;
        $('c-charge').textContent = res.charge_name;
        if (data.charge_phone) $('b-charge-name').textContent = res.charge_name + ' (chargé)';
      }
      return seal('ok', 'Bracelet authentique', 'Vérifié en ligne · ' + (res.event || 'Sèmè Kids'));
    }
    if (res.status === 'replaced') return bad('Bracelet plus à jour', 'Les informations de cet enfant ont été corrigées depuis l\'impression de ce bracelet. N\'utilisez pas les numéros qu\'il contient : appelez l\'administration Sèmè Kids.');
    if (res.status === 'revoked') return bad('Bracelet désactivé', 'Ce bracelet a été déclaré perdu ou volé. Appelez l\'administration Sèmè Kids.');
    if (res.status === 'expired') return bad('Bracelet expiré', 'Les données de cet événement ont été effacées. Si un enfant est perdu, appelez l\'administration.');
    if (res.status === 'forged') return bad('Bracelet FALSIFIÉ', 'Ce code n\'a pas été produit par Sèmè Kids. Les numéros pourraient être faux. Appelez l\'administration.');
    if (local === true) seal('offline', 'Bracelet authentique', 'Signature vérifiée dans ce téléphone');
  }
  // Un autre code collé dans la même page : on recommence toute la vérification.
  window.addEventListener('hashchange', function () { location.reload(); });
  run();
})();
