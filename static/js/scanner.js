/* Sèmè Kids — scanner intégré : détecte aussi les QR qui imitent Sèmè Kids depuis un autre site. */
(function () {
  'use strict';
  var root = document.querySelector('[data-origin]');
  if (!root) return;
  var video = document.getElementById('cam');
  var canvas = document.getElementById('frame');
  var msg = document.getElementById('scan-msg');
  var btn = document.getElementById('start');
  var ctx = canvas.getContext('2d', { willReadFrequently: true });
  var origins = [location.origin];
  try { origins.push(new URL(root.dataset.origin).origin); } catch (e) {}
  var stream = null, busy = false;

  function say(kind, text) {
    msg.hidden = false;
    msg.className = 'scan-msg ' + kind;
    msg.textContent = text;
  }

  function stop() {
    if (stream) stream.getTracks().forEach(function (t) { t.stop(); });
    stream = null;
    root.classList.remove('live');
  }

  function handle(text) {
    var url;
    try { url = new URL(text); } catch (e) { url = null; }
    if (url && origins.indexOf(url.origin) !== -1 && /^\/v\/[A-Za-z0-9]{12}\/?$/.test(url.pathname) && url.hash.length > 10) {
      say('ok', 'Bracelet Sèmè Kids détecté. Ouverture…');
      stop();
      location.href = location.origin + url.pathname + url.hash;
      return true;
    }
    say('bad', '⚠ Ce code N\'EST PAS un bracelet Sèmè Kids officiel. Ne faites pas confiance aux numéros qu\'il affiche. Appelez l\'administration.');
    if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
    return false;
  }

  function loop() {
    if (!stream) return;
    if (video.readyState >= 2 && !busy) {
      busy = true;
      var w = video.videoWidth, h = video.videoHeight;
      var scale = Math.min(1, 720 / Math.max(w, h));
      canvas.width = Math.round(w * scale); canvas.height = Math.round(h * scale);
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      var img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      var code = window.jsQR ? jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' }) : null;
      busy = false;
      if (code && code.data) {
        if (handle(code.data)) return;
        setTimeout(function () { requestAnimationFrame(loop); }, 1500);
        return;
      }
    }
    setTimeout(function () { requestAnimationFrame(loop); }, 120);
  }

  btn.addEventListener('click', async function () {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      say('bad', 'Ce téléphone ne permet pas d\'utiliser la caméra ici. Utilisez l\'appareil photo normal.');
      return;
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
      video.srcObject = stream;
      await video.play();
      root.classList.add('live');
      msg.hidden = true;
      loop();
    } catch (e) {
      say('bad', 'Caméra refusée ou indisponible. Autorisez la caméra, ou utilisez l\'appareil photo normal du téléphone.');
    }
  });
  window.addEventListener('pagehide', stop);
})();
