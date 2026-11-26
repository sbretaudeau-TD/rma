'use strict';
/* Icône RMA du téléphone : retrouve la dernière adresse du tunnel publiée par le PC et vérifie sa signature. */
(function (g) {
  var NTFY = 'https://ntfy.sh';
  var enc = new TextEncoder();
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
  function sujet(code) {
    return crypto.subtle.digest('SHA-256', enc.encode('rma-sujet|' + code)).then(function (d) { return 'rma-' + hex(d).slice(0, 32); });
  }
  function signer(code, u, t) {
    return crypto.subtle.importKey('raw', enc.encode(code), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, enc.encode(u + '|' + t)); }).then(hex);
  }
  // Un tunnel fermé garde son adresse (erreur Cloudflare 1033) : on vérifie qu'il répond en chargeant l'icône de la page
  // téléphone (une image passe d'un site à l'autre sans autorisation spéciale). Hors navigateur (tests Node) : pas de vérif.
  function vivant(u) {
    if (typeof Image === 'undefined') return Promise.resolve(true);
    return new Promise(function (ok) {
      var img = new Image(), t = setTimeout(function () { ok(false); }, 8000);
      img.onload = function () { clearTimeout(t); ok(true); };
      img.onerror = function () { clearTimeout(t); ok(false); };
      img.src = u + '/m/icone.svg?t=' + Date.now();
    });
  }
  // Renvoie l'adresse https://xxx.trycloudflare.com la plus récente, bien signée ET qui répond, sinon null.
  async function derniereAdresse(code, fetchFn) {
    var r = await (fetchFn || fetch)(NTFY + '/' + (await sujet(code)) + '/json?poll=1&since=12h');
    if (!r.ok) throw new Error('ntfy.sh a répondu ' + r.status);
    var evts = (await r.text()).split('\n').filter(Boolean).map(function (l) { try { return JSON.parse(l); } catch (e) { return null; } })
      .filter(function (e) { return e && e.event === 'message'; }).sort(function (a, b) { return b.time - a.time; });
    for (var i = 0; i < evts.length; i++) {
      var m; try { m = JSON.parse(evts[i].message); } catch (e) { continue; }
      if (!m || !/^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(m.u)) continue;
      if ((await signer(code, m.u, m.t)) === m.s && (await vivant(m.u))) return m.u;
    }
    return null;
  }
  var api = { sujet: sujet, signer: signer, derniereAdresse: derniereAdresse, vivant: vivant };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else g.RMAPanneau = api;
})(this);
