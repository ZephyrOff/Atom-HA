'use strict';
// Pages : historique et versions, certificats. S'appuie sur les outils de app.js.

const COL_LABEL = {
  settings: 'Réglages DNS', upstreams: 'Upstream', lists: 'Liste de filtrage', rewrites: 'Réécriture', zones: 'Zone',
  records: 'Enregistrement', rules: 'Règles perso', clients: 'Client', groups: 'Groupe', tokens: "Jeton d'API",
};
const whenFull = ms => new Date(ms).toLocaleString('fr-FR');
const copyText = async (text, okMsg) => {
  try { await navigator.clipboard.writeText(text); toast(okMsg || 'Copié'); }
  catch { toast('Copie impossible : sélectionne le texte à la main', true); }
};
const shortJson = v => { const s = JSON.stringify(v); return s && s.length > 160 ? s.slice(0, 160) + '…' : (s || ''); };
const readFileText = file => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.onerror = () => rej(new Error('lecture impossible')); r.readAsText(file); });

// ---------- historique, versions, conflits, sauvegarde ----------

pages.history = async function (token) {
  let tab = 'changes', q = '', col = '';
  main.innerHTML = `<div class="head"><div><h1>Historique</h1><p>Toutes les modifications de configuration, les versions auxquelles revenir, les conflits entre nœuds et les sauvegardes.</p></div>
    <div class="seg" id="htabs"><button data-t="changes">Modifications</button><button data-t="versions">Versions</button><button data-t="conflicts">Conflits</button><button data-t="backup">Sauvegarde</button><button data-t="maint">Maintenance</button></div></div>
    <div id="hbody"></div>`;
  const body = () => $('#hbody');
  const setTab = t => { tab = t; $$('#htabs button').forEach(b => b.classList.toggle('on', b.dataset.t === t)); render().catch(fail); };

  async function viewChanges() {
    const p = new URLSearchParams({ limit: 300, search: q, col });
    const d = await get('history?' + p);
    if (token !== routeToken) return;
    const who = e => e.source === 'remote' ? `nœud ${d.node_names[e.node] || e.node}` : e.actor;
    const nodeName = e => d.node_names[e.node] || e.node;
    const act = { create: ['Ajout', 'ok'], update: ['Modification', 'acc'], delete: ['Suppression', 'bad'] };
    body().innerHTML = `<div class="card"><div class="row" style="margin-bottom:12px">
      <input class="f grow" id="hq" type="search" placeholder="Rechercher dans l'historique" value="${esc(q)}" aria-label="Rechercher">
      <select class="f" id="hc" style="width:auto" aria-label="Type d'objet"><option value="">Tous les objets</option>${Object.entries(COL_LABEL).map(([k, v]) => `<option value="${k}" ${k === col ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
      <div class="tblwrap"><table><thead><tr><th>Date</th><th>Par</th><th>Nœud</th><th>Action</th><th>Objet</th><th>Détail</th><th></th></tr></thead><tbody>
      ${d.entries.length ? d.entries.map(e => { const [t, c] = act[e.action] || [e.action, '']; const undo = e.col !== 'tokens' && (e.before || e.action === 'create');
        return `<tr><td>${whenFull(e.ts)}</td><td>${esc(who(e))}</td><td>${esc(nodeName(e))}</td><td><span class="tag ${c}">${t}</span></td><td>${esc(COL_LABEL[e.col] || e.col)}</td>
        <td class="wrap mono">${esc(e.summary)}</td><td>${undo ? `<button class="btn sm" data-undo="${e.ts}|${esc(e.col)}|${esc(e.id)}" title="Remettre l'état d'avant cette modification">Annuler</button>` : ''}</td></tr>`; }).join('') : '<tr><td colspan="7" class="empty">Aucune modification enregistrée</td></tr>'}</tbody></table></div>
      <p class="note" style="margin-top:12px">« Annuler » remet l'objet dans l'état qu'il avait avant la modification. L'annulation est elle-même une modification, visible ici et synchronisée sur le cluster.</p></div>`;
  }

  async function viewVersions() {
    const d = await get('versions');
    if (token !== routeToken) return;
    body().innerHTML = `<div class="card"><h2>Créer une version</h2><div class="row"><input class="f grow" id="vl" placeholder="Nom (ex. avant le changement de DNS)" aria-label="Nom de la version"><button class="btn pri" id="vnew">Créer</button></div>
      <p class="note" style="margin-top:12px">Atom crée aussi une version automatique au plus une fois par heure quand la configuration a changé, et avant chaque restauration. Les 30 dernières versions automatiques sont conservées. Les jetons d'API ne sont pas inclus.</p></div>
      <div class="card"><h2>Versions <span class="muted" style="font-weight:400;font-size:12px">configuration actuelle : ${d.current_objects} objets</span></h2><div class="tblwrap"><table><thead><tr><th>Date</th><th>Nom</th><th>Type</th><th>Objets</th><th></th></tr></thead><tbody>
      ${d.versions.length ? d.versions.map(v => `<tr><td>${whenFull(v.ts)}</td><td>${esc(v.label)}</td><td>${v.auto ? '<span class="tag">automatique</span>' : '<span class="tag acc">manuelle</span>'}</td><td>${v.objects}</td>
        <td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-diff="${v.id}">Comparer</button><button class="btn sm" data-restore="${v.id}">Restaurer</button><button class="btn sm danger" data-vdel="${v.id}">Supprimer</button></td></tr>`).join('') : '<tr><td colspan="5" class="empty">Aucune version</td></tr>'}</tbody></table></div></div>
      <div id="vdiff"></div>`;
  }

  async function viewConflicts() {
    const d = await get('conflicts');
    if (token !== routeToken) return;
    const nm = id => d.node_names[id] || id;
    const open = d.conflicts.filter(c => !c.resolved), done = d.conflicts.filter(c => c.resolved);
    const side = (s, label) => `<div><div class="muted" style="font-size:12px">${label} · nœud ${esc(nm(s.node))} · ${whenFull(s.ts)}</div><div class="mono" style="word-break:break-all">${s.val ? esc(shortJson(s.val)) : '<span class="muted">supprimé</span>'}</div></div>`;
    body().innerHTML = `<div class="card"><h2>Conflits à examiner <span class="tag ${open.length ? 'warn' : 'ok'}">${open.length}</span></h2>
      <p class="muted" style="margin-bottom:12px">Un conflit apparaît quand deux nœuds modifient le même objet en même temps. La version la plus récente est conservée automatiquement ; tu peux ici restaurer l'autre.</p>
      ${open.length ? open.map(c => `<div class="card" style="margin-top:10px"><div class="row sp"><b>${esc(COL_LABEL[c.col] || c.col)} · ${esc(c.summary)}</b><span class="muted">${whenFull(c.ts)}</span></div>
        <div class="cols" style="margin-top:8px">${side(c.winner, 'Version conservée')}${side(c.loser, 'Version écrasée')}</div>
        <div class="row" style="margin-top:10px"><button class="btn sm" data-keep="${c.cid}">Garder la version conservée</button><button class="btn sm pri" data-loser="${c.cid}">Restaurer la version écrasée</button></div></div>`).join('') : '<div class="empty">Aucun conflit en attente</div>'}</div>
      ${done.length ? `<div class="card"><h2>Résolus <button class="btn sm" id="cclear">Effacer</button></h2><div class="tblwrap"><table><tbody>${done.map(c => `<tr><td>${whenFull(c.ts)}</td><td>${esc(COL_LABEL[c.col] || c.col)}</td><td class="mono wrap">${esc(c.summary)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}`;
  }

  function viewBackup() {
    body().innerHTML = `<div class="cols"><div class="card"><h2>Sauvegarder</h2><p class="muted" style="margin-bottom:12px">Un fichier avec toute la configuration : listes (et leurs sources), règles, réécritures, zones, enregistrements, clients, groupes, upstreams, réglages. Ne contient ni le journal, ni le cache, ni les jetons d'API, ni les certificats.</p>
        <a class="btn pri" href="api/backup" style="text-decoration:none;display:inline-block" id="dl">Télécharger la sauvegarde</a></div>
      <div class="card"><h2>Restaurer</h2><div class="stack"><input type="file" id="bf" accept=".json,application/json" aria-label="Fichier de sauvegarde">
        <div id="binfo" class="muted"></div>
        <label class="lbl">Mode<select class="f" id="bm"><option value="replace">Remplacer : la configuration devient celle du fichier</option><option value="merge">Fusionner : ajouter et mettre à jour, sans rien supprimer</option></select></label>
        <div class="row"><button class="btn pri" id="brestore" disabled>Restaurer</button></div>
        <p class="note">Une version « Avant restauration » est créée automatiquement, tu peux donc revenir en arrière depuis l'onglet Versions.</p></div></div></div>`;
    let parsed = null;
    $('#bf').onchange = guard(async e => {
      const f = e.target.files[0]; parsed = null; $('#brestore').disabled = true;
      if (!f) return;
      try { parsed = JSON.parse(await readFileText(f)); } catch { $('#binfo').textContent = 'Ce fichier n\'est pas du JSON valide.'; return; }
      if (parsed.format !== 'atom-backup') { $('#binfo').textContent = 'Ce fichier n\'est pas une sauvegarde Atom.'; parsed = null; return; }
      $('#binfo').textContent = `Sauvegarde du ${whenFull(parsed.created_at)} · nœud ${parsed.node} · ${parsed.objects.length} objets · Atom ${parsed.atom_version}`;
      $('#brestore').disabled = false;
    });
    $('#brestore').onclick = guard(async e => {
      const t = e.target;
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = $('#bm').value === 'replace' ? 'Confirmer : remplacer la configuration' : 'Confirmer la fusion'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Restaurer'; }, 4000); return; }
      const r = await api('POST', 'backup/restore', { backup: parsed, mode: $('#bm').value });
      t.dataset.sure = ''; t.textContent = 'Restaurer';
      toast(`Restauré : ${r.written} écrit(s), ${r.deleted} supprimé(s)`);
    });
  }

  async function viewMaint() {
    const m = await get('maintenance');
    if (token !== routeToken) return;
    body().innerHTML = `<div class="card"><h2>Nettoyage des suppressions</h2>
      <p class="muted" style="margin-bottom:12px">Quand tu supprimes un élément, Atom garde une trace de la suppression pour la transmettre aux autres nœuds. Une fois que tous les nœuds l'ont reçue, et après ${m.min_age_days} jours, cette trace est effacée automatiquement chaque jour. Elle est conservée tant qu'un nœud ne l'a pas reçue, pour qu'un nœud resté éteint ne fasse pas réapparaître un élément supprimé.</p>
      <div class="tiles" style="max-width:520px"><div class="tile"><small>Traces de suppression</small><strong>${m.tombstones}</strong></div><div class="tile"><small>Autres nœuds suivis</small><strong>${m.peers}</strong></div></div>
      <div class="row"><button class="btn" id="compact">Nettoyer maintenant</button></div></div>`;
  }

  async function render() {
    $$('#htabs button').forEach(b => b.classList.toggle('on', b.dataset.t === tab));
    ({ changes: viewChanges, versions: viewVersions, conflicts: viewConflicts, backup: async () => viewBackup(), maint: viewMaint })[tab]();
  }

  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.closest('#htabs')) return setTab(t.dataset.t);
    if (t.dataset.undo) {
      const [ts, c, id] = t.dataset.undo.split('|');
      await api('POST', 'history/revert', { ts: +ts, col: c, id }); toast('Modification annulée'); return render();
    }
    if (t.id === 'vnew') { await api('POST', 'versions', { label: $('#vl').value }); toast('Version créée'); return render(); }
    if (t.dataset.vdel) { await api('DELETE', `versions/${t.dataset.vdel}`); return render(); }
    if (t.dataset.diff) {
      const d = await get(`versions/${t.dataset.diff}/diff`);
      const lbl = { add: ['sera rétabli', 'ok'], modify: ['sera modifié', 'warn'], remove: ['sera supprimé', 'bad'] };
      $('#vdiff').innerHTML = `<div class="card"><h2>Différences avec la configuration actuelle</h2>${d.changes.length ? `<div class="tblwrap"><table><tbody>${d.changes.map(c => `<tr><td><span class="tag ${lbl[c.change][1]}">${lbl[c.change][0]}</span></td><td>${esc(COL_LABEL[c.col] || c.col)}</td><td class="mono wrap">${esc(c.summary)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">Identique à la configuration actuelle</div>'}</div>`;
      return;
    }
    if (t.dataset.restore) {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Restaurer'; }, 3000); return; }
      const r = await api('POST', `versions/${t.dataset.restore}/restore`); toast(`Version restaurée : ${r.written} écrit(s), ${r.deleted} supprimé(s)`); return render();
    }
    if (t.dataset.keep) { await api('POST', `conflicts/${t.dataset.keep}/resolve`); return render(); }
    if (t.dataset.loser) { await api('POST', `conflicts/${t.dataset.loser}/restore-loser`); toast('Version restaurée'); return render(); }
    if (t.id === 'cclear') { await api('POST', 'conflicts/clear'); return render(); }
    if (t.id === 'compact') { const r = await api('POST', 'maintenance/compact'); toast(`${r.removed} trace(s) supprimée(s)`); return render(); }
  });
  let deb;
  main.oninput = e => { if (e.target.id === 'hq') { q = e.target.value; clearTimeout(deb); deb = setTimeout(() => { const p = e.target.selectionStart; render().then(() => { const el = $('#hq'); if (el) { el.focus(); el.setSelectionRange(p, p); } }).catch(fail); }, 250); } };
  main.onchange = e => { if (e.target.id === 'hc') { col = e.target.value; render().catch(fail); } };
  await render();
  every(async () => { if (tab === 'changes' && document.activeElement && !['hq', 'hc'].includes(document.activeElement.id)) await render(); if (tab === 'conflicts') await render(); }, 8000);
};

// ---------- certificats ----------

pages.certs = async function (token) {
  const day = 86400000;
  const certCard = (c, title, extra = '') => {
    if (!c) return `<div class="muted">${title} : aucun certificat</div>`;
    const left = Math.floor((c.not_after - Date.now()) / day);
    const cls = left < 0 ? 'bad' : left < 30 ? 'warn' : 'ok';
    return `<div class="stack" style="font-size:13px"><div class="row sp"><b>${title}</b><span class="tag ${cls}">${left < 0 ? 'expiré' : `expire dans ${left} j`}</span></div>
      <div><span class="muted">Sujet</span> <span class="mono">${esc(c.subject)}</span></div><div><span class="muted">Émetteur</span> <span class="mono">${esc(c.issuer)}</span></div>
      ${c.names.length ? `<div><span class="muted">Noms (SAN)</span> <span class="mono">${esc(c.names.map(n => (c.ips || []).includes(n) ? 'IP ' + n : 'DNS ' + n).join(', '))}</span></div>` : ''}
      <div><span class="muted">Valide jusqu'au</span> ${new Date(c.not_after).toLocaleDateString('fr-FR')}</div>
      <div><span class="muted">Empreinte SHA-256</span> <span class="mono" style="word-break:break-all">${esc(c.fingerprint.match(/.{2}/g).join(':'))}</span></div>${extra}</div>`;
  };
  main.innerHTML = `<div class="head"><div><h1>Certificats</h1><p>HTTPS pour l'interface web, et chiffrement des échanges entre les nœuds.</p></div></div><div id="cbody"></div>`;
  async function draw() {
    const s = await get('tls/status');
    if (token !== routeToken) return;
    const st = s.settings, mode = st.cluster_mode;
    const modeName = { off: 'Désactivé', ca: 'Autorité du cluster', selfsigned: 'Certificats auto-signés', pki: 'PKI privée' }[mode];
    const ae = document.activeElement;
    if (ae && ae.closest && ae.closest('#cbody') && ['INPUT', 'TEXTAREA', 'SELECT'].includes(ae.tagName)) return;
    $('#cbody').innerHTML = `
      ${s.error ? `<div class="card" style="border-color:var(--bad)"><b style="color:var(--bad)">Erreur</b> <span class="mono">${esc(s.error)}</span></div>` : ''}
      <div class="card"><h2>Interface web en HTTPS <span class="tag ${s.listening ? 'ok' : ''}">${s.listening ? 'port ' + s.listening : 'inactif'}</span></h2>
        <div class="cols"><div class="stack">
          <label class="lbl">Nom d'hôte de l'interface<input class="f" id="th" value="${esc(st.hostname)}" placeholder="atom.maison.lan"></label>
          <label class="lbl">Adresse de ce nœud vue par les autres nœuds<input class="f" id="tu" value="${esc(s.advertise_url)}" placeholder="https://192.168.1.2:${st.web_port}"></label>
          <label class="lbl">Port HTTPS<input class="f" id="tp" type="number" value="${st.web_port}"></label>
          <label class="row sp"><span>Activer HTTPS pour l'interface</span>${sw(st.web_enabled, 'id="twe"')}</label>
          <label class="row sp"><span>Rediriger HTTP vers HTTPS<br><span class="muted">L'accès par Home Assistant n'est pas redirigé</span></span>${sw(st.redirect_http, 'id="trd"')}</label>
          <div class="row"><button class="btn pri" id="tsave">Enregistrer</button></div></div>
        <div class="stack">${certCard(s.web, 'Certificat de l\'interface')}
          <div class="row"><button class="btn" id="tgen">Générer un certificat</button><button class="btn" id="timp">Importer…</button>${s.web ? '<button class="btn danger" id="trm">Supprimer</button>' : ''}</div>
          <p class="note">Générer crée un certificat pour ${esc(st.hostname || 'le nom d\'hôte ci-contre')} et les adresses de ce nœud. Il est signé par l'autorité du cluster si ce nœud la détient, sinon il est auto-signé et le navigateur affichera un avertissement.</p></div></div>
        <div id="importbox" class="stack" style="margin-top:14px" hidden>
          <h2>Importer un certificat et sa clé</h2>
          <label class="lbl">Certificat (PEM, avec la chaîne si besoin)<textarea class="f" id="icrt" style="min-height:120px" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
          <label class="lbl">Clé privée (PEM, non chiffrée)<textarea class="f" id="ikey" style="min-height:120px" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>
          <div class="row"><input type="file" id="ifc" multiple aria-label="Fichiers de certificat et de clé"><button class="btn pri" id="iok">Importer</button><button class="btn" id="icancel">Annuler</button></div></div></div>

      <div class="card"><h2>Chiffrement des échanges entre nœuds <span class="tag ${mode === 'off' ? 'warn' : 'ok'}">${modeName}</span></h2>
        <p class="muted" style="margin-bottom:12px">Quand il est activé, les nœuds se parlent en HTTPS et chacun présente un certificat que les autres vérifient (mTLS). Les échanges en clair sont refusés. Un nœud retiré ne peut plus se connecter.</p>
        ${mode === 'off' && st.previous_mode && s.node ? `<div class="card" style="border-color:var(--warn);margin-bottom:12px"><b>Le chiffrement était activé (${esc({ ca: 'autorité du cluster', selfsigned: 'auto-signés', pki: 'PKI privée' }[st.previous_mode] || st.previous_mode)}).</b> Les certificats sont conservés : tu peux le réactiver sans refaire l'appairage.<div class="row" style="margin-top:8px"><button class="btn pri" id="mresume">Réactiver le chiffrement</button></div></div>` : ''}
        <div class="grid" style="display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(min(100%,230px),1fr))">
          <div class="card" ${mode === 'ca' ? 'style="border-color:var(--accent)"' : ''}><h2>Autorité du cluster</h2><p class="muted">Atom crée une autorité de certification. Ce nœud signe les certificats des autres au moment de l'appairage.</p><div class="row" style="margin-top:10px"><button class="btn ${mode === 'ca' ? '' : 'pri'}" id="mca" ${mode === 'ca' && s.ca_has_key ? 'disabled' : ''}>${mode === 'ca' ? 'Active' : 'Activer'}</button></div></div>
          <div class="card" ${mode === 'selfsigned' ? 'style="border-color:var(--accent)"' : ''}><h2>Auto-signés</h2><p class="muted">Chaque nœud a sa propre autorité. Les nœuds échangent leurs autorités lors de l'appairage et se les transmettent.</p><div class="row" style="margin-top:10px"><button class="btn ${mode === 'selfsigned' ? '' : 'pri'}" id="mss" ${mode === 'selfsigned' ? 'disabled' : ''}>${mode === 'selfsigned' ? 'Actif' : 'Activer'}</button></div></div>
          <div class="card" ${mode === 'pki' ? 'style="border-color:var(--accent)"' : ''}><h2>PKI privée</h2><p class="muted">Tu fournis le certificat de ce nœud, sa clé et l'autorité de ta PKI. Le certificat doit couvrir l'adresse du nœud et autoriser l'usage serveur et client.</p><div class="row" style="margin-top:10px"><button class="btn ${mode === 'pki' ? '' : 'pri'}" id="mpki">${mode === 'pki' ? 'Remplacer…' : 'Importer…'}</button></div></div>
          <div class="card"><h2>Sans chiffrement</h2><p class="muted">Les nœuds se parlent en HTTP simple, protégé par le seul code du cluster. <b>Ce bouton coupe le chiffrement entre les nœuds</b> : il ne ferme pas le port HTTP de l'interface (pour cela, active « Rediriger HTTP vers HTTPS » ci-dessus).</p><div class="row" style="margin-top:10px"><button class="btn danger" id="moff" ${mode === 'off' ? 'disabled' : ''}>${mode === 'off' ? 'Actif' : 'Revenir sans chiffrement'}</button></div></div></div>
        <div id="pkibox" class="stack" style="margin-top:14px" hidden><h2>Importer ta PKI</h2>
          <label class="lbl">Certificat de ce nœud (PEM)<textarea class="f" id="pcrt" style="min-height:110px"></textarea></label>
          <label class="lbl">Clé privée de ce nœud (PEM)<textarea class="f" id="pkey" style="min-height:110px"></textarea></label>
          <label class="lbl">Autorité(s) de confiance (PEM, une ou plusieurs)<textarea class="f" id="pca" style="min-height:110px"></textarea></label>
          <div class="row"><input type="file" id="pf" multiple aria-label="Fichiers"><button class="btn pri" id="pok">Importer et activer</button><button class="btn" id="pcancel">Annuler</button></div></div>
        ${mode !== 'off' ? `<div class="cols" style="margin-top:14px"><div class="stack">${certCard(s.node, 'Certificat de ce nœud')}
            <div class="row">${mode !== 'pki' ? '<button class="btn" id="mrenew">Renouveler</button>' : ''}</div></div>
          <div class="stack">${s.ca ? certCard(s.ca, mode === 'selfsigned' ? 'Autorité de ce nœud' : 'Autorité', `<div class="row"><a class="btn" href="api/tls/ca.crt" style="text-decoration:none">Télécharger</a></div>`) : ''}
            ${mode === 'ca' || mode === 'selfsigned' ? `<div><div class="muted" style="font-size:12px;margin-bottom:4px">Code d'appairage à saisir sur le nouveau nœud (page Cluster)</div><div class="token">${esc(s.pairing_code)}</div><div class="row" style="margin-top:8px"><button class="btn sm" id="mcp">Copier</button></div></div>` : ''}</div></div>
          <p class="note" style="margin-top:14px">Les nœuds doivent avoir la même heure (NTP) : un certificat est refusé s'il n'est pas encore valide. Les adresses utilisées entre nœuds (https://…) doivent figurer dans leur certificat. ${s.peers.some(p => !p.https) ? '<b style="color:var(--bad)">Certains nœuds du cluster sont encore enregistrés en HTTP : retire-les et refais l\'appairage.</b>' : ''}</p>` : ''}
      </div>`;
    const bind = (id, fn) => { const el = $('#' + id); if (el) el.onclick = guard(fn); };
    bind('tsave', async () => { await api('POST', 'tls/settings', { web_enabled: $('#twe').checked, web_port: +$('#tp').value, hostname: $('#th').value, redirect_http: $('#trd').checked, advertise_url: $('#tu').value }); toast('Réglages enregistrés'); setTimeout(() => draw().catch(() => {}), 600); });
    bind('tgen', async () => { const r = await api('POST', 'tls/web/generate', { hostname: $('#th').value }); toast(r.signed_by_ca ? 'Certificat généré et signé par l\'autorité' : 'Certificat auto-signé généré'); draw(); });
    bind('timp', async () => { $('#importbox').hidden = false; $('#icrt').focus(); });
    bind('icancel', async () => { $('#importbox').hidden = true; });
    bind('iok', async () => { await api('POST', 'tls/web/import', { cert_pem: $('#icrt').value, key_pem: $('#ikey').value }); toast('Certificat importé'); draw(); });
    bind('trm', async () => { await api('POST', 'tls/web/remove'); toast('Certificat supprimé, HTTPS désactivé'); draw(); });
    const dispatchFiles = async (input, targets) => {
      for (const f of input.files) {
        const t = await readFileText(f);
        if (/PRIVATE KEY/.test(t)) $('#' + targets.key).value = t;
        else if (targets.ca && /ca|root|chain/i.test(f.name)) $('#' + targets.ca).value = t;
        else $('#' + targets.crt).value = t;
      }
    };
    if ($('#ifc')) $('#ifc').onchange = guard(() => dispatchFiles($('#ifc'), { crt: 'icrt', key: 'ikey' }));
    if ($('#pf')) $('#pf').onchange = guard(() => dispatchFiles($('#pf'), { crt: 'pcrt', key: 'pkey', ca: 'pca' }));
    bind('mca', async () => { await api('POST', 'tls/cluster/init-ca'); toast('Autorité du cluster créée'); draw(); });
    bind('mss', async () => { await api('POST', 'tls/cluster/selfsigned'); toast('Chiffrement activé (auto-signé)'); draw(); });
    bind('mpki', async () => { $('#pkibox').hidden = false; $('#pcrt').focus(); });
    bind('pcancel', async () => { $('#pkibox').hidden = true; });
    bind('pok', async () => { await api('POST', 'tls/cluster/pki', { cert_pem: $('#pcrt').value, key_pem: $('#pkey').value, ca_pem: $('#pca').value }); toast('PKI importée, chiffrement activé'); draw(); });
    bind('moff', async e => { const t = $('#moff'); if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer : couper le chiffrement entre les nœuds'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Revenir sans chiffrement'; }, 4000); return; } await api('POST', 'tls/cluster/off'); toast('Chiffrement du cluster désactivé'); draw(); });
    bind('mresume', async () => { await api('POST', 'tls/cluster/resume'); toast('Chiffrement réactivé'); draw(); });
    bind('mrenew', async () => { await api('POST', 'tls/cluster/renew'); toast('Certificat renouvelé'); draw(); });
    bind('mcp', async () => copyText(s.pairing_code, 'Code copié'));
  }
  await draw();
  every(draw, 10000);
};
