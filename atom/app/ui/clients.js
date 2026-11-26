'use strict';
// Pages : clients, groupes, accès réseau, cache, réécritures. S'appuie sur les outils de app.js.

// ---------- outils communs ----------

let DIR = { clients: [], groups: [] };
async function loadDir() {
  DIR = await get('clients');
  return DIR;
}
const known = () => DIR.clients.filter(c => c.id);
const cLabel = c => c.name || c.ids[0] || c.key;
const gName = id => (DIR.groups.find(g => g.id === id) || {}).name || id;
const cNameById = id => { const c = DIR.clients.find(x => x.id === id); return c ? cLabel(c) : id; };

function until(ms) {
  if (!ms) return '';
  return new Date(ms).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}
function blockInfo(o) {
  const live = !o.block_until || o.block_until > Date.now();
  const t = [];
  if (live && o.block_internet) t.push('Internet');
  if (live && o.block_lan) t.push('LAN');
  return t;
}
const bypassUntil = o => (o.filter_bypass_until && o.filter_bypass_until > Date.now() ? o.filter_bypass_until : 0);
const BYPASS_OPTS = '<option value="15">15 min</option><option value="60" selected>1 h</option><option value="240">4 h</option><option value="1440">24 h</option>';
function accessTags(o) {
  const t = blockInfo(o);
  if (!t.length) return '<span class="muted">libre</span>';
  return `<span class="tag bad">${t.join(' + ')} bloqué</span>${o.block_until ? ` <span class="muted">jusqu'à ${until(o.block_until)}</span>` : ''}`;
}
const percent = (a, b) => (b ? (a / b * 100).toFixed(1).replace('.', ',') + ' %' : '0 %');
const recent = ms => ms && Date.now() - ms < 5 * 60 * 1000;
const keyHref = k => '#client/' + encodeURIComponent(k);

function scopeTags(o) {
  const t = [
    ...(o.groups || []).map(id => `<span class="tag acc">groupe ${esc(gName(id))}</span>`),
    ...(o.clients || []).map(id => `<span class="tag acc">${esc(cNameById(id))}</span>`),
  ];
  return t.length ? t.join(' ') : '<span class="muted">tous</span>';
}

// Sélecteur de portée : puces + liste déroulante. Vide = tous les clients.
function mountScope(el, value) {
  const st = { clients: [...((value && value.clients) || [])], groups: [...((value && value.groups) || [])] };
  function draw() {
    const chips = [
      ...st.groups.map(id => ['g', id, 'Groupe ' + gName(id)]),
      ...st.clients.map(id => ['c', id, cNameById(id)]),
    ];
    const gs = DIR.groups.filter(g => !st.groups.includes(g.id));
    const cs = known().filter(c => !st.clients.includes(c.id));
    el.innerHTML = `<div class="chips">${chips.length
      ? chips.map(([k, id, n]) => `<button type="button" class="chip" data-rmscope="${k}:${esc(id)}" title="Retirer">${esc(n)} ✕</button>`).join('')
      : '<span class="muted">Tous les clients</span>'}</div>
      <select class="f" data-addscope aria-label="Limiter à un client ou un groupe" ${gs.length || cs.length ? '' : 'disabled'}>
        <option value="">${gs.length || cs.length ? 'Limiter à…' : 'Aucun client ni groupe enregistré'}</option>
        ${gs.length ? `<optgroup label="Groupes">${gs.map(g => `<option value="g:${esc(g.id)}">${esc(g.name)}</option>`).join('')}</optgroup>` : ''}
        ${cs.length ? `<optgroup label="Clients">${cs.map(c => `<option value="c:${esc(c.id)}">${esc(cLabel(c))}</option>`).join('')}</optgroup>` : ''}
      </select>`;
  }
  el.onclick = e => {
    const b = e.target.closest('[data-rmscope]');
    if (!b) return;
    const [k, id] = b.dataset.rmscope.split(/:(.+)/);
    const arr = k === 'g' ? st.groups : st.clients;
    arr.splice(arr.indexOf(id), 1);
    draw();
  };
  el.onchange = e => {
    if (!e.target.matches('[data-addscope]') || !e.target.value) return;
    const [k, id] = e.target.value.split(/:(.+)/);
    (k === 'g' ? st.groups : st.clients).push(id);
    draw();
  };
  draw();
  return {
    get: () => ({ clients: st.clients.slice(), groups: st.groups.slice() }),
    set: v => { st.clients = [...((v && v.clients) || [])]; st.groups = [...((v && v.groups) || [])]; draw(); },
  };
}

function chartSvg(hours) {
  const max = Math.max(10, ...hours.map(h => h[0]));
  const p = Math.pow(10, Math.floor(Math.log10(max)));
  let nice = Math.ceil(max / p) * p;
  if (nice % 4) nice = Math.ceil(nice / 4) * 4;
  const W = 720, H = 170, L = 40, B = 22, T = 8, ch = H - B - T, cw = W - L - 4, bw = cw / 24;
  let svg = '';
  for (let i = 0; i <= 4; i++) {
    const v = nice / 4 * i, y = T + ch - v / nice * ch;
    svg += `<line x1="${L}" x2="${W - 4}" y1="${y}" y2="${y}"/><text x="${L - 6}" y="${y + 3}" text-anchor="end">${v >= 1000 ? (v / 1000).toFixed(v % 1000 ? 1 : 0) + 'k' : Math.round(v)}</text>`;
  }
  const nowH = new Date().getHours();
  hours.forEach((h, i) => {
    const ok = h[0] - h[1], x = L + i * bw + 2, w = bw - 4, hg = ok / nice * ch, hb = h[1] / nice * ch;
    svg += `<rect x="${x}" y="${T + ch - hg - hb}" width="${w}" height="${hg}" fill="var(--accent)"/><rect x="${x}" y="${T + ch - hb}" width="${w}" height="${hb}" fill="var(--bad)"/>`;
    if (i % 4 === 3) svg += `<text x="${x + w / 2}" y="${H - 6}" text-anchor="middle">${String((nowH - (23 - i) + 24) % 24).padStart(2, '0')}h</text>`;
  });
  return `<svg class="bars" viewBox="0 0 ${W} ${H}" role="img" aria-label="Requêtes par heure" style="width:100%;height:auto">${svg}</svg>`;
}
function rankHtml(list, cls) {
  const m = Math.max(1, ...list.map(x => x[1]));
  return list.length
    ? `<div class="rank ${cls}">${list.map(([n, c]) => `<div><span title="${esc(n)}">${esc(n)}</span><span class="mono">${num(c)}</span><u style="width:${c / m * 100}%"></u></div>`).join('')}</div>`
    : '<div class="empty">Aucune donnée</div>';
}
function statsHtml(st) {
  return `<div class="tiles">
    <div class="tile"><small>Requêtes (24 h)</small><strong>${num(st.total)}</strong></div>
    <div class="tile"><small>Bloquées</small><strong>${percent(st.blocked, st.total)}</strong><span>${num(st.blocked)} requêtes</span></div>
    <div class="tile"><small>Latence moyenne</small><strong>${Math.round(st.avg_ms)} ms</strong><span>hors cache</span></div>
    <div class="tile"><small>Réponses du cache</small><strong>${st.total ? Math.round(st.cached / st.total * 100) : 0} %</strong></div></div>
    <div class="card"><h2>Requêtes par heure <span class="row muted" style="font-weight:400;font-size:12px"><span><span class="dot" style="background:var(--accent)"></span>autorisées</span><span><span class="dot" style="background:var(--bad)"></span>bloquées</span></span></h2>${chartSvg(st.hours)}</div>
    <div class="cols" style="margin-top:14px">
      <div class="card"><h2>Domaines les plus demandés</h2>${rankHtml(st.top_domains, '')}</div>
      <div class="card"><h2>Domaines les plus bloqués</h2>${rankHtml(st.top_blocked, 'bl')}</div></div>`;
}
const stampShort = ms => new Date(ms).toLocaleTimeString('fr-FR');

// ---------- liste des clients et des groupes ----------

pages.clients = async function (token) {
  let tab = 'clients', q = '';
  main.innerHTML = `<div class="head"><div><h1>Clients</h1><p>Les appareils qui interrogent le DNS. Clique sur l'un d'eux pour voir son activité, son journal et ses configurations dédiées.</p></div>
    <div class="seg" id="tabs2"><button data-t="clients" class="on">Clients</button><button data-t="groups">Groupes</button></div></div>
    <div id="cbody"></div>`;
  function draw() {
    if (token !== routeToken) return;
    $$('#tabs2 button').forEach(b => b.classList.toggle('on', b.dataset.t === tab));
    if (tab === 'clients') {
      const term = q.trim().toLowerCase();
      const rows = DIR.clients.filter(c => !term || [c.name, ...c.ids, c.notes, gName(c.group)].join(' ').toLowerCase().includes(term));
      $('#cbody').innerHTML = `<div class="card"><div class="row" style="margin-bottom:12px"><input class="f grow" id="cq" type="search" placeholder="Rechercher un nom ou une adresse" value="${esc(q)}" aria-label="Rechercher un client"><span class="muted">${rows.length} sur ${DIR.clients.length}</span></div>
        <div class="tblwrap"><table><thead><tr><th>Client</th><th>Adresses</th><th>Groupe</th><th>Requêtes (24 h)</th><th>Bloquées</th><th>Dernière activité</th><th>Accès</th></tr></thead><tbody>
        ${rows.length ? rows.map(c => `<tr><td><span class="dot ${recent(c.last_seen) ? 'up' : ''}" title="${recent(c.last_seen) ? 'actif' : 'inactif'}"></span><a href="${keyHref(c.key)}"><b>${esc(c.name || c.ids[0])}</b></a>${c.id ? '' : ' <span class="tag">non enregistré</span>'}</td>
          <td class="mono muted">${esc(c.ids.join(', '))}</td><td>${c.group ? `<a href="#group/${encodeURIComponent(c.group)}">${esc(gName(c.group))}</a>` : '<span class="muted">aucun</span>'}</td>
          <td>${num(c.queries)}</td><td>${percent(c.blocked, c.queries)}</td><td>${c.last_seen ? ago(c.last_seen) : '<span class="muted">aucune</span>'}</td><td>${accessTags(c)}</td></tr>`).join('') : '<tr><td colspan="7" class="empty">Aucun client</td></tr>'}</tbody></table></div></div>
        <div class="card"><h2>Enregistrer un client</h2><div class="row">
          <input class="f grow" id="nn" placeholder="Nom (ex. Téléphone de Léa)" aria-label="Nom du client"><input class="f grow" id="ni" placeholder="Adresse IP ou plage (192.168.1.20, 192.168.1.0/24)" aria-label="Adresses">
          <select class="f" id="ng" style="width:auto" aria-label="Groupe"><option value="">Sans groupe</option>${DIR.groups.map(g => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('')}</select>
          <button class="btn pri" id="nadd">Enregistrer</button></div>
          <p class="note" style="margin-top:12px">Les appareils sont identifiés par leur adresse IP : donne une adresse fixe (réservation DHCP) à ceux que tu veux suivre ou configurer. Plusieurs adresses sont possibles, séparées par des virgules.</p></div>`;
    } else {
      $('#cbody').innerHTML = `<div class="card"><div class="tblwrap"><table><thead><tr><th>Groupe</th><th>Description</th><th>Clients</th><th>Requêtes (24 h)</th><th>Bloquées</th><th>Accès</th></tr></thead><tbody>
        ${DIR.groups.length ? DIR.groups.map(g => `<tr><td><a href="#group/${encodeURIComponent(g.id)}"><b>${esc(g.name)}</b></a></td><td class="wrap muted">${esc(g.description)}</td><td>${g.members}</td><td>${num(g.queries)}</td><td>${percent(g.blocked, g.queries)}</td><td>${accessTags(g)}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">Aucun groupe</td></tr>'}</tbody></table></div></div>
        <div class="card"><h2>Créer un groupe</h2><div class="row"><input class="f grow" id="gn" placeholder="Nom (ex. Enfants)" aria-label="Nom du groupe"><input class="f grow" id="gd" placeholder="Description (facultatif)" aria-label="Description"><button class="btn pri" id="gadd">Créer</button></div>
        <p class="note" style="margin-top:12px">Un groupe réunit des clients. Il porte des réécritures, des enregistrements et un blocage d'accès communs.</p></div>`;
    }
  }
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.closest('#tabs2')) { tab = t.dataset.t; draw(); return; }
    if (t.id === 'nadd') {
      await api('POST', 'c/clients', { name: $('#nn').value, ids: $('#ni').value.split(/[,\s]+/).filter(Boolean), group: $('#ng').value });
      toast('Client enregistré'); await loadDir(); draw();
    } else if (t.id === 'gadd') {
      await api('POST', 'c/groups', { name: $('#gn').value, description: $('#gd').value });
      toast('Groupe créé'); await loadDir(); draw();
    }
  });
  main.oninput = e => { if (e.target.id === 'cq') { q = e.target.value; const pos = e.target.selectionStart; draw(); const el = $('#cq'); el.focus(); el.setSelectionRange(pos, pos); } };
  await loadDir(); draw();
  every(async () => { if (document.activeElement && ['INPUT', 'SELECT'].includes(document.activeElement.tagName)) return; await loadDir(); draw(); }, 8000);
};

// ---------- fiche d'un client ou d'un groupe ----------

async function entityPage(token, kind, key) {
  await loadDir();
  if (token !== routeToken) return;
  const isGroup = kind === 'group';
  let ent = isGroup ? DIR.groups.find(g => g.id === key) : DIR.clients.find(c => c.key === key || c.id === key);
  if (!ent) { main.innerHTML = `<div class="card"><h2>${isGroup ? 'Groupe' : 'Client'} introuvable</h2><p><a href="#clients">Retour à la liste</a></p></div>`; return; }
  const registered = isGroup || !!ent.id;
  const col = isGroup ? 'groups' : 'clients';
  const members = () => (isGroup ? DIR.clients.filter(c => c.group === ent.id) : []);
  const idsParam = () => isGroup ? members().flatMap(c => c.ids).join(',') : ent.ids.join(',');
  const title = isGroup ? ent.name : (ent.name || ent.ids[0]);
  let editing = null; // { kind: 'rw'|'rec', id }
  let scopeCtl = null;

  main.innerHTML = `<div class="head"><div><a href="#clients" class="muted">← ${isGroup ? 'Groupes' : 'Clients'}</a><h1 id="et"></h1><p id="es"></p></div><div class="row" id="eb"></div></div>
    <div class="cols"><div class="card" id="ident"></div><div class="card" id="acc"></div></div>
    <div class="card" id="cfg" style="margin-top:14px" ${registered ? '' : 'hidden'}></div>
    <div id="stats" style="margin-top:14px"></div>
    <div class="card" style="margin-top:14px"><h2>Journal en direct <span class="row"><label class="row muted" style="font-weight:400;font-size:12px"><span id="livedot" class="dot up"></span><span id="livetxt">en direct</span></label><button class="btn sm" id="livebtn">Pause</button></span></h2>
      <div class="tblwrap"><table><thead><tr><th>Heure</th><th>Domaine</th><th>Type</th><th>Résultat</th><th>Détail</th><th>Durée</th></tr></thead><tbody id="elog"></tbody></table></div></div>`;

  function drawHead() {
    $('#et').textContent = title;
    $('#es').innerHTML = isGroup
      ? `${members().length} client(s) dans ce groupe${ent.description ? ' · ' + esc(ent.description) : ''}`
      : `<span class="mono">${esc(ent.ids.join(', '))}</span>${ent.group ? ` · groupe <a href="#group/${encodeURIComponent(ent.group)}">${esc(gName(ent.group))}</a>` : ''}${registered ? '' : ' · appareil non enregistré'}`;
  }

  function drawIdent() {
    if (isGroup) {
      $('#ident').innerHTML = `<h2>Groupe</h2><div class="stack">
        <label class="lbl">Nom<input class="f" id="in" value="${esc(ent.name)}"></label>
        <label class="lbl">Description<input class="f" id="id" value="${esc(ent.description)}"></label>
        <div><div class="muted" style="font-size:12px;margin-bottom:6px">Clients du groupe</div>${members().length ? members().map(c => `<a class="tag acc" href="${keyHref(c.key)}">${esc(cLabel(c))}</a>`).join(' ') : '<span class="muted">Aucun. Ajoute un client à ce groupe depuis sa fiche.</span>'}</div>
        <div class="row"><button class="btn pri" id="isave">Enregistrer</button><button class="btn danger" id="idel">Supprimer le groupe</button></div></div>`;
    } else if (registered) {
      $('#ident').innerHTML = `<h2>Client</h2><div class="stack">
        <label class="lbl">Nom<input class="f" id="in" value="${esc(ent.name)}"></label>
        <label class="lbl">Adresses IP ou plages (séparées par des virgules)<input class="f" id="ii" value="${esc(ent.ids.join(', '))}"></label>
        <label class="lbl">Groupe<select class="f" id="ig"><option value="">Aucun</option>${DIR.groups.map(g => `<option value="${esc(g.id)}" ${g.id === ent.group ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}</select></label>
        <label class="lbl">Notes<input class="f" id="inotes" value="${esc(ent.notes)}"></label>
        <div class="row"><button class="btn pri" id="isave">Enregistrer</button><button class="btn danger" id="idel">Supprimer le client</button></div></div>`;
    } else {
      $('#ident').innerHTML = `<h2>Appareil non enregistré</h2><p class="muted" style="margin-bottom:12px">Enregistre-le pour lui donner un nom, l'ajouter à un groupe, lui appliquer des configurations dédiées ou bloquer son accès.</p>
        <div class="stack"><label class="lbl">Nom<input class="f" id="in" placeholder="Ex. Téléviseur du salon"></label>
        <div class="row"><button class="btn pri" id="ireg">Enregistrer ce client</button></div></div>`;
    }
  }

  function drawAcc() {
    const live = !ent.block_until || ent.block_until > Date.now();
    const bi = live && ent.block_internet, bl = live && ent.block_lan;
    $('#acc').innerHTML = `<h2>Accès réseau</h2>
      <div class="stack">
        <label class="row sp"><span><b>Bloquer Internet</b><br><span class="muted">Aucun nom extérieur n'est résolu</span></span>${sw(bi, 'data-acc="internet"')}</label>
        <label class="row sp"><span><b>Bloquer le réseau local</b><br><span class="muted">Noms locaux et réponses vers des adresses privées refusés</span></span>${sw(bl, 'data-acc="lan"')}</label>
        <label class="lbl">Durée du blocage à l'activation<select class="f" id="adur"><option value="0">Jusqu'à ce que je le rétablisse</option><option value="60">1 heure</option><option value="240">4 heures</option><option value="1440">24 heures</option></select></label>
        <div>${bi || bl ? `${accessTags(ent)}` : '<span class="muted">Aucun blocage en cours</span>'}</div>
        <hr style="border:0;border-top:1px solid var(--line);width:100%">
        <div><b>Suspendre les filtres</b><br><span class="muted">Toutes les requêtes passent, sans liste ni règle de blocage, puis le filtrage revient tout seul.</span></div>
        ${bypassUntil(ent) ? `<div class="row"><span class="tag ok">suspendus jusqu'à ${until(bypassUntil(ent))}</span><button class="btn sm" id="bpoff">Reprendre le filtrage</button></div>`
          : `<div class="row"><select class="f" id="bpdur" style="width:auto" aria-label="Durée">${BYPASS_OPTS}</select><button class="btn" id="bpgo">Suspendre les filtres</button></div>`}
        <p class="note">Le blocage agit au niveau du DNS : il empêche l'appareil de trouver les adresses. Un appareil qui utilise une adresse IP directe ou un autre serveur DNS n'est pas arrêté. Pour une coupure réseau réelle, il faut aussi une règle sur le routeur.</p></div>`;
  }

  async function saveAccess(patch) {
    let id = ent.id;
    if (!isGroup && !ent.id) {
      const r = await api('POST', 'c/clients', { name: ent.ids[0], ids: ent.ids });
      id = r.id;
    }
    const cur = (await get('c/' + col)).find(x => x.id === id) || {};
    const body = { ...cur, ...patch }; delete body.id; delete body.updated_at;
    await api('PUT', `c/${col}/${id}`, body);
    await loadDir();
    ent = isGroup ? DIR.groups.find(g => g.id === id) : DIR.clients.find(c => c.id === id);
    return id;
  }

  // ----- configurations dédiées -----
  let zones = [], rws = [], recs = [];
  async function loadCfg() {
    [zones, rws, recs] = await Promise.all([get('c/zones'), get('c/rewrites'), get('c/records')]);
  }
  const mine = o => isGroup ? (o.groups || []).includes(ent.id) : (o.clients || []).includes(ent.id);
  const inherited = o => !isGroup && ent.group && (o.groups || []).includes(ent.group);
  function drawCfg() {
    if (!registered) return;
    const rows = [
      ...rws.filter(o => mine(o) || inherited(o)).map(o => ({ k: 'rw', o, name: o.domain, val: o.answer, type: 'Réécriture' })),
      ...recs.filter(o => mine(o) || inherited(o)).map(o => ({ k: 'rec', o, name: o.name ? `${o.name}.${o.zone}` : o.zone, val: o.value, type: o.type })),
    ];
    $('#cfg').innerHTML = `<h2>Configurations dédiées</h2>
      <p class="muted" style="margin-bottom:12px">Réécritures et enregistrements qui ne s'appliquent qu'à ${isGroup ? 'ce groupe' : 'ce client'}. Pour ce nom, ils remplacent la configuration générale.</p>
      <div class="tblwrap"><table><thead><tr><th>Type</th><th>Nom</th><th>Valeur</th><th>Origine</th><th></th></tr></thead><tbody>
      ${rows.length ? rows.map(r => `<tr><td><span class="tag acc">${esc(r.type)}</span></td><td class="mono">${esc(r.name)}</td><td class="mono wrap">${esc(r.val)}</td>
        <td>${mine(r.o) ? (isGroup ? 'ce groupe' : 'ce client') : '<span class="tag">hérité du groupe</span>'}</td>
        <td class="row" style="flex-wrap:nowrap">${mine(r.o) ? `<button class="btn sm" data-cedit="${r.k}:${r.o.id}">Modifier</button><button class="btn sm danger" data-cdel="${r.k}:${r.o.id}">Supprimer</button>` : ''}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">Aucune configuration dédiée</td></tr>'}</tbody></table></div>
      <h2 style="margin-top:18px" id="cfgh">Ajouter</h2>
      <div class="row">
        <select class="f" id="ck" style="width:auto" aria-label="Type"><option value="rw">Réécriture DNS</option><option value="rec">Enregistrement DNS</option></select>
        <span class="row grow" id="recfields" hidden><select class="f" id="cz" style="width:auto" aria-label="Zone">${zones.map(z => `<option>${esc(z.name)}</option>`).join('')}</select>
          <select class="f" id="ct" style="width:auto" aria-label="Type d'enregistrement">${['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR', 'NS', 'CAA'].map(t => `<option>${t}</option>`).join('')}</select></span>
        <input class="f grow" id="cn" placeholder="domaine ou nom" aria-label="Nom"><input class="f grow" id="cv" placeholder="réponse ou valeur" aria-label="Valeur">
        <button class="btn pri" id="csave">Ajouter</button><button class="btn" id="ccancel" hidden>Annuler</button></div>`;
    $('#ck').onchange = () => { $('#recfields').hidden = $('#ck').value !== 'rec'; $('#cn').placeholder = $('#ck').value === 'rec' ? 'nom (nas, *.apps, @)' : 'nom de domaine (nas.maison.lan)'; };
  }
  function resetCfg() {
    editing = null;
    if (!$('#ck')) return;
    $('#ck').disabled = false; $('#cn').value = ''; $('#cv').value = ''; $('#csave').textContent = 'Ajouter'; $('#cfgh').textContent = 'Ajouter'; $('#ccancel').hidden = true;
  }
  const scopeOf = () => (isGroup ? { clients: [], groups: [ent.id] } : { clients: [ent.id], groups: [] });

  // ----- statistiques et journal -----
  let live = true;
  async function drawStats() {
    const ids = idsParam();
    if (!ids) { $('#stats').innerHTML = '<div class="card empty">Aucun client dans ce groupe : pas de statistiques.</div>'; return; }
    const st = await get('stats?ids=' + encodeURIComponent(ids));
    if (token !== routeToken) return;
    $('#stats').innerHTML = statsHtml(st);
  }
  async function drawLog() {
    if (!live) return;
    const ids = idsParam();
    if (!ids) { $('#elog').innerHTML = '<tr><td colspan="6" class="empty">Aucun client</td></tr>'; return; }
    const rows = await get('log?limit=100&ids=' + encodeURIComponent(ids));
    if (token !== routeToken) return;
    $('#elog').innerHTML = rows.length ? rows.map(r => `<tr><td class="mono">${stampShort(r.ts)}</td><td class="mono" title="${esc(r.name)}">${esc(r.name)}</td><td>${esc(r.qtype)}</td><td>${resTag(r.result, r.cached)}</td><td class="wrap muted mono">${esc(r.reason || r.list || r.upstream)}</td><td>${r.ms} ms</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">Aucune requête récente</td></tr>';
  }

  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.id === 'bpgo' || t.id === 'bpoff') {
      const mins = t.id === 'bpgo' ? +$('#bpdur').value : 0;
      const id = await saveAccess({ filter_bypass_until: mins ? Date.now() + mins * 60000 : null });
      toast(mins ? 'Filtres suspendus' : 'Filtrage rétabli');
      if (!isGroup && key !== id && !DIR.clients.find(c => c.key === key)) { location.hash = keyHref(id); return; }
      drawHead(); drawAcc(); return;
    }
    if (t.id === 'livebtn') { live = !live; t.textContent = live ? 'Pause' : 'Reprendre'; $('#livedot').className = 'dot' + (live ? ' up' : ''); $('#livetxt').textContent = live ? 'en direct' : 'en pause'; if (live) drawLog(); return; }
    if (t.id === 'ireg') {
      const r = await api('POST', 'c/clients', { name: $('#in').value, ids: ent.ids });
      toast('Client enregistré'); location.hash = keyHref(r.id); return;
    }
    if (t.id === 'isave') {
      if (isGroup) await api('PUT', `c/groups/${ent.id}`, { ...ent, id: undefined, updated_at: undefined, name: $('#in').value, description: $('#id').value });
      else await api('PUT', `c/clients/${ent.id}`, { ...ent, id: undefined, updated_at: undefined, key: undefined, queries: undefined, blocked: undefined, last_seen: undefined, ips: undefined, name: $('#in').value, ids: $('#ii').value.split(/[,\s]+/).filter(Boolean), group: $('#ig').value, notes: $('#inotes').value });
      toast('Enregistré'); await loadDir();
      ent = isGroup ? DIR.groups.find(g => g.id === ent.id) : DIR.clients.find(c => c.id === ent.id);
      drawHead(); drawIdent(); return;
    }
    if (t.id === 'idel') {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer ? Les configurations dédiées seront supprimées'; return; }
      await api('DELETE', `c/${col}/${ent.id}`); toast('Supprimé'); location.hash = '#clients'; return;
    }
    if (t.id === 'csave') {
      const kindSel = $('#ck').value, sc = scopeOf();
      if (kindSel === 'rw') {
        const old = editing && rws.find(x => x.id === editing.id);
        const body = { ...(old || { enabled: true }), domain: $('#cn').value, answer: $('#cv').value, ...sc };
        delete body.id; delete body.updated_at;
        editing ? await api('PUT', `c/rewrites/${editing.id}`, body) : await api('POST', 'c/rewrites', body);
      } else {
        const old = editing && recs.find(x => x.id === editing.id);
        const body = { ...(old || { enabled: true, ttl: 300 }), zone: $('#cz').value, type: $('#ct').value, name: $('#cn').value, value: $('#cv').value, ...sc };
        delete body.id; delete body.updated_at;
        editing ? await api('PUT', `c/records/${editing.id}`, body) : await api('POST', 'c/records', body);
      }
      toast('Configuration enregistrée'); await loadCfg(); drawCfg(); resetCfg(); return;
    }
    if (t.id === 'ccancel') { resetCfg(); return; }
    if (t.dataset.cdel) {
      const [k, id] = t.dataset.cdel.split(':');
      await api('DELETE', `c/${k === 'rw' ? 'rewrites' : 'records'}/${id}`); await loadCfg(); drawCfg(); return;
    }
    if (t.dataset.cedit) {
      const [k, id] = t.dataset.cedit.split(':');
      editing = { kind: k, id };
      $('#ck').value = k; $('#ck').disabled = true; $('#recfields').hidden = k !== 'rec';
      if (k === 'rw') { const o = rws.find(x => x.id === id); $('#cn').value = o.domain; $('#cv').value = o.answer; }
      else { const o = recs.find(x => x.id === id); $('#cz').value = o.zone; $('#ct').value = o.type; $('#cn').value = o.name; $('#cv').value = o.value; }
      $('#csave').textContent = 'Enregistrer'; $('#cfgh').textContent = 'Modifier'; $('#ccancel').hidden = false; $('#cn').focus();
    }
  });
  main.onchange = guard(async e => {
    const a = e.target.dataset.acc; if (!a) return;
    const minutes = +$('#adur').value;
    const patch = a === 'internet' ? { block_internet: e.target.checked } : { block_lan: e.target.checked };
    const cur = { block_internet: ent.block_internet, block_lan: ent.block_lan, ...patch };
    patch.block_until = (cur.block_internet || cur.block_lan) ? (minutes ? Date.now() + minutes * 60000 : null) : null;
    const id = await saveAccess(patch);
    toast(e.target.checked ? 'Blocage activé' : 'Blocage levé');
    if (!isGroup && !ent.id) return;
    if (!isGroup && key !== id && !DIR.clients.find(c => c.key === key)) { location.hash = keyHref(id); return; }
    drawHead(); drawAcc(); drawIdent();
  });

  drawHead(); drawIdent(); drawAcc();
  if (registered) { await loadCfg(); drawCfg(); }
  await Promise.all([drawStats(), drawLog()]);
  every(drawStats, 6000);
  every(drawLog, 3000);
  every(async () => { await loadDir(); const f = isGroup ? DIR.groups.find(g => g.id === ent.id) : DIR.clients.find(c => c.key === ent.key || c.id === ent.id); if (f && !(document.activeElement && ['INPUT', 'SELECT'].includes(document.activeElement.tagName))) { ent = f; drawAcc(); } }, 10000);
}
pages.client = (token, key) => entityPage(token, 'client', key);
pages.group = (token, key) => entityPage(token, 'group', key);

// ---------- accès réseau ----------

pages.access = async function (token) {
  let q = '';
  main.innerHTML = `<div class="head"><div><h1>Accès réseau</h1><p>Couper l'accès à Internet, au réseau local, ou aux deux, pour un client ou un groupe. Le blocage peut être temporaire.</p></div></div>
    <div class="card"><div class="row" style="margin-bottom:12px"><input class="f grow" id="aq" type="search" placeholder="Rechercher un client ou un groupe" aria-label="Rechercher">
      <label class="row"><span class="muted">Durée à l'activation</span><select class="f" id="adur" style="width:auto"><option value="0">Jusqu'au rétablissement</option><option value="60">1 heure</option><option value="240">4 heures</option><option value="1440">24 heures</option></select></label></div>
      <div class="tblwrap"><table><thead><tr><th>Nom</th><th>Type</th><th>Internet</th><th>Réseau local</th><th>État</th><th>Filtres</th><th></th></tr></thead><tbody id="atb"></tbody></table></div>
      <p class="note" style="margin-top:12px"><b>Suspendre les filtres</b> laisse passer toutes les requêtes d'un client ou d'un groupe pendant la durée choisie (listes et règles ignorées), puis le filtrage revient tout seul. Les réécritures, zones locales et blocages d'accès restent appliqués.</p><p class="note" style="margin-top:8px">Le blocage agit au niveau du DNS : l'appareil ne trouve plus les adresses demandées. Un appareil qui se connecte à une adresse IP directe, ou qui utilise un autre serveur DNS (DNS privé d'un téléphone, DoH d'un navigateur), n'est pas arrêté. Pour une coupure réseau réelle, ajoute une règle sur le routeur.</p></div>`;
  function rows() {
    const term = q.trim().toLowerCase();
    const items = [
      ...DIR.groups.map(g => ({ ...g, kind: 'group', label: g.name })),
      ...DIR.clients.map(c => ({ ...c, kind: 'client', label: cLabel(c) })),
    ].filter(o => !term || (o.label + ' ' + (o.ids || []).join(' ')).toLowerCase().includes(term));
    $('#atb').innerHTML = items.length ? items.map(o => {
      const t = blockInfo(o), bi = t.includes('Internet'), bl = t.includes('LAN'), id = o.kind === 'group' ? o.id : (o.id || '');
      const link = o.kind === 'group' ? `#group/${encodeURIComponent(o.id)}` : keyHref(o.key);
      return `<tr><td><a href="${link}"><b>${esc(o.label)}</b></a>${o.kind === 'client' && !o.id ? ' <span class="tag">non enregistré</span>' : ''}<div class="mono muted" style="font-size:11px">${esc((o.ids || []).join(', '))}</div></td>
        <td>${o.kind === 'group' ? 'Groupe' : 'Client'}</td>
        <td>${sw(bi, `data-a="internet" data-k="${o.kind}" data-key="${esc(o.key || o.id)}"`)}</td><td>${sw(bl, `data-a="lan" data-k="${o.kind}" data-key="${esc(o.key || o.id)}"`)}</td>
        <td>${accessTags(o)}</td><td>${bypassCell(o)}</td><td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-all="${o.kind}:${esc(o.key || o.id)}">Tout bloquer</button><button class="btn sm" data-none="${o.kind}:${esc(o.key || o.id)}" ${bi || bl ? '' : 'disabled'}>Rétablir</button></td></tr>`;
    }).join('') : '<tr><td colspan="7" class="empty">Aucun client ni groupe</td></tr>';
  }
  const bypassCell = o => {
    const k = `${o.kind}:${esc(o.key || o.id)}`, b = bypassUntil(o);
    return b ? `<span class="tag ok">suspendus jusqu'à ${until(b)}</span> <button class="btn sm" data-w data-bp="${k}" data-min="0">Reprendre</button>`
      : `<span class="row" style="flex-wrap:nowrap;gap:4px" data-w><select class="f" data-bpdur style="width:auto" aria-label="Durée">${BYPASS_OPTS}</select><button class="btn sm" data-bp="${k}">Suspendre</button></span>`;
  };
  async function apply(kind, key, patch, keepBlock) {
    const minutes = +$('#adur').value;
    let o = kind === 'group' ? DIR.groups.find(g => g.id === key) : DIR.clients.find(c => c.key === key);
    if (!o) return;
    const col = kind === 'group' ? 'groups' : 'clients';
    let id = o.id;
    if (kind === 'client' && !id) { const r = await api('POST', 'c/clients', { name: o.ids[0], ids: o.ids }); id = r.id; }
    const cur = (await get('c/' + col)).find(x => x.id === id) || {};
    const next = { ...cur, ...patch };
    if (!keepBlock) next.block_until = (next.block_internet || next.block_lan) ? (minutes ? Date.now() + minutes * 60000 : null) : null;
    delete next.id; delete next.updated_at;
    await api('PUT', `c/${col}/${id}`, next);
    await loadDir(); rows();
  }
  main.onchange = guard(async e => {
    const a = e.target.dataset.a; if (!a) return;
    await apply(e.target.dataset.k, e.target.dataset.key, a === 'internet' ? { block_internet: e.target.checked } : { block_lan: e.target.checked });
    toast(e.target.checked ? 'Blocage activé' : 'Blocage levé');
  });
  main.onclick = guard(async e => {
    const bp = e.target.closest('[data-bp]');
    if (bp) {
      const [bk, bkey] = bp.dataset.bp.split(/:(.+)/);
      const sel = bp.parentElement.querySelector('[data-bpdur]');
      const mins = bp.dataset.min !== undefined ? +bp.dataset.min : +sel.value;
      await apply(bk, bkey, { filter_bypass_until: mins ? Date.now() + mins * 60000 : null }, true);
      toast(mins ? `Filtres suspendus pendant ${mins >= 60 ? mins / 60 + ' h' : mins + ' min'}` : 'Filtrage rétabli');
      return;
    }
    const t = e.target.closest('[data-all],[data-none]'); if (!t) return;
    const [k, key] = (t.dataset.all || t.dataset.none).split(/:(.+)/);
    await apply(k, key, t.dataset.all ? { block_internet: true, block_lan: true } : { block_internet: false, block_lan: false });
    toast(t.dataset.all ? 'Accès bloqué' : 'Accès rétabli');
  });
  main.oninput = e => { if (e.target.id === 'aq') { q = e.target.value; rows(); } };
  await loadDir(); rows();
  every(async () => { if (document.activeElement && ['INPUT', 'SELECT'].includes(document.activeElement.tagName)) return; await loadDir(); rows(); }, 8000);
};

// ---------- cache ----------

pages.cache = async function (token) {
  let q = '', selected = new Set(), data = { entries: [] }, info = {};
  main.innerHTML = `<div class="head"><div><h1>Cache DNS</h1><p>Réponses mémorisées par ce nœud. Supprimer une entrée force une nouvelle résolution à la prochaine requête.</p></div>
    <div class="row"><button class="btn danger" id="flush">Vider tout le cache</button></div></div>
    <div id="ctiles"></div><div id="cdiag"></div>
    <div class="card"><h2>Tester la résolution</h2><div class="row"><input class="f grow" id="ctd" placeholder="exemple.com" aria-label="Domaine à résoudre"><select class="f" id="ctt" style="width:auto" aria-label="Type"><option>A</option><option>AAAA</option><option>HTTPS</option><option>MX</option><option>TXT</option></select><button class="btn pri" id="ctest">Résoudre</button></div>
      <div class="out" id="ctout" style="margin-top:12px" aria-live="polite"><span class="muted">Résout le nom avec ce nœud, comme le ferait un appareil. Le résultat entre dans le cache : relance deux fois pour voir « depuis le cache ».</span></div></div>
    <div class="card"><div class="row" style="margin-bottom:12px"><input class="f grow" id="cq" type="search" placeholder="Rechercher un domaine" aria-label="Rechercher dans le cache">
      <button class="btn" id="delsel" disabled>Supprimer la sélection</button><span class="muted" id="ccount"></span></div>
      <div class="tblwrap"><table><thead><tr><th><input type="checkbox" id="selall" aria-label="Tout sélectionner"></th><th>Domaine</th><th>Type</th><th>Réponse</th><th>Expire dans</th><th>Taille</th><th></th></tr></thead><tbody id="ctb"></tbody></table></div>
      <p class="note" style="margin-top:12px">Le cache est propre à chaque nœud : une suppression ici ne touche pas celui des autres nœuds. Les réponses des zones locales et des réécritures ne passent pas par le cache.</p></div>`;
  const key = e => e.name + '|' + e.type;
  const ttlText = s => (s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.floor(s % 3600 / 60)} min` : s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`);
  function draw() {
    if (token !== routeToken) return;
    const rate = data.hits + data.misses ? Math.round(data.hits / (data.hits + data.misses) * 100) : 0;
    $('#ctiles').innerHTML = `<div class="tiles"><div class="tile"><small>Entrées</small><strong>${num(data.total || 0)}</strong><span>capacité ${num(data.capacity || 0)}</span></div>
      <div class="tile"><small>Taux de réussite</small><strong>${rate} %</strong><span>${num(data.hits || 0)} réussites · ${num(data.misses || 0)} échecs</span></div>
      <div class="tile"><small>État</small><strong>${data.enabled === false ? 'Désactivé' : 'Actif'}</strong><span>depuis le démarrage</span></div></div>`;
    const keys = new Set(data.entries.map(key));
    selected = new Set([...selected].filter(k => keys.has(k)));
    $('#ctb').innerHTML = data.entries.length ? data.entries.map(e => `<tr><td><input type="checkbox" data-sel="${esc(key(e))}" ${selected.has(key(e)) ? 'checked' : ''} aria-label="Sélectionner ${esc(e.name)}"></td>
      <td class="mono">${esc(e.name)}</td><td><span class="tag acc">${esc(e.type)}</span></td>
      <td class="mono wrap">${e.answers.length ? esc(e.answers.join(', ')) : `<span class="muted">${e.rcode === 3 ? 'NXDOMAIN' : e.rcode === 0 ? 'sans adresse' : 'code ' + e.rcode}</span>`}</td>
      <td>${ttlText(e.ttl)}</td><td>${e.size} o</td><td><button class="btn sm danger" data-one="${esc(key(e))}">Supprimer</button></td></tr>`).join('')
      : `<tr><td colspan="7" class="empty">${q ? 'Aucune entrée ne correspond' : 'Le cache est vide'}</td></tr>`;
    const reasons = [];
    if (!info.dns_ok) reasons.push(`Le serveur DNS de ce nœud n'écoute pas${info.dns_error ? ' (' + info.dns_error + ')' : ''} : aucune requête n'arrive, donc le cache reste vide.`);
    if (data.enabled === false) reasons.push('Le cache est désactivé dans les paramètres DNS.');
    if (!data.entries.length && !q && !reasons.length) reasons.push("Aucune réponse n'est en cache. Les appareils interrogent peut-être l'autre nœud, ou les réponses ont expiré (certains sites utilisent des durées de 30 secondes). Utilise le test ci-dessous pour vérifier que ce nœud met bien les réponses en cache.");
    $('#cdiag').innerHTML = reasons.length ? `<div class="card" style="border-color:var(--warn);margin-bottom:14px"><b>Pourquoi la liste est vide ?</b><ul style="margin:8px 0 0;padding-left:18px">${reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul></div>` : '';
    $('#ccount').textContent = q ? `${data.entries.length} sur ${data.total}` : '';
    $('#delsel').disabled = !selected.size;
    $('#delsel').textContent = selected.size ? `Supprimer la sélection (${selected.size})` : 'Supprimer la sélection';
    $('#selall').checked = data.entries.length > 0 && selected.size === data.entries.length;
  }
  async function load() { [data, info] = await Promise.all([get('cache?limit=1000&search=' + encodeURIComponent(q)), get('info')]); draw(); }
  const toEntries = list => list.map(k => { const i = k.lastIndexOf('|'); return { name: k.slice(0, i), type: k.slice(i + 1) }; });
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.id === 'ctest') {
      const r = await api('POST', 'resolve', { domain: $('#ctd').value, type: $('#ctt').value });
      const [tag, cls] = RESULT[r.result] || [r.result, ''];
      $('#ctout').innerHTML = `<span class="tag ${cls}">${tag}</span> ${r.cached ? '<span class="tag ok">depuis le cache</span>' : ''}${r.ad ? ' <span class="tag ok">DNSSEC</span>' : ''} en ${r.ms} ms${r.upstream ? ' via ' + esc(r.upstream) : ''}
        <div class="mono" style="margin-top:6px">${r.answers.length ? esc(r.answers.join(', ')) : (r.rcode === 3 ? 'NXDOMAIN' : r.rcode ? 'code ' + r.rcode : 'aucune adresse')}</div>${r.reason ? `<div class="muted mono" style="margin-top:4px">${esc(r.reason)}</div>` : ''}`;
      await load(); return;
    }
    if (t.id === 'flush') {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer : tout vider'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Vider tout le cache'; }, 3000); return; }
      const r = await api('POST', 'cache/flush'); toast(`${r.deleted} entrée(s) supprimée(s)`); selected.clear(); t.textContent = 'Vider tout le cache'; t.dataset.sure = ''; await load();
    } else if (t.id === 'delsel') {
      const r = await api('POST', 'cache/delete', { entries: toEntries([...selected]) }); toast(`${r.deleted} entrée(s) supprimée(s)`); selected.clear(); await load();
    } else if (t.dataset.one) {
      const r = await api('POST', 'cache/delete', { entries: toEntries([t.dataset.one]) }); toast(`${r.deleted} entrée supprimée`); selected.delete(t.dataset.one); await load();
    }
  });
  main.onchange = e => {
    if (e.target.id === 'selall') { selected = e.target.checked ? new Set(data.entries.map(key)) : new Set(); draw(); }
    else if (e.target.dataset.sel) { e.target.checked ? selected.add(e.target.dataset.sel) : selected.delete(e.target.dataset.sel); draw(); }
  };
  let deb;
  main.oninput = e => { if (e.target.id === 'cq') { q = e.target.value; clearTimeout(deb); deb = setTimeout(() => load().catch(fail), 250); } };
  await load();
  every(async () => { if (document.activeElement && document.activeElement.id === 'cq') return; await load(); }, 5000);
};

// ---------- réécritures DNS ----------

pages.rewrites = async function (token) {
  let rws = [], editing = null, scope = null;
  main.innerHTML = `<div class="head"><div><h1>Réécritures DNS</h1><p>Un domaine répond avec l'adresse (ou le nom) de ton choix. Les jokers sont acceptés : <span class="mono">*.apps.maison.lan</span>. Une réécriture peut être limitée à des clients ou des groupes.</p></div>
    <label class="row"><span class="muted">Toutes les réécritures</span>${sw(true, 'id="rwall"')}</label></div>
    <div class="card"><div class="tblwrap"><table><thead><tr><th>Actif</th><th>Domaine</th><th>Réponse</th><th>Portée</th><th>Expire</th><th></th></tr></thead><tbody id="rt"></tbody></table></div></div>
    <div class="card"><h2 id="rh">Ajouter une réécriture</h2><div class="stack">
      <div class="row"><input class="f grow" id="rd" placeholder="nas.maison.lan" aria-label="Domaine"><input class="f grow" id="ra" placeholder="192.168.1.20 ou autre.domaine.lan" aria-label="Réponse">
        <select class="f" id="rx" style="width:auto" aria-label="Expiration"><option value="keep" hidden>Conserver l'expiration</option><option value="0">Sans expiration</option><option value="60">Pendant 1 h</option><option value="120">Pendant 2 h</option><option value="1440">Pendant 24 h</option></select></div>
      <div class="row" style="align-items:flex-start"><span class="muted" style="padding-top:8px">Portée</span><div id="rscope" class="grow"></div></div>
      <div class="row"><button class="btn pri" id="radd">Ajouter</button><button class="btn" id="rcancel" hidden>Annuler</button></div></div></div>`;
  async function draw() {
    const [r, set] = await Promise.all([get('c/rewrites'), getSettings()]);
    if (token !== routeToken) return;
    rws = r;
    $('#rwall').checked = set.rewrites_enabled;
    $('#rt').innerHTML = rws.length ? rws.map(r => `<tr><td>${sw(r.enabled, `data-tog="${r.id}"`)}</td><td class="mono">${esc(r.domain)}</td><td class="mono">${esc(r.answer)}</td><td>${scopeTags(r)}</td>
      <td>${r.expires_at ? (r.expires_at < Date.now() ? '<span class="tag warn">expirée</span>' : 'à ' + clock(r.expires_at)) : 'jamais'}</td>
      <td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-edit="${r.id}">Modifier</button><button class="btn sm danger" data-del="${r.id}">Supprimer</button></td></tr>`).join('') : '<tr><td colspan="6" class="empty">Aucune réécriture</td></tr>';
  }
  function reset() {
    editing = null; $('#rd').value = ''; $('#ra').value = ''; $('#rx').value = '0'; scope.set({});
    $('#radd').textContent = 'Ajouter'; $('#rh').textContent = 'Ajouter une réécriture'; $('#rcancel').hidden = true;
  }
  $('#radd').onclick = guard(async () => {
    const m = $('#rx').value;
    const body = { domain: $('#rd').value, answer: $('#ra').value, enabled: true, ...scope.get() };
    if (editing) {
      const old = rws.find(x => x.id === editing);
      body.enabled = old.enabled;
      body.expires_at = m === 'keep' ? old.expires_at : (+m ? Date.now() + +m * 60000 : null);
      await api('PUT', `c/rewrites/${editing}`, body);
      toast('Réécriture modifiée');
    } else {
      body.expires_at = +m ? Date.now() + +m * 60000 : null;
      await api('POST', 'c/rewrites', body);
      toast('Réécriture ajoutée');
    }
    reset(); draw();
  });
  $('#rcancel').onclick = reset;
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.dataset.del) { await api('DELETE', `c/rewrites/${t.dataset.del}`); if (editing === t.dataset.del) reset(); draw(); }
    else if (t.dataset.edit) {
      const r = rws.find(x => x.id === t.dataset.edit); editing = r.id;
      $('#rd').value = r.domain; $('#ra').value = r.answer; $('#rx').value = 'keep'; scope.set(r);
      $('#radd').textContent = 'Enregistrer'; $('#rh').textContent = 'Modifier une réécriture'; $('#rcancel').hidden = false; $('#rd').focus();
    }
  });
  main.onchange = guard(async e => {
    if (e.target.id === 'rwall') { await saveSettings({ rewrites_enabled: e.target.checked }); toast(e.target.checked ? 'Réécritures activées' : 'Réécritures désactivées'); return; }
    const id = e.target.dataset.tog; if (!id) return;
    const r = rws.find(x => x.id === id), body = { ...r }; delete body.id; delete body.updated_at; body.enabled = e.target.checked;
    await api('PUT', `c/rewrites/${id}`, body); draw();
  });
  await loadDir();
  scope = mountScope($('#rscope'), {});
  $('#rx').value = '0';
  await draw();
  every(async () => { if (document.activeElement && ['INPUT', 'SELECT'].includes(document.activeElement.tagName)) return; await draw(); }, 6000);
};
