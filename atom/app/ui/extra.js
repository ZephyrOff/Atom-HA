'use strict';
// Santé du cluster, recherche globale, détail d'une requête, autorisations temporaires, accès en lecture seule.

const dateFr = ms => new Date(ms).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
const daysTo = ms => Math.floor((ms - Date.now()) / 86400000);
function certTag(ms) {
  if (!ms) return '<span class="muted">–</span>';
  const d = daysTo(ms);
  const cls = d < 7 ? 'bad' : d < 30 ? 'warn' : 'ok';
  return `<span class="tag ${cls}" title="${esc(dateFr(ms))}">${d < 0 ? 'expiré' : d + ' j'}</span>`;
}
function remaining(until) {
  const s = Math.max(0, Math.round((until - Date.now()) / 1000));
  if (s < 90) return s + ' s';
  if (s < 5400) return Math.round(s / 60) + ' min';
  if (s < 129600) return Math.round(s / 3600) + ' h';
  return Math.round(s / 86400) + ' j';
}

// ---------- « Pourquoi cette requête ? » ----------

async function showWhy(r, host, names) {
  if (!r) return;
  let chk = null;
  try { chk = await api('POST', 'check', { domain: r.name, client: r.client, type: r.qtype }); } catch { /* ignoré */ }
  const [rt, rc] = RESULT[r.result] || [r.result, ''];
  const net = r.list === 'Accès réseau';
  const temp = r.list === 'Autorisation temporaire';
  const susp = r.list === 'Filtrage suspendu';
  let cause;
  if (r.result === 'blocked') {
    cause = net ? `Le client est soumis à un blocage d'accès réseau : <b>${esc(r.reason)}</b>. <a href="#access">Voir les accès réseau</a>.`
      : `Bloquée par la règle <b class="mono">${esc(r.reason)}</b>${r.list ? ` de la liste <b>${esc(r.list)}</b>` : ''}.`;
  } else if (r.result === 'rewritten') {
    cause = `Réponse réécrite : <b class="mono">${esc(r.reason)}</b>${r.list ? ` (liste <b>${esc(r.list)}</b>)` : ''}.`;
  } else if (r.result === 'zone') {
    cause = 'Répondue par une zone locale (enregistrements DNS d\'Atom).';
  } else if (susp) {
    cause = `Autorisée parce que le filtrage est suspendu (${esc(r.reason)}). <a href="#access">Voir les accès réseau</a>.`;
  } else if (temp) {
    cause = `Autorisée parce que le domaine est autorisé temporairement (<span class="mono">${esc(r.reason)}</span>).`;
  } else if (r.result === 'allowed' && r.reason) {
    cause = `Autorisée par l'exception <b class="mono">${esc(r.reason)}</b>${r.list ? ` (liste <b>${esc(r.list)}</b>)` : ''}.`;
  } else if (r.result === 'error') {
    cause = `Erreur de résolution : <span class="mono">${esc(r.reason || 'aucun upstream n\'a répondu')}</span>.`;
  } else {
    cause = `Aucune règle ne correspond. Réponse obtenue ${r.cached ? 'du cache' : `de l'upstream <b>${esc(r.upstream || '?')}</b>`}.`;
  }
  let today = '';
  if (chk && chk.result !== r.result) {
    const [t] = RESULT[chk.result] || [chk.result];
    today = `<p class="note" style="margin-top:10px">Aujourd'hui, ce domaine serait <b>${esc(t.toLowerCase())}</b>${chk.rule ? ` (règle <span class="mono">${esc(chk.rule)}</span>)` : ''} : la configuration a changé depuis cette requête.</p>`;
  }
  const canOff = r.result === 'blocked' && !net && r.reason && !/^(autorisation|réécriture)/i.test(r.reason);
  const acts = [];
  if (r.result === 'blocked' && !net) {
    acts.push(`<button class="btn sm" data-w data-allow="${esc(r.name)}">Autoriser pour toujours</button>`);
    acts.push(`<span class="row" data-w style="gap:4px"><select class="f" id="tmpm" style="width:auto"><option value="15">15 min</option><option value="60" selected>1 h</option><option value="1440">1 jour</option><option value="10080">7 jours</option></select><button class="btn sm" data-tmp="${esc(r.name)}">Autoriser temporairement</button></span>`);
    if (canOff) acts.push(`<button class="btn sm" data-w data-off="${esc(r.reason)}" title="Ajoute la règle avec $badfilter dans les règles personnalisées">Désactiver cette règle</button>`);
  } else if (r.result === 'allowed' || r.result === 'error') {
    acts.push(`<button class="btn sm" data-w data-block="${esc(r.name)}">Bloquer</button>`);
  }
  host.innerHTML = `<div class="card" style="margin-top:14px"><h2>Pourquoi cette requête ? <button class="btn sm" id="whyx">Fermer</button></h2>
    <div class="row" style="gap:8px 18px"><span class="mono"><b>${esc(r.name)}</b></span><span class="tag">${esc(r.qtype)}</span><span>${resTag(r.result, r.cached)}</span>
      <span class="muted">client <span class="mono">${esc(r.client)}</span> · nœud ${esc((names && names[r.node]) || r.node)} · ${r.ms} ms · ${esc(new Date(r.ts).toLocaleString('fr-FR'))}</span></div>
    <p style="margin-top:10px">${cause}</p>${today}
    ${acts.length ? `<div class="row" style="margin-top:12px">${acts.join('')}</div>` : ''}</div>`;
  $('#whyx').onclick = () => { host.innerHTML = ''; };
  host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ---------- santé du cluster ----------

const dur = s => {
  if (!s && s !== 0) return '–';
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d} j ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
};
const yesno = (v, a = 'oui', b = 'non') => v ? `<span class="tag ok">${a}</span>` : `<span class="tag">${b}</span>`;

pages.health = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Santé</h1><p>L'état de ce nœud et des autres : ce qui demande de l'attention d'abord, puis le détail des nœuds, des upstreams, des listes, des certificats et du stockage.</p></div></div><div id="hbody"></div>`;
  async function draw() {
    const h = await get('health');
    if (token !== routeToken) return;
    const me = h.self, d = me.detail, now = Date.now();
    const bad = h.problems.filter(p => p.level === 'bad').length, warn = h.problems.length - bad;
    const probs = h.problems.length
      ? `<div class="stack">${h.problems.map(p => `<div class="card prob ${p.level}"><span class="tag ${p.level === 'bad' ? 'bad' : 'warn'}">${p.level === 'bad' ? 'Important' : 'À surveiller'}</span> <b>${esc(p.scope)}</b> · ${esc(p.text)}</div>`).join('')}</div>`
      : '<div class="card prob ok"><span class="tag ok">Tout va bien</span> Tous les nœuds répondent, avec la même version et des certificats valides.</div>';
    const online = 1 + h.peers.filter(p => p.ok).length, total = 1 + h.peers.length;
    const upOn = h.upstreams.filter(u => u.enabled), upOk = upOn.filter(u => u.up === true).length;
    const lsOn = h.lists.filter(l => l.enabled), lsErr = lsOn.filter(l => l.error).length;
    const days = [me.cert_expires, me.cluster_mode === 'pki' ? null : me.ca_expires, me.web_expires].filter(Boolean).map(daysTo);
    const minDays = days.length ? Math.min(...days) : null;
    const tile = (cls, label, val, sub) => `<div class="tile ${cls}"><small>${label}</small><strong>${val}</strong><span>${sub}</span></div>`;
    const sum = `<div class="hsum">
      ${tile(online === total ? 'good' : 'warn', 'Nœuds en ligne', `${online}/${total}`, total > 1 ? 'cluster' : 'nœud seul')}
      ${tile(!upOn.length || upOk === 0 ? 'bad' : upOk < upOn.length ? 'warn' : 'good', 'Upstreams', `${upOk}/${upOn.length}`, 'joignables')}
      ${tile(lsErr ? 'warn' : 'good', 'Listes', `${lsOn.length - lsErr}/${lsOn.length}`, lsErr ? `${lsErr} en échec` : 'à jour')}
      ${tile('', 'Requêtes (24 h)', num(d.queries_24h), `${d.queries_24h ? (d.blocked_24h / d.queries_24h * 100).toFixed(1).replace('.', ',') : 0} % bloquées`)}
      ${tile(minDays == null ? '' : minDays < 7 ? 'bad' : minDays < 30 ? 'warn' : 'good', 'Prochaine échéance', minDays == null ? '–' : minDays + ' j', 'certificats')}</div>`;

    const skew = ms => { const a = Math.abs(ms); return a < 1000 ? '< 1 s' : `${ms > 0 ? '+' : '−'}${Math.round(a / 1000)} s`; };
    const rows = [`<tr><td><b>${esc(me.name)}</b> <span class="tag acc">ce nœud</span></td><td><span class="dot up"></span>local</td><td class="mono">${esc(me.version)}</td><td>–</td><td>–</td><td>–</td><td>–</td><td>${dur(me.uptime_s)}</td><td>${num(d.rules_loaded)}</td><td>${num(d.cache.entries)}</td><td>${me.dns_ok ? '<span class="tag ok">actif</span>' : '<span class="tag bad">arrêté</span>'}</td><td>${certTag(me.cert_expires)}</td></tr>`]
      .concat(h.peers.map(p => `<tr><td><b>${esc(p.name)}</b><br><span class="muted mono" style="font-size:11px">${esc(p.url)}</span></td>
        <td>${p.ok ? '<span class="dot up"></span>joint' : `<span class="dot down"></span><span title="${esc(p.last_error || '')}">injoignable</span>`}</td>
        <td class="mono">${p.version ? `<span class="${p.version !== me.version ? 'tag warn' : ''}">${esc(p.version)}</span>` : '<span class="muted">inconnue</span>'}</td>
        <td>${p.ok ? p.latency_ms + ' ms' : '–'}</td><td>${ago(p.last_ok)}</td>
        <td>${p.ok ? (p.behind_ops ? `<span class="tag warn">${p.behind_ops}</span>` : '<span class="tag ok">à jour</span>') : '–'}</td>
        <td>${p.ok ? `<span class="${Math.abs(p.skew_ms) > 5000 ? 'tag warn' : ''}">${skew(p.skew_ms)}</span>` : '–'}</td>
        <td>${p.ok ? dur(p.uptime_s) : '–'}</td><td>${p.ok ? num(p.rules_loaded) : '–'}</td><td>${p.ok ? num(p.cache_entries) : '–'}</td>
        <td>${p.dns_ok == null ? '–' : p.dns_ok ? '<span class="tag ok">actif</span>' : '<span class="tag bad">arrêté</span>'}</td><td>${certTag(p.cert_expires)}</td></tr>`));

    const cacheTot = d.cache.hits + d.cache.misses;
    const thisNode = `<div class="card"><h2>Ce nœud</h2><div class="kv">
      <div><small>Version</small><b>${esc(me.version)}</b></div>
      <div><small>En fonctionnement depuis</small><b>${dur(me.uptime_s)}</b></div>
      <div><small>Serveur DNS</small><b>${esc(d.dns_listen)} ${me.dns_ok ? '<span class="tag ok">actif</span>' : `<span class="tag bad">arrêté</span>`}</b>${d.dns_error ? `<small style="color:var(--bad)">${esc(d.dns_error)}</small>` : ''}</div>
      <div><small>Interface web</small><b>${esc(d.http_listen)}</b></div>
      <div><small>HTTPS</small><b>${d.tls.web_enabled ? (d.tls.listening ? `port ${d.tls.web_port} <span class="tag ok">actif</span>` : '<span class="tag bad">erreur</span>') : '<span class="muted">désactivé</span>'}${d.tls.redirect_http ? ' · redirection' : ''}</b>${d.tls.error ? `<small style="color:var(--bad)">${esc(d.tls.error)}</small>` : ''}</div>
      <div><small>Chiffrement du cluster</small><b>${({ off: 'désactivé', ca: 'autorité du cluster', selfsigned: 'auto-signés', pki: 'PKI privée' })[d.tls.cluster_mode] || esc(d.tls.cluster_mode)}</b></div>
      <div><small>Filtrage</small><b>${d.filtering_enabled ? (d.paused_until ? `<span class="tag warn">en pause jusqu'à ${clock(d.paused_until)}</span>` : '<span class="tag ok">actif</span>') : '<span class="tag bad">désactivé</span>'}</b></div>
      <div><small>Mode de blocage</small><b>${({ null_ip: 'adresse nulle', nxdomain: 'NXDOMAIN', refused: 'REFUSED' })[d.block_mode] || esc(d.block_mode)}</b></div>
      <div><small>Upstreams</small><b>${d.upstream_mode === 'parallel' ? 'en parallèle' : 'par priorité'}</b></div>
      <div><small>DNSSEC</small><b>${yesno(d.dnssec, 'demandé', 'non demandé')}</b></div>
      <div><small>Règles chargées</small><b>${num(d.rules_loaded)} <span class="muted">dont ${num(d.custom_rules)} perso</span></b></div>
      <div><small>Latence moyenne</small><b>${Math.round(d.avg_ms)} ms <span class="muted">hors cache, 24 h</span></b></div>
      <div><small>Cache</small><b>${num(d.cache.entries)} / ${num(d.cache.capacity)} ${d.cache.enabled ? '' : '<span class="tag">désactivé</span>'}</b><small>${cacheTot ? Math.round(d.cache.hits / cacheTot * 100) + ' % de réussite depuis le démarrage' : 'aucune requête depuis le démarrage'}</small></div>
      <div><small>Journal</small><b>${num(d.log_entries)} entrées</b></div>
      <div><small>Autorisations temporaires</small><b>${d.temp_allow}</b></div>
      <div><small>Sessions ouvertes</small><b>${d.auth.sessions}${d.auth.locked ? ` · <span class="tag warn">${d.auth.locked} IP bloquée${d.auth.locked > 1 ? 's' : ''}</span>` : ''}</b></div></div></div>`;

    const objs = d.store.objects;
    const store = `<div class="card"><h2>Configuration et stockage</h2><div class="kv">
      <div><small>Listes / règles</small><b>${objs.lists} listes · règles perso ${objs.rules ? 'oui' : 'non'}</b></div>
      <div><small>Upstreams</small><b>${objs.upstreams}</b></div>
      <div><small>Réécritures</small><b>${objs.rewrites}</b></div>
      <div><small>Zones / enregistrements</small><b>${objs.zones} / ${objs.records}</b></div>
      <div><small>Clients / groupes</small><b>${objs.clients} / ${objs.groups}</b></div>
      <div><small>Marqueurs de suppression</small><b>${d.store.tombstones}</b></div>
      <div><small>Conflits non résolus</small><b>${d.store.conflicts ? `<span class="tag warn">${d.store.conflicts}</span> <a href="#history">voir</a>` : '<span class="tag ok">aucun</span>'}</b></div></div></div>`;

    const ups = `<div class="card"><h2>Upstreams <small class="muted" style="font-weight:400">vus depuis ce nœud</small></h2><div class="tblwrap"><table><thead><tr><th>Nom</th><th>Adresse</th><th>État</th><th>Latence</th><th>Réussites</th><th>Dernière erreur</th></tr></thead><tbody>
      ${h.upstreams.length ? h.upstreams.map(u => { const t = u.ok_count + u.fail_count; return `<tr><td><b>${esc(u.name)}</b>${u.backup ? ' <span class="tag warn">secours</span>' : ''}</td><td class="mono muted">${esc(u.address)}</td>
        <td>${!u.enabled ? '<span class="tag">désactivé</span>' : u.up === true ? '<span class="dot up"></span>en ligne' : u.up === false ? '<span class="dot down"></span>hors service' : '<span class="dot"></span>inconnu'}</td>
        <td>${u.enabled && u.up && u.latency_ms != null ? u.latency_ms + ' ms' : '–'}</td><td>${t ? Math.round(u.ok_count / t * 100) + ' % <span class="muted">(' + num(t) + ' essais)</span>' : '–'}</td>
        <td class="wrap muted">${u.up === false ? esc(u.last_error || '') : ''}</td></tr>`; }).join('') : '<tr><td colspan="6" class="empty">Aucun upstream</td></tr>'}</tbody></table></div></div>`;

    const lists = `<div class="card"><h2>Listes de filtrage</h2><div class="tblwrap"><table><thead><tr><th>Nom</th><th>État</th><th>Règles</th><th>Dernière synchro</th><th>S'applique à</th></tr></thead><tbody>
      ${h.lists.length ? h.lists.map(l => `<tr><td><b>${esc(l.name)}</b></td>
        <td>${!l.enabled ? '<span class="tag">désactivée</span>' : l.kind === 'inline' ? '<span class="tag ok">locale</span>' : l.error ? `<span class="tag warn" title="${esc(l.error)}">échec${l.updated_at ? ' · ancienne copie' : ''}</span>` : l.updated_at ? '<span class="tag ok">à jour</span>' : '<span class="tag">en attente</span>'}</td>
        <td>${l.kind === 'inline' ? '–' : num(l.rules)}${l.unsupported ? ` <span class="muted">(${num(l.unsupported)} ignorées)</span>` : ''}</td>
        <td>${l.kind === 'url' ? ago(l.updated_at) : '–'}</td><td>${l.scoped ? `${l.scoped} cible${l.scoped > 1 ? 's' : ''}` : '<span class="muted">tous</span>'}</td></tr>${l.error && l.enabled ? `<tr><td colspan="5" class="wrap muted" style="color:var(--warn)">${esc(l.error)}</td></tr>` : ''}`).join('') : '<tr><td colspan="5" class="empty">Aucune liste</td></tr>'}</tbody></table></div></div>`;

    const cl = h.cert_log.length ? `<div class="card"><h2>Renouvellements automatiques</h2><div class="tblwrap"><table><tbody>${h.cert_log.map(c => `<tr><td class="mono">${esc(dateFr(c.ts))}</td><td class="wrap">${esc(c.text)}</td></tr>`).join('')}</tbody></table></div></div>` : '';
    const certs = [['Certificat du nœud', me.cert_expires, me.node_auto ? 'renouvelé automatiquement 30 jours avant l\'échéance' : me.cluster_mode === 'pki' ? 'ta PKI : à renouveler toi-même' : 'chiffrement du cluster inactif'],
      ['Autorité du cluster', me.cluster_mode === 'pki' ? null : me.ca_expires, 'valable 10 ans, non renouvelée automatiquement'],
      ['Interface web (HTTPS)', me.web_expires, me.web_auto ? 'renouvelé automatiquement 30 jours avant l\'échéance' : 'certificat importé : à renouveler toi-même']].filter(c => c[1]);
    $('#hbody').innerHTML = `${probs}${sum}
      <div class="card"><h2>Nœuds</h2><div class="tblwrap"><table><thead><tr><th>Nœud</th><th>État</th><th>Version</th><th>Latence</th><th>Dernière synchro</th><th>Retard</th><th>Horloge</th><th>Actif depuis</th><th>Règles</th><th>Cache</th><th>DNS</th><th>Certificat</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>
        <p class="note" style="margin-top:12px">« Retard » : modifications de configuration que le nœud n'a pas encore reçues de celui-ci. « Horloge » : écart estimé avec ce nœud ; au-delà de quelques secondes, les certificats et l'ordre des modifications peuvent poser problème.</p></div>
      <div class="stack" style="margin-top:14px">${thisNode}${ups}${lists}${store}
      ${certs.length ? `<div class="card"><h2>Certificats de ce nœud</h2><div class="tblwrap"><table><tbody>${certs.map(c => `<tr><td>${esc(c[0])}</td><td>${certTag(c[1])}</td><td class="muted">${esc(dateFr(c[1]))}</td><td class="wrap muted">${esc(c[2])}</td></tr>`).join('')}</tbody></table></div></div>` : ''}${cl}</div>`;
  }
  await draw();
  every(draw, 5000);
};

// ---------- autorisations temporaires (page Règles) ----------

{
  const orig = pages.rules;
  pages.rules = async function (token) {
    await orig(token);
    if (token !== routeToken) return;
    const card = document.createElement('div');
    card.className = 'card'; card.id = 'tmpcard'; card.style.marginTop = '14px';
    card.innerHTML = `<h2>Autorisations temporaires</h2>
      <p class="muted" style="margin-bottom:10px">Le filtrage est ignoré pour ce domaine et ses sous-domaines, puis revient tout seul. Utile quand un site casse.</p>
      <div class="row" data-w><input class="f grow" id="tad" placeholder="www.exemple.com" aria-label="Domaine"><select class="f" id="tam" style="width:auto"><option value="15">15 min</option><option value="60" selected>1 h</option><option value="1440">1 jour</option><option value="10080">7 jours</option></select><button class="btn pri" id="taadd">Autoriser</button></div>
      <div id="talist" style="margin-top:12px"></div>`;
    main.appendChild(card);
    async function draw() {
      const list = (await get('c/tempallow')).filter(t => t.until > Date.now()).sort((a, b) => a.until - b.until);
      if (token !== routeToken) return;
      $('#talist').innerHTML = list.length
        ? `<div class="tblwrap"><table><tbody>${list.map(t => `<tr><td class="mono">${esc(t.domain)}</td><td>encore ${remaining(t.until)}</td><td><button class="btn sm" data-w data-tadel="${esc(t.id)}">Retirer</button></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="empty" style="padding:8px">Aucune autorisation en cours</div>';
    }
    $('#taadd').onclick = guard(async () => {
      await api('POST', 'tempallow', { domain: $('#tad').value, minutes: +$('#tam').value });
      $('#tad').value = ''; toast('Domaine autorisé temporairement'); await draw();
    });
    main.onclick = guard(async e => {
      const t = e.target.closest('[data-tadel]');
      if (t) { await api('DELETE', 'c/tempallow/' + encodeURIComponent(t.dataset.tadel)); toast('Autorisation retirée'); await draw(); }
    });
    await draw();
    every(draw, 10000);
  };
}

// ---------- accès en lecture seule (page Sécurité) ----------

{
  const orig = pages.security;
  pages.security = async function (token, p) {
    await orig(token, p);
    if (token !== routeToken) return;
    const [ev, me] = await Promise.all([get('auth/events'), get('auth/me')]);
    if (token !== routeToken || me.readonly) return;
    const card = document.createElement('div');
    card.className = 'card'; card.style.marginTop = '14px';
    card.innerHTML = `<h2>Accès en lecture seule ${ev.readonly_enabled ? '<span class="tag ok">activé</span>' : '<span class="tag">désactivé</span>'}</h2>
      <p class="muted" style="margin-bottom:10px">Un second mot de passe pour consulter l'interface sans pouvoir rien modifier (écran mural, proche). À la connexion, l'utilisateur est <b class="mono">lecture</b>. Cet accès ne voit ni les jetons, ni les sauvegardes, ni les certificats, ni le code d'appairage. Ce réglage est propre à ce nœud.</p>
      <div class="row"><input class="f grow" id="rop" type="password" autocomplete="new-password" placeholder="Mot de passe de lecture seule (8 caractères minimum)" aria-label="Mot de passe de lecture seule"><button class="btn pri" id="rosave">${ev.readonly_enabled ? 'Changer le mot de passe' : 'Activer'}</button>${ev.readonly_enabled ? '<button class="btn danger" id="rooff">Supprimer cet accès</button>' : ''}</div>`;
    main.appendChild(card);
    const set = guard(async pw => { await api('POST', 'auth/readonly', { password: pw }); toast(pw ? 'Accès en lecture seule enregistré' : 'Accès en lecture seule supprimé'); route(); });
    $('#rosave').onclick = () => set($('#rop').value);
    if ($('#rooff')) $('#rooff').onclick = () => set('');
    // adresses d'écoute (DNS et interface web)
    const L = await get('listen');
    if (token !== routeToken) return;
    const lc = document.createElement('div');
    lc.className = 'card';
    const opt = (cur, v, label) => `<option value="${v}" ${cur === v ? 'selected' : ''}>${label}</option>`;
    const sel = (id, cur, locked) => `<select class="f" id="${id}" ${locked ? 'disabled' : ''}>${opt(cur, '0.0.0.0', '0.0.0.0 : tout le réseau')}${opt(cur, '127.0.0.1', '127.0.0.1 : cette machine seulement')}</select>`;
    lc.innerHTML = `<h2>Adresses d'écoute</h2>
      <p class="muted" style="margin-bottom:10px">Choisis qui peut joindre le serveur DNS (port ${esc(L.dns.port)}) et l'interface web (port ${esc(L.http.port)}). En <b class="mono">127.0.0.1</b>, seule cette machine y accède. Le changement s'applique au prochain redémarrage d'Atom.</p>
      <div class="cols"><label class="lbl">Serveur DNS${sel('lbd', L.dns.host)}</label>
      <label class="lbl">Interface web${sel('lbh', L.http.host, L.ingress)}${L.ingress ? '<span class="muted">Imposé en 0.0.0.0 avec l’accès Home Assistant.</span>' : ''}</label></div>
      <div class="row" style="margin-top:12px"><button class="btn pri" id="lbsave">Enregistrer</button><span class="muted" id="lbinfo">Actuellement : DNS ${esc(L.dns.host)} · web ${esc(L.http.host)}</span></div>`;
    main.appendChild(lc);
    $('#lbsave').onclick = guard(async () => {
      const dns = $('#lbd').value, http = $('#lbh').value;
      if (http === '127.0.0.1' && !confirm('Après le redémarrage, l’interface ne sera plus accessible depuis un autre appareil que cette machine. Continuer ?')) return;
      await api('POST', 'listen', { dns, http });
      toast('Enregistré : redémarre Atom pour appliquer');
      $('#lbinfo').textContent = 'À appliquer : redémarre Atom (add-on, service ou conteneur).';
    });
  };
}

// ---------- recherche globale ----------

{
  const ov = $('#sov'), inp = $('#sq'), res = $('#sres');
  let items = [], sel = 0, deb, seq = 0;
  const open = () => { ov.hidden = false; inp.value = ''; res.innerHTML = '<p class="muted" style="padding:8px">Tape un domaine pour savoir s\'il est bloqué, ou un nom pour retrouver un client, une règle, une réécriture…</p>'; items = []; inp.focus(); };
  const close = () => { ov.hidden = true; };
  const go = i => { const it = items[i]; if (!it) return; close(); location.hash = '#' + it.route.split('#')[0]; };
  function paint() {
    res.querySelectorAll('.sit').forEach((el, i) => el.classList.toggle('on', i === sel));
  }
  async function run() {
    const q = inp.value.trim(), my = ++seq;
    if (!q) return;
    let r;
    try { r = await get('search?q=' + encodeURIComponent(q)); } catch (e) { res.innerHTML = `<p class="muted" style="padding:8px">${esc(e.message)}</p>`; return; }
    if (my !== seq) return;
    items = r.results; sel = 0;
    let html = '';
    if (r.verdict) {
      const v = r.verdict, [t, c] = RESULT[v.result] || [v.result, ''];
      html += `<div class="sverdict"><span class="tag ${c}">${esc(t)}</span> <b class="mono">${esc(v.domain)}</b> ${v.rule ? `par <span class="mono">${esc(v.rule)}</span>${v.list ? ` <span class="muted">(${esc(v.list)})</span>` : ''}` : `<span class="muted">${esc(v.detail || '')}</span>`}</div>`;
    }
    html += items.length ? items.map((it, i) => `<button class="sit" data-i="${i}" type="button"><span class="tag acc">${esc(it.kind)}</span><span class="mono grow">${esc(it.title)}</span><span class="muted">${esc(it.detail)}</span></button>`).join('')
      : (r.verdict ? '' : '<p class="muted" style="padding:8px">Aucun résultat</p>');
    res.innerHTML = html; paint();
  }
  inp.oninput = () => { clearTimeout(deb); deb = setTimeout(run, 200); };
  inp.onkeydown = e => {
    if (e.key === 'ArrowDown') { sel = Math.min(items.length - 1, sel + 1); paint(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { sel = Math.max(0, sel - 1); paint(); e.preventDefault(); }
    else if (e.key === 'Enter') go(sel);
  };
  res.onclick = e => { const b = e.target.closest('.sit'); if (b) go(+b.dataset.i); };
  ov.onclick = e => { if (e.target === ov) close(); };
  $('#searchbtn').onclick = open;
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !ov.hidden) close();
    else if (e.key === '/' && ov.hidden && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && !e.ctrlKey && !e.metaKey) { e.preventDefault(); open(); }
  });
}

// ---------- mode lecture seule ----------

get('auth/me').then(m => {
  if (m.readonly) { document.body.classList.add('ro'); $('#robanner').hidden = false; }
}).catch(() => {});

// ---------- menu sur petit écran ----------

{
  const side = $('#side'), btn = $('#menubtn');
  const set = open => {
    side.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? '✕ Fermer' : '☰ Menu';
  };
  btn.onclick = () => set(!side.classList.contains('open'));
  $('#nav').addEventListener('click', e => { if (e.target.closest('a')) set(false); });
  $('#searchbtn').addEventListener('click', () => set(false));
  window.addEventListener('hashchange', () => set(false));
  matchMedia('(min-width: 821px)').addEventListener('change', e => { if (e.matches) set(false); });
}

// ---------- menu en groupes repliables ----------

{
  const KEY = 'atom-nav';
  let saved = [];
  try { saved = JSON.parse(localStorage.getItem(KEY) || '[]'); } catch { /* stockage indisponible */ }
  const grps = $$('#nav .grp');
  const store = () => { try { localStorage.setItem(KEY, JSON.stringify(grps.filter(g => g.classList.contains('open')).map(g => g.dataset.g))); } catch { /* ignoré */ } };
  const setOpen = (g, open) => { g.classList.toggle('open', open); $('.gh', g).setAttribute('aria-expanded', String(open)); };
  grps.forEach(g => setOpen(g, saved.includes(g.dataset.g)));
  // Le groupe de la page affichée est toujours ouvert et repéré par sa pastille.
  window.syncNav = () => {
    grps.forEach(g => {
      const cur = !!$('a.on', g);
      g.classList.toggle('cur', cur);
      if (cur) setOpen(g, true);
    });
    store();
  };
  $('#nav').addEventListener('click', e => {
    const h = e.target.closest('.gh');
    if (!h) return;
    const g = h.parentElement;
    setOpen(g, !g.classList.contains('open'));
    store();
  });
  syncNav();
}
