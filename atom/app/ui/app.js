'use strict';
// Interface web d'Atom. Chemins relatifs partout, pour fonctionner derrière l'ingress de Home Assistant.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const main = $('#main');
let timers = [];
let routeToken = 0;

async function api(method, path, body) {
  const r = await fetch('api/' + path, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json', 'x-atom': '1' } : { 'x-atom': '1' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { location.href = 'login.html'; throw new Error('Session expirée'); }
  let j = null;
  try { j = await r.json(); } catch { /* corps vide */ }
  if (!r.ok) throw new Error((j && j.error) || r.statusText);
  return j;
}
const get = p => api('GET', p);

let toastT;
function toast(msg, err) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show' + (err ? ' err' : '');
  clearTimeout(toastT);
  toastT = setTimeout(() => (t.className = ''), err ? 4500 : 2200);
}
const fail = e => toast(e.message || String(e), true);
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { fail(e); } };

function every(fn, ms) { timers.push(setInterval(() => { fn().catch(() => {}); }, ms)); }
function ago(ms) {
  if (!ms) return 'jamais';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 5) return "à l'instant";
  if (s < 60) return `il y a ${s} s`;
  if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`;
  return `il y a ${Math.round(s / 86400)} j`;
}
const clock = ms => new Date(ms).toLocaleTimeString('fr-FR');
const num = n => Number(n).toLocaleString('fr-FR');
function sw(checked, attrs = '') { return `<label class="sw"><input type="checkbox" ${checked ? 'checked' : ''} ${attrs}><i></i></label>`; }

async function getSettings() { return (await get('c/settings')).find(s => s.id === 'main') || {}; }
async function saveSettings(patch) {
  const s = { ...(await getSettings()), ...patch };
  delete s.id; delete s.updated_at;
  await api('PUT', 'c/settings/main', s);
}

const RESULT = {
  allowed: ['Autorisée', 'ok'], blocked: ['Bloquée', 'bad'], rewritten: ['Réécrite', 'acc'],
  zone: ['Zone locale', 'acc'], error: ['Erreur', 'warn'],
};
const resTag = (r, cached) => {
  const [t, c] = RESULT[r] || [r, ''];
  return `<span class="tag ${c}">${t}${cached ? ' · cache' : ''}</span>`;
};

// ---------- pages ----------

const pages = {};

pages.dashboard = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Tableau de bord</h1><p>Dernières 24 heures, tous les nœuds du cluster.</p></div>
    <div class="row" id="dctl"></div></div><div id="dbody"></div>`;
  async function draw() {
    const [info, st, set, cl] = await Promise.all([get('info'), get('stats'), getSettings(), get('cluster')]);
    if (token !== routeToken) return;
    const pct = st.total ? (st.blocked / st.total * 100) : 0;
    const paused = info.paused_until;
    $('#dctl').innerHTML = paused
      ? `<span class="tag warn">Filtrage en pause jusqu'à ${clock(paused)}</span><button class="btn" data-a="resume">Reprendre</button>`
      : `<span class="muted">Pause :</span>${[5, 30, 60].map(m => `<button class="btn sm" data-pause="${m}">${m} min</button>`).join('')}
         <span class="row" style="margin-left:8px">Filtrage ${sw(set.filtering_enabled, 'data-a="filtering"')}</span>`;
    const max = Math.max(10, ...st.hours.map(h => h[0]));
    const nice = (() => { const p = Math.pow(10, Math.floor(Math.log10(max))); const n = Math.ceil(max / p) * p; return n % 4 ? Math.ceil(n / 4) * 4 : n; })();
    const W = 720, H = 190, L = 40, B = 22, T = 8, ch = H - B - T, cw = W - L - 4, bw = cw / 24;
    let svg = '';
    for (let i = 0; i <= 4; i++) {
      const v = nice / 4 * i, y = T + ch - v / nice * ch;
      svg += `<line x1="${L}" x2="${W - 4}" y1="${y}" y2="${y}"/><text x="${L - 6}" y="${y + 3}" text-anchor="end">${v >= 1000 ? (v / 1000).toFixed(v % 1000 ? 1 : 0) + 'k' : Math.round(v)}</text>`;
    }
    const nowH = new Date().getHours();
    st.hours.forEach((h, i) => {
      const ok = h[0] - h[1], x = L + i * bw + 2, w = bw - 4, hg = ok / nice * ch, hb = h[1] / nice * ch;
      svg += `<rect x="${x}" y="${T + ch - hg - hb}" width="${w}" height="${hg}" fill="var(--accent)"/><rect x="${x}" y="${T + ch - hb}" width="${w}" height="${hb}" fill="var(--bad)"/>`;
      if (i % 4 === 3) svg += `<text x="${x + w / 2}" y="${H - 6}" text-anchor="middle">${String((nowH - (23 - i) + 24) % 24).padStart(2, '0')}h</text>`;
    });
    const rank = (list, cls) => {
      const m = Math.max(1, ...list.map(x => x[1]));
      return list.length ? `<div class="rank ${cls}">${list.map(([n, c]) => `<div><span title="${esc(n)}">${esc(n)}</span><span class="mono">${num(c)}</span><u style="width:${c / m * 100}%"></u></div>`).join('')}</div>` : '<div class="empty">Aucune donnée</div>';
    };
    const nodes = Object.entries(st.per_node).map(([id, c]) => `<tr><td>${esc(st.node_names[id] || id)}</td><td>${num(c)}</td></tr>`).join('');
    let hp = [];
    try { hp = (await get('health')).problems; } catch { /* ignoré */ }
    $('#dbody').innerHTML = `${hp.length ? `<a class="card hbanner ${hp.some(p => p.level === 'bad') ? 'bad' : 'warn'}" href="#health"><b>${hp.length} problème${hp.length > 1 ? 's' : ''} détecté${hp.length > 1 ? 's' : ''}</b> : ${esc(hp[0].scope)} · ${esc(hp[0].text)}${hp.length > 1 ? ` <span class="muted">et ${hp.length - 1} autre(s)</span>` : ''}</a>` : ''}${info.dns_error || !info.dns_ok ? `<div class="card" style="border-color:var(--bad);margin-bottom:14px"><b style="color:var(--bad)">Le serveur DNS de ce nœud n'écoute pas.</b> ${info.dns_error ? `<span class="mono">${esc(info.dns_error)}</span>` : ''}<p class="muted" style="margin-top:6px">Aucun appareil ne peut l'interroger. Le plus souvent, le port 53 est déjà utilisé (systemd-resolved, dnsmasq, un autre serveur DNS) ou demande des droits supplémentaires. Voir le README, section « Installation ».</p></div>` : ''}
      <div class="tiles">
        <div class="tile"><small>Requêtes</small><strong>${num(st.total)}</strong></div>
        <div class="tile"><small>Bloquées</small><strong>${pct.toFixed(1).replace('.', ',')} %</strong><span>${num(st.blocked)} requêtes</span></div>
        <div class="tile"><small>Latence moyenne</small><strong>${Math.round(st.avg_ms)} ms</strong><span>hors cache</span></div>
        <div class="tile"><small>Réponses du cache</small><strong>${st.total ? Math.round(st.cached / st.total * 100) : 0} %</strong><span>${num(st.cached)} requêtes</span></div>
        <div class="tile"><small>Règles chargées</small><strong>${num(info.rules_loaded)}</strong><span>${cl.peers.length + 1} nœud(s)</span></div>
      </div>
      <div class="card"><h2>Requêtes par heure <span class="row muted" style="font-weight:400;font-size:12px"><span><span class="dot" style="background:var(--accent)"></span>autorisées</span><span><span class="dot" style="background:var(--bad)"></span>bloquées</span></span></h2>
        <svg class="bars" viewBox="0 0 ${W} ${H}" role="img" aria-label="Requêtes par heure" style="width:100%;height:auto">${svg}</svg></div>
      <div class="cols" style="margin-top:14px">
        <div class="card"><h2>Domaines les plus demandés</h2>${rank(st.top_domains, '')}</div>
        <div class="card"><h2>Domaines les plus bloqués</h2>${rank(st.top_blocked, 'bl')}</div>
        <div class="card"><h2>Clients les plus actifs</h2>${rank(st.top_clients, '')}</div>
        <div class="card"><h2>Requêtes par nœud</h2>${nodes ? `<div class="tblwrap"><table><tbody>${nodes}</tbody></table></div>` : '<div class="empty">Aucune donnée</div>'}</div>
      </div>`;
  }
  main.onclick = guard(async e => {
    const t = e.target.closest('[data-pause],[data-a="resume"]');
    if (!t) return;
    await api('POST', 'pause', { minutes: t.dataset.pause ? +t.dataset.pause : 0 });
    toast(t.dataset.pause ? 'Filtrage en pause' : 'Filtrage repris');
    draw();
  });
  main.onchange = guard(async e => {
    if (e.target.dataset.a === 'filtering') { await saveSettings({ filtering_enabled: e.target.checked }); toast(e.target.checked ? 'Filtrage activé' : 'Filtrage désactivé'); }
  });
  await draw();
  every(draw, 5000);
};

pages.log = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Journal des requêtes</h1><p>Répliqué entre les nœuds. Les entrées les plus récentes sont en haut.</p></div></div>
    <div class="card"><div class="filters">
      <label class="lbl grow2">Recherche<input class="f" id="q" placeholder="Domaine, règle, liste, upstream…"></label>
      <label class="lbl">Résultat<select class="f" id="st"><option value="">Tous</option><option value="blocked">Bloquées</option><option value="allowed">Autorisées</option><option value="rewritten">Réécrites</option><option value="zone">Zone locale</option><option value="cached">Depuis le cache</option><option value="error">Erreurs</option></select></label>
      <label class="lbl">Nœud<select class="f" id="nd"><option value="">Tous</option></select></label>
      <label class="lbl">Client enregistré<select class="f" id="cs"><option value="">Tous</option></select></label>
      <label class="lbl">Adresse IP<input class="f" id="cl" list="clients" placeholder="192.168.1.20"><datalist id="clients"></datalist></label>
      <label class="lbl">Type<select class="f" id="ty"><option value="">Tous</option></select></label>
      <label class="lbl">Période<select class="f" id="pe"><option value="0">Tout</option><option value="15">15 dernières minutes</option><option value="60">Dernière heure</option><option value="360">6 dernières heures</option><option value="1440">24 dernières heures</option><option value="10080">7 derniers jours</option><option value="custom">Personnalisée…</option></select></label>
      <label class="lbl" id="fromw" hidden>Du<input class="f" id="from" type="datetime-local"></label>
      <label class="lbl" id="tow" hidden>Au<input class="f" id="to" type="datetime-local"></label>
      <label class="lbl">Afficher<select class="f" id="li"><option>100</option><option selected>200</option><option>500</option><option>1000</option></select></label>
      <div class="row" style="align-self:end"><button class="btn" id="reset">Réinitialiser</button></div>
    </div>
    <div class="row sp" style="margin:12px 0 8px"><span class="muted" id="cnt"></span><span class="row" id="chips"></span></div>
    <div class="tblwrap" id="logw"><table id="logt"><thead><tr><th>Heure</th><th>Domaine</th><th>Type</th><th>Client</th><th>Nœud</th><th>Résultat</th><th>Détail</th><th>Durée</th><th></th></tr></thead><tbody id="lb"></tbody></table></div></div>
    <div id="why"></div>`;
  let shown = [];
  let names = {};
  const stamp = ms => new Date(ms).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const csIds = () => {
    const v = $('#cs').value;
    if (!v) return '';
    const [k, id] = v.split(/:(.+)/);
    const ids = k === 'g' ? DIR.clients.filter(c => c.group === id).flatMap(c => c.ids) : (DIR.clients.find(c => c.id === id) || { ids: [] }).ids;
    return ids.length ? ids.join(',') : '-';
  };
  const cname = ip => { const c = DIR.clients.find(c => c.id && ((c.ips || []).includes(ip) || c.ids.includes(ip))); return c ? c.name : ''; };
  const params = () => {
    const p = { limit: $('#li').value, search: $('#q').value, status: $('#st').value, node: $('#nd').value, client: $('#cl').value.trim(), qtype: $('#ty').value, ids: csIds() };
    const pe = $('#pe').value;
    if (pe === 'custom') {
      if ($('#from').value) p.from = new Date($('#from').value).getTime();
      if ($('#to').value) p.to = new Date($('#to').value).getTime();
    } else if (+pe) p.from = Date.now() - pe * 60000;
    return new URLSearchParams(Object.entries(p).filter(([, v]) => v !== '' && v !== undefined && !Number.isNaN(v)));
  };
  async function facets() {
    const [f, st] = await Promise.all([get('log/facets'), get('stats'), loadDir()]);
    if (token !== routeToken) return;
    names = st.node_names;
    const fill = (sel, items) => { const cur = sel.value; sel.length = 1; items.forEach(([v, t]) => sel.add(new Option(t, v))); sel.value = cur; };
    fill($('#nd'), Object.entries(names));
    { const cur = $('#cs').value;
      $('#cs').innerHTML = '<option value="">Tous</option>'
        + (DIR.groups.length ? `<optgroup label="Groupes">${DIR.groups.map(g => `<option value="g:${esc(g.id)}">${esc(g.name)}</option>`).join('')}</optgroup>` : '')
        + (DIR.clients.some(c => c.id) ? `<optgroup label="Clients">${DIR.clients.filter(c => c.id).map(c => `<option value="c:${esc(c.id)}">${esc(c.name)}</option>`).join('')}</optgroup>` : '');
      $('#cs').value = cur; }
    fill($('#ty'), f.qtypes.map(t => [t, t]));
    $('#clients').innerHTML = f.clients.map(c => `<option value="${esc(c)}">`).join('');
  }
  async function draw() {
    const rows = await get('log?' + params());
    if (token !== routeToken) return;
    $('#cnt').textContent = rows.length >= +$('#li').value ? `${num(rows.length)} entrées affichées (limite atteinte, affine les filtres)` : `${num(rows.length)} entrée(s)`;
    const active = [];
    if ($('#st').value) active.push($('#st').selectedOptions[0].text);
    if ($('#nd').value) active.push('nœud ' + $('#nd').selectedOptions[0].text);
    if ($('#cs').value) active.push($('#cs').selectedOptions[0].text);
    if ($('#cl').value) active.push('adresse ' + $('#cl').value);
    if ($('#ty').value) active.push('type ' + $('#ty').value);
    if ($('#pe').value !== '0') active.push($('#pe').selectedOptions[0].text.toLowerCase());
    $('#chips').innerHTML = active.map(a => `<span class="tag acc">${esc(a)}</span>`).join('');
    shown = rows;
    $('#lb').innerHTML = rows.length ? rows.map((r, i) => `<tr>
      <td class="mono" title="${esc(new Date(r.ts).toLocaleString('fr-FR'))}">${stamp(r.ts)}</td><td class="mono" title="${esc(r.name)}">${esc(r.name)}</td><td>${esc(r.qtype)}</td>
      <td class="mono"><a href="#" class="plain" data-fcl="${esc(r.client)}" title="Filtrer sur cette adresse">${esc(r.client)}</a>${cname(r.client) ? ` <b style="font-family:var(--sans)">${esc(cname(r.client))}</b>` : ''}</td>
      <td>${esc(names[r.node] || r.node)}</td><td>${resTag(r.result, r.cached)}</td>
      <td class="wrap muted mono">${r.ad ? '<span class="tag ok" title="Réponse validée par DNSSEC">DNSSEC</span> ' : ''}${esc(r.reason || r.list || r.upstream)}</td><td>${r.ms} ms</td>
      <td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-why="${i}">Pourquoi ?</button>${r.result === 'blocked' ? `<button class="btn sm" data-w data-allow="${esc(r.name)}">Autoriser</button>` : r.result === 'allowed' || r.result === 'error' ? `<button class="btn sm" data-w data-block="${esc(r.name)}">Bloquer</button>` : ''}</td></tr>`).join('')
      : '<tr><td colspan="9" class="empty">Aucune requête ne correspond à ces filtres</td></tr>';
  }
  main.onclick = guard(async e => {
    const wy = e.target.closest('[data-why]');
    if (wy) { await showWhy(shown[+wy.dataset.why], $('#why'), names); return; }
    const tmp = e.target.closest('[data-tmp]');
    if (tmp) {
      const mins = +$('#tmpm').value;
      await api('POST', 'tempallow', { domain: tmp.dataset.tmp, minutes: mins });
      toast(`${tmp.dataset.tmp} autorisé temporairement`); $('#why').innerHTML = ''; return;
    }
    const off = e.target.closest('[data-off]');
    if (off) {
      const rule = off.dataset.off;
      const line = rule.includes('$') ? rule + ',badfilter' : rule + '$badfilter';
      const cur = (await get('c/rules')).find(r => r.id === 'main');
      await api('PUT', 'c/rules/main', { text: (((cur && cur.text) || '').replace(/\s*$/, '') + '\n' + line + '\n').replace(/^\n/, '') });
      toast('Règle désactivée : ' + rule); $('#why').innerHTML = ''; return;
    }
    const fc = e.target.closest('[data-fcl]');
    if (fc) { e.preventDefault(); $('#cl').value = fc.dataset.fcl; draw(); return; }
    if (e.target.id === 'reset') {
      ['q', 'cl', 'from', 'to'].forEach(i => ($('#' + i).value = ''));
      ['st', 'nd', 'ty', 'cs'].forEach(i => ($('#' + i).value = '')); $('#pe').value = '0'; $('#li').value = '200';
      $('#fromw').hidden = $('#tow').hidden = true; draw(); return;
    }
    const t = e.target.closest('[data-allow],[data-block]');
    if (!t) return;
    $('#why').innerHTML = '';
    const rule = t.dataset.allow ? `@@||${t.dataset.allow}^` : `||${t.dataset.block}^`;
    const cur = (await get('c/rules')).find(r => r.id === 'main');
    const text = ((cur && cur.text) || '').replace(/\s*$/, '') + '\n' + rule + '\n';
    await api('PUT', 'c/rules/main', { text: text.replace(/^\n/, '') });
    toast('Règle ajoutée : ' + rule);
  });
  let deb;
  main.oninput = e => { if (e.target.type === 'datetime-local') return; clearTimeout(deb); deb = setTimeout(() => draw().catch(fail), 250); };
  main.onchange = e => { if (e.target.id === 'pe') { const c = e.target.value === 'custom'; $('#fromw').hidden = $('#tow').hidden = !c; } draw().catch(fail); };
  await facets(); await draw();
  every(async () => { if (!['q', 'cl'].includes(document.activeElement.id) && $('#pe').value !== 'custom') await draw(); }, 3000);
  every(facets, 30000);
};

pages.filters = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Filtres</h1><p>Listes synchronisées (syntaxe AdGuard, hosts ou liste de domaines) et listes locales. Chaque nœud télécharge ses listes lui-même.</p></div>
    <button class="btn" id="refall">Tout synchroniser</button></div>
    <div class="card"><h2>Listes</h2><div class="tblwrap"><table><thead><tr><th>Actif</th><th>Nom</th><th>Source</th><th>Règles</th><th>Synchro</th><th>État</th><th></th></tr></thead><tbody id="lt"></tbody></table></div></div>
    <div class="card" id="lform"><h2 id="fh">Ajouter une liste</h2>
      <div class="row" style="margin-bottom:12px"><div class="seg" id="kind"><button class="on" data-k="url">Depuis une URL</button><button data-k="inline">Texte ou fichier</button></div></div>
      <div class="cols">
        <div class="stack"><label class="lbl">Nom<input class="f" id="ln" placeholder="Ma liste"></label>
          <div id="fu"><label class="lbl">URL<input class="f" id="lu" placeholder="https://exemple.org/liste.txt"></label>
          <label class="lbl" style="margin-top:10px">Synchronisation<select class="f" id="li"><option value="1">Toutes les heures</option><option value="6">Toutes les 6 heures</option><option value="12" selected>Toutes les 12 heures</option><option value="24">Tous les jours</option><option value="168">Toutes les semaines</option></select></label></div>
          <div id="fi" hidden><label class="lbl">Règles<textarea class="f" id="lc" style="min-height:160px" placeholder="||tracker.exemple.com^&#10;0.0.0.0 pub.exemple.net"></textarea></label>
          <div class="row" style="margin-top:8px"><input type="file" id="lf" accept=".txt,.list,text/plain"><span class="muted">Le contenu du fichier est lu ici, puis enregistré dans la configuration.</span></div></div>
          <div class="row"><button class="btn pri" id="ladd">Ajouter</button><button class="btn" id="lcancel" hidden>Annuler</button></div></div>
        <div class="note">Une liste enregistrée comme texte ou fichier est répliquée sur tous les nœuds. Une liste distante n'enregistre que son adresse : si le téléchargement échoue, la dernière copie valide reste active.</div>
      </div></div>`;
  let kind = 'url', editing = null, lists = [];
  async function draw() {
    let meta; [lists, meta] = await Promise.all([get('c/lists'), get('lists/status')]);
    if (token !== routeToken) return;
    $('#lt').innerHTML = lists.length ? lists.map(l => {
      const m = meta[l.id] || {};
      const st = l.kind === 'inline' ? '<span class="tag ok">locale</span>'
        : !l.enabled ? '<span class="tag">désactivée</span>'
        : m.error ? `<span class="tag warn" title="${esc(m.error)}">échec${m.updated_at ? ' · ancienne copie' : ''}</span>`
        : m.updated_at ? '<span class="tag ok">à jour</span>' : '<span class="tag">en attente</span>';
      const count = l.kind === 'inline' ? '' : (m.rules ? num(m.rules) : '–');
      return `<tr><td>${sw(l.enabled, `data-tog="${l.id}"`)}</td><td>${esc(l.name)}</td>
        <td class="mono muted" title="${esc(l.url)}">${l.kind === 'url' ? esc(l.url.replace(/^https?:\/\//, '').slice(0, 44)) : 'texte local'}</td>
        <td>${count}${m.unsupported ? ` <span class="muted" title="Règles ignorées : modificateurs non gérés">(${num(m.unsupported)} ignorées)</span>` : ''}</td>
        <td>${l.kind === 'url' ? ago(m.updated_at) : ago(l.updated_at)}</td><td>${st}</td>
        <td class="row"><button class="btn sm" data-edit="${l.id}">Modifier</button>${l.kind === 'url' ? `<button class="btn sm" data-ref="${l.id}">Synchroniser</button>` : ''}<button class="btn sm danger" data-del="${l.id}">Supprimer</button></td></tr>`;
    }).join('') : '<tr><td colspan="7" class="empty">Aucune liste</td></tr>';
  }
  function setKind(k) {
    kind = k;
    $$('#kind button').forEach(x => x.classList.toggle('on', x.dataset.k === k));
    $('#fu').hidden = k !== 'url'; $('#fi').hidden = k !== 'inline';
  }
  function resetForm() {
    editing = null;
    ['ln', 'lu', 'lc'].forEach(i => ($('#' + i).value = ''));
    $('#li').value = '12'; $('#fh').textContent = 'Ajouter une liste'; $('#ladd').textContent = 'Ajouter';
    $('#lcancel').hidden = true; $('#kind').hidden = false; setKind('url');
  }
  function startEdit(id) {
    const l = lists.find(x => x.id === id); if (!l) return;
    editing = id; setKind(l.kind);
    $('#ln').value = l.name; $('#lu').value = l.url || ''; $('#lc').value = l.content || '';
    if (![...$('#li').options].some(o => o.value === String(l.interval_hours))) $('#li').add(new Option(`Toutes les ${l.interval_hours} h`, l.interval_hours));
    $('#li').value = String(l.interval_hours);
    $('#fh').textContent = 'Modifier la liste'; $('#ladd').textContent = 'Enregistrer';
    $('#lcancel').hidden = false; $('#kind').hidden = true;
    $('#lform').scrollIntoView({ behavior: 'smooth', block: 'center' }); $('#ln').focus();
  }
  $('#kind').onclick = e => { const b = e.target.closest('button'); if (b) setKind(b.dataset.k); };
  $('#lcancel').onclick = resetForm;
  $('#lf').onchange = e => { const f = e.target.files[0]; if (f) { f.text().then(t => { $('#lc').value = t; if (!$('#ln').value) $('#ln').value = f.name; }); } };
  $('#ladd').onclick = guard(async () => {
    const body = { name: $('#ln').value, kind, enabled: true };
    if (kind === 'url') { body.url = $('#lu').value.trim(); body.interval_hours = +$('#li').value; } else body.content = $('#lc').value;
    if (editing) {
      const old = lists.find(x => x.id === editing);
      body.enabled = old.enabled;
      await api('PUT', `c/lists/${editing}`, body);
      toast('Liste modifiée');
    } else {
      await api('POST', 'c/lists', body);
      toast('Liste ajoutée');
    }
    resetForm();
    draw();
  });
  $('#refall').onclick = guard(async () => { toast('Synchronisation en cours…'); const r = await api('POST', 'lists/refresh'); r.ok ? toast('Listes synchronisées') : toast(r.errors.join(' · '), true); draw(); });
  main.onclick = guard(async e => {
    const t = e.target.closest('[data-ref],[data-del],[data-edit]');
    if (!t) return;
    if (t.dataset.edit) startEdit(t.dataset.edit);
    else if (t.dataset.ref) { t.disabled = true; const r = await api('POST', `lists/${t.dataset.ref}/refresh`); r.ok ? toast('Liste synchronisée') : toast(r.error, true); draw(); }
    else if (t.dataset.del) {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer ?'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Supprimer'; }, 3000); return; }
      await api('DELETE', `c/lists/${t.dataset.del}`); draw();
    }
  });
  main.onchange = guard(async e => {
    const id = e.target.dataset.tog; if (!id) return;
    const l = (await get('c/lists')).find(x => x.id === id);
    delete l.id; delete l.updated_at; l.enabled = e.target.checked;
    await api('PUT', `c/lists/${id}`, l); draw();
  });
  await draw();
  every(draw, 5000);
};

pages.dns = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Paramètres DNS</h1><p>Les upstreams sont essayés dans l'ordre de la liste. Glisse une ligne ou utilise les flèches pour changer la priorité.</p></div></div>
    <div class="card"><h2>Upstreams <span class="row"><div class="seg" id="mode"><button data-m="ordered">Par priorité</button><button data-m="parallel">En parallèle</button></div></span></h2>
      <div class="tblwrap"><table><thead><tr><th></th><th>Priorité</th><th>Actif</th><th>État</th><th>Nom</th><th>Adresse</th><th>Latence</th><th></th></tr></thead><tbody id="ut"></tbody></table></div>
      <p class="note" style="margin-top:12px" id="modenote"></p></div>
    <div class="card"><h2 id="uh">Ajouter un upstream</h2>
      <div class="cols"><div class="stack">
        <label class="lbl">Nom<input class="f" id="un" placeholder="Mon résolveur"></label>
        <label class="lbl">Adresse<input class="f" id="ua" placeholder="1.1.1.1 · tls://dns.quad9.net · https://dns.google/dns-query"></label>
        <label class="lbl">Bootstrap (IP du serveur DoH/DoT, évite de dépendre d'un autre DNS)<input class="f" id="ub" placeholder="optionnel"></label>
        <label class="lbl">Domaines dédiés (séparés par des virgules, vide = tous)<input class="f" id="ud" placeholder="lan, maison.lan"></label>
        <label class="row" style="gap:8px"><input type="checkbox" id="ubk"> <span>Upstream de secours : interrogé seulement si les autres n'ont pas répondu (par exemple la box)</span></label>
        <div class="row"><button class="btn pri" id="usave">Ajouter</button><button class="btn" id="utest">Tester</button><button class="btn" id="ucancel" hidden>Annuler</button><span id="ures" class="muted"></span></div></div>
        <div class="note">Formats : <span class="mono">8.8.8.8</span> (UDP), <span class="mono">tcp://8.8.8.8</span>, <span class="mono">tls://dns.google</span> (DoT), <span class="mono">https://dns.google/dns-query</span> (DoH). Avec des domaines dédiés, l'upstream ne sert que pour ces domaines : utile pour envoyer <span class="mono">lan</span> vers ton routeur.</div></div></div>
    <div class="cols" style="margin-top:14px">
      <div class="card"><h2>Blocage</h2><label class="lbl">Réponse pour un domaine bloqué<select class="f" id="bm"><option value="null_ip">Adresse nulle (0.0.0.0)</option><option value="nxdomain">NXDOMAIN</option><option value="refused">REFUSED</option></select></label></div>
      <div class="card"><h2>DNSSEC</h2><div class="row">${sw(false, 'id="dsec"')}<span>Demander la validation DNSSEC aux upstreams</span></div>
        <p class="note" style="margin-top:12px">Atom demande à l'upstream de valider les signatures (bits DO et AD) et signale dans le journal les réponses authentifiées. La validation est faite par l'upstream, pas par Atom : choisis des upstreams qui valident (Cloudflare, Quad9, Google). Une réponse falsifiée est alors refusée (SERVFAIL). Les enregistrements de signature peuvent alourdir les réponses.</p></div>
      <div class="card"><h2>Cache <span class="row"><button class="btn sm" id="flush">Vider</button></span></h2>
        <div class="row">${sw(true, 'id="ce"')}<span>Cache activé</span></div>
        <label class="lbl" style="margin-top:10px">Taille maximale (entrées)<input class="f" id="cs" type="number" min="100"></label>
        <label class="lbl" style="margin-top:10px">Délai d'attente par upstream (ms)<input class="f" id="ct" type="number" min="200" step="100"></label>
        <div class="row" style="margin-top:12px"><button class="btn pri" id="csave">Enregistrer</button></div></div></div>`;
  let ups = [], health = {}, editing = null, set = {};
  async function load() {
    [ups, health, set] = await Promise.all([get('c/upstreams'), get('upstreams/status'), getSettings()]);
    ups.sort((a, b) => a.order - b.order);
  }
  function draw() {
    if (token !== routeToken) return;
    $$('#mode button').forEach(b => b.classList.toggle('on', b.dataset.m === set.upstream_mode));
    $('#modenote').textContent = set.upstream_mode === 'parallel'
      ? 'Toutes les requêtes partent vers tous les upstreams actifs en même temps, la première réponse valide gagne.'
      : 'Chaque requête est envoyée au premier upstream disponible. Si celui-ci échoue ou est hors service, le suivant prend le relais. Les upstreams de secours ne sont utilisés que si tous les autres ont échoué.';
    $('#ut').innerHTML = ups.length ? ups.map((u, i) => {
      const h = health[u.id] || {};
      const state = !u.enabled ? '<span class="dot"></span><span class="muted">désactivé</span>'
        : h.up === true ? '<span class="dot up"></span>en ligne'
        : h.up === false ? `<span class="dot down"></span><span title="${esc(h.last_error || '')}">hors service</span>`
        : '<span class="dot"></span><span class="muted">inconnu</span>';
      return `<tr draggable="true" data-id="${u.id}"><td class="handle" title="Glisser pour réordonner">⠿</td>
        <td><div class="row" style="flex-wrap:nowrap"><b>${i + 1}</b><button class="btn sm" data-up="${u.id}" ${i === 0 ? 'disabled' : ''} aria-label="Monter">▲</button><button class="btn sm" data-down="${u.id}" ${i === ups.length - 1 ? 'disabled' : ''} aria-label="Descendre">▼</button></div></td>
        <td>${sw(u.enabled, `data-tog="${u.id}"`)}</td><td>${state}</td>
        <td>${esc(u.name)}${u.domains.length ? ` <span class="tag acc">${esc(u.domains.join(', '))}</span>` : ''}${u.backup ? ' <span class="tag warn" title="Interrogé seulement si les autres upstreams échouent">secours</span>' : ''}</td>
        <td class="mono">${esc(u.address)}</td><td class="mono">${u.enabled && h.latency_ms != null && h.up ? h.latency_ms + ' ms' : '–'}</td>
        <td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-t="${u.id}">Tester</button><button class="btn sm" data-edit="${u.id}">Modifier</button><button class="btn sm danger" data-del="${u.id}">Supprimer</button></td></tr>`;
    }).join('') : '<tr><td colspan="8" class="empty">Aucun upstream : aucune requête ne pourra être résolue.</td></tr>';
    if (document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT') {
      $('#bm').value = set.block_mode; $('#dsec').checked = !!set.dnssec; $('#ce').checked = set.cache_enabled; $('#cs').value = set.cache_size; $('#ct').value = set.timeout_ms;
    }
  }
  async function reorder(ids) { await api('POST', 'upstreams/reorder', { ids }); await load(); draw(); toast('Priorité mise à jour'); }
  function form() {
    return { name: $('#un').value, address: $('#ua').value, bootstrap: $('#ub').value, domains: $('#ud').value.split(',').map(s => s.trim()).filter(Boolean), backup: $('#ubk').checked };
  }
  function resetForm() { editing = null; $('#ubk').checked = false; ['un', 'ua', 'ub', 'ud'].forEach(i => ($('#' + i).value = '')); $('#usave').textContent = 'Ajouter'; $('#uh').textContent = 'Ajouter un upstream'; $('#ucancel').hidden = true; }
  $('#ucancel').onclick = resetForm;
  $('#utest').onclick = guard(async () => {
    $('#ures').textContent = 'Test en cours…';
    const r = await api('POST', 'upstreams/test', { ...form(), enabled: true });
    $('#ures').textContent = r.ok ? `Répond en ${r.latency_ms} ms` : `Échec : ${r.error}`;
  });
  $('#usave').onclick = guard(async () => {
    const body = form();
    if (editing) {
      const u = ups.find(x => x.id === editing);
      await api('PUT', `c/upstreams/${editing}`, { ...body, enabled: u.enabled, order: u.order });
    } else {
      await api('POST', 'c/upstreams', { ...body, enabled: true, order: (ups.length ? Math.max(...ups.map(u => u.order)) : 0) + 1 });
    }
    toast('Upstream enregistré'); resetForm(); await load(); draw();
  });
  $('#mode').onclick = guard(async e => { const b = e.target.closest('button'); if (!b) return; await saveSettings({ upstream_mode: b.dataset.m }); set.upstream_mode = b.dataset.m; draw(); });
  $('#csave').onclick = guard(async () => {
    await saveSettings({ block_mode: $('#bm').value, dnssec: $('#dsec').checked, cache_enabled: $('#ce').checked, cache_size: +$('#cs').value, timeout_ms: +$('#ct').value });
    toast('Réglages enregistrés'); await load(); draw();
  });
  $('#flush').onclick = guard(async () => { await api('POST', 'cache/flush'); toast('Cache vidé'); });
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    const ids = ups.map(u => u.id);
    if (t.dataset.up || t.dataset.down) {
      const id = t.dataset.up || t.dataset.down, i = ids.indexOf(id), j = t.dataset.up ? i - 1 : i + 1;
      [ids[i], ids[j]] = [ids[j], ids[i]]; await reorder(ids);
    } else if (t.dataset.t) {
      t.textContent = '…'; const r = await api('POST', `upstreams/${t.dataset.t}/test`);
      toast(r.ok ? `Répond en ${r.latency_ms} ms` : `Échec : ${r.error}`, !r.ok); await load(); draw();
    } else if (t.dataset.edit) {
      const u = ups.find(x => x.id === t.dataset.edit); editing = u.id;
      $('#un').value = u.name; $('#ua').value = u.address; $('#ub').value = u.bootstrap; $('#ud').value = u.domains.join(', '); $('#ubk').checked = !!u.backup;
      $('#usave').textContent = 'Enregistrer'; $('#uh').textContent = 'Modifier un upstream'; $('#ucancel').hidden = false; $('#un').focus();
    } else if (t.dataset.del) {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer ?'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Supprimer'; }, 3000); return; }
      await api('DELETE', `c/upstreams/${t.dataset.del}`); await load(); draw();
    }
  });
  main.onchange = guard(async e => {
    const id = e.target.dataset.tog; if (!id) return;
    const u = ups.find(x => x.id === id), body = { ...u }; delete body.id; delete body.updated_at; body.enabled = e.target.checked;
    await api('PUT', `c/upstreams/${id}`, body); await load(); draw();
  });
  let dragId = null;
  main.ondragstart = e => { const r = e.target.closest('tr[data-id]'); if (r) { dragId = r.dataset.id; e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', dragId); } };
  main.ondragover = e => { const r = e.target.closest('tr[data-id]'); if (r && dragId) { e.preventDefault(); $$('#ut tr').forEach(x => x.classList.toggle('dragover', x === r)); } };
  main.ondragend = () => { dragId = null; $$('#ut tr').forEach(x => x.classList.remove('dragover')); };
  main.ondrop = guard(async e => {
    const r = e.target.closest('tr[data-id]'); if (!r || !dragId || r.dataset.id === dragId) return;
    e.preventDefault();
    const ids = ups.map(u => u.id).filter(i => i !== dragId);
    ids.splice(ids.indexOf(r.dataset.id), 0, dragId);
    dragId = null; await reorder(ids);
  });
  await load(); draw();
  every(async () => { if (dragId) return; health = await get('upstreams/status'); draw(); }, 4000);
};

pages.rules = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Règles personnalisées</h1><p>Syntaxe AdGuard. Ces règles passent avant toutes les listes.</p></div></div>
    <div class="cols"><div class="card"><h2>Éditeur</h2><textarea class="f" id="rtxt" spellcheck="false" aria-label="Règles"></textarea>
      <div class="row" style="margin-top:12px"><button class="btn pri" id="rsave">Enregistrer</button><span class="muted" id="rinfo"></span></div></div>
      <div class="stack"><div class="card"><h2>Tester un domaine</h2><div class="row"><input class="f grow" id="td" placeholder="www.exemple.com" aria-label="Domaine à tester"><button class="btn" id="tgo">Tester</button></div>
        <div class="out" id="tout" style="margin-top:12px" aria-live="polite"><span class="muted">Le test utilise les règles enregistrées, les réécritures, les zones et les listes actives.</span></div></div>
      <div class="card"><h2>Aide-mémoire</h2><div class="mono" style="line-height:1.9">
        ||exemple.com^ <span class="muted">bloque le domaine et ses sous-domaines</span><br>@@||exemple.com^ <span class="muted">exception</span><br>||exemple.com^$important <span class="muted">prioritaire sur les exceptions</span><br>/^ad[0-9]+\\./ <span class="muted">expression régulière</span><br>||pub*.site.fr^ <span class="muted">joker</span><br>||jeu.lan^$dnsrewrite=10.0.0.5 <span class="muted">réécriture</span><br>! commentaire</div></div></div></div>`;
  const cur = (await get('c/rules')).find(r => r.id === 'main');
  if (token !== routeToken) return;
  $('#rtxt').value = (cur && cur.text) || '';
  const count = () => { const n = $('#rtxt').value.split('\n').filter(l => l.trim() && !/^[!#]/.test(l.trim())).length; $('#rinfo').textContent = `${n} règle(s)`; };
  count(); $('#rtxt').oninput = count;
  $('#rsave').onclick = guard(async () => { await api('PUT', 'c/rules/main', { text: $('#rtxt').value }); toast('Règles enregistrées et synchronisées'); });
  const test = guard(async () => {
    const r = await api('POST', 'check', { domain: $('#td').value });
    const [t, c] = RESULT[r.result] || [r.result, ''];
    $('#tout').innerHTML = `<span class="tag ${c}">${t}</span> ${r.rule ? `par <b class="mono">${esc(r.rule)}</b>${r.list ? ` <span class="muted">(${esc(r.list)})</span>` : ''}` : esc(r.detail || '')}`;
  });
  $('#tgo').onclick = test; $('#td').onkeydown = e => { if (e.key === 'Enter') test(); };
};

pages.records = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Enregistrements DNS</h1><p>Atom répond avec autorité pour les zones ci-dessous. Un nom absent d'une zone locale reçoit NXDOMAIN, sans interroger les upstreams.</p></div></div>
    <div class="card"><h2>Zones</h2><div class="row"><div class="seg" id="zs"></div><input class="f" id="zn" style="width:200px" placeholder="maison.lan" aria-label="Nouvelle zone"><button class="btn" id="zadd">Créer la zone</button></div></div>
    <div id="zbody"></div>`;
  let zones = [], recs = [], zone = null, editing = null, q = '', scopeCtl = null;
  async function load() { [zones, recs] = await Promise.all([get('c/zones'), get('c/records'), loadDir()]); if (!zone || !zones.find(z => z.name === zone)) zone = zones[0] ? zones[0].name : null; }
  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR', 'NS', 'CAA'];
  const HINT = { A: '192.168.1.20', AAAA: 'fd00::20', CNAME: 'cible.maison.lan', MX: '10 mail.maison.lan', TXT: 'texte libre', SRV: '0 5 1883 hote.maison.lan', PTR: 'nas.maison.lan', NS: 'ns.maison.lan', CAA: '0 issue "letsencrypt.org"' };
  function renderRows() {
    if (!$('#rtb')) return;
    const all = recs.filter(r => r.zone === zone).sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type));
    const term = q.trim().toLowerCase();
    const rs = term ? all.filter(r => [r.name || '@', r.name ? `${r.name}.${zone}` : zone, r.type, r.value].join(' ').toLowerCase().includes(term)) : all;
    $('#rcount').textContent = term ? `${rs.length} sur ${all.length}` : `${all.length} enregistrement(s)`;
    $('#rtb').innerHTML = rs.length ? rs.map(r => `<tr><td>${sw(r.enabled, `data-tog="${r.id}"`)}</td><td><span class="tag acc">${r.type}</span></td><td class="mono">${esc(r.name || '@')}</td><td class="mono wrap">${esc(r.value)}</td><td>${r.ttl} s</td><td>${r.type === 'A' ? sw(r.ptr, `data-ptr="${r.id}"`) : ''}</td><td>${scopeTags(r)}</td>
      <td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-edit="${r.id}">Modifier</button><button class="btn sm danger" data-del="${r.id}">Supprimer</button></td></tr>`).join('')
      : `<tr><td colspan="8" class="empty">${all.length ? 'Aucun enregistrement ne correspond à la recherche' : 'Aucun enregistrement'}</td></tr>`;
  }
  function draw() {
    if (token !== routeToken) return;
    $('#zs').innerHTML = zones.length ? zones.map(z => `<button data-z="${esc(z.name)}" class="${z.name === zone ? 'on' : ''}">${esc(z.name)}</button>`).join('') : '<span class="muted" style="padding:6px 12px">Aucune zone</span>';
    if (!zone) { $('#zbody').innerHTML = '<div class="card empty">Crée une première zone, par exemple <span class="mono">maison.lan</span>.</div>'; return; }
    $('#zbody').innerHTML = `<div class="card" style="margin-top:14px"><h2>${esc(zone)} <button class="btn sm danger" data-zdel="1">Supprimer la zone</button></h2>
      <div class="row" style="margin-bottom:12px"><input class="f grow" id="rq" type="search" placeholder="Rechercher par nom, type ou valeur" value="${esc(q)}" aria-label="Rechercher un enregistrement"><span class="muted" id="rcount"></span></div>
      <div class="tblwrap"><table><thead><tr><th>Actif</th><th>Type</th><th>Nom</th><th>Valeur</th><th>TTL</th><th>PTR</th><th>Portée</th><th></th></tr></thead><tbody id="rtb"></tbody></table></div></div>
      <div class="card" style="margin-top:14px"><h2 id="rh">Ajouter un enregistrement</h2><div class="row">
        <select class="f" id="rtype" style="width:auto" aria-label="Type">${TYPES.map(t => `<option>${t}</option>`).join('')}</select>
        <input class="f grow" id="rname" placeholder="nom (nas, *.apps, @)" aria-label="Nom"><input class="f grow" id="rval" placeholder="valeur (${HINT.A})" aria-label="Valeur">
        <input class="f" id="rttl" style="width:90px" value="300" aria-label="TTL en secondes"><label class="row" id="rptrl"><span class="muted">PTR</span>${sw(false, 'id="rptr"')}</label>
        <button class="btn pri" id="rsave">Ajouter</button><button class="btn" id="rcancel" hidden>Annuler</button></div>
        <div class="row" style="margin-top:12px;align-items:flex-start"><span class="muted" style="padding-top:8px">Portée</span><div id="rscope" class="grow"></div></div>
        <p class="note" style="margin-top:12px">Le numéro de série SOA évolue tout seul. Avec l'option PTR, un enregistrement A génère aussi la résolution inverse de son adresse.</p></div>`;
    renderRows();
    scopeCtl = mountScope($('#rscope'), editing ? recs.find(x => x.id === editing) : {});
    $('#rtype').onchange = () => { $('#rval').placeholder = `valeur (${HINT[$('#rtype').value]})`; $('#rptrl').hidden = $('#rtype').value !== 'A'; };
  }
  function reset() { editing = null; if (scopeCtl) scopeCtl.set({}); if ($('#rname')) { $('#rname').value = ''; $('#rval').value = ''; $('#rttl').value = 300; $('#rsave').textContent = 'Ajouter'; $('#rh').textContent = 'Ajouter un enregistrement'; $('#rcancel').hidden = true; } }
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.id === 'zadd') { const n = $('#zn').value; await api('POST', 'c/zones', { name: n }); zone = n.trim().toLowerCase().replace(/\.$/, ''); $('#zn').value = ''; toast('Zone créée'); await load(); draw(); }
    else if (t.dataset.z) { zone = t.dataset.z; editing = null; draw(); }
    else if (t.dataset.zdel) {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer ? Les enregistrements seront supprimés'; return; }
      const z = zones.find(x => x.name === zone); await api('DELETE', `c/zones/${z.id}`); await load(); draw();
    }
    else if (t.id === 'rsave') {
      const body = { zone, type: $('#rtype').value, name: $('#rname').value, value: $('#rval').value, ttl: +$('#rttl').value || 300, ptr: $('#rptr').checked, enabled: true, ...scopeCtl.get() };
      if (editing) { const old = recs.find(r => r.id === editing); body.enabled = old.enabled; await api('PUT', `c/records/${editing}`, body); }
      else await api('POST', 'c/records', body);
      toast('Enregistrement enregistré'); const keep = zone; await load(); zone = keep; draw();
    }
    else if (t.id === 'rcancel') reset();
    else if (t.dataset.del) { await api('DELETE', `c/records/${t.dataset.del}`); await load(); draw(); }
    else if (t.dataset.edit) {
      const r = recs.find(x => x.id === t.dataset.edit); editing = r.id;
      $('#rtype').value = r.type; $('#rname').value = r.name; $('#rval').value = r.value; $('#rttl').value = r.ttl; $('#rptr').checked = r.ptr; $('#rptrl').hidden = r.type !== 'A'; scopeCtl.set(r);
      $('#rsave').textContent = 'Enregistrer'; $('#rh').textContent = 'Modifier un enregistrement'; $('#rcancel').hidden = false; $('#rname').focus();
    }
  });
  main.oninput = e => { if (e.target.id === 'rq') { q = e.target.value; renderRows(); } };
  main.onchange = guard(async e => {
    const id = e.target.dataset.tog || e.target.dataset.ptr; if (!id) return;
    const r = recs.find(x => x.id === id), body = { ...r }; delete body.id; delete body.updated_at;
    if (e.target.dataset.tog) body.enabled = e.target.checked; else body.ptr = e.target.checked;
    await api('PUT', `c/records/${id}`, body); await load(); draw();
  });
  await load(); draw();
};

pages.cluster = async function (token) {
  main.innerHTML = `<div class="head"><div><h1>Cluster</h1><p>Les nœuds appairés partagent la configuration et le journal en direct. Chacun reste utilisable seul si l'autre tombe.</p></div>
    <button class="btn" id="syncnow">Synchroniser maintenant</button></div><div id="cbody"></div>`;
  async function draw() {
    const c = await get('cluster');
    if (token !== routeToken) return;
    const active = document.activeElement && document.activeElement.closest('#joinbox');
    if (active) return;
    $('#cbody').innerHTML = `<div class="card"><h2>Nœuds</h2><div class="tblwrap"><table><thead><tr><th>Nœud</th><th>Adresse</th><th>État</th><th>Latence</th><th>Dernière synchro</th><th></th></tr></thead><tbody>
      <tr><td><b>${esc(c.node.name)}</b> <span class="muted">(ce nœud)</span></td><td class="mono">${esc(c.node.advertise_url || location.origin)}</td><td><span class="dot up"></span>en ligne</td><td>–</td><td>–</td><td></td></tr>
      ${c.peers.map(p => `<tr><td><b>${esc(p.name)}</b></td><td class="mono">${esc(p.url)}</td>
        <td>${p.ok ? '<span class="dot up"></span>synchronisé' : `<span class="dot down"></span><span title="${esc(p.error || '')}">injoignable</span>`}</td>
        <td>${p.ok ? p.latency_ms + ' ms' : '–'}</td><td>${ago(p.last_ok)}</td><td><button class="btn sm danger" data-rm="${p.id}">Retirer</button></td></tr>`).join('')}</tbody></table></div></div>
      <div class="cols" style="margin-top:14px" id="joinbox">
        <div class="card"><h2>Ajouter ce nœud à un cluster</h2><div class="stack">
          <label class="lbl">Adresse de l'autre nœud<input class="f" id="ju" placeholder="http://192.168.1.2:3000 ou https://192.168.1.2:3443"></label>
          <label class="lbl">Code d'appairage de l'autre nœud (copie-le en entier, avec l'empreinte s'il y en a une)<input class="f" id="jt" placeholder="affiché sur son écran Cluster"></label>
          <label class="lbl">Adresse de ce nœud, telle que l'autre nœud peut la joindre<input class="f" id="js" value="${esc(c.node.advertise_url || location.origin)}"></label>
          <div class="row"><button class="btn pri" id="jgo">Rejoindre</button></div>
          <p class="note">Ce nœud adopte le code de l'autre, puis récupère sa configuration. Les valeurs par défaut de ce nœud sont remplacées par celles du cluster. Si tu avais déjà modifié des réglages ici, les deux versions sont fusionnées objet par objet, la plus récente gagne.</p></div></div>
        <div class="card"><h2>Code d'appairage de ce nœud</h2>
          <p class="muted" style="margin-bottom:10px">À saisir sur l'autre nœud pour qu'il rejoigne celui-ci.</p>
          <div class="token" id="tk">${esc(c.pairing_code)}</div>
          <div class="row" style="margin-top:10px"><button class="btn sm" id="cp">Copier</button></div>
          <p class="note" style="margin-top:14px">Les échanges entre nœuds passent en HTTP simple, protégés par ce code. Garde le cluster sur ton réseau local, ou place les nœuds derrière un VPN ou un reverse proxy HTTPS.</p></div></div>`;
  }
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.id === 'syncnow') { await api('POST', 'cluster/sync'); toast('Synchronisation effectuée'); draw(); }
    else if (t.id === 'jgo') {
      t.disabled = true;
      try { await api('POST', 'cluster/join', { url: $('#ju').value, token: $('#jt').value, self_url: $('#js').value }); toast('Nœud ajouté au cluster'); } finally { t.disabled = false; }
      draw();
    }
    else if (t.id === 'cp') { try { await navigator.clipboard.writeText($('#tk').textContent); toast('Code copié'); } catch { const r = document.createRange(); r.selectNodeContents($('#tk')); getSelection().removeAllRanges(); getSelection().addRange(r); toast('Sélectionné, copie avec Ctrl+C'); } }
    else if (t.dataset.rm) { await api('DELETE', `cluster/peers/${t.dataset.rm}`); draw(); }
  });
  await draw();
  every(draw, 3000);
};

pages.security = async function (token) {
  const [me, ev, tk] = await Promise.all([get('auth/me'), get('auth/events'), get('tokens')]);
  if (token !== routeToken) return;
  const KIND = {
    login_ok: ['Connexion réussie', 'ok'], readonly: ['Accès lecture seule', 'acc'], login_fail: ['Échec de connexion', 'bad'], locked: ['Adresse bloquée', 'warn'],
    sync_fail: ['Échec côté cluster', 'warn'], unlock: ['Adresse débloquée', 'acc'], password_changed: ['Mot de passe modifié', 'acc'], logout: ['Déconnexion', ''],
  };
  const when = ms => new Date(ms).toLocaleString('fr-FR');
  main.innerHTML = `<div class="head"><div><h1>Sécurité</h1><p>Compte administrateur, sessions ouvertes et tentatives de connexion récentes.</p></div></div>
    <div class="cols">
      <div class="card"><h2>Mot de passe</h2>
        ${me.pw_locked ? '<p class="note">Le mot de passe est imposé par la configuration (variable <span class="mono">ATOM_PASSWORD</span> ou option de l\'add-on). Modifie-le à cet endroit.</p>'
          : me.ingress ? '<p class="note">Tu es connecté par Home Assistant. Le mot de passe sert à l\'accès direct sur le port de l\'interface.</p>' : ''}
        ${me.pw_locked ? '' : `<div class="stack">
          <label class="lbl">Mot de passe actuel<input class="f" id="pc" type="password" autocomplete="current-password"></label>
          <label class="lbl">Nouveau mot de passe (10 caractères minimum)<input class="f" id="pn" type="password" autocomplete="new-password"></label>
          <label class="lbl">Confirmer<input class="f" id="pn2" type="password" autocomplete="new-password"></label>
          <div class="row"><button class="btn pri" id="pw">Changer le mot de passe</button></div></div>
          <p class="note" style="margin-top:12px">Les autres sessions sont fermées après le changement.</p>`}
      </div>
      <div class="card"><h2>Sessions ouvertes <button class="btn sm" id="rev" ${ev.sessions.filter(s => !s.current).length ? '' : 'disabled'}>Déconnecter les autres</button></h2>
        <div class="tblwrap"><table><thead><tr><th>Adresse</th><th>Ouverte</th><th>Dernière activité</th><th></th></tr></thead><tbody>
        ${ev.sessions.length ? ev.sessions.map(s => `<tr><td class="mono">${esc(s.ip)}</td><td>${when(s.created)}</td><td>${ago(s.last_seen)}</td><td>${s.current ? '<span class="tag acc">cette session</span>' : ''}${s.ro ? ' <span class="tag">lecture seule</span>' : ''}</td></tr>`).join('') : `<tr><td colspan="4" class="empty">${me.ingress ? 'Accès via Home Assistant, sans session propre' : 'Aucune session'}</td></tr>`}
        </tbody></table></div>
        ${ev.locked.length ? `<h2 style="margin-top:16px">Adresses bloquées <button class="btn sm" data-unlock="">Tout débloquer</button></h2><div class="tblwrap"><table><tbody>${ev.locked.map(l => `<tr><td class="mono">${esc(l.ip)}</td><td>encore ${l.seconds} s</td><td><button class="btn sm" data-unlock="${esc(l.ip)}">Débloquer</button></td></tr>`).join('')}</tbody></table></div>` : ''}
      </div>
    </div>
    <div class="card" style="margin-top:14px"><h2>Jetons d'API</h2>
      <p class="muted" style="margin-bottom:12px">Pour les scripts et les automatisations. Un jeton se présente dans l'en-tête <span class="mono">Authorization: Bearer atm_…</span>. Il peut être limité à la lecture et à certaines adresses. Voir la documentation de l'API dans <span class="mono">docs/API.md</span>.</p>
      ${window.__atomNewToken ? `<div class="card" style="border-color:var(--good);margin-bottom:12px"><b>Nouveau jeton : copie-le maintenant, il ne sera plus affiché.</b><div class="token" style="margin-top:8px">${esc(window.__atomNewToken)}</div><div class="row" style="margin-top:8px"><button class="btn sm" id="tkcopy">Copier</button><button class="btn sm" id="tkdone">C'est fait</button></div></div>` : ''}
      <div class="tblwrap"><table><thead><tr><th>Nom</th><th>Début</th><th>Droits</th><th>Adresses autorisées</th><th>Expire</th><th>Dernière utilisation</th><th></th></tr></thead><tbody>
      ${tk.length ? tk.map(t => `<tr><td>${esc(t.name)}</td><td class="mono">${esc(t.prefix)}…</td><td><span class="tag ${t.scope === 'write' ? 'warn' : 'ok'}">${t.scope === 'write' ? 'lecture et écriture' : 'lecture seule'}</span></td>
        <td class="mono wrap">${t.ips.length ? esc(t.ips.join(', ')) : '<span class="muted">toutes</span>'}</td><td>${t.expires_at ? (t.expires_at < Date.now() ? '<span class="tag bad">expiré</span>' : when(t.expires_at)) : 'jamais'}</td>
        <td>${t.last_used ? `${ago(t.last_used)} <span class="muted mono">${esc(t.last_ip || '')}</span>` : '<span class="muted">jamais</span>'}</td><td><button class="btn sm danger" data-tkdel="${t.id}">Révoquer</button></td></tr>`).join('') : '<tr><td colspan="7" class="empty">Aucun jeton</td></tr>'}</tbody></table></div>
      <h2 style="margin-top:16px">Créer un jeton</h2>
      <div class="row"><input class="f grow" id="tkname" placeholder="Nom (ex. Home Assistant)" aria-label="Nom du jeton">
        <select class="f" id="tkscope" style="width:auto" aria-label="Droits"><option value="read">Lecture seule</option><option value="write">Lecture et écriture</option></select>
        <select class="f" id="tkexp" style="width:auto" aria-label="Validité"><option value="0">Sans expiration</option><option value="30">30 jours</option><option value="90">90 jours</option><option value="365">1 an</option></select></div>
      <div class="row" style="margin-top:8px"><input class="f grow" id="tkips" placeholder="Adresses autorisées, séparées par des virgules (vide = toutes). Ex. 192.168.1.10, 192.168.1.0/24" aria-label="Adresses autorisées"><button class="btn pri" id="tkgo">Créer</button></div></div>
    <div class="card" style="margin-top:14px"><h2>Tentatives récentes</h2>
      <div class="tblwrap"><table><thead><tr><th>Date</th><th>Adresse</th><th>Événement</th><th>Détail</th></tr></thead><tbody>
      ${ev.events.length ? ev.events.map(e => { const [t, c] = KIND[e.kind] || [e.kind, '']; return `<tr><td>${when(e.ts)}</td><td class="mono">${esc(e.ip)}</td><td><span class="tag ${c}">${t}</span></td><td class="muted wrap">${esc(e.detail)}</td></tr>`; }).join('') : '<tr><td colspan="4" class="empty">Aucun événement depuis le démarrage</td></tr>'}
      </tbody></table></div>
      <p class="note" style="margin-top:12px">Après 4 échecs, l'adresse est bloquée 1 minute, puis la durée double à chaque nouvel échec (jusqu'à 1 heure). Les échecs sur la synchronisation du cluster comptent aussi.</p></div>`;
  const pw = $('#pw');
  if (pw) pw.onclick = guard(async () => {
    if ($('#pn').value !== $('#pn2').value) throw new Error('La confirmation ne correspond pas');
    await api('POST', 'auth/password', { current: $('#pc').value, new: $('#pn').value });
    toast('Mot de passe modifié');
    ['pc', 'pn', 'pn2'].forEach(i => ($('#' + i).value = ''));
  });
  main.onclick = guard(async e => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.dataset.unlock !== undefined) {
      await api('POST', 'auth/unlock', { ip: t.dataset.unlock }); toast('Adresse débloquée'); pages.security(token); return;
    }
    if (t.id === 'tkgo') {
      const r = await api('POST', 'tokens', { name: $('#tkname').value, scope: $('#tkscope').value, ips: $('#tkips').value.split(/[,\s]+/).filter(Boolean), expires_in_days: +$('#tkexp').value || undefined });
      window.__atomNewToken = r.token; toast('Jeton créé'); pages.security(token);
    } else if (t.id === 'tkcopy') {
      try { await navigator.clipboard.writeText(window.__atomNewToken); toast('Jeton copié'); } catch { toast('Copie impossible : sélectionne le jeton à la main', true); }
    } else if (t.id === 'tkdone') { window.__atomNewToken = null; pages.security(token); }
    else if (t.dataset.tkdel) {
      if (t.dataset.sure !== '1') { t.dataset.sure = '1'; t.textContent = 'Confirmer'; setTimeout(() => { t.dataset.sure = ''; t.textContent = 'Révoquer'; }, 3000); return; }
      await api('DELETE', `tokens/${t.dataset.tkdel}`); toast('Jeton révoqué'); pages.security(token);
    }
  });
  $('#rev').onclick = guard(async () => { await api('POST', 'auth/revoke-others'); toast('Autres sessions fermées'); pages.security(token); });
};

// ---------- routeur ----------

async function logout() {
  try { await api('POST', 'auth/logout'); } catch { /* déjà déconnecté */ }
  location.href = 'login.html';
}

async function nodeChip() {
  try {
    const [i, c] = await Promise.all([get('info'), get('cluster')]);
    const ok = c.peers.filter(p => p.ok).length;
    $('#nodechip').innerHTML = `<b>${esc(i.name)}</b><br>v${esc(i.version)} · DNS ${i.dns_ok ? 'actif' : '<span style="color:var(--bad)">inactif</span>'}<br>${c.peers.length ? `cluster : ${ok + 1}/${c.peers.length + 1} nœuds` : 'nœud seul'}`;
  } catch { /* ignoré */ }
}

async function route() {
  timers.forEach(clearInterval); timers = [];
  main.onclick = main.onchange = main.oninput = main.ondragstart = main.ondragover = main.ondragend = main.ondrop = null;
  const full = (location.hash || '#dashboard').slice(1);
  const [name, ...rest] = full.split('/');
  let param = rest.join('/');
  try { param = decodeURIComponent(param); } catch { /* garde la valeur brute */ }
  const r = pages[name] ? name : 'dashboard';
  const navKey = r === 'client' || r === 'group' ? 'clients' : r;
  $$('#nav a').forEach(a => a.classList.toggle('on', a.dataset.r === navKey));
  const token = ++routeToken;
  try { await pages[r](token, param); } catch (e) { if (token === routeToken) main.innerHTML = `<div class="card"><h2>Erreur</h2><p>${esc(e.message)}</p></div>`; }
  nodeChip();
}
window.addEventListener('hashchange', route);
const effectiveTheme = () => document.documentElement.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
function themeLabel() { $('#theme').textContent = effectiveTheme() === 'dark' ? '☀ Mode clair' : '☾ Mode sombre'; }
$('#theme').onclick = () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('atom-theme', next); } catch { /* stockage indisponible */ }
  themeLabel();
};
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', themeLabel);
themeLabel();
$('#logout').onclick = logout;
get('auth/me').then(m => { if (m.ingress) $('#logout').hidden = true; }).catch(() => {});
setInterval(nodeChip, 10000);
// Les pages de clients.js sont chargées après ce fichier : on démarre quand tout est prêt.
window.addEventListener('load', route);
