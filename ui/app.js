// Панель xm: интерфейс. Всё, что приходит с сервера (имена клиентов, строки логов, вывод
// проверок), попадает в страницу только через textContent: в логах fallback лежит SNI,
// который присылают сканеры, и разметкой он стать не должен.
(() => {
  'use strict';

  const $ = (q, r = document) => r.querySelector(q);
  const $$ = (q, r = document) => Array.from(r.querySelectorAll(q));
  function h(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    if (attrs) for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of kids) if (c != null) n.append(c);
    return n;
  }
  const NS = 'http://www.w3.org/2000/svg';
  function sv(tag, attrs) {
    const n = document.createElementNS(NS, tag);
    if (attrs) for (const k of Object.keys(attrs)) n.setAttribute(k, String(attrs[k]));
    return n;
  }

  // ───────── сеть ─────────
  class Gone extends Error {}
  async function api(path, opts = {}) {
    const headers = { 'X-Xm': '1' };
    if (opts.bg) headers['X-Xm-Bg'] = '1';
    const hasBody = opts.body !== undefined;
    if (hasBody) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch('api/' + path, {
        method: hasBody || opts.post ? 'POST' : 'GET',
        headers,
        body: hasBody ? JSON.stringify(opts.body) : undefined,
        cache: 'no-store',
      });
    } catch (e) {
      throw new Gone();
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* пустое тело */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || ('HTTP ' + res.status));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // ───────── форматы ─────────
  const f0 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });
  const f1 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
  const f2 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 2 });
  const NB = ' ';
  function fmtBytes(b) {
    if (!(b > 0)) return '0';
    const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
    let i = 0;
    while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
    return (b >= 100 || i === 0 ? f0 : f1).format(b) + NB + u[i];
  }
  function fmtRate(v) { return (v >= 10 ? f0 : v >= 1 ? f1 : f2).format(v); }
  function fmtDur(s) {
    s = Math.max(0, Math.floor(s));
    const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return d + ' д ' + hh + ' ч';
    if (hh) return hh + ' ч ' + m + ' мин';
    return Math.max(1, m) + ' мин';
  }
  const MON = ['янв', 'фев', 'мар', 'апр', 'мая', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];
  const WD = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб'];
  const pad = n => String(n).padStart(2, '0');
  let tzOff = 0;                           // минуты: серверное время = UTC + tzOff
  const sd = ep => new Date((ep + tzOff * 60) * 1000);   // читать getUTC*: это серверные часы
  const hm = d => pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
  const dm = d => d.getUTCDate() + NB + MON[d.getUTCMonth()];
  const ST = { good: '✓', warn: '!', crit: '✗', off: '–' };
  const stIcon = kind => h('span', { class: 'st ' + kind, 'aria-hidden': 'true', text: ST[kind] });

  let toastTimer = 0;
  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 3600);
  }
  function showErr(box, e) {
    box.textContent = '';
    box.append(h('b', { text: 'Не удалось получить данные' }), h('p', { class: 'sub', text: e.message || String(e) }));
    box.hidden = false;
  }
  function onFail(e, box) {
    if (e instanceof Gone) return gone('Панель остановлена');
    if (box) showErr(box, e); else toast(e.message || String(e));
  }

  // ───────── сессия ─────────
  let idleLeft = 0, idleAt = Date.now(), idleMax = 1800, fails = 0, lastPing = 0, ended = false;
  function gone(title) {
    if (ended) return;
    ended = true;
    followOff();
    $('#ov-title').textContent = title;
    $('#overlay').hidden = false;
  }
  async function pollSession() {
    if (ended) return;
    try {
      const s = await api('session', { bg: true });
      idleLeft = s.idle_left; idleMax = s.idle_max; idleAt = Date.now(); tzOff = s.tz_offset; fails = 0;
    } catch (e) {
      if (e instanceof Gone && ++fails >= 2) gone('Панель остановлена');
    }
  }
  function tickIdle() {
    const left = Math.max(0, idleLeft - (Date.now() - idleAt) / 1000);
    $('#idle').textContent = pad(Math.floor(left / 60)) + ':' + pad(Math.floor(left % 60));
  }
  function ping() {
    const now = Date.now();
    if (now - lastPing < 20000 || ended) return;
    lastPing = now;
    api('ping', { post: true }).then(() => { idleLeft = idleMax; idleAt = Date.now(); }, () => {});
  }

  // ───────── вкладки ─────────
  const TABS = ['overview', 'clients', 'charts', 'logs'];
  const loaded = {};
  function setTab(id, focus) {
    if (!TABS.includes(id)) id = 'overview';
    TABS.forEach(t => {
      const on = t === id;
      const b = $('#t-' + t);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      $('#p-' + t).hidden = !on;
    });
    if (focus) $('#t-' + id).focus();
    if (id !== 'logs') followOff();
    if (id === 'overview') loadOverview();
    else if (id === 'clients') loadClients();
    else if (id === 'charts') loadCharts();
    else loadLogs();
    try { history.replaceState(null, '', '#' + id); } catch (e) { /* рамка может запрещать */ }
  }
  TABS.forEach((t, i) => {
    const b = $('#t-' + t);
    b.addEventListener('click', () => setTab(t));
    b.addEventListener('keydown', e => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      e.preventDefault();
      setTab(TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length], true);
    });
  });

  // ───────── обзор ─────────
  async function loadOverview() {
    try {
      const d = await api('overview');
      $('#ov-err').hidden = true;
      renderOverview(d);
    } catch (e) { onFail(e, $('#ov-err')); }
  }

  function renderOverview(d) {
    const x = d.xray || {}, s = d.services || {}, c = d.config || {}, sys = d.sys || {}, st = d.stats || {};
    $('#srv').textContent = d.hostname || 'сервер';
    $('#ip').textContent = d.server_ip || '';
    const pill = $('#xray-pill');
    pill.textContent = '';
    pill.append(stIcon(x.active ? 'good' : 'crit'), document.createTextNode(
      x.active ? 'Xray работает ' + fmtDur(d.now - x.since) : 'Xray не запущен'));
    pill.hidden = false;

    const t = d.traffic_24h;
    $('#tile-traffic').textContent = t ? fmtBytes(t[0] + t[1]) : '—';
    $('#tile-traffic-sub').textContent = t ? '↓' + NB + fmtBytes(t[1]) + ' к клиентам · ↑' + NB + fmtBytes(t[0]) + ' от клиентов'
      : (st.enabled ? 'Данных пока нет: первый замер в течение 5 минут' : 'Не считается. На сервере: sudo xm stats on');
    $('#tile-conns').textContent = d.conns_now == null ? '—' : f0.format(d.conns_now);
    $('#tile-load').textContent = sys.load1 == null ? '—' : f2.format(sys.load1);
    $('#tile-load-sub').textContent = ['ядер: ' + sys.ncpu,
      sys.mem_total_mb ? 'RAM ' + f0.format(sys.mem_used_mb) + ' из ' + f0.format(sys.mem_total_mb) + ' МБ' : null,
      sys.disk_pct == null ? null : 'диск ' + sys.disk_pct + ' %'].filter(Boolean).join(' · ');

    const ul = $('#svc');
    ul.textContent = '';
    const add = (kind, name, desc) => ul.append(h('li', null, stIcon(kind),
      h('div', null, h('b', { text: name }), document.createTextNode(' '), h('span', { class: 'd', text: desc }))));
    add(x.active ? 'good' : 'crit', 'Xray', x.active ? 'v' + (x.version || '?') + ' · работает ' + fmtDur(d.now - x.since)
      : 'не запущен: sudo systemctl status xray');
    add(s.nginx ? 'good' : 'crit', 'nginx', s.nginx ? (c.front ? 'фронт делит публичный порт по SNI' : 'fallback отвечает зондам сайтом-маской')
      : 'не запущен: зонд получит обрыв вместо сайта');
    add(s.watchdog ? 'good' : 'off', 'watchdog', s.watchdog ? 'проверяет сквозной путь каждые 2 минуты' : 'выключен: sudo xm tune');
    add(s.fail2ban ? 'good' : 'warn', 'fail2ban', s.fail2ban ? 'защита SSH' : 'не запущен');
    add(s.chrony ? 'good' : 'warn', 'chrony', s.chrony ? 'время синхронизировано' : 'не запущен: REALITY чувствителен к времени');
    if (st.enabled) add(st.collector ? 'good' : 'warn', 'Статистика', st.collector ? 'замер раз в 5 минут' : 'таймер не работает: sudo xm stats on');

    const dl = $('#cfg');
    dl.textContent = '';
    const yn = (v, a, b) => v == null ? 'не определено' : (v ? a : b);
    const row = (label, value, opt = {}) => dl.append(h('div', null, h('dt', { text: label }),
      h('dd', { class: (opt.mono ? 'mono ' : '') + (opt.bad ? 'bad' : '') }, document.createTextNode(value),
        opt.bad && opt.hint ? h('small', { text: opt.hint }) : null)));
    row('Протокол', 'VLESS · REALITY · ' + String(c.transport || '?').toUpperCase());
    row('Публичный порт', String(c.public_port));
    row('Домен-маска (SNI)', c.sni || '—', { mono: true });
    row('Отпечаток клиента', c.fp || '—', { mono: true });
    row('TCP · Vision', c.tcp ? 'включён, порт ' + c.tcp_port : 'выключен');
    row('DNS сервера', c.doh == null ? 'не определено' : (c.doh ? 'DoH' + (c.hijack53 ? ', :53 из тоннеля перехвачен' : ', :53 не перехвачен') : 'резолвер хостера, открытым текстом'),
      { bad: c.doh === false || c.hijack53 === false, hint: 'sudo xm harden' });
    row('Строгий DoT в системе', yn(c.dot, 'включён', 'выключен'), { bad: c.dot === false, hint: 'sudo xm harden' });
    row('Ответ зондам', yn(c.mimic, 'настоящий сайт-маска', 'обрыв соединения'), { bad: c.mimic === false, hint: 'sudo xm harden' });
    row('Российские адреса из тоннеля', yn(c.ru_block, 'блокируются', 'пропускаются'), { bad: c.ru_block === false, hint: 'sudo xm harden --ru on' });
    row('Сетевой стек (tune)', yn(c.tune, 'включён', 'выключен'), { bad: c.tune === false, hint: 'sudo xm tune' });
    row('Деление 443 по SNI', yn(c.front, 'включено', 'выключено'));
    row('Подпись ML-DSA', yn(c.pq, 'включена', 'выключена'));
    row('Файрвол UFW', yn(c.ufw, 'активен', 'выключен'), { bad: c.ufw === false, hint: 'sudo ufw status' });
    row('Access-лог Xray', c.access_log ? 'ВКЛЮЧЁН: пишет адреса клиентов' : 'выключен', { bad: !!c.access_log, hint: 'sudo xm log-access off' });
    row('Отладка REALITY', c.reality_debug ? 'ВКЛЮЧЕНА: пишет IP клиентов' : 'выключена', { bad: !!c.reality_debug, hint: 'sudo xm reality-debug off' });
    row('Статистика для панели', st.enabled ? 'включена' : 'выключена');
  }

  // ───────── проверки ─────────
  const CHECK_TITLE = { 'selftest': 'sudo xm selftest', 'diag-dpi': 'sudo xm diag-dpi --quick' };
  const ANSI = /\x1b\[([0-9;]*)([A-Za-z])/g;
  const COLORS = { 31: 'fail', 32: 'ok', 33: 'warn', 36: 'info' };
  function ansiLine(text) {
    const line = h('div');
    let last = 0, bold = false, color = '', m;
    const push = s => {
      if (!s) return;
      const cls = (color + (bold ? ' b' : '')).trim();
      line.append(cls ? h('span', { class: cls, text: s }) : document.createTextNode(s));
    };
    ANSI.lastIndex = 0;
    while ((m = ANSI.exec(text))) {
      push(text.slice(last, m.index));
      last = ANSI.lastIndex;
      if (m[2] !== 'm') continue;
      for (const code of (m[1] || '0').split(';')) {
        if (code === '' || code === '0') { bold = false; color = ''; }
        else if (code === '1') bold = true;
        else if (COLORS[code]) color = COLORS[code];
      }
    }
    push(text.slice(last));
    if (!line.childNodes.length) line.append(document.createTextNode('​'));
    return line;
  }

  let jobTimer = 0, jobKind = '';
  function setBusy(on) { $$('[data-run]').forEach(b => { b.disabled = on; }); $('#term-cancel').hidden = !on; }
  function setMeta(kind, level, text) {
    const meta = $('#meta-' + kind);
    meta.textContent = '';
    meta.append(stIcon(level), h('span', { text }));
  }
  async function runCheck(kind) {
    const term = $('#term');
    try { await api('run', { body: { cmd: kind } }); } catch (e) { return onFail(e); }
    jobKind = kind;
    $('#term-head').hidden = false; term.hidden = false; term.textContent = '';
    $('#term-cmd').textContent = CHECK_TITLE[kind];
    $('#term-state').textContent = 'выполняется…';
    setBusy(true);
    setMeta(kind, 'off', 'выполняется…');
    let since = 0;
    const poll = async () => {
      try {
        const j = await api('job?since=' + since, { bg: true });
        const stick = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
        j.lines.forEach(l => term.append(ansiLine(l)));
        since = j.total;
        if (stick) term.scrollTop = term.scrollHeight;
        if (!j.done) { jobTimer = setTimeout(poll, 800); return; }
        setBusy(false);
        finishCheck(kind, j);
      } catch (e) { setBusy(false); onFail(e); }
    };
    poll();
  }
  function finishCheck(kind, j) {
    const at = hm(sd(Math.floor(Date.now() / 1000)));
    if (j.truncated) $('#term').append(h('div', { class: 'dim', text: '… вывод обрезан' }));
    let level, text;
    if (kind === 'selftest') {
      level = j.rc === 0 ? 'good' : 'crit';
      text = j.rc === 0 ? 'прошёл' : 'не прошёл';
    } else if (j.result) {
      level = j.result.crit > 0 ? 'crit' : (j.result.warn > 0 ? 'warn' : 'good');
      text = 'критично ' + j.result.crit + ' · предупреждений ' + j.result.warn;
    } else {
      level = 'warn';
      text = j.rc === 0 ? 'итог не разобран, смотри вывод' : 'прервана или упала (код ' + j.rc + ')';
    }
    setMeta(kind, level, text + ' · ' + at);
    $('#term-state').textContent = 'готово · код ' + j.rc;
  }
  $$('[data-run]').forEach(b => b.addEventListener('click', () => runCheck(b.dataset.run)));
  $('#term-cancel').addEventListener('click', () => { api('job/cancel', { post: true }).catch(() => {}); });

  // ───────── клиенты ─────────
  let clients = [], sel = null, kind = 'xhttp', statsOn = false, serverNow = 0;
  const NAME_RE = /^[\p{L}\p{N}_][\p{L}\p{N}_.-]{0,31}$/u;

  async function loadClients(keep) {
    try {
      const d = await api('clients');
      $('#cl-err').hidden = true;
      clients = d.clients;
      statsOn = !!(d.stats && d.stats.enabled);
      serverNow = d.now;
      if (keep && clients.some(c => c.uuid === keep)) sel = keep;
      else if (!clients.some(c => c.uuid === sel)) sel = clients[0] ? clients[0].uuid : null;
      renderClients();
      renderDetail();
    } catch (e) { onFail(e, $('#cl-err')); }
  }
  function ago(ep) {
    if (!ep) return 'нет трафика';
    const s = serverNow - ep;
    return s < 600 ? 'сейчас' : fmtDur(s) + ' назад';
  }
  function renderClients() {
    const tb = $('#ctbody');
    tb.textContent = '';
    $('#ccount').textContent = String(clients.length);
    $$('[data-st]').forEach(n => { n.hidden = !statsOn; });
    $('#cl-stats-hint').hidden = statsOn;
    if (!clients.length) tb.append(h('tr', null, h('td', { class: 'empty', colspan: 5, text: 'Клиентов нет. «Добавить клиента» создаст ссылку и QR-код.' })));
    clients.forEach(c => {
      const s = c.stats;
      const cells = [
        h('td', { class: 'cname', text: c.name || '—' }),
        h('td', { class: 'mono uuid', text: c.uuid.slice(0, 4) + '…' + c.uuid.slice(-4) }),
      ];
      if (statsOn) {
        cells.push(h('td', { class: 'r', text: s ? fmtBytes(s.today[0] + s.today[1]) : '—' }));
        cells.push(h('td', { class: 'r m30', text: s ? fmtBytes(s.d30[0] + s.d30[1]) : '—' }));
        cells.push(h('td', null, h('span', { class: 'act' },
          h('i', { class: 'dot' + (s && s.last && serverNow - s.last < 600 ? ' on' : ''), 'aria-hidden': 'true' }),
          document.createTextNode(s ? ago(s.last) : 'нет данных'))));
      }
      const tr = h('tr', { tabindex: 0, 'aria-selected': c.uuid === sel ? 'true' : 'false' }, ...cells);
      const choose = kb => { sel = c.uuid; renderClients(); renderDetail(); if (kb) $('#ctbody [aria-selected="true"]').focus(); };
      tr.addEventListener('click', () => choose(false));
      tr.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(true); } });
      tb.append(tr);
    });
  }
  function current() { return clients.find(c => c.uuid === sel) || null; }
  function renderDetail() {
    const c = current();
    $('#detail').hidden = !c;
    if (!c) return;
    $('#d-name').textContent = c.name || '—';
    $('#d-uuid').textContent = c.uuid;
    $('#k-tcp').disabled = !c.uri_tcp;
    if (kind === 'tcp' && !c.uri_tcp) kind = 'xhttp';
    $('#k-xhttp').setAttribute('aria-pressed', kind === 'xhttp' ? 'true' : 'false');
    $('#k-tcp').setAttribute('aria-pressed', kind === 'tcp' ? 'true' : 'false');
    $('#k-tcp').title = c.uri_tcp ? '' : 'TCP-inbound не включён: sudo xm add-tcp';
    const uri = kind === 'tcp' ? c.uri_tcp : c.uri;
    $('#d-uri').textContent = uri || 'Ссылку собрать не удалось: sudo xm pubkey';
    const box = $('#qrbox');
    box.textContent = '';
    if (uri) {
      const img = h('img', { alt: 'QR-код ссылки', src: 'api/qr?uuid=' + encodeURIComponent(c.uuid) + '&kind=' + kind });
      img.addEventListener('error', () => {
        box.textContent = '';
        box.append(h('div', { class: 'none', text: 'QR недоступен. На сервере нужен qrencode: sudo apt install -y qrencode. Ссылка ниже работает и без него.' }));
      });
      box.append(img);
    }
    $('#del-box').hidden = true;
    $('#del-confirm').value = '';
    $('#del-do').disabled = true;
    $('#del-label').textContent = '';
    $('#del-label').append(document.createTextNode('Введите '), h('b', { text: c.name }), document.createTextNode(', чтобы удалить. Ссылка перестанет работать сразу, Xray перезапустится.'));
  }
  $('#k-xhttp').addEventListener('click', () => { kind = 'xhttp'; renderDetail(); });
  $('#k-tcp').addEventListener('click', () => { kind = 'tcp'; renderDetail(); });

  $('#copy').addEventListener('click', () => {
    const node = $('#d-uri');
    const fallback = () => {
      const rg = document.createRange();
      rg.selectNodeContents(node);
      const s = window.getSelection();
      s.removeAllRanges(); s.addRange(rg);
      toast('Ссылка выделена, нажмите Ctrl+C');
    };
    try { navigator.clipboard.writeText(node.textContent).then(() => toast('Ссылка скопирована'), fallback); } catch (e) { fallback(); }
  });

  $('#add-open').addEventListener('click', () => { $('#add-form').hidden = false; $('#new-name').focus(); });
  $('#add-cancel').addEventListener('click', () => { $('#add-form').hidden = true; $('#add-err').textContent = ''; });
  $('#add-form').addEventListener('submit', async e => {
    e.preventDefault();
    const name = $('#new-name').value.trim();
    const err = $('#add-err');
    if (!NAME_RE.test(name)) { err.textContent = 'Имя до 32 символов: буквы, цифры, точка, дефис, подчёркивание. Пробелы нельзя.'; return; }
    err.textContent = '';
    const go = $('#add-go');
    go.disabled = true; go.textContent = 'Создаю, Xray перезапускается…';
    try {
      const r = await api('clients/add', { body: { name } });
      $('#new-name').value = '';
      $('#add-form').hidden = true;
      toast('Клиент «' + name + '» создан');
      await loadClients(r.client.uuid);
    } catch (e2) {
      if (e2 instanceof Gone) onFail(e2); else err.textContent = e2.message;
    } finally {
      go.disabled = false; go.textContent = 'Создать и показать QR';
    }
  });
  $('#del-open').addEventListener('click', () => { $('#del-box').hidden = false; $('#del-confirm').focus(); });
  $('#del-confirm').addEventListener('input', e => { const c = current(); $('#del-do').disabled = !c || e.target.value !== c.name; });
  $('#del-do').addEventListener('click', async () => {
    const c = current();
    if (!c) return;
    $('#del-do').disabled = true;
    try {
      await api('clients/del', { body: { uuid: c.uuid } });
      toast('Клиент «' + c.name + '» удалён');
      sel = null;
      await loadClients();
    } catch (e) { onFail(e); $('#del-do').disabled = false; }
  });

  // ───────── графики ─────────
  let range = '24h';
  // Шаг оси из «круглых» (1, 2, 2.5, 5 × 10^k) с 3–5 делениями: максимум занимает
  // большую часть высоты, а не половину.
  function axis(vmax, whole) {
    if (!(vmax > 0)) return { step: 1, n: 4 };
    const e0 = Math.floor(Math.log10(vmax)) - 2;
    for (let e = e0; e <= e0 + 6; e++) {
      for (const m of [1, 2, 2.5, 5]) {
        const step = m * Math.pow(10, e);
        if (whole && (step < 1 || step !== Math.floor(step))) continue;
        const n = Math.ceil(vmax / step - 1e-9);
        if (n >= 3 && n <= 5) return { step, n };
      }
    }
    return { step: vmax / 4, n: 4 };
  }
  function segments(values) {
    const out = [];
    let start = -1;
    values.forEach((v, i) => {
      if (v == null) { if (start >= 0) out.push([start, i - 1]); start = -1; } else if (start < 0) start = i;
    });
    if (start >= 0) out.push([start, values.length - 1]);
    return out;
  }
  function xTicks(d) {
    const out = [];
    d.edges.forEach((e, i) => {
      const t = sd(e);
      if (d.range === '24h') { if (t.getUTCMinutes() === 0 && t.getUTCHours() % 4 === 0) out.push([i, hm(t)]); }
      else if (d.range === '7d') { if (t.getUTCHours() === 0) out.push([i, WD[t.getUTCDay()] + NB + t.getUTCDate()]); }
      else if ((d.edges.length - 1 - i) % 5 === 0) out.push([i, pad(t.getUTCDate()) + '.' + pad(t.getUTCMonth() + 1)]);
    });
    return out;
  }
  function spanLabel(d, i) {
    const a = sd(d.edges[i]), b = sd(d.ends[i]);
    if (d.range === '24h') return dm(a) + ', ' + hm(a) + '–' + hm(b);
    if (d.range === '7d') return WD[a.getUTCDay()] + NB + dm(a) + ', ' + hm(a) + '–' + hm(b);
    return WD[a.getUTCDay()] + NB + dm(a);
  }

  function renderLine(host, cfg) {
    host.textContent = '';
    const W = Math.floor(host.clientWidth);
    if (W < 80) return;
    const H = 232, multi = cfg.series.length > 1;
    const m = { l: 44, r: multi ? 58 : 34, t: 12, b: 26 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b, n = cfg.edges.length;
    const all = [].concat(...cfg.series.map(s => s.values.filter(v => v != null)));
    const vmax = all.length ? Math.max(...all) : 0;
    const { step, n: ticks } = axis(vmax, cfg.int);
    const ymax = step * ticks;
    const X = i => m.l + (n === 1 ? iw / 2 : (i * iw) / (n - 1));
    const Y = v => m.t + ih - (v / ymax) * ih;
    const root = sv('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': cfg.label });

    for (let k = 0; k <= ticks; k++) {
      const y = Y(k * step);
      root.append(sv('line', { x1: m.l, x2: m.l + iw, y1: y, y2: y, class: k === 0 ? 'base-line' : 'grid-line' }));
      const tx = sv('text', { x: m.l - 8, y: y + 4, 'text-anchor': 'end' });
      tx.textContent = cfg.tick(k * step);
      root.append(tx);
    }
    let lastX = -Infinity;
    cfg.xticks.forEach(([i, lab]) => {
      const x = X(i);
      if (x - lastX < 46) return;
      lastX = x;
      const tx = sv('text', { x, y: H - 7, 'text-anchor': 'middle' });
      tx.textContent = lab;
      root.append(tx);
    });
    cfg.series.forEach(s => {
      segments(s.values).forEach(([a, b]) => {
        let line = '';
        for (let i = a; i <= b; i++) line += (i === a ? 'M' : 'L') + X(i).toFixed(1) + ' ' + Y(s.values[i]).toFixed(1);
        root.append(sv('path', { d: line + 'L' + X(b).toFixed(1) + ' ' + Y(0) + 'L' + X(a).toFixed(1) + ' ' + Y(0) + 'Z', class: 'ar ' + s.cls }));
        root.append(sv('path', { d: line, class: 'ln ' + s.cls }));
      });
    });
    const ends = cfg.series.map(s => {
      let i = s.values.length - 1;
      while (i >= 0 && s.values[i] == null) i--;
      return { s, i };
    }).filter(e => e.i >= 0);
    const collide = ends.length > 1 && Math.abs(Y(ends[0].s.values[ends[0].i]) - Y(ends[1].s.values[ends[1].i])) < 14;
    ends.forEach(({ s, i }) => {
      root.append(sv('circle', { cx: X(i), cy: Y(s.values[i]), r: 4, class: 'pt ' + s.cls }));
      if (!collide) {
        const tx = sv('text', { x: X(i) + 9, y: Y(s.values[i]) + 4, class: 'lbl' });
        tx.textContent = (s.short ? s.short + ' ' : '') + cfg.tick(s.values[i]);
        root.append(tx);
      }
    });

    const cross = sv('line', { y1: m.t, y2: m.t + ih, class: 'cross', visibility: 'hidden' });
    root.append(cross);
    const dots = cfg.series.map(s => {
      const c = sv('circle', { r: 4, visibility: 'hidden', class: 'pt ' + s.cls });
      root.append(c);
      return c;
    });
    const area = sv('rect', { x: m.l, y: m.t, width: Math.max(1, iw), height: ih, class: 'hit' });
    root.append(area);
    host.append(root);
    const tip = h('div', { class: 'tip', hidden: true });
    host.append(tip);

    let cur = -1;
    function show(i) {
      i = Math.min(n - 1, Math.max(0, i));
      cur = i;
      const x = X(i);
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.setAttribute('visibility', 'visible');
      cfg.series.forEach((s, k) => {
        const v = s.values[i];
        dots[k].setAttribute('visibility', v == null ? 'hidden' : 'visible');
        if (v != null) { dots[k].setAttribute('cx', x); dots[k].setAttribute('cy', Y(v)); }
      });
      tip.textContent = '';
      tip.append(h('div', { class: 'tt', text: cfg.time(i) }));
      cfg.series.forEach(s => tip.append(h('div', { class: 'tr' },
        h('i', { class: 'k ' + s.cls }), h('b', { text: s.values[i] == null ? 'нет данных' : cfg.tick(s.values[i], true) }), h('span', { text: s.name }))));
      tip.hidden = false;
      let left = x + 12;
      if (left + tip.offsetWidth > W) left = x - 12 - tip.offsetWidth;
      tip.style.left = Math.max(0, left) + 'px';
      tip.style.top = m.t + 'px';
    }
    function hide() {
      cur = -1;
      tip.hidden = true;
      cross.setAttribute('visibility', 'hidden');
      dots.forEach(d => d.setAttribute('visibility', 'hidden'));
    }
    const at = e => {
      const r = root.getBoundingClientRect();
      show(Math.round(((e.clientX - r.left - m.l) / iw) * (n - 1)));
    };
    area.addEventListener('pointermove', at);
    area.addEventListener('pointerdown', at);
    area.addEventListener('pointerleave', hide);
    host.onfocus = () => show(cur < 0 ? n - 1 : cur);
    host.onblur = hide;
    host.onkeydown = e => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); show((cur < 0 ? n - 1 : cur) + (e.key === 'ArrowRight' ? 1 : -1)); }
      else if (e.key === 'Home') { e.preventDefault(); show(0); }
      else if (e.key === 'End') { e.preventDefault(); show(n - 1); }
      else if (e.key === 'Escape') hide();
    };
  }

  function renderBars(host, items) {
    host.textContent = '';
    if (!items.length) { host.append(h('p', { class: 'hint', text: 'Клиентов со статистикой пока нет.' })); return; }
    const max = Math.max(1, ...items.map(it => it.v));
    const total = items.reduce((a, it) => a + it.v, 0);
    const tip = h('div', { class: 'tip', hidden: true });
    items.forEach(it => {
      const fill = h('span', { class: 'bar-fill' });
      fill.style.width = (it.v > 0 ? Math.max(0.6, (it.v / max) * 78) : 0) + '%';
      const row = h('div', { class: 'bar-row', tabindex: 0, 'aria-label': it.name + ': ' + fmtBytes(it.v) },
        h('span', { class: 'bar-name', text: it.name, title: it.name }),
        h('span', { class: 'bar-track' }, fill, h('span', { class: 'bar-val', text: fmtBytes(it.v) })));
      const show = () => {
        tip.textContent = '';
        tip.append(h('div', { class: 'tt', text: it.name }), h('div', { class: 'tr' },
          h('i', { class: 'k s1' }), h('b', { text: fmtBytes(it.v) }),
          h('span', { text: total ? f0.format((it.v / total) * 100) + NB + '% от всех' : '' })));
        tip.hidden = false;
        tip.style.left = Math.max(0, Math.min(host.clientWidth - tip.offsetWidth, fill.offsetLeft + fill.offsetWidth + 70)) + 'px';
        tip.style.top = (row.offsetTop - tip.offsetHeight - 4) + 'px';
      };
      const hide = () => { tip.hidden = true; };
      row.addEventListener('pointerenter', show);
      row.addEventListener('pointerleave', hide);
      row.addEventListener('focus', show);
      row.addEventListener('blur', hide);
      host.append(row);
    });
    host.append(tip);
  }

  function tableView(host, head, rows) {
    host.textContent = '';
    const tb = h('tbody');
    rows.forEach(r => tb.append(h('tr', null, ...r.map((x, i) => h('td', { class: i ? 'r' : null, text: x })))));
    host.append(h('table', null, h('thead', null, h('tr', null, ...head.map((x, i) => h('th', { class: i ? 'r' : null, text: x })))), tb));
  }

  const RANGE_WORD = { '24h': 'за сутки', '7d': 'за 7 дней', '30d': 'за 30 дней' };
  const STEP_WORD = { '24h': 'среднее за 15 минут', '7d': 'среднее за час', '30d': 'среднее за сутки' };
  let chartData = null;
  async function loadCharts() {
    try {
      chartData = await api('stats?range=' + range);
      $('#ch-err').hidden = true;
      renderCharts();
    } catch (e) { onFail(e, $('#ch-err')); }
  }
  function renderCharts() {
    const d = chartData;
    if ($('#p-charts').hidden || !d) return;
    const st = d.state || {};
    const off = $('#ch-off');
    let title = '', text = '';
    if (!st.enabled) {
      title = 'Графики не включены';
      text = 'Включите сбор статистики: в Xray добавятся счётчики и локальный API на 127.0.0.1, раз в 5 минут записываются суммы трафика и число соединений. Команда меняет config.json и перезапускает Xray. Отключить и стереть данные: sudo xm stats off.';
    } else if (!st.collector) {
      title = 'Сбор статистики остановлен';
      text = 'Счётчики в Xray включены, но таймер замеров не работает. Запустить заново:';
    } else if (!d.has_data) {
      title = 'Данных пока нет';
      text = 'Первый замер появится в течение 5 минут после включения. Страницу можно не перезагружать: откройте вкладку ещё раз.';
    }
    off.hidden = !title;
    $('#ch-body').hidden = !!title && !d.has_data;
    $('#ch-off-title').textContent = title;
    $('#ch-off-text').textContent = text;
    $('#ch-off-cmd').hidden = !!st.enabled && !!st.collector;
    if ($('#ch-body').hidden) return;

    const xt = xTicks(d);
    const time = i => spanLabel(d, i);
    const sum = a => a.reduce((s, v) => s + (v || 0), 0);
    $('#traffic-sub').textContent = 'Мбит/с, ' + STEP_WORD[range] + ' · всего ' + RANGE_WORD[range] + ' ' + fmtBytes(sum(d.up_bytes) + sum(d.down_bytes)) + ' · время серверное';
    renderLine($('#plot-traffic'), {
      label: 'Трафик клиентов, Мбит/с', edges: d.edges, xticks: xt, time,
      tick: (v, full) => fmtRate(v) + (full ? NB + 'Мбит/с' : ''),
      series: [
        { name: 'к клиентам', short: '↓', cls: 's1', values: d.down_mbit },
        { name: 'от клиентов', short: '↑', cls: 's2', values: d.up_mbit },
      ],
    });
    renderLine($('#plot-conns'), {
      label: 'Соединения на публичном порту', edges: d.edges, xticks: xt, time, int: true,
      tick: (v, full) => f0.format(v) + (full ? NB + 'соединений' : ''),
      series: [{ name: 'максимум на интервал', cls: 's1', values: d.conns_max }],
    });
    const items = d.clients.map(c => ({ name: c.name, v: c.up + c.down }));
    $('#clients-sub').textContent = (range === '24h' ? 'Сегодня с 00:00 по времени сервера' : range === '7d' ? 'Последние 7 суток, считая сегодня' : 'Последние 30 суток, считая сегодня') + ', обе стороны вместе';
    renderBars($('#bars-clients'), items);

    if (!$('#tv-traffic').hidden) tableView($('#tv-traffic'), ['Интервал', '↓ к клиентам, Мбит/с', '↑ от клиентов, Мбит/с'],
      d.edges.map((_, i) => [time(i), d.down_mbit[i] == null ? '—' : fmtRate(d.down_mbit[i]), d.up_mbit[i] == null ? '—' : fmtRate(d.up_mbit[i])]).reverse());
    if (!$('#tv-clients').hidden) tableView($('#tv-clients'), ['Клиент', 'Трафик'], items.map(it => [it.name, fmtBytes(it.v)]));
    if (!$('#tv-conns').hidden) tableView($('#tv-conns'), ['Интервал', 'Соединений, максимум'],
      d.edges.map((_, i) => [time(i), d.conns_max[i] == null ? '—' : f0.format(d.conns_max[i])]).reverse());
  }
  $$('[data-range]').forEach(b => b.addEventListener('click', () => {
    range = b.dataset.range;
    $$('[data-range]').forEach(x => x.setAttribute('aria-pressed', x === b ? 'true' : 'false'));
    loadCharts();
  }));
  $$('[data-table]').forEach(b => b.addEventListener('click', () => {
    const tv = $('#' + b.dataset.table);
    tv.hidden = !tv.hidden;
    b.setAttribute('aria-pressed', tv.hidden ? 'false' : 'true');
    renderCharts();
  }));
  let rq = 0;
  new ResizeObserver(() => { cancelAnimationFrame(rq); rq = requestAnimationFrame(renderCharts); }).observe($('main'));

  // ───────── логи ─────────
  const LOGNOTE = {
    xray: 'только ошибки (loglevel error)',
    nginx: 'соединения без ключа REALITY или с чужим SNI, отданные сайту-маске',
    watchdog: 'проверка пути каждые 2 минуты, пишет только при сбое',
    f2b: 'баны за перебор паролей SSH',
    journal: 'выводы разборов этой установки (sudo xm journal)',
  };
  let src = 'xray', logLines = [], logMissing = false, logPath = '', followTimer = 0;
  function lineClass(l) {
    if (/\[(Error|Fatal)\]|\bERROR\b|не резолвится|всё ещё мёртв/.test(l)) return 'fail';
    if (/\[Warning\]|\bWARNING\b|\bBan\b|перезапускаю/.test(l)) return 'warn';
    if (/\bUnban\b|восстановлен/.test(l)) return 'ok';
    if (src === 'journal' && /^## /.test(l)) return 'h';
    return '';
  }
  async function loadLogs(bg) {
    try {
      const d = await api('logs?src=' + src + '&n=500', { bg: !!bg });
      logLines = d.lines; logMissing = d.missing; logPath = d.path;
      renderLogs();
    } catch (e) { onFail(e); }
  }
  function renderLogs() {
    $('#lpath').textContent = logPath || '';
    $('#lnote').textContent = LOGNOTE[src] || '';
    const view = $('#logview');
    const stick = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const q = $('#lfilter').value.trim().toLowerCase();
    view.textContent = '';
    const shown = logLines.filter(l => !q || l.toLowerCase().includes(q));
    if (!shown.length) view.append(h('div', { class: 'dim', text: logMissing ? 'Файла или журнала нет: источник не включён или не создан' : (q ? 'Нет строк с «' + q + '»' : 'Лог пуст') }));
    shown.forEach(l => {
      const cls = lineClass(l);
      view.append(h('div', { class: cls }, document.createTextNode(l || '​')));
    });
    if (stick) view.scrollTop = view.scrollHeight;
  }
  $$('[data-src]').forEach(b => b.addEventListener('click', () => {
    src = b.dataset.src;
    $$('[data-src]').forEach(x => x.setAttribute('aria-pressed', x === b ? 'true' : 'false'));
    loadLogs();
  }));
  $('#lfilter').addEventListener('input', renderLogs);
  $('#lreload').addEventListener('click', () => loadLogs());
  function followOff() { $('#follow').checked = false; clearInterval(followTimer); followTimer = 0; }
  $('#follow').addEventListener('change', e => {
    clearInterval(followTimer);
    followTimer = 0;
    if (e.target.checked) followTimer = setInterval(() => loadLogs(true), 3000);
  });

  // ───────── старт ─────────
  $('#stop').addEventListener('click', async () => {
    try { await api('stop', { post: true }); } catch (e) { /* сервер мог закрыться раньше ответа */ }
    gone('Панель остановлена');
  });
  ['pointerdown', 'keydown'].forEach(ev => window.addEventListener(ev, ping, { passive: true }));
  setInterval(pollSession, 10000);
  setInterval(tickIdle, 1000);
  pollSession().then(() => {
    tickIdle();
    const tab = location.hash.slice(1) || 'overview';
    if (tab !== 'overview') loadOverview();   // шапка (имя сервера, состояние Xray) — на любой вкладке
    setTab(tab);
  });
})();
