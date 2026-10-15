// HoneyForge Cyber SOC Console Logic

let currentUser = null;
let authToken = null;
let ws = null;
let eventChart = null;
let currentDeployTrapId = null;
let currentDeployFormat = "docker-compose";
let allEventsCache = [];
let activeFilters = {
    trap: "",
    type: "",
    severity: "",
    ip: "",
    period: "all"
};

// ----------------- Инициализация и авторизация -----------------
document.addEventListener("DOMContentLoaded", () => {
    renderTabIcons();
    checkAuthSession();
});

function renderTabIcons() {
    if (typeof ICONS === "undefined") return;
    if (document.getElementById("icon-tab-live")) document.getElementById("icon-tab-live").innerHTML = ICONS.live || "";
    if (document.getElementById("icon-tab-traps")) document.getElementById("icon-tab-traps").innerHTML = ICONS.traps || "";
    if (document.getElementById("icon-tab-profiles")) document.getElementById("icon-tab-profiles").innerHTML = ICONS.profiles || "";
    if (document.getElementById("icon-tab-sessions")) document.getElementById("icon-tab-sessions").innerHTML = ICONS.sessions || "";
    if (document.getElementById("icon-tab-honeytokens")) document.getElementById("icon-tab-honeytokens").innerHTML = ICONS.honeytokens || "";
    if (document.getElementById("icon-tab-alerts")) document.getElementById("icon-tab-alerts").innerHTML = ICONS.alerts_ioc || "";
    if (document.getElementById("icon-tab-audit")) document.getElementById("icon-tab-audit").innerHTML = ICONS.audit || "";
    if (document.getElementById("icon-tab-users")) document.getElementById("icon-tab-users").innerHTML = ICONS.users || "";
    if (document.getElementById("icon-export-lock")) document.getElementById("icon-export-lock").innerHTML = ICONS.lock || "";
    if (document.getElementById("icon-inspect-key")) document.getElementById("icon-inspect-key").innerHTML = ICONS.key || "";
}

async function checkAuthSession() {
    const urlParams = new URLSearchParams(window.location.search);
    const isJuryAuto = urlParams.get("demo") === "jury" || urlParams.get("jury") === "1" || urlParams.get("guest") === "1";

    if (isJuryAuto) {
        try {
            await performLogin("jury", "jury2026");
            return;
        } catch (e) {
            console.warn("Jury auto-login fallback", e);
        }
    }

    const savedToken = localStorage.getItem("hf_token");
    const savedUser = localStorage.getItem("hf_user");
    if (!savedToken || !savedUser) {
        showLoginScreen();
        return;
    }
    try {
        authToken = savedToken;
        currentUser = JSON.parse(savedUser);
        
        // Проверяем валидность токена на сервере (FR-C5)
        const meRes = await fetch("/api/v1/auth/me", { headers: apiHeaders() });
        if (!meRes.ok) {
            handleLogout();
            return;
        }
        const meUser = await meRes.json();
        currentUser = meUser;
        localStorage.setItem("hf_user", JSON.stringify(currentUser));

        applyUserSessionUI();
        initApp();
    } catch (e) {
        showLoginScreen();
    }
}

function showLoginScreen() {
    document.getElementById("login-screen").style.display = "flex";
}

async function performLogin(u, p) {
    const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: u, password: p })
    });
    if (!res.ok) {
        throw new Error("Неверное имя пользователя или пароль");
    }
    const data = await res.json();
    authToken = data.access_token;
    currentUser = data.user;
    localStorage.setItem("hf_token", authToken);
    localStorage.setItem("hf_user", JSON.stringify(currentUser));
    document.getElementById("login-screen").style.display = "none";
    applyUserSessionUI();
    initApp();
}

async function quickLoginJury() {
    const errBox = document.getElementById("login-error");
    if (errBox) errBox.style.display = "none";
    try {
        await performLogin("jury", "jury2026");
    } catch (e) {
        if (errBox) {
            errBox.innerText = e.message || "Ошибка быстрого входа";
            errBox.style.display = "block";
        }
    }
}

async function handleLoginSubmit(event) {
    event.preventDefault();
    const u = document.getElementById("login-username").value.trim();
    const p = document.getElementById("login-password").value;
    const errBox = document.getElementById("login-error");
    errBox.style.display = "none";

    try {
        await performLogin(u, p);
    } catch (e) {
        errBox.innerText = e.message || "Ошибка соединения с сервером";
        errBox.style.display = "block";
    }
}

function handleLogout() {
    if (authToken) {
        fetch("/api/v1/auth/logout", {
            method: "POST",
            headers: { "Authorization": "Bearer " + authToken }
        }).catch(() => {});
    }
    localStorage.removeItem("hf_token");
    localStorage.removeItem("hf_user");
    authToken = null;
    currentUser = null;
    if (ws) ws.close();
    location.reload();
}

function applyUserSessionUI() {
    if (!currentUser) return;
    document.getElementById("op-username").innerText = currentUser.username;
    const roleMap = (typeof STRINGS !== "undefined" && STRINGS.roles) || {
        admin: "Главный администратор (CISO)",
        soc_lead: "Руководитель смены SOC",
        analyst_l2: "Старший аналитик L2 (Threat Hunter)",
        analyst_l1: "Дежурный аналитик L1 (Triage)",
        auditor: "Аудитор ИБ (Комплаенс)",
        analyst: "Аналитик SOC"
    };
    if (currentUser.username === "jury" || currentUser.username === "demo") {
        document.getElementById("op-role").innerText = "Эксперт жюри (Просмотр)";
        document.getElementById("op-role").style.borderColor = "var(--accent-2)";
        document.getElementById("op-role").style.color = "var(--accent-2)";
    } else {
        document.getElementById("op-role").innerText = roleMap[currentUser.role] || currentUser.role;
    }

    // Права администратора (управление ловушками, пользователями, правилами)
    const isAdmin = currentUser.role === "admin";
    document.querySelectorAll(".admin-only").forEach(el => {
        el.style.display = isAdmin ? "" : "none";
    });
}

function apiHeaders() {
    const h = { "Content-Type": "application/json" };
    if (authToken) {
        h["Authorization"] = `Bearer ${authToken}`;
    }
    return h;
}

function initApp() {
    initWebSocket();
    loadOverviewStats();
    loadEventsFeed();
    loadTrapsFilterOptions();
    loadAlerts();

    // Фоновые обновления
    setInterval(loadOverviewStats, 10000);
}

// ----------------- WebSocket подключение -----------------
async function initWebSocket() {
    if (!authToken) return;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    let queryParam = "";

    try {
        const ticketRes = await fetch("/api/v1/auth/ws-ticket", {
            method: "POST",
            headers: { "Authorization": "Bearer " + authToken }
        });
        if (ticketRes.ok) {
            const ticketData = await ticketRes.json();
            if (ticketData.ticket) {
                queryParam = `?ticket=${encodeURIComponent(ticketData.ticket)}`;
            }
        }
    } catch (e) {
        queryParam = `?token=${encodeURIComponent(authToken)}`;
    }

    if (!queryParam) {
        queryParam = `?token=${encodeURIComponent(authToken)}`;
    }

    const wsUrl = `${proto}//${location.host}/ws/attacks${queryParam}`;
    ws = new WebSocket(wsUrl);

    const indText = document.getElementById("ws-status-text");
    const indDot = document.getElementById("ws-dot");

    ws.onopen = () => {
        indText.innerText = "Канал событий: подключено";
        indDot.className = "channel-dot";
    };

    ws.onclose = () => {
        indText.innerText = "Канал событий: переподключение...";
        indDot.className = "channel-dot reconnecting";
        setTimeout(initWebSocket, 3000);
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWsMessage(msg);
        } catch (e) {
            console.error("Ошибка парсинга WS сообщения", e);
        }
    };
}

function handleWsMessage(msg) {
    if (msg.type === "attack_event") {
        const ev = msg.data;
        allEventsCache.unshift(ev);
        if (allEventsCache.length > 500) allEventsCache.pop();

        if (eventMatchesFilters(ev)) {
            renderEventItem(ev, true);
        }
        incrementCounter("metric-total-events");
        if (ev.severity === "critical") {
            incrementCounter("metric-critical-events");
        }
        if (ev.credentials) {
            incrementCounter("metric-credentials");
        }
    } else if (msg.type === "alert") {
        prependAlertItem(msg.data);
    } else if (msg.type === "trap_heartbeat") {
        updateTrapHeartbeatUI(msg.data);
    } else if (msg.type === "honeytoken_triggered") {
        incrementCounter("metric-ht-triggered");
        loadOverviewStats();
        if (document.getElementById("tab-honeytokens").classList.contains("active")) {
            loadHoneytokens();
        }
    }
}

// ----------------- Статистика и метрики -----------------
async function loadOverviewStats() {
    try {
        const res = await fetch("/api/v1/stats/overview", { headers: apiHeaders() });
        if (!res.ok) return;
        const d = await res.json();

        document.getElementById("metric-online-traps").innerText = d.online_traps;
        document.getElementById("metric-total-traps").innerText = d.total_traps;
        document.getElementById("metric-traps-breakdown").innerText = `Low: ${d.traps_low || 1} · Medium: ${d.traps_medium || 1}`;
        document.getElementById("metric-total-events").innerText = d.total_events;
        document.getElementById("metric-critical-events").innerText = d.critical_events;
        document.getElementById("metric-credentials").innerText = d.captured_credentials;

        // Корректный подсчет Honeytokens: сработало / всего активных
        const activeCount = Math.max(0, d.honeytokens_count - d.honeytokens_triggered);
        document.getElementById("metric-ht-triggered").innerText = d.honeytokens_triggered;
        document.getElementById("metric-ht-total").innerText = activeCount || d.honeytokens_count;

        updateEventTypesChart(d.events_per_type);
        updateTopAttackersList(d.top_attackers);
    } catch (e) {
        console.error(e);
    }
}

function updateEventTypesChart(typesMap) {
    const ctx = document.getElementById("chart-event-types");
    if (!ctx) return;

    const translations = STRINGS.event_types || {};
    const rawKeys = Object.keys(typesMap || {});
    const labels = rawKeys.map(k => translations[k] || k);
    const dataVals = Object.values(typesMap || {});

    const total = dataVals.reduce((a, b) => a + b, 0) || 1;

    // Цвета из палитры «Медь и патина»
    const chartColors = ['#c08b60', '#6fa597', '#c4524f', '#9a8bb0', '#d0b070', '#7f98a3'];

    if (eventChart) {
        eventChart.data.labels = labels;
        eventChart.data.datasets[0].data = dataVals;
        eventChart.update();
    } else {
        eventChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels.length ? labels : ['Сканирование', 'Вход', 'Команда'],
                datasets: [{
                    data: dataVals.length ? dataVals : [1, 1, 1],
                    backgroundColor: chartColors,
                    borderColor: '#191917',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // Легенда с подписями на русском, числами и процентами
    const legendEl = document.getElementById("chart-legend");
    legendEl.innerHTML = "";
    rawKeys.slice(0, 4).forEach((k, idx) => {
        const count = typesMap[k];
        const pct = Math.round((count / total) * 100);
        const name = translations[k] || k;
        const color = chartColors[idx % chartColors.length];
        const item = document.createElement("div");
        item.style.display = "flex";
        item.style.justifyContent = "space-between";
        item.style.alignItems = "center";
        item.style.marginBottom = "4px";
        item.innerHTML = `
            <span style="display:flex; align-items:center; gap:6px;">
                <span style="width:8px; height:8px; border-radius:50%; background:${color}; display:inline-block;"></span>
                <span>${name}</span>
            </span>
            <span style="color:var(--text-muted); font-family:var(--font-mono); font-size:11px;">${count} (${pct}%)</span>
        `;
        legendEl.appendChild(item);
    });
}

function updateTopAttackersList(attackers) {
    const list = document.getElementById("top-attackers-list");
    list.innerHTML = "";
    if (!attackers || attackers.length === 0) {
        list.innerHTML = `<div style="color:var(--text-muted); font-size:12px; text-align:center; padding:10px;">Нет данных</div>`;
        return;
    }
    attackers.forEach(a => {
        const item = document.createElement("div");
        item.style.display = "flex";
        item.style.justifyContent = "space-between";
        item.style.alignItems = "center";
        item.style.padding = "6px 8px";
        item.style.borderBottom = "1px solid var(--border)";
        item.style.fontSize = "12px";

        const country = a.country || "Тестовая сеть";
        const asn = a.asn || "AS-LOCAL";

        item.innerHTML = `
            <div>
                <div style="font-family:var(--font-mono); color:var(--text); font-weight:600;">${a.ip}</div>
                <div style="color:var(--text-muted); font-size:11px;">${country} · ${asn}</div>
            </div>
            <div style="color:var(--accent); font-family:var(--font-mono); font-weight:600;">${a.count}</div>
        `;
        list.appendChild(item);
    });
}

// ----------------- Лента событий и фильтрация -----------------
async function loadEventsFeed() {
    let url = `/api/v1/events?limit=100`;
    if (activeFilters.trap) url += `&trap_id=${encodeURIComponent(activeFilters.trap)}`;
    if (activeFilters.type) url += `&event_type=${encodeURIComponent(activeFilters.type)}`;
    if (activeFilters.severity) url += `&severity=${encodeURIComponent(activeFilters.severity)}`;
    if (activeFilters.ip) url += `&source_ip=${encodeURIComponent(activeFilters.ip)}`;
    if (activeFilters.period && activeFilters.period !== "all") url += `&period=${encodeURIComponent(activeFilters.period)}`;

    try {
        const res = await fetch(url, { headers: apiHeaders() });
        if (!res.ok) return;
        const events = await res.json();
        allEventsCache = events;
        renderEventsList(events);
    } catch (e) {
        console.error(e);
    }
}

function renderEventsList(events) {
    const container = document.getElementById("feed-container");
    container.innerHTML = "";
    document.getElementById("feed-count-display").innerText = `${events.length} событий`;

    if (events.length === 0) {
        container.innerHTML = `<div style="text-align:center; color:var(--text-muted); padding:40px; font-size:13px;">Событий не найдено по заданным фильтрам</div>`;
        return;
    }

    events.forEach(ev => renderEventItem(ev, false));
}

function renderEventItem(ev, isPrepend) {
    const container = document.getElementById("feed-container");
    if (!container) return;

    // Группировка схожих событий (от одного IP к одной ловушке в пределах 10 с)
    const existingGroup = findMergeableGroup(ev);
    if (existingGroup) {
        updateGroupedRow(existingGroup, ev);
        return;
    }

    const row = document.createElement("div");
    row.className = "feed-row";
    row.dataset.eventId = ev.event_id;
    row.dataset.timestamp = ev.timestamp;
    row.dataset.sourceIp = ev.source_ip;
    row.dataset.trapId = ev.trap_id;
    row.dataset.eventType = ev.event_type;
    row.dataset.groupCount = "1";

    const sev = ev.severity || "low";
    const sevBadge = `<span class="badge badge-${sev}">${STRINGS.severities[sev] || sev.toUpperCase()}</span>`;
    const timeFormatted = formatDateTimeUTC(ev.timestamp);
    const relTime = formatRelativeTime(ev.timestamp);
    const country = ev.geo_country && ev.geo_country !== "Unknown" ? ev.geo_country : "Тестовая сеть";
    const desc = buildHumanReadableDescription(ev);

    row.innerHTML = `
        <div>${sevBadge}</div>
        <div class="feed-time">
            <div style="font-family:var(--font-mono); font-size:13px; font-weight:600; color:var(--text);">${formatTimeMSK(ev.timestamp)}</div>
        </div>
        <div class="feed-trap">
            <div>${ev.trap_id}</div>
            <div style="color:var(--text-muted); font-size:11px;">${ev.protocol}</div>
        </div>
        <div class="feed-source">
            <div>${ev.source_ip}</div>
            <div style="color:var(--text-muted); font-size:11px;">${country}</div>
        </div>
        <div class="feed-port">:${ev.destination_port}</div>
        <div class="feed-desc" title="${escapeHtml(desc)}">
            <span class="feed-desc-text">${escapeHtml(desc)}</span>
        </div>
    `;

    row.onclick = () => openEventDrawer(ev);

    if (isPrepend && container.firstChild) {
        container.insertBefore(row, container.firstChild);
    } else {
        container.appendChild(row);
    }
}

function findMergeableGroup(ev) {
    const rows = document.querySelectorAll(".feed-row");
    const dEv = parseUTCDate(ev.timestamp);
    const evTime = dEv ? dEv.getTime() : 0;
    for (let i = 0; i < Math.min(rows.length, 5); i++) {
        const r = rows[i];
        if (
            r.dataset.sourceIp === ev.source_ip &&
            r.dataset.trapId === ev.trap_id &&
            r.dataset.eventType === ev.event_type
        ) {
            const dRow = parseUTCDate(r.dataset.timestamp);
            const rowTime = dRow ? dRow.getTime() : 0;
            if (Math.abs(evTime - rowTime) <= 10000) {
                return r;
            }
        }
    }
    return null;
}

function updateGroupedRow(row, newEv) {
    let count = parseInt(row.dataset.groupCount || "1", 10) + 1;
    row.dataset.groupCount = String(count);

    const descBox = row.querySelector(".feed-desc");
    let badge = descBox.querySelector(".group-badge");
    if (!badge) {
        badge = document.createElement("span");
        badge.className = "group-badge";
        descBox.insertBefore(badge, descBox.firstChild);
    }
    badge.innerText = `[${count} повтора] `;

    const timeEl = row.querySelector(".feed-time div");
    if (timeEl && newEv.timestamp) {
        timeEl.innerText = formatTimeMSK(newEv.timestamp);
    }
}

function buildHumanReadableDescription(ev) {
    if (ev.event_type === "port_scan") {
        return `Сканирование порта ${ev.destination_port} (${ev.protocol})`;
    }
    if (ev.event_type === "banner_probe") {
        return `Запрос баннера службы на порту ${ev.destination_port}`;
    }
    if (ev.event_type === "auth_attempt") {
        if (ev.credentials) {
            return `Попытка входа: ${ev.credentials.username} / ${ev.credentials.password}`;
        }
        return `Попытка авторизации на порту ${ev.destination_port}`;
    }
    if (ev.event_type === "shell_command") {
        return `Команда: ${ev.command_text || ev.payload_raw || ''}`;
    }
    if (ev.event_type === "file_download") {
        return `Загрузка файла (SHA-256: ${ev.artifact_hash ? ev.artifact_hash.slice(0, 16) + '...' : 'отсутствует'})`;
    }
    if (ev.event_type === "honeytoken_triggered") {
        return `Срабатывание приманки: ${ev.payload_raw || 'доступ к honeytoken'}`;
    }
    if (ev.event_type === "web_request" || ev.event_type === "sql_injection") {
        return `HTTP-запрос: ${ev.http_data?.path || '/'} [${ev.http_data?.method || 'GET'}]`;
    }
    return ev.payload_raw || "Сетевой зонд зафиксирован";
}

function eventMatchesFilters(ev) {
    if (activeFilters.trap && ev.trap_id !== activeFilters.trap) return false;
    if (activeFilters.type && ev.event_type !== activeFilters.type) return false;
    if (activeFilters.severity && ev.severity !== activeFilters.severity) return false;
    if (activeFilters.ip && !ev.source_ip.includes(activeFilters.ip)) return false;
    return true;
}

function applyFilters() {
    activeFilters.trap = document.getElementById("filter-trap").value;
    activeFilters.type = document.getElementById("filter-type").value;
    activeFilters.severity = document.getElementById("filter-severity").value;
    activeFilters.ip = document.getElementById("filter-ip").value.trim();
    activeFilters.period = document.getElementById("filter-period").value;
    loadEventsFeed();
}

function resetFilters() {
    document.getElementById("filter-trap").value = "";
    document.getElementById("filter-type").value = "";
    document.getElementById("filter-severity").value = "";
    document.getElementById("filter-ip").value = "";
    document.getElementById("filter-period").value = "all";
    activeFilters = { trap: "", type: "", severity: "", ip: "", period: "all" };
    loadEventsFeed();
}

async function loadTrapsFilterOptions() {
    try {
        const res = await fetch("/api/v1/traps", { headers: apiHeaders() });
        if (!res.ok) return;
        const traps = await res.json();
        const sel = document.getElementById("filter-trap");
        sel.innerHTML = `<option value="">Все ловушки</option>`;
        traps.forEach(t => {
            sel.innerHTML += `<option value="${t.trap_id}">${t.trap_id} (${t.name})</option>`;
        });
    } catch (e) {}
}

// ----------------- Боковая панель деталей события (Drawer) -----------------
function openEventDrawer(ev) {
    const drawer = document.getElementById("event-drawer");
    const content = document.getElementById("drawer-content");

    const timeUtc = formatDateTimeUTC(ev.timestamp);
    const country = ev.geo_country && ev.geo_country !== "Unknown" ? ev.geo_country : "Тестовая сеть";
    const asn = ev.source_asn || "AS-LOCAL";

    let credsHtml = "—";
    if (ev.credentials) {
        credsHtml = `<strong>Логин:</strong> ${escapeHtml(ev.credentials.username || '')} &nbsp;|&nbsp; <strong>Пароль:</strong> ${escapeHtml(ev.credentials.password || '')}`;
    }

    let artifactHtml = "—";
    if (ev.artifact_hash) {
        artifactHtml = `<div class="detail-val mono">${ev.artifact_hash}</div><div style="margin-top:4px;"><a href="#" style="color:var(--accent); font-size:12px;">Скачать артефакт (.bin)</a></div>`;
    }

    content.innerHTML = `
        <div class="detail-row">
            <div class="detail-label">Важность события</div>
            <div class="detail-val"><span class="badge badge-${ev.severity}">${STRINGS.severities[ev.severity] || ev.severity}</span></div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Идентификатор события (UUID)</div>
            <div class="detail-val mono">${ev.event_id}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Время фиксации (МСК)</div>
            <div class="detail-val mono">${formatDateTimeMSK(ev.timestamp)}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Задержка доставки в центр</div>
            <div class="detail-val mono">${ev.ingest_latency_seconds !== undefined && ev.ingest_latency_seconds !== null ? (ev.ingest_latency_seconds + ' с') : 'Мгновенно (<0.1 с)'}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Ловушка и сетевой уровень</div>
            <div class="detail-val"><strong>${ev.trap_id}</strong> (Порт назначения: ${ev.destination_port}, Протокол: ${ev.protocol})</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Источник атаки (IP, Страна, ASN)</div>
            <div class="detail-val mono">${ev.source_ip} : ${ev.source_port || 0}</div>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">${country} · ${asn}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Перехваченные учётные данные</div>
            <div class="detail-val">${credsHtml}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Команда или HTTP-запрос</div>
            <div class="detail-val mono">${escapeHtml(ev.command_text || ev.http_data?.path || '—')}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Сырой полезный груз (Payload)</div>
            <div class="detail-val mono" style="max-height:120px; overflow-y:auto;">${escapeHtml(ev.payload_raw || '—')}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Перехваченный файл и хэш SHA-256</div>
            <div class="detail-val">${artifactHtml}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Идентификатор сессии</div>
            <div class="detail-val mono">${ev.session_id || '—'}</div>
        </div>
    `;

    drawer.style.display = "flex";
}

function closeDrawer(event) {
    if (event && event.target !== document.getElementById("event-drawer") && !event.target.classList.contains("modal-close")) {
        return;
    }
    document.getElementById("event-drawer").style.display = "none";
}

// ----------------- Контрольная проверка обнаружения -----------------
async function triggerSimulation(scenario) {
    const statusEl = document.getElementById("sim-status-display");
    const buttons = document.querySelectorAll("#sim-buttons-group button");

    buttons.forEach(b => b.disabled = true);
    statusEl.innerText = "Выполняется сетевое воздействие на ловушку...";
    statusEl.style.color = "var(--accent)";

    try {
        const res = await fetch("/api/v1/simulator/run", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        if (res.ok) {
            statusEl.innerText = data.message || `Событие получено центром за ${data.latency_seconds} с`;
            statusEl.style.color = "var(--success)";
            loadOverviewStats();
            loadEventsFeed();
        } else {
            statusEl.innerText = data.detail || "Ошибка сценария";
            statusEl.style.color = "var(--sev-critical)";
        }
    } catch (e) {
        statusEl.innerText = "Ошибка соединения";
        statusEl.style.color = "var(--sev-critical)";
    } finally {
        buttons.forEach(b => b.disabled = false);
    }
}

// ----------------- Оповещения SOC -----------------
async function loadAlerts() {
    try {
        const res = await fetch("/api/v1/events/alerts?limit=20", { headers: apiHeaders() });
        if (!res.ok) return;
        const alerts = await res.json();
        const container = document.getElementById("alerts-list");
        container.innerHTML = "";

        if (alerts.length === 0) {
            container.innerHTML = `
                <div style="color:var(--text-muted); font-size:12px; text-align:center; padding:18px 12px; border:1px dashed var(--border); border-radius:6px;">
                    <span style="color:var(--status-online); font-weight:600;">✓ Все инциденты отработаны</span>
                    <div style="font-size:11px; color:var(--text-secondary); margin-top:4px;">Нет активных неквитированных оповещений</div>
                </div>
            `;
            return;
        }

        alerts.forEach(a => prependAlertItem(a));
    } catch (e) {}
}

function prependAlertItem(a) {
    const container = document.getElementById("alerts-list");
    // Clear placeholder if it was showing empty state
    if (container.children.length === 1 && !container.firstElementChild.classList.contains("alert-card")) {
        container.innerHTML = "";
    }

    const item = document.createElement("div");
    item.className = "alert-card";
    item.dataset.alertId = String(a.id);
    item.style.background = "rgba(196, 82, 79, 0.08)";
    item.style.border = "1px solid var(--sev-critical)";
    item.style.borderRadius = "6px";
    item.style.padding = "8px 10px";
    item.style.marginBottom = "6px";
    item.style.fontSize = "12px";
    item.style.transition = "opacity 0.25s ease, transform 0.25s ease";

    const timeFormatted = formatDateTimeUTC(a.created_at);

    item.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:var(--sev-critical);">${escapeHtml(a.rule_name)}</strong>
            <button class="btn btn-contour" style="padding:2px 6px; font-size:11px;" onclick="ackAlert(${a.id}, this)">Принять</button>
        </div>
        <div style="margin-top:4px; color:var(--text);">${escapeHtml(a.message)}</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px; font-family:var(--font-mono);">
            ${a.source_ip} · ${a.trap_id} · ${timeFormatted}
        </div>
    `;

    container.insertBefore(item, container.firstChild);
}

async function ackAlert(alertId, btnEl) {
    try {
        btnEl.disabled = true;
        btnEl.innerText = "✓";
        await fetch(`/api/v1/events/alerts/${alertId}/ack`, {
            method: "POST",
            headers: apiHeaders()
        });
        const card = btnEl.closest(".alert-card") || btnEl.closest("div[data-alert-id]") || btnEl.parentElement.parentElement;
        if (card) {
            card.style.opacity = "0";
            card.style.transform = "translateX(25px)";
            setTimeout(() => {
                card.remove();
                const container = document.getElementById("alerts-list");
                if (container && !container.querySelector(".alert-card")) {
                    container.innerHTML = `
                        <div style="color:var(--text-muted); font-size:12px; text-align:center; padding:18px 12px; border:1px dashed var(--border); border-radius:6px;">
                            <span style="color:var(--status-online); font-weight:600;">✓ Все инциденты отработаны</span>
                            <div style="font-size:11px; color:var(--text-secondary); margin-top:4px;">Нет активных неквитированных оповещений</div>
                        </div>
                    `;
                }
            }, 250);
        }
    } catch (e) {}
}

async function ackAllAlerts() {
    const btn = document.getElementById("btn-ack-all");
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Очистка...";
    }
    try {
        await fetch("/api/v1/events/alerts/ack-all", {
            method: "POST",
            headers: apiHeaders()
        });
        const container = document.getElementById("alerts-list");
        if (container) {
            container.innerHTML = `
                <div style="color:var(--text-muted); font-size:12px; text-align:center; padding:18px 12px; border:1px dashed var(--border); border-radius:6px;">
                    <span style="color:var(--status-online); font-weight:600;">✓ Все инциденты отработаны</span>
                    <div style="font-size:11px; color:var(--text-secondary); margin-top:4px;">Нет активных неквитированных оповещений</div>
                </div>
            `;
        }
    } catch (e) {
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Принять все";
        }
    }
}

// ----------------- Парк ловушек -----------------
async function loadTraps() {
    try {
        const res = await fetch("/api/v1/traps", { headers: apiHeaders() });
        if (!res.ok) return;
        const traps = await res.json();
        const tbody = document.getElementById("traps-tbody");
        tbody.innerHTML = "";

        traps.forEach(t => {
            const tr = document.createElement("tr");
            const statusClass = t.status === "online" ? "online" : "offline";
            const statusText = t.status === "online" ? "Онлайн" : "Офлайн";
            const timeUtc = formatDateTimeUTC(t.last_seen);
            const relTime = formatRelativeTime(t.last_seen);
            const servicesStr = t.services && t.services.length ? t.services.join(", ") : "ssh, http";

            tr.innerHTML = `
                <td class="mono" style="font-weight:600;">${t.trap_id}</td>
                <td>${escapeHtml(t.name)}</td>
                <td><span class="badge badge-low">${t.interaction_level.toUpperCase()}</span></td>
                <td>${escapeHtml(t.profile_name || 'Базовый')}</td>
                <td style="color:var(--accent-2);">${servicesStr}</td>
                <td class="mono">${t.ip_address}</td>
                <td class="mono" style="color:var(--accent-2);">${t.mgmt_ip}</td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td style="font-size:11px;" class="mono">
                    <div>${timeUtc}</div>
                </td>
                <td class="mono" style="color:var(--accent); font-weight:600;">${t.events_24h || 0}</td>
                <td>
                    <select class="filter-select" style="font-size:11px; padding:3px 6px;" onchange="handleTrapAction('${t.trap_id}', this.value); this.value='';">
                        <option value="">Действия...</option>
                        <option value="deploy">Развернуть</option>
                        ${t.status === 'online' ? '<option value="stop">Остановить</option>' : '<option value="start">Запустить (Онлайн)</option>'}
                        <option value="update_config">Обновить конфигурацию</option>
                        <option value="rotate_creds">Ротировать креды</option>
                        <option value="change_profile">Сменить профиль</option>
                        <option value="delete" style="color:var(--sev-critical);">Удалить</option>
                    </select>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

function handleTrapAction(trapId, action) {
    if (!action) return;
    if (action === "deploy") {
        openDeployModal(trapId);
    } else if (action === "change_profile") {
        openChangeProfileModal(trapId);
    } else if (action === "delete") {
        deleteTrap(trapId);
    } else {
        executeTrapApiAction(trapId, action);
    }
}

async function deleteTrap(trapId) {
    if (!confirm(`Вы действительно хотите удалить ловушку '${trapId}'?`)) return;
    try {
        const res = await fetch(`/api/v1/traps/${trapId}`, {
            method: "DELETE",
            headers: apiHeaders()
        });
        if (res.ok) {
            loadTraps();
        } else {
            const err = await res.json();
            alert(err.detail || "Ошибка удаления ловушки");
        }
    } catch (e) {
        alert("Ошибка соединения");
    }
}

async function executeTrapApiAction(trapId, action, extra = {}) {
    try {
        const res = await fetch(`/api/v1/traps/${trapId}/action`, {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ action: action, ...extra })
        });
        if (res.ok) {
            loadTraps();
        }
    } catch (e) {}
}

function updateTrapHeartbeatUI(data) {
    loadTraps();
}

// ----------------- Развертывание ловушки -----------------
async function openDeployModal(trapId) {
    currentDeployTrapId = trapId;
    document.getElementById("modal-deploy").style.display = "flex";
    loadDeployArtifact();
}

function switchDeployFormat(fmt) {
    currentDeployFormat = fmt;
    loadDeployArtifact();
}

async function loadDeployArtifact() {
    if (!currentDeployTrapId) return;
    const block = document.getElementById("deploy-code-block");
    block.innerText = "Генерация артефакта развертывания...";
    try {
        const res = await fetch(`/api/v1/traps/${currentDeployTrapId}/deploy-artifact?format=${currentDeployFormat}&server_url=${encodeURIComponent(location.origin)}`, { headers: apiHeaders() });
        const text = await res.text();
        block.innerText = text;
    } catch (e) {
        block.innerText = "Ошибка генерации";
    }
}

function copyDeployCode() {
    const text = document.getElementById("deploy-code-block").innerText;
    navigator.clipboard.writeText(text);
    alert("Артефакт развертывания скопирован в буфер обмена");
}

function openRegisterTrapModal() {
    // Populate profiles select
    fetch("/api/v1/profiles", { headers: apiHeaders() })
        .then(r => r.json())
        .then(profs => {
            const sel = document.getElementById("reg-trap-profile");
            sel.innerHTML = "";
            profs.forEach(p => {
                sel.innerHTML += `<option value="${p.id}" data-level="${p.interaction_level}">${escapeHtml(p.name)} (${p.interaction_level.toUpperCase()})</option>`;
            });
            document.getElementById("modal-register-trap").style.display = "flex";
        });
}

async function submitRegisterTrapForm(e) {
    e.preventDefault();
    const trapId = document.getElementById("reg-trap-id").value.trim();
    const name = document.getElementById("reg-trap-name").value.trim();
    const sel = document.getElementById("reg-trap-profile");
    const opt = sel.options[sel.selectedIndex];
    const profId = parseInt(sel.value, 10);
    const level = opt ? opt.dataset.level || "medium" : "medium";
    const ip = document.getElementById("reg-trap-ip").value.trim();

    try {
        const res = await fetch("/api/v1/traps", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({
                trap_id: trapId,
                name: name,
                profile_id: profId,
                ip_address: ip,
                interaction_level: level
            })
        });
        if (res.ok) {
            closeModal("modal-register-trap");
            loadTraps();
            // Сразу открываем окно развертывания созданной ловушки
            openDeployModal(trapId);
        } else {
            const err = await res.json();
            alert(err.detail || "Ошибка регистрации");
        }
    } catch (e) {
        alert("Ошибка соединения с сервером");
    }
}

function openChangeProfileModal(trapId) {
    document.getElementById("change-prof-trap-id").value = trapId;
    fetch("/api/v1/profiles", { headers: apiHeaders() })
        .then(r => r.json())
        .then(profs => {
            const sel = document.getElementById("change-prof-select");
            sel.innerHTML = "";
            profs.forEach(p => {
                sel.innerHTML += `<option value="${p.id}">${escapeHtml(p.name)}</option>`;
            });
            document.getElementById("modal-change-profile").style.display = "flex";
        });
}

async function submitChangeProfileForm(e) {
    e.preventDefault();
    const trapId = document.getElementById("change-prof-trap-id").value;
    const profId = document.getElementById("change-prof-select").value;
    await executeTrapApiAction(trapId, "change_profile", { profile_id: profId });
    closeModal("modal-change-profile");
}

// ----------------- Профили -----------------
async function loadProfiles() {
    try {
        const res = await fetch("/api/v1/profiles", { headers: apiHeaders() });
        if (!res.ok) return;
        const profiles = await res.json();
        const tbody = document.getElementById("profiles-tbody");
        tbody.innerHTML = "";

        profiles.forEach(p => {
            const tr = document.createElement("tr");
            const dateStr = formatDateTimeUTC(p.updated_at || p.created_at);
            const servicesStr = p.services ? p.services.join(", ") : "ssh, http";

            tr.innerHTML = `
                <td style="font-weight:600; color:var(--text);">${escapeHtml(p.name)}</td>
                <td><span class="badge badge-low">${p.interaction_level.toUpperCase()}</span></td>
                <td style="color:var(--accent-2);">${servicesStr}</td>
                <td class="mono">${p.traps_count || 0}</td>
                <td style="font-size:11px; color:var(--text-muted);">${dateStr}</td>
                <td>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-contour admin-only" style="padding:3px 8px; font-size:11px;" onclick="copyProfile(${p.id})">Копировать</button>
                        <button class="btn btn-contour admin-only" style="padding:3px 8px; font-size:11px;" onclick="deleteProfile(${p.id})">Удалить</button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

function openCreateProfileModal() {
    document.getElementById("modal-profile").style.display = "flex";
}

async function submitProfileForm(e) {
    e.preventDefault();
    const name = document.getElementById("prof-name").value.trim();
    const level = document.getElementById("prof-level").value;
    const desc = document.getElementById("prof-desc").value.trim();
    const services = document.getElementById("prof-services").value.split(",").map(s => s.trim()).filter(Boolean);
    const rawCreds = document.getElementById("prof-creds").value.split(",").map(s => s.trim()).filter(Boolean);
    const decoyCreds = rawCreds.map(c => {
        const parts = c.split(":");
        return { user: parts[0] || "admin", pass: parts[1] || "password" };
    });

    const personaUsers = (document.getElementById("prof-persona-users") ? document.getElementById("prof-persona-users").value : "root, deploy, ubuntu")
        .split(",").map(u => u.trim()).filter(Boolean);
    const personaObj = {
        hostname: document.getElementById("prof-persona-hostname") ? document.getElementById("prof-persona-hostname").value.trim() : "prod-srv-01",
        os: document.getElementById("prof-persona-os") ? document.getElementById("prof-persona-os").value.trim() : "Ubuntu 22.04.4 LTS",
        kernel: document.getElementById("prof-persona-kernel") ? document.getElementById("prof-persona-kernel").value.trim() : "5.15.0-89-generic",
        users: personaUsers.length > 0 ? personaUsers : ["root", "deploy", "ubuntu"],
        uptime_base: parseInt(document.getElementById("prof-persona-uptime") ? document.getElementById("prof-persona-uptime").value : "172800", 10),
        timezone: document.getElementById("prof-persona-tz") ? document.getElementById("prof-persona-tz").value.trim() : "UTC",
        ip: document.getElementById("prof-persona-ip") ? document.getElementById("prof-persona-ip").value.trim() : "10.0.1.5",
        mac: "02:42:0a:c8:00:2c"
    };

    const payload = {
        name: name,
        interaction_level: level,
        description: desc,
        services: services,
        decoy_credentials: decoyCreds,
        logging_params: {
            level: document.getElementById("prof-log-level").value,
            max_payload_bytes: parseInt(document.getElementById("prof-file-limit").value, 10)
        },
        stealth_params: {
            proc_name: document.getElementById("prof-proc-name").value.trim(),
            endpoint: document.getElementById("prof-endpoint").value.trim(),
            beacon_interval_s: parseInt(document.getElementById("prof-beacon").value, 10),
            jitter_pct: parseInt(document.getElementById("prof-jitter").value, 10),
            dummy_padding: true
        },
        persona: personaObj
    };

    try {
        const res = await fetch("/api/v1/profiles", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            closeModal("modal-profile");
            loadProfiles();
        } else {
            const err = await res.json();
            alert(err.detail || "Ошибка сохранения профиля");
        }
    } catch (e) {}
}

async function copyProfile(id) {
    try {
        const res = await fetch(`/api/v1/profiles/${id}/copy`, {
            method: "POST",
            headers: apiHeaders()
        });
        if (res.ok) {
            loadProfiles();
        }
    } catch (e) {}
}

async function deleteProfile(id) {
    if (!confirm("Удалить данный профиль?")) return;
    try {
        const res = await fetch(`/api/v1/profiles/${id}`, {
            method: "DELETE",
            headers: apiHeaders()
        });
        if (res.ok) {
            loadProfiles();
        } else {
            const err = await res.json();
            alert(err.detail || "Невозможно удалить профиль");
        }
    } catch (e) {}
}

// ----------------- Сессии -----------------
async function loadSessions() {
    try {
        const res = await fetch("/api/v1/events/sessions?limit=50", { headers: apiHeaders() });
        if (!res.ok) return;
        const sessions = await res.json();
        const tbody = document.getElementById("sessions-tbody");
        tbody.innerHTML = "";

        sessions.forEach(s => {
            const tr = document.createElement("tr");
            const startUtc = formatDateTimeUTC(s.started_at);
            const filesCount = s.captured_artifacts ? s.captured_artifacts.length : 0;
            const statusBadge = `<span class="badge badge-medium">ЗАВЕРШЕНА</span>`;

            tr.innerHTML = `
                <td class="mono" style="color:var(--accent); font-weight:600;">${s.session_id}</td>
                <td>${s.trap_id}</td>
                <td class="mono">${s.source_ip}</td>
                <td><span class="badge badge-low">${s.protocol}</span></td>
                <td style="font-size:11px;">${startUtc}</td>
                <td class="mono">28 с</td>
                <td class="mono">${s.total_commands}</td>
                <td class="mono" style="color:${filesCount ? 'var(--sev-critical)' : 'inherit'};">${filesCount}</td>
                <td>${statusBadge}</td>
                <td>
                    <button class="btn btn-contour" style="padding:3px 8px; font-size:11px;" onclick="openSessionDetails('${s.session_id}')">Открыть</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

async function openSessionDetails(sessionId) {
    try {
        const res = await fetch(`/api/v1/events/sessions/${sessionId}`, { headers: apiHeaders() });
        if (!res.ok) return;
        const s = await res.json();

        const title = document.getElementById("modal-session-title");
        const body = document.getElementById("modal-session-body");
        title.innerText = `Сессия ${s.session_id} (${s.protocol}) — ${s.source_ip}`;

        let commandsHtml = "";
        if (s.commands_history && s.commands_history.length) {
            commandsHtml = `<div class="code-block" style="margin-bottom:16px;">`;
            s.commands_history.forEach(c => {
                commandsHtml += `<div style="color:var(--accent);"><span style="color:var(--text-muted);">$</span> ${escapeHtml(c.cmd || '')}</div>`;
                if (c.output) {
                    commandsHtml += `<div style="color:var(--text-secondary); margin-bottom:6px;">${escapeHtml(c.output)}</div>`;
                }
            });
            commandsHtml += `</div>`;
        } else {
            commandsHtml = `<div style="color:var(--text-muted); margin-bottom:16px;">Команды не зафиксированы</div>`;
        }

        let artifactsHtml = "";
        if (s.captured_artifacts && s.captured_artifacts.length) {
            artifactsHtml = `
                <div style="font-weight:600; color:var(--accent); margin-bottom:8px; font-size:13px;">Перехваченные файлы</div>
                <table class="data-table" style="margin-bottom:12px;">
                    <thead>
                        <tr><th>Файл</th><th>Размер</th><th>Хэш SHA-256</th><th>Действие</th></tr>
                    </thead>
                    <tbody>
            `;
            s.captured_artifacts.forEach(a => {
                artifactsHtml += `
                    <tr>
                        <td>${escapeHtml(a.filename || 'malware.sh')}</td>
                        <td class="mono">${a.size || 1024} B</td>
                        <td class="mono" style="font-size:11px;">${a.sha256}</td>
                        <td><button class="btn btn-contour" style="padding:2px 6px; font-size:11px;">Скачать</button></td>
                    </tr>
                `;
            });
            artifactsHtml += `</tbody></table>`;
        }

        body.innerHTML = `
            <div style="font-weight:600; color:var(--accent); margin-bottom:8px; font-size:13px;">Хронология команд</div>
            ${commandsHtml}
            ${artifactsHtml}
        `;

        document.getElementById("modal-session").style.display = "flex";
    } catch (e) {}
}

// ----------------- Honeytokens -----------------
async function loadHoneytokens() {
    try {
        const res = await fetch("/api/v1/honeytokens", { headers: apiHeaders() });
        if (!res.ok) return;
        const tokens = await res.json();
        const tbody = document.getElementById("honeytokens-tbody");
        tbody.innerHTML = "";

        tokens.forEach(t => {
            const tr = document.createElement("tr");
            const isTriggered = t.is_triggered;
            const statusBadge = isTriggered 
                ? `<span class="badge badge-critical">СРАБОТАЛ</span>` 
                : `<span class="badge badge-medium">АКТИВЕН</span>`;

            // Маскированное значение (e.g. AKIA...7F2Q)
            let maskedVal = t.token_value || "";
            if (maskedVal.length > 12) {
                maskedVal = maskedVal.slice(0, 4) + "..." + maskedVal.slice(-4);
            }

            const trigTime = t.triggered_at ? formatDateTimeUTC(t.triggered_at) : "—";
            const trigIp = t.triggered_by_ip || "—";

            tr.innerHTML = `
                <td class="mono" style="font-weight:600;">${t.token_id}</td>
                <td><span class="badge badge-low">${t.token_type.toUpperCase()}</span></td>
                <td>${escapeHtml(t.canary_path || t.trap_id || 'Локация')}</td>
                <td class="mono" style="color:var(--accent-2);">${maskedVal}</td>
                <td>${statusBadge}</td>
                <td style="font-size:11px;">${trigTime}</td>
                <td class="mono" style="color:var(--sev-critical);">${trigIp}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

function openCreateHoneytokenModal() {
    fetch("/api/v1/traps", { headers: apiHeaders() })
        .then(r => r.json())
        .then(traps => {
            const sel = document.getElementById("ht-trap");
            sel.innerHTML = "";
            traps.filter(t => t.interaction_level === "medium").forEach(t => {
                sel.innerHTML += `<option value="${t.trap_id}">${t.trap_id} (${t.name})</option>`;
            });
            document.getElementById("modal-honeytoken").style.display = "flex";
        });
}

async function submitHoneytokenForm(e) {
    e.preventDefault();
    const type = document.getElementById("ht-type").value;
    const trap = document.getElementById("ht-trap").value;
    const path = document.getElementById("ht-path").value.trim();
    const desc = document.getElementById("ht-desc").value.trim();

    try {
        const res = await fetch("/api/v1/honeytokens", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({
                token_type: type,
                trap_id: trap,
                canary_path: path,
                description: desc
            })
        });
        if (res.ok) {
            closeModal("modal-honeytoken");
            loadHoneytokens();
            loadOverviewStats();
        }
    } catch (e) {}
}

// ----------------- Оповещения и IoC -----------------
async function loadAlertsAndIoC() {
    loadAlertRules();
    loadIoCSummary();
    loadIoCRawSTIX();
}

async function loadAlertRules() {
    try {
        const res = await fetch("/api/v1/rules", { headers: apiHeaders() });
        if (!res.ok) return;
        const rules = await res.json();
        const tbody = document.getElementById("rules-tbody");
        tbody.innerHTML = "";

        rules.forEach(r => {
            const tr = document.createElement("tr");
            const isEnabled = r.is_enabled;
            const toggleText = isEnabled ? "Да" : "Нет";
            const btnText = isEnabled ? "Отключить" : "Включить";

            tr.innerHTML = `
                <td style="font-weight:600;">${escapeHtml(r.name)}</td>
                <td class="mono">${r.threshold}</td>
                <td class="mono">${r.window_seconds}</td>
                <td>${r.trap_id || 'Все ловушки'}</td>
                <td><span class="status-badge ${isEnabled ? 'online' : 'offline'}">${toggleText}</span></td>
                <td>
                    <button class="btn btn-contour admin-only" style="padding:2px 8px; font-size:11px;" onclick="toggleRule(${r.id})">${btnText}</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

function openAddRuleModal() {
    document.getElementById("modal-rule").style.display = "flex";
}

async function submitRuleForm(e) {
    e.preventDefault();
    const name = document.getElementById("rule-name").value.trim();
    const type = document.getElementById("rule-type").value;
    const thresh = parseInt(document.getElementById("rule-threshold").value, 10);
    const win = parseInt(document.getElementById("rule-window").value, 10);
    const sev = document.getElementById("rule-severity").value;

    try {
        const res = await fetch("/api/v1/rules", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({
                name: name,
                rule_type: type,
                threshold: thresh,
                window_seconds: win,
                severity: sev,
                is_enabled: true
            })
        });
        if (res.ok) {
            closeModal("modal-rule");
            loadAlertRules();
        }
    } catch (e) {}
}

async function toggleRule(id) {
    try {
        await fetch(`/api/v1/rules/${id}/toggle`, {
            method: "PUT",
            headers: apiHeaders()
        });
        loadAlertRules();
    } catch (e) {}
}

async function loadIoCSummary() {
    try {
        const res = await fetch("/api/v1/events/ioc/summary", { headers: apiHeaders() });
        if (!res.ok) return;
        const list = await res.json();
        const tbody = document.getElementById("ioc-tbody");
        tbody.innerHTML = "";

        list.slice(0, 30).forEach(i => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="badge badge-low">${i.type}</span></td>
                <td class="mono" style="color:var(--text);">${escapeHtml(i.value)}</td>
                <td style="font-size:11px;">${formatDateTimeUTC(i.first_seen)}</td>
                <td style="font-size:11px;">${formatDateTimeUTC(i.last_seen)}</td>
                <td class="mono" style="color:var(--accent); font-weight:600;">${i.count}</td>
                <td>${i.trap_id}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

async function loadIoCRawSTIX() {
    try {
        const res = await fetch("/api/v1/events/export/ioc?format=stix", { headers: apiHeaders() });
        if (!res.ok) return;
        const stix = await res.json();
        document.getElementById("ioc-raw-json").innerText = JSON.stringify(stix, null, 2);
    } catch (e) {}
}

function downloadIoC(format) {
    window.open(`/api/v1/events/export/ioc?format=${format}`, '_blank');
}

// ----------------- Журнал аудита -----------------
async function loadAuditLogs() {
    const user = document.getElementById("audit-filter-user")?.value || "";
    let url = `/api/v1/audit?limit=50`;
    if (user) url += `&username=${encodeURIComponent(user)}`;

    try {
        const res = await fetch(url, { headers: apiHeaders() });
        if (!res.ok) return;
        const logs = await res.json();
        const tbody = document.getElementById("audit-tbody");
        tbody.innerHTML = "";

        logs.forEach(l => {
            const tr = document.createElement("tr");
            const timeUtc = formatDateTimeUTC(l.timestamp);

            tr.innerHTML = `
                <td class="mono" style="font-size:11px;">${timeUtc}</td>
                <td><strong>${l.username}</strong></td>
                <td><span class="badge badge-low">${l.action}</span></td>
                <td>${l.target_type ? `${l.target_type} (${l.target_id || ''})` : '—'}</td>
                <td>${escapeHtml(l.details || 'OK')}</td>
                <td class="mono" style="font-size:11px; color:var(--text-muted);">${l.ip_address}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

// ----------------- Навигация по вкладкам -----------------
function switchTab(tabId) {
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));

    const targetTab = document.getElementById(tabId);
    if (targetTab) targetTab.classList.add("active");

    const navBtn = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
    if (navBtn) navBtn.classList.add("active");

    if (tabId === "tab-live") {
        loadOverviewStats();
        loadEventsFeed();
    } else if (tabId === "tab-traps") {
        loadTraps();
    } else if (tabId === "tab-profiles") {
        loadProfiles();
    } else if (tabId === "tab-sessions") {
        loadSessions();
    } else if (tabId === "tab-honeytokens") {
        loadHoneytokens();
    } else if (tabId === "tab-alerts-ioc") {
        loadAlertsAndIoC();
    } else if (tabId === "tab-audit") {
        loadAuditLogs();
    } else if (tabId === "tab-users-keystore") {
        loadUsersList();
    }
}

// ----------------- Вспомогательные функции -----------------
function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = "none";
}

function incrementCounter(id) {
    const el = document.getElementById(id);
    if (el) {
        let val = parseInt(el.innerText, 10) || 0;
        el.innerText = val + 1;
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return text.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ----------------- Пользователи SOC (RBAC) -----------------
const ROLE_DEFINITIONS = {
    admin: { label: "Главный администратор (CISO)", desc: "Полный доступ к C2, управление доступом, KeyStore", color: "var(--accent)" },
    soc_lead: { label: "Руководитель смены SOC", desc: "Мониторинг, правила корреляции, KeyStore, симуляции", color: "var(--sev-medium)" },
    analyst_l2: { label: "Старший аналитик L2", desc: "Threat Hunting, детальный анализ tty и honeytokens", color: "var(--accent-2)" },
    analyst_l1: { label: "Дежурный аналитик L1", desc: "Оперативный триаж живой ленты событий", color: "var(--sev-low)" },
    auditor: { label: "Аудитор ИБ (Комплаенс)", desc: "Аудит действий операторов и проверка политик", color: "var(--text-muted)" },
    analyst: { label: "Аналитик SOC", desc: "Анализ атак и просмотр телеметрии", color: "var(--accent)" }
};

async function loadUsersList() {
    const tbody = document.getElementById("users-tbody");
    if (!tbody) return;

    try {
        const res = await fetch("/api/v1/auth/users", { headers: apiHeaders() });
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--sev-critical); padding:20px;">Недостаточно прав для просмотра списка операторов</td></tr>`;
            return;
        }
        const users = await res.json();
        tbody.innerHTML = "";

        const isAdmin = currentUser && currentUser.role === "admin";

        users.forEach(u => {
            const roleInfo = ROLE_DEFINITIONS[u.role] || { label: u.role, desc: "—", color: "var(--text-muted)" };
            const statusClass = u.is_active ? "online" : "offline";
            const statusLabel = u.is_active ? "Активен" : "Заблокирован";
            const timeUtc = formatDateTimeUTC(u.created_at);

            const isSelf = currentUser && currentUser.id === u.id;

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="mono" style="color:var(--text-muted); font-size:12px;">#${u.id}</td>
                <td style="font-weight:600;">
                    ${escapeHtml(u.username)}
                    ${isSelf ? '<span style="font-size:10px; color:var(--accent); margin-left:4px;">(Вы)</span>' : ''}
                </td>
                <td>
                    <span class="role-pill" style="border-color:${roleInfo.color}; color:${roleInfo.color};">
                        ${escapeHtml(roleInfo.label)}
                    </span>
                </td>
                <td style="font-size:12px; color:var(--text-secondary); max-width:280px;">
                    ${escapeHtml(roleInfo.desc)}
                </td>
                <td>
                    <span class="status-badge ${statusClass}">${statusLabel}</span>
                </td>
                <td class="mono" style="font-size:11px; color:var(--text-muted);">
                    ${timeUtc}
                </td>
                <td class="admin-only">
                    <select class="filter-select" style="font-size:11px; padding:3px 6px;" onchange="handleUserAction(${u.id}, '${escapeHtml(u.username)}', '${u.role}', ${u.is_active}, this.value); this.value='';">
                        <option value="">Действия...</option>
                        <option value="change_role">Сменить роль</option>
                        <option value="reset_pwd">Сбросить пароль</option>
                        ${!isSelf ? `<option value="toggle_status">${u.is_active ? 'Заблокировать' : 'Активировать'}</option>` : ''}
                        ${!isSelf ? `<option value="delete" style="color:var(--sev-critical);">Удалить</option>` : ''}
                    </select>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Hide admin-only column if not admin
        document.querySelectorAll(".admin-only").forEach(el => {
            el.style.display = isAdmin ? "" : "none";
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--sev-critical); padding:20px;">Ошибка загрузки операторов: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function handleUserAction(id, username, role, isActive, action) {
    if (!action) return;
    if (action === "change_role") {
        openChangeRoleModal(id, username, role);
    } else if (action === "reset_pwd") {
        openResetPasswordModal(id, username);
    } else if (action === "toggle_status") {
        toggleUserStatus(id, isActive, username);
    } else if (action === "delete") {
        deleteUser(id, username);
    }
}

function openCreateUserModal() {
    document.getElementById("new-user-username").value = "";
    document.getElementById("new-user-password").value = "";
    document.getElementById("new-user-role").value = "analyst_l1";
    document.getElementById("create-user-error").style.display = "none";
    document.getElementById("modal-create-user").style.display = "flex";
}

async function submitCreateUserForm(e) {
    e.preventDefault();
    const u = document.getElementById("new-user-username").value.trim();
    const p = document.getElementById("new-user-password").value;
    const r = document.getElementById("new-user-role").value;
    const errBox = document.getElementById("create-user-error");
    errBox.style.display = "none";

    try {
        const res = await fetch("/api/v1/auth/users", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ username: u, password: p, role: r })
        });
        if (!res.ok) {
            const err = await res.json();
            errBox.innerText = err.detail || "Ошибка создания оператора";
            errBox.style.display = "block";
            return;
        }
        closeModal("modal-create-user");
        loadUsersList();
    } catch (e) {
        errBox.innerText = "Ошибка соединения с сервером";
        errBox.style.display = "block";
    }
}

function openChangeRoleModal(id, username, role) {
    document.getElementById("change-role-user-id").value = id;
    document.getElementById("change-role-username").innerText = username;
    document.getElementById("change-role-select").value = role;
    document.getElementById("change-role-error").style.display = "none";
    document.getElementById("modal-change-user-role").style.display = "flex";
}

async function submitChangeUserRoleForm(e) {
    e.preventDefault();
    const id = document.getElementById("change-role-user-id").value;
    const r = document.getElementById("change-role-select").value;
    const errBox = document.getElementById("change-role-error");
    errBox.style.display = "none";

    try {
        const res = await fetch(`/api/v1/auth/users/${id}/role`, {
            method: "PATCH",
            headers: apiHeaders(),
            body: JSON.stringify({ role: r })
        });
        if (!res.ok) {
            const err = await res.json();
            errBox.innerText = err.detail || "Ошибка смены роли";
            errBox.style.display = "block";
            return;
        }
        closeModal("modal-change-user-role");
        loadUsersList();
    } catch (e) {
        errBox.innerText = "Ошибка соединения";
        errBox.style.display = "block";
    }
}

function openResetPasswordModal(id, username) {
    document.getElementById("reset-pwd-user-id").value = id;
    document.getElementById("reset-pwd-username").innerText = username;
    document.getElementById("reset-pwd-val").value = "";
    document.getElementById("reset-pwd-error").style.display = "none";
    document.getElementById("modal-reset-user-pwd").style.display = "flex";
}

async function submitResetUserPwdForm(e) {
    e.preventDefault();
    const id = document.getElementById("reset-pwd-user-id").value;
    const newPwd = document.getElementById("reset-pwd-val").value;
    const errBox = document.getElementById("reset-pwd-error");
    errBox.style.display = "none";

    try {
        const res = await fetch(`/api/v1/auth/users/${id}/reset-password`, {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ new_password: newPwd })
        });
        if (!res.ok) {
            const err = await res.json();
            errBox.innerText = err.detail || "Ошибка обновления пароля";
            errBox.style.display = "block";
            return;
        }
        closeModal("modal-reset-user-pwd");
        alert("Пароль успешно обновлен");
    } catch (e) {
        errBox.innerText = "Ошибка соединения";
        errBox.style.display = "block";
    }
}

async function toggleUserStatus(id, currentStatus, username) {
    const actionName = currentStatus ? "заблокировать" : "активировать";
    if (!confirm(`Вы действительно хотите ${actionName} оператора ${username}?`)) return;

    try {
        const res = await fetch(`/api/v1/auth/users/${id}/status`, {
            method: "PATCH",
            headers: apiHeaders(),
            body: JSON.stringify({ is_active: !currentStatus })
        });
        if (res.ok) {
            loadUsersList();
        } else {
            const err = await res.json();
            alert(err.detail || "Ошибка изменения статуса");
        }
    } catch (e) {
        alert("Ошибка соединения");
    }
}

async function deleteUser(id, username) {
    if (!confirm(`ВНИМАНИЕ: Вы действительно хотите навсегда удалить учетную запись оператора ${username}?`)) return;

    try {
        const res = await fetch(`/api/v1/auth/users/${id}`, {
            method: "DELETE",
            headers: apiHeaders()
        });
        if (res.ok) {
            loadUsersList();
        } else {
            const err = await res.json();
            alert(err.detail || "Ошибка удаления оператора");
        }
    } catch (e) {
        alert("Ошибка соединения");
    }
}

// ----------------- Криптографический KeyStore (AES-256-GCM) -----------------
async function handleExportKeyStore() {
    const pass = document.getElementById("keystore-export-pass").value;
    const desc = document.getElementById("keystore-export-desc").value.trim();
    const statusBox = document.getElementById("export-keystore-status");

    if (!pass || pass.length < 6) {
        statusBox.style.display = "block";
        statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
        statusBox.style.border = "1px solid var(--sev-critical)";
        statusBox.style.color = "var(--sev-critical)";
        statusBox.innerText = "Мастер-пароль должен содержать не менее 6 символов.";
        return;
    }

    statusBox.style.display = "block";
    statusBox.style.backgroundColor = "rgba(111, 165, 151, 0.15)";
    statusBox.style.border = "1px solid var(--accent-2)";
    statusBox.style.color = "var(--accent-2)";
    statusBox.innerText = "Генерация ключа PBKDF2 (100,000 раундов) и шифрование AES-256-GCM...";

    try {
        const res = await fetch("/api/v1/auth/keystore/export", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ master_password: pass, description: desc })
        });

        if (!res.ok) {
            const err = await res.json();
            statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
            statusBox.style.border = "1px solid var(--sev-critical)";
            statusBox.style.color = "var(--sev-critical)";
            statusBox.innerText = err.detail || "Ошибка экспорта KeyStore";
            return;
        }

        const data = await res.json();
        const jsonStr = JSON.stringify(data, null, 2);

        // Download as file
        const blob = new Blob([jsonStr], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const fileName = `honeyforge-keystore-${Date.now()}.enc`;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        // Fill inspect box and label for convenience
        document.getElementById("keystore-inspect-json").value = jsonStr;
        document.getElementById("keystore-inspect-pass").value = pass;
        const fnLabel = document.getElementById("keystore-file-name");
        if (fnLabel) fnLabel.innerHTML = `<span style="color:var(--accent-2); font-weight:600;">${fileName}</span> <span style="color:var(--success); font-size:11px;">(готов к проверке)</span>`;

        statusBox.style.backgroundColor = "rgba(127, 165, 138, 0.15)";
        statusBox.style.border = "1px solid var(--success)";
        statusBox.style.color = "var(--success)";
        statusBox.innerHTML = `KeyStore успешно зашифрован (AES-256-GCM)! Отпечаток SHA-256: <code>${data.metadata.fingerprint}</code> (${data.metadata.node_count} узлов). Файл загружен.`;
    } catch (e) {
        statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
        statusBox.style.border = "1px solid var(--sev-critical)";
        statusBox.style.color = "var(--sev-critical)";
        statusBox.innerText = "Ошибка соединения: " + e.message;
    }
}

function handleKeyStoreFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const fnLabel = document.getElementById("keystore-file-name");
    if (fnLabel) fnLabel.innerHTML = `<span style="color:var(--text); font-weight:600;">${escapeHtml(file.name)}</span>`;
    const reader = new FileReader();
    reader.onload = function(e) {
        document.getElementById("keystore-inspect-json").value = e.target.result;
    };
    reader.readAsText(file);
}

async function handleInspectKeyStore() {
    const rawData = document.getElementById("keystore-inspect-json").value.trim();
    const pass = document.getElementById("keystore-inspect-pass").value;
    const statusBox = document.getElementById("inspect-keystore-status");
    const resultsPanel = document.getElementById("keystore-results-panel");

    if (!rawData) {
        statusBox.style.display = "block";
        statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
        statusBox.style.border = "1px solid var(--sev-critical)";
        statusBox.style.color = "var(--sev-critical)";
        statusBox.innerText = "Пожалуйста, вставьте JSON пакета KeyStore или выберите файл .enc.";
        resultsPanel.style.display = "none";
        return;
    }

    if (!pass) {
        statusBox.style.display = "block";
        statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
        statusBox.style.border = "1px solid var(--sev-critical)";
        statusBox.style.color = "var(--sev-critical)";
        statusBox.innerText = "Введите мастер-пароль для расшифровки.";
        resultsPanel.style.display = "none";
        return;
    }

    statusBox.style.display = "block";
    statusBox.style.backgroundColor = "rgba(111, 165, 151, 0.15)";
    statusBox.style.border = "1px solid var(--accent-2)";
    statusBox.style.color = "var(--accent-2)";
    statusBox.innerText = "Аутентификация тега AES-GCM и дешифрование секретов...";

    try {
        let parsedData;
        try {
            parsedData = JSON.parse(rawData);
        } catch (err) {
            statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
            statusBox.style.border = "1px solid var(--sev-critical)";
            statusBox.style.color = "var(--sev-critical)";
            statusBox.innerText = "Некорректный JSON в пакете KeyStore.";
            resultsPanel.style.display = "none";
            return;
        }

        const res = await fetch("/api/v1/auth/keystore/inspect", {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ master_password: pass, keystore_data: parsedData })
        });

        if (!res.ok) {
            const err = await res.json();
            statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
            statusBox.style.border = "1px solid var(--sev-critical)";
            statusBox.style.color = "var(--sev-critical)";
            statusBox.innerText = err.detail || "Неверный мастер-пароль KeyStore или нарушена целостность.";
            resultsPanel.style.display = "none";
            return;
        }

        const inspectResult = await res.json();
        const payload = inspectResult.payload;

        statusBox.style.backgroundColor = "rgba(127, 165, 138, 0.15)";
        statusBox.style.border = "1px solid var(--success)";
        statusBox.style.color = "var(--success)";
        statusBox.innerHTML = `Криптографическая проверка успешна! Аутентификационный тег AES-256-GCM валиден.`;

        // Render results
        resultsPanel.style.display = "block";
        document.getElementById("keystore-results-title").innerText = payload.description || "Криптографический KeyStore";
        document.getElementById("keystore-results-meta").innerText = `Экспортировал: ${payload.exported_by} · Узлов: ${payload.summary?.total_nodes || payload.node_keys?.length || 0} · Формат: ${payload.format} v${payload.version}`;

        const tbody = document.getElementById("keystore-nodes-tbody");
        tbody.innerHTML = "";

        (payload.node_keys || []).forEach(node => {
            const tr = document.createElement("tr");
            const maskedKey = "••••••••••••••••••••••••";
            tr.innerHTML = `
                <td class="mono" style="font-weight:600;">${node.trap_id}</td>
                <td>${escapeHtml(node.name)}</td>
                <td><span class="badge badge-low">${node.interaction_level.toUpperCase()}</span></td>
                <td class="mono">${node.ip_address}</td>
                <td class="mono" style="color:var(--accent-2);">
                    <span class="key-secret-text" data-secret="${escapeHtml(node.secret_key)}" data-masked="1">${maskedKey}</span>
                    <button class="btn btn-contour" style="padding:2px 6px; font-size:11px; margin-left:8px;" onclick="toggleKeySecretMask(this)">Показать</button>
                </td>
                <td>
                    <span class="status-badge ${node.status === 'online' ? 'online' : 'offline'}">
                        ${node.status === 'online' ? 'Онлайн' : 'Офлайн'}
                    </span>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (e) {
        statusBox.style.backgroundColor = "rgba(196, 82, 79, 0.15)";
        statusBox.style.border = "1px solid var(--sev-critical)";
        statusBox.style.color = "var(--sev-critical)";
        statusBox.innerText = "Ошибка: " + e.message;
        resultsPanel.style.display = "none";
    }
}

function toggleKeySecretMask(btn) {
    const parentTd = btn.closest("td");
    const span = parentTd.querySelector(".key-secret-text");
    const secret = span.dataset.secret;
    const isMasked = span.dataset.masked === "1";

    if (isMasked) {
        span.innerText = secret;
        span.dataset.masked = "0";
        btn.innerText = "Скрыть";
    } else {
        span.innerText = "••••••••••••••••••••••••";
        span.dataset.masked = "1";
        btn.innerText = "Показать";
    }
}

