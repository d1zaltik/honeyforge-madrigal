// HoneyForge Cyber SOC Dashboard Logic

let currentDeployTrapId = null;
let currentDeployFormat = "docker-compose";
let ws = null;
let chartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
    initWebSocket();
    loadOverviewStats();
    loadTraps();
    loadProfiles();
    loadSessions();
    loadHoneytokens();
    loadAlerts();
    loadIoCPreview();

    // Refresh metrics periodically
    setInterval(loadOverviewStats, 10000);
    setInterval(loadTraps, 15000);
});

// ----------------- WebSocket Real-Time Connection -----------------
function initWebSocket() {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${location.host}/ws/attacks`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        document.getElementById("ws-status-text").innerText = "C2 Realtime Linked";
        document.getElementById("ws-badge").style.background = "rgba(16, 185, 129, 0.1)";
        document.getElementById("ws-badge").style.color = "var(--green)";
    };

    ws.onclose = () => {
        document.getElementById("ws-status-text").innerText = "Reconnecting...";
        document.getElementById("ws-badge").style.background = "rgba(239, 68, 68, 0.1)";
        document.getElementById("ws-badge").style.color = "var(--red)";
        setTimeout(initWebSocket, 3000);
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWsMessage(msg);
        } catch (e) {
            console.error("WS parse error", e);
        }
    };
}

function handleWsMessage(msg) {
    if (msg.type === "attack_event") {
        prependAttackFeed(msg.data);
        incrementCounter("metric-total-events");
        if (msg.data.severity === "critical" || msg.data.severity === "high") {
            incrementCounter("metric-critical-events");
        }
        if (msg.data.credentials) {
            incrementCounter("metric-credentials");
        }
    } else if (msg.type === "alert") {
        prependAlert(msg.data);
    } else if (msg.type === "trap_heartbeat") {
        updateTrapHeartbeatUI(msg.data);
    } else if (msg.type === "honeytoken_triggered") {
        incrementCounter("metric-ht-triggered");
        loadHoneytokens();
    }
}

// ----------------- Feed & Alerts UI -----------------
function prependAttackFeed(ev) {
    const feed = document.getElementById("attack-feed");
    const item = document.createElement("div");
    item.className = "feed-item";

    const sevClass = `sev-${ev.severity || 'low'}`;
    const timeStr = new Date(ev.timestamp).toLocaleTimeString();

    let details = ev.payload_raw || "";
    if (ev.credentials) {
        details = `🔑 User: ${ev.credentials.username} | Pwd: ${ev.credentials.password}`;
    } else if (ev.command_text) {
        details = `$ ${ev.command_text}`;
    }

    item.innerHTML = `
        <span class="severity-pill ${sevClass}">${ev.severity || 'INFO'}</span>
        <div>
            <div class="feed-ip">${ev.source_ip}</div>
            <div class="feed-trap">${ev.geo_city ? ev.geo_city + ', ' + ev.geo_country : 'Port ' + ev.destination_port}</div>
        </div>
        <div style="font-size:12px; font-weight:600; color:var(--cyan);">${ev.protocol} : ${ev.destination_port}</div>
        <div class="feed-details">${escapeHtml(details)}</div>
        <div class="feed-time">${timeStr}</div>
    `;

    feed.insertBefore(item, feed.firstChild);
    if (feed.children.length > 100) {
        feed.removeChild(feed.lastChild);
    }
}

function prependAlert(alert) {
    const list = document.getElementById("alerts-list");
    const item = document.createElement("div");
    item.style.background = "rgba(239, 68, 68, 0.1)";
    item.style.border = "1px solid var(--red)";
    item.style.borderRadius = "6px";
    item.style.padding = "10px";
    item.style.marginBottom = "8px";
    item.style.fontSize = "12px";

    item.innerHTML = `
        <div style="font-weight:700; color:var(--red); display:flex; justify-content:space-between;">
            <span>🚨 ${escapeHtml(alert.rule_name)}</span>
            <span style="font-size:10px; color:var(--text-muted);">${new Date(alert.created_at).toLocaleTimeString()}</span>
        </div>
        <div style="margin-top:4px; color:#fff;">${escapeHtml(alert.message)}</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Source: ${alert.source_ip} | Trap: ${alert.trap_id}</div>
    `;

    list.insertBefore(item, list.firstChild);
}

function updateTrapHeartbeatUI(data) {
    // If trap row exists, toggle online badge
    const badge = document.getElementById(`trap-status-${data.trap_id}`);
    if (badge) {
        badge.className = "status-badge status-online";
        badge.innerText = "● Online";
    }
}

// ----------------- Stats & Charts -----------------
async function loadOverviewStats() {
    try {
        const res = await fetch("/api/v1/stats/overview");
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById("metric-online-traps").innerText = data.online_traps;
        document.getElementById("metric-total-traps").innerText = data.total_traps;
        document.getElementById("metric-total-events").innerText = data.total_events;
        document.getElementById("metric-critical-events").innerText = data.critical_events;
        document.getElementById("metric-credentials").innerText = data.captured_credentials;
        document.getElementById("metric-ht-total").innerText = data.honeytokens_count;
        document.getElementById("metric-ht-triggered").innerText = data.honeytokens_triggered;

        updateAttackChart(data.events_per_type);
    } catch (e) {
        console.error(e);
    }
}

function updateAttackChart(typesMap) {
    const ctx = document.getElementById("attackTypeChart");
    if (!ctx) return;

    const labels = Object.keys(typesMap);
    const dataVals = Object.values(typesMap);

    if (chartInstance) {
        chartInstance.data.labels = labels;
        chartInstance.data.datasets[0].data = dataVals;
        chartInstance.update();
        return;
    }

    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.length ? labels : ['port_scan', 'auth_attempt', 'shell_command'],
            datasets: [{
                data: dataVals.length ? dataVals : [1, 1, 1],
                backgroundColor: ['#06b6d4', '#f59e0b', '#ef4444', '#8b5cf6', '#10b981'],
                borderColor: '#11192d',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12 } }
            }
        }
    });
}

// ----------------- Traps Fleet -----------------
async function loadTraps() {
    const res = await fetch("/api/v1/traps");
    if (!res.ok) return;
    const traps = await res.json();
    const tbody = document.getElementById("traps-table-body");
    tbody.innerHTML = "";

    traps.forEach(t => {
        const tr = document.createElement("tr");
        const statusClass = t.status === "online" ? "status-online" : "status-offline";
        const lastSeenStr = t.last_seen ? new Date(t.last_seen).toLocaleTimeString() : "Never";

        tr.innerHTML = `
            <td style="font-family:var(--font-mono); font-weight:600; color:#fff;">${t.trap_id}</td>
            <td>${escapeHtml(t.name)}</td>
            <td><span class="severity-pill sev-medium">${escapeHtml(t.profile_name || 'Standard')}</span></td>
            <td><span class="severity-pill sev-low">${t.interaction_level.toUpperCase()}</span></td>
            <td style="font-family:var(--font-mono);">${t.ip_address}</td>
            <td style="font-family:var(--font-mono); color:var(--cyan);">${t.mgmt_ip}</td>
            <td><span id="trap-status-${t.trap_id}" class="status-badge ${statusClass}">● ${t.status.toUpperCase()}</span></td>
            <td style="font-size:11px; color:var(--text-muted);">${lastSeenStr}</td>
            <td>
                <button class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="openDeployModal('${t.trap_id}')">🚀 1-Click Deploy</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ----------------- Profiles Constructor -----------------
async function loadProfiles() {
    const res = await fetch("/api/v1/profiles");
    if (!res.ok) return;
    const profiles = await res.json();
    const tbody = document.getElementById("profiles-table-body");
    tbody.innerHTML = "";

    profiles.forEach(p => {
        const tr = document.createElement("tr");
        const servicesStr = p.services ? p.services.join(", ") : "ssh, http";
        const procName = p.stealth_params?.proc_name || "systemd-resolved";
        const jitter = p.stealth_params?.jitter_pct || "35%";

        tr.innerHTML = `
            <td>#${p.id}</td>
            <td style="font-weight:600; color:#fff;">${escapeHtml(p.name)}</td>
            <td><span class="severity-pill sev-low">${p.interaction_level.toUpperCase()}</span></td>
            <td>${servicesStr}</td>
            <td style="font-family:var(--font-mono); color:var(--cyan);">${procName}</td>
            <td>±${jitter}%</td>
            <td style="font-size:11px; color:var(--text-muted);">${new Date(p.created_at).toLocaleDateString()}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ----------------- Interactive Sessions Replay -----------------
async function loadSessions() {
    const res = await fetch("/api/v1/events/sessions");
    if (!res.ok) return;
    const sessions = await res.json();
    const tbody = document.getElementById("sessions-table-body");
    tbody.innerHTML = "";

    sessions.forEach(s => {
        const tr = document.createElement("tr");
        const artifactsCount = s.captured_artifacts ? s.captured_artifacts.length : 0;
        
        tr.innerHTML = `
            <td style="font-family:var(--font-mono); color:var(--cyan);">${s.session_id}</td>
            <td>${s.trap_id}</td>
            <td style="font-family:var(--font-mono);">${s.source_ip}</td>
            <td><span class="severity-pill sev-medium">${s.protocol}</span></td>
            <td>${s.total_commands} commands</td>
            <td><span style="color:${artifactsCount ? 'var(--red)' : 'var(--text-muted)'}; font-weight:600;">${artifactsCount} payloads</span></td>
            <td style="font-size:11px; color:var(--text-muted);">${new Date(s.started_at).toLocaleTimeString()}</td>
            <td>
                <button class="btn btn-cyan" style="padding:4px 8px; font-size:11px;" onclick="openSessionReplay('${s.session_id}')">▶ Replay</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function openSessionReplay(sessionId) {
    const res = await fetch(`/api/v1/events/sessions/${sessionId}`);
    if (!res.ok) return;
    const session = await res.json();

    const terminal = document.getElementById("session-terminal");
    terminal.innerHTML = "";
    document.getElementById("modal-replay").style.display = "flex";

    terminal.innerHTML += `[*] Connecting to HoneyForge Terminal Session Replay: ${sessionId}\n`;
    terminal.innerHTML += `[*] Source Attacker IP: ${session.source_ip} | Protocol: ${session.protocol}\n`;
    terminal.innerHTML += `--------------------------------------------------------------------------------\n`;

    if (!session.commands_history || session.commands_history.length === 0) {
        terminal.innerHTML += `[!] No interactive shell commands captured for this session.\n`;
        return;
    }

    let i = 0;
    function printNextCommand() {
        if (i >= session.commands_history.length) {
            terminal.innerHTML += `\n[✔] Session concluded by attacker.\n`;
            return;
        }
        const item = session.commands_history[i];
        terminal.innerHTML += `<span style="color:#38bdf8;">root@prod-srv-01:~#</span> ${escapeHtml(item.cmd)}\n`;
        if (item.output) {
            terminal.innerHTML += `<span style="color:#cbd5e1;">${escapeHtml(item.output)}</span>`;
        }
        terminal.scrollTop = terminal.scrollHeight;
        i++;
        setTimeout(printNextCommand, 400);
    }
    printNextCommand();
}

// ----------------- Honeytokens Hub -----------------
async function loadHoneytokens() {
    const res = await fetch("/api/v1/honeytokens");
    if (!res.ok) return;
    const tokens = await res.json();
    const tbody = document.getElementById("honeytokens-table-body");
    tbody.innerHTML = "";

    tokens.forEach(t => {
        const tr = document.createElement("tr");
        const statusBadge = t.is_triggered 
            ? '<span class="status-badge" style="background:rgba(239,68,68,0.2); color:var(--red); border:1px solid var(--red);">🚨 BREACHED</span>' 
            : '<span class="status-badge status-online">● ARMED / SECURE</span>';

        tr.innerHTML = `
            <td style="font-family:var(--font-mono); font-weight:600;">${t.token_id}</td>
            <td><span class="severity-pill sev-low">${t.token_type.toUpperCase()}</span></td>
            <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(t.canary_path || t.token_value)}</td>
            <td>${t.trap_id || 'All Traps'}</td>
            <td>${statusBadge}</td>
            <td style="font-size:11px; color:var(--text-muted);">${t.triggered_at ? new Date(t.triggered_at).toLocaleTimeString() : '—'}</td>
            <td style="font-family:var(--font-mono); color:var(--red);">${t.triggered_by_ip || '—'}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ----------------- IoC Preview & Export -----------------
async function loadIoCPreview() {
    const res = await fetch("/api/v1/events/export/ioc?format=stix");
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById("ioc-preview-block").innerText = JSON.stringify(data, null, 2);
}

function exportIoC(format) {
    window.open(`/api/v1/events/export/ioc?format=${format}`, '_blank');
}

// ----------------- 1-Click Deployment Generator -----------------
async function openDeployModal(trapId) {
    currentDeployTrapId = trapId;
    document.getElementById("modal-deploy").style.display = "flex";
    loadDeployArtifact();
}

async function switchDeployFormat(fmt) {
    currentDeployFormat = fmt;
    loadDeployArtifact();
}

async function loadDeployArtifact() {
    if (!currentDeployTrapId) return;
    const block = document.getElementById("deploy-code-block");
    block.innerText = "Generating deployment payload...";
    const res = await fetch(`/api/v1/traps/${currentDeployTrapId}/deploy-artifact?format=${currentDeployFormat}&server_url=${encodeURIComponent(location.origin)}`);
    const text = await res.text();
    block.innerText = text;
}

function copyDeployCode() {
    const text = document.getElementById("deploy-code-block").innerText;
    navigator.clipboard.writeText(text);
    alert("Deployment artifact copied to clipboard!");
}

// ----------------- Attack Simulator -----------------
async function runSim(scenario) {
    try {
        const res = await fetch("/api/v1/simulator/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        console.log("Sim run:", data);
    } catch (e) {
        console.error("Simulation trigger failed", e);
    }
}

// ----------------- Navigation & UI Utils -----------------
function switchTab(tabId) {
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    
    document.getElementById(tabId).classList.add("active");
    event.target.classList.add("active");

    if (tabId === "tab-traps") loadTraps();
    if (tabId === "tab-profiles") loadProfiles();
    if (tabId === "tab-sessions") loadSessions();
    if (tabId === "tab-honeytokens") loadHoneytokens();
    if (tabId === "tab-threatintel") loadIoCPreview();
}

function closeModal(id) {
    document.getElementById(id).style.display = "none";
}

function openCreateProfileModal() {
    document.getElementById("modal-create-profile").style.display = "flex";
}

async function submitCreateProfile(event) {
    event.preventDefault();
    const name = document.getElementById("prof-name").value;
    const level = document.getElementById("prof-level").value;
    const services = document.getElementById("prof-services").value.split(",").map(s => s.trim());
    const proc = document.getElementById("prof-proc").value;
    const jitter = parseInt(document.getElementById("prof-jitter").value, 10);

    const payload = {
        name: name,
        interaction_level: level,
        services: services,
        stealth_params: {
            proc_name: proc,
            jitter_pct: jitter,
            dummy_padding: true
        }
    };

    const res = await fetch("/api/v1/profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (res.ok) {
        closeModal("modal-create-profile");
        loadProfiles();
        alert("Profile created successfully!");
    } else {
        alert("Failed to create profile: duplicate name or invalid data");
    }
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
