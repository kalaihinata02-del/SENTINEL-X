// SENTINEL-X SOC Application Logic
let currentIncident = null;
let severityChart = null;

const MITRE_TACTICS = [
    { name: "Initial Access", id: "TA0001", icon: "fa-right-to-bracket" },
    { name: "Execution", id: "TA0002", icon: "fa-terminal" },
    { name: "Persistence", id: "TA0003", icon: "fa-anchor" },
    { name: "Privilege Escalation", id: "TA0004", icon: "fa-angles-up" },
    { name: "Defense Evasion", id: "TA0005", icon: "fa-mask" },
    { name: "Credential Access", id: "TA0006", icon: "fa-key" },
    { name: "Discovery", id: "TA0007", icon: "fa-compass" },
    { name: "Lateral Movement", id: "TA0008", icon: "fa-network-wired" },
    { name: "Command and Control", id: "TA0011", icon: "fa-satellite-dish" },
    { name: "Exfiltration", id: "TA0010", icon: "fa-upload" },
    { name: "Impact", id: "TA0040", icon: "fa-skull-crossbones" }
];

document.addEventListener("DOMContentLoaded", () => {
    refreshAllData();
    setInterval(refreshMetricsQuick, 10000);
});

// Tab Switcher
function switchTab(tabId) {
    const tabs = ['overview', 'incidents', 'simulator', 'rules', 'logs', 'soar'];
    tabs.forEach(t => {
        const section = document.getElementById(`tab-${t}`);
        const btn = document.getElementById(`tab-btn-${t}`);
        if (section) section.classList.add('hidden');
        if (btn) btn.classList.remove('active', 'border-cyan-400', 'text-cyan-400');
    });

    const activeSec = document.getElementById(`tab-${tabId}`);
    const activeBtn = document.getElementById(`tab-btn-${tabId}`);
    if (activeSec) activeSec.classList.remove('hidden');
    if (activeBtn) activeBtn.classList.add('active', 'border-cyan-400', 'text-cyan-400');

    if (tabId === 'overview') {
        loadMetrics();
        loadRecentIncidentsOverview();
    } else if (tabId === 'incidents') {
        loadIncidents();
    } else if (tabId === 'rules') {
        loadRules();
    } else if (tabId === 'logs') {
        loadLogs();
    } else if (tabId === 'soar') {
        loadSoarState();
    }
}

// Master Refresh
function refreshAllData() {
    const icon = document.getElementById('refresh-icon');
    if (icon) icon.classList.add('fa-spin');
    
    Promise.all([
        loadMetrics(),
        loadRecentIncidentsOverview(),
        loadRules(),
        loadSoarState()
    ]).finally(() => {
        if (icon) icon.classList.remove('fa-spin');
    });
}

function refreshMetricsQuick() {
    loadMetrics();
}

// Load Metrics & Overview
async function loadMetrics() {
    try {
        const res = await fetch('/api/metrics');
        const data = await res.json();

        document.getElementById('stat-total-logs').textContent = data.total_logs;
        document.getElementById('stat-total-alerts').textContent = data.total_alerts;
        document.getElementById('stat-open-incidents').textContent = data.open_incidents;
        document.getElementById('badge-open-incidents').textContent = data.open_incidents;

        const totalContainments = data.active_blocked_ips + data.active_isolated_hosts + data.active_locked_accounts;
        document.getElementById('stat-total-containments').textContent = totalContainments;
        document.getElementById('top-containments-count').textContent = totalContainments;
        document.getElementById('top-rules-count').textContent = data.loaded_rules;

        renderMitreGrid(data.mitre_tactic_counts || {});
        renderSeverityChart(data.incident_severities || {});
    } catch (err) {
        console.error("Failed to load metrics:", err);
    }
}

function renderMitreGrid(counts) {
    const grid = document.getElementById('mitre-tactics-grid');
    if (!grid) return;
    grid.innerHTML = '';

    MITRE_TACTICS.forEach(tac => {
        let count = 0;
        for (const [k, v] of Object.entries(counts)) {
            if (k.toLowerCase().includes(tac.name.toLowerCase()) || tac.name.toLowerCase().includes(k.toLowerCase())) {
                count += v;
            }
        }

        const isHit = count > 0;
        const card = document.createElement('div');
        card.className = `p-2.5 rounded-lg border transition ${
            isHit 
                ? 'bg-rose-950/40 border-rose-500/60 shadow-md shadow-rose-900/20' 
                : 'bg-slate-900/80 border-slate-800/80 opacity-70'
        }`;
        card.innerHTML = `
            <div class="flex items-center justify-between">
                <span class="text-[10px] font-mono text-slate-400">${tac.id}</span>
                ${isHit ? `<span class="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-500 text-slate-950">${count}</span>` : ''}
            </div>
            <div class="mt-1 flex items-center space-x-1.5 font-bold ${isHit ? 'text-rose-300' : 'text-slate-300'}">
                <i class="fa-solid ${tac.icon} text-xs"></i>
                <span class="truncate">${tac.name}</span>
            </div>
        `;
        grid.appendChild(card);
    });
}

function renderSeverityChart(severities) {
    const ctx = document.getElementById('chart-severity');
    if (!ctx) return;

    const critical = severities.critical || 0;
    const high = severities.high || 0;
    const medium = severities.medium || 0;
    const low = severities.low || 0;

    const data = [critical, high, medium, low];
    const total = data.reduce((a, b) => a + b, 0);

    if (severityChart) {
        severityChart.data.datasets[0].data = total > 0 ? data : [0, 0, 0, 1];
        severityChart.update();
        return;
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: total > 0 ? data : [0, 0, 0, 1],
                backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            cutout: '72%'
        }
    });
}

async function loadRecentIncidentsOverview() {
    const tbody = document.getElementById('overview-recent-incidents');
    if (!tbody) return;
    try {
        const res = await fetch('/api/incidents?limit=5');
        const data = await res.json();
        tbody.innerHTML = '';

        if (!data.incidents || data.incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-500">No active incidents yet. Run a simulation scenario to generate incident tickets!</td></tr>`;
            return;
        }

        data.incidents.forEach(inc => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-800/40 transition cursor-pointer';
            tr.onclick = () => openInvestigationModal(inc.incident_id);
            tr.innerHTML = `
                <td class="p-3 font-bold text-cyan-400">${inc.incident_id}</td>
                <td class="p-3">${getSeverityBadge(inc.severity)}</td>
                <td class="p-3 text-white max-w-xs truncate">${inc.title}</td>
                <td class="p-3 text-slate-400">${inc.primary_host || inc.primary_ip || 'N/A'}</td>
                <td class="p-3 text-slate-300">${inc.mitre_tactics && inc.mitre_tactics[0] ? inc.mitre_tactics[0] : 'N/A'}</td>
                <td class="p-3">${getStatusBadge(inc.status)}</td>
                <td class="p-3 text-right">
                    <button class="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-600 hover:text-white text-cyan-400 text-xs transition">Investigate</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Error loading overview incidents:", err);
    }
}

// Incidents Tab
async function loadIncidents() {
    const tbody = document.getElementById('incidents-table-body');
    const statusFilter = document.getElementById('filter-incident-status').value;
    if (!tbody) return;

    try {
        const res = await fetch(`/api/incidents?limit=50&status=${statusFilter}`);
        const data = await res.json();
        tbody.innerHTML = '';

        if (!data.incidents || data.incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-500">No incidents found matching status filter '${statusFilter}'.</td></tr>`;
            return;
        }

        data.incidents.forEach(inc => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-800/50 transition cursor-pointer';
            tr.onclick = () => openInvestigationModal(inc.incident_id);
            tr.innerHTML = `
                <td class="p-3.5 font-bold text-cyan-400">${inc.incident_id}</td>
                <td class="p-3.5">${getSeverityBadge(inc.severity)}</td>
                <td class="p-3.5 text-white font-medium">${inc.title}</td>
                <td class="p-3.5 uppercase text-slate-400">${inc.category}</td>
                <td class="p-3.5 text-slate-300">${inc.primary_host || inc.primary_ip || 'N/A'}</td>
                <td class="p-3.5 text-slate-400">${inc.assigned_analyst || 'Unassigned'}</td>
                <td class="p-3.5">${getStatusBadge(inc.status)}</td>
                <td class="p-3.5 text-right">
                    <button class="px-3 py-1 rounded-lg bg-slate-800 hover:bg-cyan-600 hover:text-white text-cyan-400 transition">Investigate →</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load incidents:", err);
    }
}

// Investigation Modal
async function openInvestigationModal(incidentId) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        if (!res.ok) return alert("Failed to fetch incident details");
        const inc = await res.json();
        currentIncident = inc;

        document.getElementById('modal-incident-id').textContent = inc.incident_id;
        document.getElementById('modal-incident-title').textContent = inc.title;
        document.getElementById('modal-incident-meta').textContent = `Created: ${new Date(inc.created_at).toLocaleString()} | Analyst: ${inc.assigned_analyst}`;
        document.getElementById('modal-incident-summary').textContent = inc.summary;
        document.getElementById('modal-status-select').value = inc.status;

        // Severity badge
        const sevBadge = document.getElementById('modal-incident-severity-badge');
        sevBadge.className = `px-2.5 py-1 rounded text-xs font-black uppercase font-mono ${getSeverityClass(inc.severity)}`;
        sevBadge.textContent = inc.severity;

        // MITRE badges
        const mitreContainer = document.getElementById('modal-mitre-badges');
        mitreContainer.innerHTML = '';
        (inc.mitre_tactics || []).forEach(t => {
            mitreContainer.innerHTML += `<span class="px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-800 text-[10px] font-mono">${t}</span>`;
        });
        (inc.mitre_techniques || []).forEach(t => {
            mitreContainer.innerHTML += `<span class="px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800 text-[10px] font-mono">${t}</span>`;
        });

        // Context Enrichment Grid
        const enrGrid = document.getElementById('modal-enrichment-grid');
        enrGrid.innerHTML = '';
        const enr = inc.enrichment || {};
        const ipIntel = enr.ip_intelligence || {};
        const assetCtx = enr.asset_context || {};
        const idCtx = enr.identity_context || {};

        document.getElementById('modal-composite-score').textContent = `Calculated Risk Score: ${enr.composite_risk_score || 0}/100`;

        enrGrid.innerHTML = `
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <div class="text-slate-400 font-semibold mb-1"><i class="fa-solid fa-location-dot text-rose-400 mr-1"></i> Threat Intel & GeoIP</div>
                <div class="font-mono text-slate-200">IP: <span class="text-cyan-400">${ipIntel.ip || inc.primary_ip || 'N/A'}</span></div>
                <div class="text-slate-400">Reputation: <span class="font-bold ${ipIntel.reputation === 'MALICIOUS' ? 'text-rose-400' : 'text-amber-400'}">${ipIntel.reputation || 'UNKNOWN'}</span></div>
                <div class="text-slate-400">Geo: ${ipIntel.city || ''}, ${ipIntel.country || 'Unknown'} (${ipIntel.isp || 'ISP'})</div>
                ${ipIntel.threat_category ? `<div class="text-rose-300 text-[10px] mt-1 font-mono">${ipIntel.threat_category}</div>` : ''}
            </div>
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <div class="text-slate-400 font-semibold mb-1"><i class="fa-solid fa-server text-blue-400 mr-1"></i> Asset Inventory (CMDB)</div>
                <div class="font-mono text-slate-200">Host: <span class="text-cyan-400">${inc.primary_host || 'N/A'}</span></div>
                <div class="text-slate-400">Role: <span class="text-white font-medium">${assetCtx.role || 'Workstation'}</span></div>
                <div class="text-slate-400">Criticality: <span class="font-bold ${assetCtx.criticality === 'CRITICAL' ? 'text-rose-400' : 'text-blue-300'}">${assetCtx.criticality || 'MEDIUM'}</span> (${assetCtx.tier || 'Tier-3'})</div>
            </div>
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                <div class="text-slate-400 font-semibold mb-1"><i class="fa-solid fa-user-shield text-emerald-400 mr-1"></i> Identity & Access</div>
                <div class="font-mono text-slate-200">User: <span class="text-cyan-400">${inc.primary_user || 'N/A'}</span></div>
                <div class="text-slate-400">Privilege: <span class="text-white">${idCtx.privilege || 'Standard'}</span></div>
                <div class="text-slate-400">Department: ${idCtx.department || 'Corporate'}</div>
                <div class="text-[10px] ${idCtx.is_privileged ? 'text-amber-400' : 'text-slate-400'}">${idCtx.is_privileged ? '⚠️ Privileged Administrative Identity' : 'Standard Identity'}</div>
            </div>
        `;

        // Timeline
        const tlContainer = document.getElementById('modal-timeline');
        tlContainer.innerHTML = '';
        (inc.timeline || []).forEach(tl => {
            tlContainer.innerHTML += `
                <div class="relative pl-3">
                    <span class="absolute -left-[23px] top-1 w-2.5 h-2.5 rounded-full ${tl.status === 'ALERT' ? 'bg-rose-500 ring-4 ring-rose-950' : 'bg-cyan-500 ring-4 ring-cyan-950'}"></span>
                    <div class="text-slate-400 text-[10px] font-mono">${new Date(tl.timestamp).toLocaleTimeString()}</div>
                    <div class="font-semibold text-slate-200">${tl.detail}</div>
                </div>
            `;
        });

        // Evidence Logs
        const evTbody = document.getElementById('modal-evidence-table');
        evTbody.innerHTML = '';
        (inc.evidence || []).forEach(ev => {
            evTbody.innerHTML += `
                <tr>
                    <td class="p-2 text-slate-400">${ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}</td>
                    <td class="p-2 text-cyan-400">${ev.event_source}</td>
                    <td class="p-2 text-amber-300">${ev.action}</td>
                    <td class="p-2 text-slate-300 truncate max-w-md">${ev.raw_log || ev.process_command_line || JSON.stringify(ev)}</td>
                </tr>
            `;
        });

        // Recommended Response & SOAR Playbooks
        document.getElementById('modal-recommended-response').textContent = inc.recommended_response || "Conduct host containment, audit credentials, and review network flows.";
        
        const soarBtnContainer = document.getElementById('modal-soar-buttons');
        soarBtnContainer.innerHTML = '';
        if (inc.primary_ip) {
            soarBtnContainer.innerHTML += `
                <button onclick="executeModalPlaybook('block_ip', '${inc.primary_ip}')" class="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center space-x-1.5 transition">
                    <i class="fa-solid fa-ban"></i>
                    <span>Execute Playbook: Block IP (${inc.primary_ip})</span>
                </button>
            `;
        }
        if (inc.primary_host) {
            soarBtnContainer.innerHTML += `
                <button onclick="executeModalPlaybook('isolate_host', '${inc.primary_host}')" class="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs flex items-center space-x-1.5 transition">
                    <i class="fa-solid fa-network-wired"></i>
                    <span>Execute Playbook: EDR Isolate Host (${inc.primary_host})</span>
                </button>
            `;
        }
        if (inc.primary_user) {
            soarBtnContainer.innerHTML += `
                <button onclick="executeModalPlaybook('revoke_user', '${inc.primary_user}')" class="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs flex items-center space-x-1.5 transition">
                    <i class="fa-solid fa-user-slash"></i>
                    <span>Execute Playbook: Revoke User (${inc.primary_user})</span>
                </button>
            `;
        }

        // Analyst Notes
        renderModalNotes(inc.analyst_notes || []);

        document.getElementById('investigation-modal').classList.remove('hidden');
    } catch (err) {
        console.error("Error opening modal:", err);
    }
}

function renderModalNotes(notes) {
    const list = document.getElementById('modal-notes-list');
    list.innerHTML = '';
    notes.forEach(n => {
        list.innerHTML += `
            <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div class="flex justify-between text-[10px] text-slate-400 font-mono mb-1">
                    <span class="text-cyan-400 font-semibold">${n.author}</span>
                    <span>${new Date(n.timestamp).toLocaleTimeString()}</span>
                </div>
                <div class="text-slate-300 text-xs">${n.note}</div>
            </div>
        `;
    });
}

async function submitModalNote() {
    const input = document.getElementById('modal-note-input');
    const text = input.value.trim();
    if (!text || !currentIncident) return;

    try {
        const res = await fetch(`/api/incidents/${currentIncident.incident_id}/notes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ author: "SOC Senior Analyst", note: text })
        });
        if (res.ok) {
            input.value = '';
            const updated = await res.json();
            renderModalNotes(updated.incident.analyst_notes);
        }
    } catch (err) {
        console.error("Failed to add note:", err);
    }
}

async function updateModalIncidentStatus() {
    if (!currentIncident) return;
    const newStatus = document.getElementById('modal-status-select').value;
    try {
        await fetch(`/api/incidents/${currentIncident.incident_id}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus, assigned_analyst: "SOC Senior Analyst" })
        });
        loadMetrics();
        loadIncidents();
    } catch (err) {
        console.error("Failed to update status:", err);
    }
}

async function executeModalPlaybook(playbook, target) {
    if (!currentIncident) return;
    try {
        const res = await fetch(`/api/incidents/${currentIncident.incident_id}/playbook`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ playbook_name: playbook, target: target })
        });
        const data = await res.json();
        alert(data.action.message);
        openInvestigationModal(currentIncident.incident_id);
        loadSoarState();
        loadMetrics();
    } catch (err) {
        alert("Error executing playbook: " + err);
    }
}

function closeInvestigationModal() {
    document.getElementById('investigation-modal').classList.add('hidden');
    currentIncident = null;
}

// Attack Simulation Execution
async function runSimulation(scenario) {
    appendSimConsole(`[>] Initiating scenario: ${scenario}...`);
    try {
        const res = await fetch('/api/simulation/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        appendSimConsole(`[+] ${data.scenario} executed!`);
        appendSimConsole(`[i] ${data.description}`);
        
        if (data.result) {
            appendSimConsole(`[+] Pipeline Output: Logs Processed: ${data.result.total_processed || 1}, Alerts Generated: ${data.result.total_alerts || data.result.alerts_generated || 0}`);
            if (data.result.incidents && data.result.incidents.length > 0) {
                data.result.incidents.forEach(inc => {
                    appendSimConsole(`[!] INCIDENT CREATED: ${inc.incident_id} - ${inc.title}`);
                });
            } else if (data.result.incidents_created && data.result.incidents_created.length > 0) {
                data.result.incidents_created.forEach(inc => {
                    appendSimConsole(`[!] INCIDENT CREATED: ${inc.incident_id} - ${inc.title}`);
                });
            }
        }

        refreshAllData();
    } catch (err) {
        appendSimConsole(`[-] Error running scenario: ${err}`);
    }
}

function appendSimConsole(msg) {
    const term = document.getElementById('sim-console');
    if (!term) return;
    const line = document.createElement('div');
    const time = new Date().toLocaleTimeString();
    line.innerHTML = `<span class="text-slate-500">[${time}]</span> ${msg}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

function clearSimConsole() {
    const term = document.getElementById('sim-console');
    if (term) term.innerHTML = '';
}

// Detection Rules Tab
async function loadRules() {
    const grid = document.getElementById('rules-grid');
    if (!grid) return;
    try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        grid.innerHTML = '';

        data.rules.forEach(r => {
            const isEnabled = r.status === 'enabled';
            const card = document.createElement('div');
            card.className = `p-5 rounded-xl border ${isEnabled ? 'bg-[#0d1527] border-slate-800' : 'bg-slate-950/60 border-slate-900 opacity-60'} shadow-lg`;
            card.innerHTML = `
                <div class="flex items-center justify-between mb-2">
                    <span class="font-mono text-xs font-bold text-cyan-400">${r.id}</span>
                    <div class="flex items-center space-x-2">
                        ${getSeverityBadge(r.severity)}
                        <button onclick="toggleRule('${r.id}')" class="px-2 py-0.5 rounded text-[10px] font-bold ${isEnabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-400'}">
                            ${r.status.toUpperCase()}
                        </button>
                    </div>
                </div>
                <h4 class="font-bold text-white text-sm mb-1">${r.title}</h4>
                <p class="text-xs text-slate-400 mb-3">${r.description}</p>
                <div class="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span>MITRE: ${r.mitre_attack ? r.mitre_attack.technique_id : 'N/A'}</span>
                    <span>Threshold: ${r.detection ? r.detection.threshold : 1} req / ${r.detection ? r.detection.time_window_seconds : 60}s</span>
                </div>
            `;
            grid.appendChild(card);
        });
    } catch (err) {
        console.error("Failed to load rules:", err);
    }
}

async function toggleRule(ruleId) {
    try {
        await fetch(`/api/rules/${ruleId}/toggle`, { method: 'POST' });
        loadRules();
    } catch (err) {
        console.error("Failed to toggle rule:", err);
    }
}

async function reloadRules() {
    try {
        const res = await fetch('/api/rules/reload', { method: 'POST' });
        const data = await res.json();
        alert(data.message);
        loadRules();
    } catch (err) {
        console.error("Failed to reload rules:", err);
    }
}

// Live Logs Tab
async function loadLogs() {
    const tbody = document.getElementById('logs-table-body');
    const search = document.getElementById('log-search-input').value;
    const cat = document.getElementById('log-category-filter').value;
    if (!tbody) return;

    try {
        const res = await fetch(`/api/logs?limit=50&category=${cat}&search=${search}`);
        const data = await res.json();
        tbody.innerHTML = '';

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-500">No logs found. Try injecting logs via Simulator tab!</td></tr>`;
            return;
        }

        data.logs.forEach(l => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-800/50 transition';
            tr.innerHTML = `
                <td class="p-3 text-slate-400 text-[11px]">${new Date(l.timestamp).toLocaleTimeString()}</td>
                <td class="p-3 text-cyan-400">${l.event_source}</td>
                <td class="p-3 text-amber-300 font-semibold">${l.action}</td>
                <td class="p-3 text-slate-200">${l.actor_user || '-'}</td>
                <td class="p-3 text-slate-300">${l.src_ip || '-'}</td>
                <td class="p-3 text-slate-300">${l.hostname || '-'}</td>
                <td class="p-3 text-slate-400 truncate max-w-xs">${l.process_name || l.process_command_line || l.raw_log || '-'}</td>
                <td class="p-3">${l.status === 'SUCCESS' ? '<span class="text-emerald-400">SUCCESS</span>' : '<span class="text-rose-400 font-bold">FAIL/ATTEMPT</span>'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load logs:", err);
    }
}

// SOAR State Tab
async function loadSoarState() {
    try {
        const res = await fetch('/api/soar/state');
        const data = await res.json();

        // Blocked IPs
        const ipTbody = document.getElementById('soar-blocked-ips-table');
        document.getElementById('soar-blocked-count').textContent = data.blocked_ips.length;
        if (ipTbody) {
            ipTbody.innerHTML = '';
            if (data.blocked_ips.length === 0) {
                ipTbody.innerHTML = `<tr><td colspan="4" class="p-3 text-center text-slate-500">No IP blocks active.</td></tr>`;
            } else {
                data.blocked_ips.forEach(b => {
                    ipTbody.innerHTML += `
                        <tr>
                            <td class="p-2.5 font-bold text-rose-400">${b.ip}</td>
                            <td class="p-2.5 text-slate-400">${b.rule_id}</td>
                            <td class="p-2.5 text-slate-400 text-[10px]">${new Date(b.blocked_at).toLocaleTimeString()}</td>
                            <td class="p-2.5 text-right">
                                <button onclick="unblockIp('${b.ip}')" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]">Unblock</button>
                            </td>
                        </tr>
                    `;
                });
            }
        }

        // Isolated Hosts
        const hostTbody = document.getElementById('soar-isolated-hosts-table');
        document.getElementById('soar-isolated-count').textContent = data.isolated_hosts.length;
        if (hostTbody) {
            hostTbody.innerHTML = '';
            if (data.isolated_hosts.length === 0) {
                hostTbody.innerHTML = `<tr><td colspan="4" class="p-3 text-center text-slate-500">No hosts quarantined.</td></tr>`;
            } else {
                data.isolated_hosts.forEach(h => {
                    hostTbody.innerHTML += `
                        <tr>
                            <td class="p-2.5 font-bold text-amber-400">${h.hostname}</td>
                            <td class="p-2.5 text-rose-400 text-[10px]">ISOLATED</td>
                            <td class="p-2.5 text-slate-400 text-[10px]">${new Date(h.isolated_at).toLocaleTimeString()}</td>
                            <td class="p-2.5 text-right">
                                <button onclick="unisolateHost('${h.hostname}')" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]">Restore</button>
                            </td>
                        </tr>
                    `;
                });
            }
        }

        // Actions History
        const histTbody = document.getElementById('soar-actions-history-table');
        if (histTbody) {
            histTbody.innerHTML = '';
            (data.recent_actions || []).forEach(a => {
                histTbody.innerHTML += `
                    <tr>
                        <td class="p-3 text-cyan-400 font-bold">${a.action_id}</td>
                        <td class="p-3 uppercase text-amber-300">${a.playbook}</td>
                        <td class="p-3 font-semibold text-white">${a.target}</td>
                        <td class="p-3 text-slate-400">${a.incident_id || 'Global'}</td>
                        <td class="p-3 text-slate-300">${a.message}</td>
                        <td class="p-3 text-slate-400 text-[11px]">${new Date(a.timestamp).toLocaleTimeString()}</td>
                    </tr>
                `;
            });
        }
    } catch (err) {
        console.error("Failed to load SOAR state:", err);
    }
}

async function unblockIp(ip) {
    try {
        await fetch('/api/soar/unblock-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: ip })
        });
        loadSoarState();
        loadMetrics();
    } catch (err) {
        console.error("Failed to unblock IP:", err);
    }
}

async function unisolateHost(hostname) {
    try {
        await fetch('/api/soar/unisolate-host', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: hostname })
        });
        loadSoarState();
        loadMetrics();
    } catch (err) {
        console.error("Failed to unisolate host:", err);
    }
}

// Helpers
function getSeverityBadge(sev) {
    sev = (sev || 'medium').toLowerCase();
    const cls = getSeverityClass(sev);
    return `<span class="px-2 py-0.5 rounded text-[10px] font-black uppercase font-mono ${cls}">${sev}</span>`;
}

function getSeverityClass(sev) {
    switch (sev) {
        case 'critical': return 'bg-rose-500/20 text-rose-400 border border-rose-500/30';
        case 'high': return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
        case 'medium': return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
        default: return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
    }
}

function getStatusBadge(st) {
    st = (st || 'open').toLowerCase();
    switch (st) {
        case 'open': return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">OPEN</span>`;
        case 'triaged': return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">TRIAGED</span>`;
        case 'in_progress': return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">IN PROGRESS</span>`;
        case 'mitigated': return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">MITIGATED</span>`;
        case 'closed': return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">CLOSED</span>`;
        default: return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300">${st.toUpperCase()}</span>`;
    }
}
