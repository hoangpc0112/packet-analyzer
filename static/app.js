document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const interfaceSelect = document.getElementById('interface-select');
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const btnClear = document.getElementById('btn-clear');
    const btnUpload = document.getElementById('btn-upload');
    const pcapUpload = document.getElementById('pcap-upload');
    const packetList = document.getElementById('packet-list');
    const emptyState = document.getElementById('empty-state');
    const detailsContent = document.getElementById('details-content');
    const selectedPacketIdSpan = document.getElementById('selected-packet-id');
    const statusIndicator = document.getElementById('status-indicator');
    const protocolStatsList = document.getElementById('protocol-stats-list');

    // Pagination Elements
    const btnPrev = document.getElementById('btn-prev');
    const btnNext = document.getElementById('btn-next');
    const pageStartSpan = document.getElementById('page-start');
    const pageEndSpan = document.getElementById('page-end');
    const totalPacketsSpan = document.getElementById('total-packets');
    const pageNumberSpan = document.getElementById('page-number');
    const itemsPerPageSelect = document.getElementById('items-per-page');
    const displayFilterInput = document.getElementById('display-filter');

    // Tabs & Analysis Elements
    const tabBtns = document.querySelectorAll('.tab-btn');
    const flowsList = document.getElementById('flows-list');
    const credsList = document.getElementById('creds-list');
    const btnExportAnalysis = document.getElementById('btn-export-analysis');
    const exportMenu = document.getElementById('export-menu');

    // State
    let isCapturing = false;
    let ws = null;
    let selectedPacketRow = null;
    let allPackets = [];
    let packetById = new Map();
    let packetDetailsById = new Map();
    let currentPage = 1;
    let itemsPerPage = 100;
    const MAX_STORED_PACKETS = 50000; // Prevent memory issues
    const RENDER_THROTTLE_MS = 120;
    const STATS_THROTTLE_MS = 120;
    let packetSort = { key: null, direction: 'asc' };
    let renderTimer = null;
    let statsTimer = null;
    
    let packetStats = { total: 0, byProtocol: {} };
    const selectedProtocolFilters = new Set();

    const escapeHtml = (value) => String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    const csvEscape = (value) => {
        const text = String(value ?? '');
        const escaped = text.replace(/"/g, '""');
        return /[",\n\r]/.test(escaped) ? `"${escaped}"` : escaped;
    };

    const toCsvRow = (...values) => values.map(csvEscape).join(',');

    const formatBytesAsKb = (bytes) => {
        if (typeof bytes !== 'number') return '-';
        return `${(bytes / 1024).toFixed(2)} KB`;
    };

    const getSummaryRows = (analysisData) => {
        const summary = (analysisData || {}).summary || {};
        return [
            ['Duration', summary.duration ?? '-'],
            ['Total Packets', summary.total_packets ?? '-'],
            ['Hosts Observed', summary.hosts_observed ?? '-'],
            ['External Dests', summary.external_dests ?? '-'],
            ['Long-lived Flows', summary.long_lived_flows ?? '-'],
            ['TCP Resets', summary.tcp_resets ?? '-'],
            ['DNS NXDOMAIN', summary.dns_nxdomain ?? '-'],
            ['Suspicious DNS', summary.suspicious_names ?? '-'],
            ['Top Protocols', summary.top_protocols ?? '-'],
            ['Top Talkers', summary.top_talkers ?? '-']
        ];
    };

    const toHtmlList = (items) => {
        if (!Array.isArray(items) || items.length === 0) return '<span class="muted">-</span>';
        return items.map(item => `<div>${escapeHtml(item)}</div>`).join('');
    };

    const toInlineText = (items) => {
        if (!Array.isArray(items) || items.length === 0) return '-';
        return items.map(item => String(item)).join('; ');
    };

    const setExportMenuOpen = (isOpen) => {
        if (!exportMenu || !btnExportAnalysis) return;
        const shouldOpen = Boolean(isOpen) && !btnExportAnalysis.disabled;
        exportMenu.classList.toggle('open', shouldOpen);
        btnExportAnalysis.setAttribute('aria-expanded', String(shouldOpen));
    };

    const setAnalysisExportState = (isReady) => {
        if (!btnExportAnalysis) return;
        btnExportAnalysis.disabled = !isReady;
        if (!isReady) {
            setExportMenuOpen(false);
        }
    };

    const resetAnalysisData = () => {
        window.lastAnalysisData = null;
        setAnalysisExportState(false);
    };

    const buildExportTimestamp = () => {
        const now = new Date();
        const yyyy = now.getFullYear();
        const mm = String(now.getMonth() + 1).padStart(2, '0');
        const dd = String(now.getDate()).padStart(2, '0');
        const hh = String(now.getHours()).padStart(2, '0');
        const mi = String(now.getMinutes()).padStart(2, '0');
        const ss = String(now.getSeconds()).padStart(2, '0');
        return `${yyyy}${mm}${dd}-${hh}${mi}${ss}`;
    };

    const buildAnalysisExportHtml = (analysisData) => {
        const d = analysisData || {};
        const summaryRows = getSummaryRows(d);
        const generatedAt = new Date().toLocaleString();

        const topFlowsRows = Array.isArray(d.top_flows) && d.top_flows.length > 0
            ? d.top_flows.map(flow => `
                <tr>
                    <td>${escapeHtml(flow.flow ?? '-')}</td>
                    <td>${escapeHtml(flow.packets ?? '-')}</td>
                    <td>${escapeHtml(formatBytesAsKb(flow.bytes))}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="3" class="muted">No flow data.</td></tr>';

        const suspiciousRows = Array.isArray(d.suspicious_flows) && d.suspicious_flows.length > 0
            ? d.suspicious_flows.map(flow => `
                <tr>
                    <td>${escapeHtml(flow.flow ?? '-')}</td>
                    <td>${escapeHtml(flow.risk_score ?? '-')}</td>
                    <td>${toHtmlList(flow.evidence)}</td>
                    <td>${escapeHtml(flow.metadata ?? '-')}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="4" class="muted">No suspicious flows detected.</td></tr>';

        const dnsRows = Array.isArray(d.dns_anomalies) && d.dns_anomalies.length > 0
            ? d.dns_anomalies.map(item => `
                <tr>
                    <td>${escapeHtml(item.domain ?? '-')}</td>
                    <td>${escapeHtml(item.count ?? '-')}</td>
                    <td>${escapeHtml(item.nxdomain ?? '-')}</td>
                    <td>${toHtmlList(item.evidence)}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="4" class="muted">No DNS data.</td></tr>';

        const cleartextRows = Array.isArray(d.cleartext_fields) && d.cleartext_fields.length > 0
            ? d.cleartext_fields.map(item => `
                <tr>
                    <td>#${escapeHtml(item.packet_no ?? '-')}</td>
                    <td>${escapeHtml(item.source ?? '-')} &rarr; ${escapeHtml(item.destination ?? '-')}</td>
                    <td>${escapeHtml(item.field ?? '-')}</td>
                    <td>${escapeHtml(item.value ?? '-')}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="4" class="muted">No clear-text fields found.</td></tr>';

        const timelineRows = Array.isArray(d.timeline) && d.timeline.length > 0
            ? d.timeline.map(item => `<li>${escapeHtml(item)}</li>`).join('')
            : '<li class="muted">No timeline events.</li>';

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PCAP Analysis Report</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #101a2e;
      --border: #2a3a56;
      --text: #e6edf7;
      --muted: #9bb0d2;
      --accent: #5ca7ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--text);
      background: radial-gradient(circle at top left, #10203f, var(--bg));
      padding: 24px;
    }
    h1, h2 { margin: 0 0 12px 0; }
    .muted { color: var(--muted); }
    .header { margin-bottom: 20px; }
    .section {
      background: rgba(16, 26, 46, 0.9);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      margin-bottom: 14px;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 10px;
    }
    .kpi {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      background: #0f172a;
    }
    .kpi .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .kpi .value {
      margin-top: 4px;
      font-size: 18px;
      font-weight: 600;
      color: var(--accent);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 8px;
      vertical-align: top;
      word-wrap: break-word;
      font-size: 13px;
    }
    th {
      background: #16253f;
      color: #cfe2ff;
      text-align: left;
    }
    ul {
      margin: 0;
      padding-left: 20px;
    }
    .meta {
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>PCAP Analysis Report</h1>
    <div class="meta">Generated at: ${escapeHtml(generatedAt)}</div>
  </div>

  <section class="section">
    <h2>Summary</h2>
    <div class="summary-grid">
      ${summaryRows.map(([label, value]) => `
        <div class="kpi">
          <div class="label">${escapeHtml(label)}</div>
          <div class="value">${escapeHtml(value)}</div>
        </div>
      `).join('')}
    </div>
  </section>

  <section class="section">
    <h2>Top Network Flows</h2>
    <table>
      <thead>
        <tr>
          <th>Flow</th>
          <th style="width: 120px;">Packets</th>
          <th style="width: 140px;">Bytes</th>
        </tr>
      </thead>
      <tbody>${topFlowsRows}</tbody>
    </table>
  </section>

  <section class="section">
    <h2>Suspicious Flows</h2>
    <table>
      <thead>
        <tr>
          <th>Flow</th>
          <th style="width: 90px;">Risk</th>
          <th>Evidence</th>
          <th>Metadata</th>
        </tr>
      </thead>
      <tbody>${suspiciousRows}</tbody>
    </table>
  </section>

  <section class="section">
    <h2>DNS Anomalies</h2>
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th style="width: 110px;">Queries</th>
          <th style="width: 130px;">NXDOMAIN</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>${dnsRows}</tbody>
    </table>
  </section>

  <section class="section">
    <h2>Clear-text Fields</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 110px;">Packet No.</th>
          <th>Flow</th>
          <th>Field</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>${cleartextRows}</tbody>
    </table>
  </section>

  <section class="section">
    <h2>Timeline</h2>
    <ul>${timelineRows}</ul>
  </section>
</body>
</html>`;
    };

    const buildAnalysisExportJson = (analysisData) => JSON.stringify(analysisData || {}, null, 2);

    const buildAnalysisExportText = (analysisData) => {
        const d = analysisData || {};
        const lines = [];
        lines.push('PCAP Analysis Report');
        lines.push(`Generated at: ${new Date().toLocaleString()}`);
        lines.push('');

        lines.push('Summary');
        getSummaryRows(d).forEach(([key, value]) => lines.push(`- ${key}: ${value}`));
        lines.push('');

        lines.push('Top Network Flows');
        if (Array.isArray(d.top_flows) && d.top_flows.length > 0) {
            d.top_flows.forEach((flow, idx) => {
                lines.push(`${idx + 1}. ${flow.flow ?? '-'} | packets: ${flow.packets ?? '-'} | bytes: ${formatBytesAsKb(flow.bytes)}`);
            });
        } else {
            lines.push('- No flow data.');
        }
        lines.push('');

        lines.push('Suspicious Flows');
        if (Array.isArray(d.suspicious_flows) && d.suspicious_flows.length > 0) {
            d.suspicious_flows.forEach((flow, idx) => {
                lines.push(`${idx + 1}. ${flow.flow ?? '-'} | risk: ${flow.risk_score ?? '-'} | evidence: ${toInlineText(flow.evidence)}`);
            });
        } else {
            lines.push('- No suspicious flows detected.');
        }
        lines.push('');

        lines.push('DNS Anomalies');
        if (Array.isArray(d.dns_anomalies) && d.dns_anomalies.length > 0) {
            d.dns_anomalies.forEach((row, idx) => {
                lines.push(`${idx + 1}. ${row.domain ?? '-'} | queries: ${row.count ?? '-'} | nxdomain: ${row.nxdomain ?? '-'} | evidence: ${toInlineText(row.evidence)}`);
            });
        } else {
            lines.push('- No DNS data.');
        }
        lines.push('');

        lines.push('Clear-text Fields');
        if (Array.isArray(d.cleartext_fields) && d.cleartext_fields.length > 0) {
            d.cleartext_fields.forEach((row, idx) => {
                lines.push(`${idx + 1}. #${row.packet_no ?? '-'} | ${row.source ?? '-'} -> ${row.destination ?? '-'} | ${row.field ?? '-'} = ${row.value ?? '-'}`);
            });
        } else {
            lines.push('- No clear-text fields found.');
        }
        lines.push('');

        lines.push('Timeline');
        if (Array.isArray(d.timeline) && d.timeline.length > 0) {
            d.timeline.forEach((item, idx) => lines.push(`${idx + 1}. ${item}`));
        } else {
            lines.push('- No timeline events.');
        }

        return lines.join('\n');
    };

    const buildAnalysisExportMarkdown = (analysisData) => {
        const d = analysisData || {};
        let md = '# PCAP Analysis Report\n\n';
        md += `Generated at: ${new Date().toLocaleString()}\n\n`;

        md += '## Summary\n';
        getSummaryRows(d).forEach(([key, value]) => {
            md += `- **${key}:** ${value}\n`;
        });

        md += '\n## Top Network Flows\n';
        md += '| Flow | Packets | Bytes |\n|---|---:|---:|\n';
        if (Array.isArray(d.top_flows) && d.top_flows.length > 0) {
            d.top_flows.forEach(flow => {
                md += `| ${flow.flow ?? '-'} | ${flow.packets ?? '-'} | ${formatBytesAsKb(flow.bytes)} |\n`;
            });
        } else {
            md += '| No flow data. | - | - |\n';
        }

        md += '\n## Suspicious Flows\n';
        md += '| Flow | Risk | Evidence | Metadata |\n|---|---:|---|---|\n';
        if (Array.isArray(d.suspicious_flows) && d.suspicious_flows.length > 0) {
            d.suspicious_flows.forEach(flow => {
                md += `| ${flow.flow ?? '-'} | ${flow.risk_score ?? '-'} | ${toInlineText(flow.evidence)} | ${flow.metadata ?? '-'} |\n`;
            });
        } else {
            md += '| No suspicious flows detected. | - | - | - |\n';
        }

        md += '\n## DNS Anomalies\n';
        md += '| Domain | Queries | NXDOMAIN | Evidence |\n|---|---:|---:|---|\n';
        if (Array.isArray(d.dns_anomalies) && d.dns_anomalies.length > 0) {
            d.dns_anomalies.forEach(row => {
                md += `| ${row.domain ?? '-'} | ${row.count ?? '-'} | ${row.nxdomain ?? '-'} | ${toInlineText(row.evidence)} |\n`;
            });
        } else {
            md += '| No DNS data. | - | - | - |\n';
        }

        md += '\n## Clear-text Fields\n';
        md += '| Packet No. | Flow | Field | Value |\n|---:|---|---|---|\n';
        if (Array.isArray(d.cleartext_fields) && d.cleartext_fields.length > 0) {
            d.cleartext_fields.forEach(row => {
                md += `| #${row.packet_no ?? '-'} | ${(row.source ?? '-') + ' -> ' + (row.destination ?? '-')} | ${row.field ?? '-'} | ${row.value ?? '-'} |\n`;
            });
        } else {
            md += '| - | No clear-text fields found. | - | - |\n';
        }

        md += '\n## Timeline\n';
        if (Array.isArray(d.timeline) && d.timeline.length > 0) {
            d.timeline.forEach(item => {
                md += `- ${item}\n`;
            });
        } else {
            md += '- No timeline events.\n';
        }

        return md;
    };

    const buildAnalysisExportCsv = (analysisData) => {
        const d = analysisData || {};
        const lines = [];
        const pushSection = (title) => {
            if (lines.length > 0) lines.push('');
            lines.push(csvEscape(title));
        };

        pushSection('Summary');
        lines.push(toCsvRow('Metric', 'Value'));
        getSummaryRows(d).forEach(([key, value]) => lines.push(toCsvRow(key, value)));

        pushSection('Top Network Flows');
        lines.push(toCsvRow('Flow', 'Packets', 'Bytes'));
        if (Array.isArray(d.top_flows) && d.top_flows.length > 0) {
            d.top_flows.forEach(flow => lines.push(toCsvRow(flow.flow ?? '-', flow.packets ?? '-', formatBytesAsKb(flow.bytes))));
        } else {
            lines.push(toCsvRow('No flow data.', '', ''));
        }

        pushSection('Suspicious Flows');
        lines.push(toCsvRow('Flow', 'Risk', 'Evidence', 'Metadata'));
        if (Array.isArray(d.suspicious_flows) && d.suspicious_flows.length > 0) {
            d.suspicious_flows.forEach(flow => lines.push(toCsvRow(flow.flow ?? '-', flow.risk_score ?? '-', toInlineText(flow.evidence), flow.metadata ?? '-')));
        } else {
            lines.push(toCsvRow('No suspicious flows detected.', '', '', ''));
        }

        pushSection('DNS Anomalies');
        lines.push(toCsvRow('Domain', 'Queries', 'NXDOMAIN', 'Evidence'));
        if (Array.isArray(d.dns_anomalies) && d.dns_anomalies.length > 0) {
            d.dns_anomalies.forEach(row => lines.push(toCsvRow(row.domain ?? '-', row.count ?? '-', row.nxdomain ?? '-', toInlineText(row.evidence))));
        } else {
            lines.push(toCsvRow('No DNS data.', '', '', ''));
        }

        pushSection('Clear-text Fields');
        lines.push(toCsvRow('Packet No.', 'Flow', 'Field', 'Value'));
        if (Array.isArray(d.cleartext_fields) && d.cleartext_fields.length > 0) {
            d.cleartext_fields.forEach(row => lines.push(toCsvRow(`#${row.packet_no ?? '-'}`, `${row.source ?? '-'} -> ${row.destination ?? '-'}`, row.field ?? '-', row.value ?? '-')));
        } else {
            lines.push(toCsvRow('No clear-text fields found.', '', '', ''));
        }

        pushSection('Timeline');
        lines.push(toCsvRow('No.', 'Event'));
        if (Array.isArray(d.timeline) && d.timeline.length > 0) {
            d.timeline.forEach((event, idx) => lines.push(toCsvRow(idx + 1, event)));
        } else {
            lines.push(toCsvRow('-', 'No timeline events.'));
        }

        return lines.join('\r\n');
    };

    const getExportPayload = (format, analysisData) => {
        const normalized = String(format || '').toLowerCase();
        if (normalized === 'json') {
            return { content: buildAnalysisExportJson(analysisData), mimeType: 'application/json;charset=utf-8', extension: 'json' };
        }
        if (normalized === 'csv') {
            return { content: buildAnalysisExportCsv(analysisData), mimeType: 'text/csv;charset=utf-8', extension: 'csv' };
        }
        if (normalized === 'txt' || normalized === 'text') {
            return { content: buildAnalysisExportText(analysisData), mimeType: 'text/plain;charset=utf-8', extension: 'txt' };
        }
        if (normalized === 'md' || normalized === 'markdown') {
            return { content: buildAnalysisExportMarkdown(analysisData), mimeType: 'text/markdown;charset=utf-8', extension: 'md' };
        }
        return { content: buildAnalysisExportHtml(analysisData), mimeType: 'text/html;charset=utf-8', extension: 'html' };
    };

    const downloadAnalysisReport = (format, analysisData) => {
        const payload = getExportPayload(format, analysisData);
        const filename = `analysis-report-${buildExportTimestamp()}.${payload.extension}`;
        const blob = new Blob([payload.content], { type: payload.mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    };

    const normalizeProtocolName = (proto) => {
        const p = String(proto || 'Unknown').trim().toUpperCase();
        return p || 'UNKNOWN';
    };

    resetAnalysisData();

    const updateStatsDisplay = () => {
        document.getElementById('stat-total').textContent = packetStats.total;

        if (!protocolStatsList) return;

        const sortedProtocols = Object.entries(packetStats.byProtocol)
            .filter(([, count]) => count > 0)
            .sort((a, b) => b[1] - a[1]);

        if (sortedProtocols.length === 0) {
            selectedProtocolFilters.clear();
            protocolStatsList.innerHTML = '<span class="text-muted">No protocol data</span>';
            return;
        }

        let prunedFilters = false;
        const availableProtocols = new Set(sortedProtocols.map(([name]) => name));
        for (const selected of Array.from(selectedProtocolFilters)) {
            if (!availableProtocols.has(selected)) {
                selectedProtocolFilters.delete(selected);
                prunedFilters = true;
            }
        }

        protocolStatsList.innerHTML = sortedProtocols.map(([name, count]) => {
            const protoClass = getProtocolClass(name);
            const isActive = selectedProtocolFilters.has(name);
            return `
                <button type="button" class="protocol-stat-chip ${isActive ? 'is-active' : ''}" data-protocol="${escapeHtml(name)}" aria-pressed="${isActive}">
                    <span class="${protoClass}">${escapeHtml(name)}</span>
                    <strong>${count}</strong>
                </button>
            `;
        }).join('');

        if (prunedFilters) {
            currentPage = 1;
            scheduleTableRender(true);
        }
    };

    const resetStats = () => {
        packetStats = { total: 0, byProtocol: {} };
        selectedProtocolFilters.clear();
        updateStatsDisplay();
    };

    const trackPacketStats = (pkt, isAdd) => {
        const protocolName = normalizeProtocolName(pkt.protocol);
        const delta = isAdd ? 1 : -1;
        
        packetStats.total += delta;
        packetStats.byProtocol[protocolName] = (packetStats.byProtocol[protocolName] || 0) + delta;
        if (packetStats.byProtocol[protocolName] <= 0) {
            delete packetStats.byProtocol[protocolName];
        }

        if (packetStats.total < 0) packetStats.total = 0;
    };

    const scheduleTableRender = (immediate = false) => {
        if (immediate) {
            if (renderTimer) {
                clearTimeout(renderTimer);
                renderTimer = null;
            }
            renderTable();
            return;
        }

        if (renderTimer) return;
        renderTimer = setTimeout(() => {
            renderTimer = null;
            renderTable();
        }, RENDER_THROTTLE_MS);
    };

    const scheduleStatsUpdate = (immediate = false) => {
        if (immediate) {
            if (statsTimer) {
                clearTimeout(statsTimer);
                statsTimer = null;
            }
            updateStatsDisplay();
            return;
        }

        if (statsTimer) return;
        statsTimer = setTimeout(() => {
            statsTimer = null;
            updateStatsDisplay();
        }, STATS_THROTTLE_MS);
    };

    const ingestPacket = (pkt) => {
        if (!pkt || typeof pkt.id === 'undefined') return null;

        if (pkt.detail !== undefined) {
            packetDetailsById.set(pkt.id, pkt.detail);
        }

        const summary = {
            id: pkt.id,
            timestamp: pkt.timestamp,
            src: pkt.src,
            sport: pkt.sport,
            dst: pkt.dst,
            dport: pkt.dport,
            protocol: pkt.protocol,
            length: pkt.length,
            info: pkt.info
        };

        allPackets.push(summary);
        packetById.set(summary.id, summary);
        trackPacketStats(summary, true);
        return summary;
    };

    const trimPacketStorage = () => {
        while (allPackets.length > MAX_STORED_PACKETS) {
            const removedPkt = allPackets.shift();
            trackPacketStats(removedPkt, false);
            packetById.delete(removedPkt.id);
            packetDetailsById.delete(removedPkt.id);
        }

        const maxPage = Math.ceil(allPackets.length / itemsPerPage) || 1;
        if (currentPage > maxPage) currentPage = maxPage;
    };

    // Format helpers
    const formatTime = (timestamp) => {
        const date = new Date(timestamp * 1000);
        return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}.${date.getMilliseconds().toString().padStart(3, '0')}`;
    };

    const getProtocolClass = (proto) => {
        const p = String(proto || '').toLowerCase();
        if (p === 'tcp') return 'proto-tcp';
        if (p === 'udp') return 'proto-udp';
        if (p === 'ip') return 'proto-ip';
        if (p === 'ethernet') return 'proto-ethernet';
        if (p === 'http') return 'proto-http';
        if (p === 'https') return 'proto-https';
        if (p === 'icmp') return 'proto-icmp';
        if (p === 'ftp') return 'proto-ftp';
        if (p === 'dns') return 'proto-dns';
        if (p === 'tls') return 'proto-tls';
        return '';
    };

    const comparePackets = (a, b, key, direction) => {
        let result = 0;

        if (key === 'id' || key === 'timestamp' || key === 'length') {
            result = (Number(a[key]) || 0) - (Number(b[key]) || 0);
        } else {
            result = String(a[key] || '').localeCompare(String(b[key] || ''), undefined, {
                numeric: true,
                sensitivity: 'base'
            });
        }

        return direction === 'asc' ? result : -result;
    };

    const parseSortNumber = (value) => {
        const normalized = String(value || '').replace(/,/g, '').trim();
        const matched = normalized.match(/-?\d+(\.\d+)?/);
        if (!matched) return null;

        const parsed = Number.parseFloat(matched[0]);
        return Number.isNaN(parsed) ? null : parsed;
    };

    const updateHeaderSortDirection = (headers, activeIndex, direction) => {
        headers.forEach((header, index) => {
            if (!header.classList.contains('sortable-header')) return;
            header.dataset.sort = index === activeIndex ? direction : 'none';
        });
    };

    const initPacketTableSort = () => {
        const packetSortMap = ['id', 'timestamp', 'src', 'dst', 'protocol', 'length', 'info'];
        const packetHeaders = Array.from(document.querySelectorAll('#packet-table thead th'));

        packetHeaders.forEach((header, index) => {
            const sortKey = packetSortMap[index];
            if (!sortKey) return;

            header.classList.add('sortable-header');
            header.dataset.sort = 'none';

            header.addEventListener('click', () => {
                if (packetSort.key === sortKey) {
                    packetSort.direction = packetSort.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    packetSort = { key: sortKey, direction: 'asc' };
                }

                currentPage = 1;
                updateHeaderSortDirection(packetHeaders, index, packetSort.direction);
                renderTable();
            });
        });
    };

    const initAnalysisTableSort = (tableId, numericColumns = []) => {
        const table = document.getElementById(tableId);
        if (!table) return;

        const headers = Array.from(table.querySelectorAll('thead th'));
        headers.forEach((header, index) => {
            if (header.dataset.noSort === 'true') return;

            header.classList.add('sortable-header');
            header.dataset.sort = 'none';

            header.addEventListener('click', () => {
                const tbody = table.querySelector('tbody');
                if (!tbody) return;

                const rows = Array.from(tbody.querySelectorAll('tr'));
                const dataRows = rows.filter(row => !(row.children.length === 1 && row.children[0].hasAttribute('colspan')));
                if (dataRows.length <= 1) return;

                const nextDirection = header.dataset.sort === 'asc' ? 'desc' : 'asc';
                dataRows.sort((rowA, rowB) => {
                    const valueA = (rowA.children[index]?.textContent || '').trim();
                    const valueB = (rowB.children[index]?.textContent || '').trim();

                    let comparison = 0;
                    if (numericColumns.includes(index)) {
                        const numA = parseSortNumber(valueA) || 0;
                        const numB = parseSortNumber(valueB) || 0;
                        comparison = numA - numB;
                    } else {
                        comparison = valueA.localeCompare(valueB, undefined, {
                            numeric: true,
                            sensitivity: 'base'
                        });
                    }

                    return nextDirection === 'asc' ? comparison : -comparison;
                });

                tbody.append(...dataRows);
                updateHeaderSortDirection(headers, index, nextDirection);
            });
        });
    };

    // Initialize
    const init = async () => {
        try {
            const res = await fetch('/api/interfaces');
            const data = await res.json();
            
            interfaceSelect.innerHTML = '';
            if (data.interfaces && data.interfaces.length > 0) {
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.id;
                    option.textContent = iface.label;
                    interfaceSelect.appendChild(option);
                });
                btnStart.disabled = false;
            } else {
                interfaceSelect.innerHTML = '<option value="">No interfaces found</option>';
            }
        } catch (err) {
            console.error('Failed to load interfaces:', err);
            interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
        }

        checkEmptyState(0);
    };

    const checkEmptyState = (count) => {
        if (count === 0) {
            emptyState.classList.add('visible');
        } else {
            emptyState.classList.remove('visible');
        }
    };

    const connectWebSocket = () => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${protocol}//${window.location.host}/ws/packets`);
        
        ws.onopen = () => {
            console.log('WebSocket connected');
        };

        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === 'packet') {
                handleNewPacket(msg.data);
            } else if (msg.type === 'packet_batch') {
                handlePacketBatch(msg.data);
            } else if (msg.type === 'error') {
                console.error('Server error:', msg.message);
                alert(`Capture Error: ${msg.message}`);
                stopCaptureUI();
            } else if (msg.type === 'status' && msg.message === 'Playback finished') {
                stopCaptureUI();
                scheduleTableRender(true);
                scheduleStatsUpdate(true);
            }
        };

        ws.onclose = () => {
            console.log('WebSocket disconnected');
            if (isCapturing) {
                // Try to reconnect if we think we are still capturing
                setTimeout(connectWebSocket, 1000);
            }
        };
    };

    const handleNewPacket = (pkt) => {
        const ingested = ingestPacket(pkt);
        if (!ingested) return;

        trimPacketStorage();

        totalPacketsSpan.textContent = allPackets.length;
        const totalPages = Math.ceil(allPackets.length / itemsPerPage) || 1;
        const shouldImmediateRender = allPackets.length <= 10 || currentPage === totalPages;
        scheduleTableRender(shouldImmediateRender);
        scheduleStatsUpdate(shouldImmediateRender);
    };

    const handlePacketBatch = (packets) => {
        if (!Array.isArray(packets) || packets.length === 0) return;

        packets.forEach(pkt => {
            ingestPacket(pkt);
        });

        trimPacketStorage();
        totalPacketsSpan.textContent = allPackets.length;
        scheduleTableRender();
        scheduleStatsUpdate();
    };

    const renderTable = () => {
        packetList.innerHTML = '';

        const filterText = displayFilterInput.value.toLowerCase().trim();
        let filteredPackets = allPackets;
        const hasProtocolFilter = selectedProtocolFilters.size > 0;

        if (hasProtocolFilter) {
            filteredPackets = filteredPackets.filter(pkt => selectedProtocolFilters.has(normalizeProtocolName(pkt.protocol)));
        }

        if (filterText) {
            filteredPackets = filteredPackets.filter(pkt => {
                const lowerFilter = filterText; // Already lowered
                
                // Simple search fallback if no operators
                if (!lowerFilter.includes('==') && !lowerFilter.includes('!=') && !lowerFilter.includes('contains') && !lowerFilter.includes('>') && !lowerFilter.includes('<')) {
                    return (pkt.src && pkt.src.toLowerCase().includes(lowerFilter)) ||
                           (pkt.dst && pkt.dst.toLowerCase().includes(lowerFilter)) ||
                           (pkt.protocol && pkt.protocol.toLowerCase().includes(lowerFilter)) ||
                           (pkt.info && pkt.info.toLowerCase().includes(lowerFilter));
                }

                try {
                    const conditions = lowerFilter.split('&&').map(s => s.trim());
                    for (let cond of conditions) {
                        let matched = false;
                        if (cond.includes('==')) {
                            let parts = cond.split('==').map(s => s.trim());
                            let key = parts[0];
                            let val = parts[1].replace(/"/g, '').replace(/'/g, '');
                            
                            if (key === 'ip.src') matched = (pkt.src && pkt.src.toLowerCase() === val);
                            else if (key === 'ip.dst') matched = (pkt.dst && pkt.dst.toLowerCase() === val);
                            else if (key === 'ip.addr') matched = (pkt.src && pkt.src.toLowerCase() === val) || (pkt.dst && pkt.dst.toLowerCase() === val);
                            else if (key === 'tcp.port' || key === 'udp.port') matched = (pkt.sport == val) || (pkt.dport == val);
                            else if (key === 'protocol') matched = (pkt.protocol && pkt.protocol.toLowerCase() === val);
                            else if (key === 'frame.number' || key === 'frame.no' || key === 'packet.id' || key === 'packet.no' || key === 'no') matched = Number(pkt.id) === Number(val);
                            else if (key === 'http.request.method') matched = (pkt.info && pkt.info.toLowerCase().includes(val.toLowerCase()));
                        } else if (cond.includes('!=')) {
                            let parts = cond.split('!=').map(s => s.trim());
                            let key = parts[0];
                            let val = parts[1].replace(/"/g, '').replace(/'/g, '');
                            
                            if (key === 'ip.src') matched = (pkt.src && pkt.src.toLowerCase() !== val);
                            else if (key === 'ip.dst') matched = (pkt.dst && pkt.dst.toLowerCase() !== val);
                            else if (key === 'ip.addr') matched = (pkt.src && pkt.src.toLowerCase() !== val) && (pkt.dst && pkt.dst.toLowerCase() !== val);
                            else if (key === 'tcp.port' || key === 'udp.port') matched = (pkt.sport != val) && (pkt.dport != val);
                            else if (key === 'protocol') matched = (pkt.protocol && pkt.protocol.toLowerCase() !== val);
                            else if (key === 'frame.number' || key === 'frame.no' || key === 'packet.id' || key === 'packet.no' || key === 'no') matched = Number(pkt.id) !== Number(val);
                            else if (key === 'http.request.method') matched = !(pkt.info && pkt.info.toLowerCase().includes(val.toLowerCase()));
                        } else if (cond.includes('contains')) {
                            let parts = cond.split('contains').map(s => s.trim());
                            let key = parts[0];
                            let val = parts[1].replace(/"/g, '').replace(/'/g, '').toLowerCase();
                            
                            if (key === 'dns.qry.name') matched = (pkt.info && pkt.info.toLowerCase().includes(val));
                            else if (key === 'http.content_type') matched = (pkt.info && (pkt.info.toLowerCase().includes(val) || pkt.info.toLowerCase().includes('png') || pkt.info.toLowerCase().includes('jpg') || pkt.info.toLowerCase().includes('gif') || pkt.info.toLowerCase().includes('webp')));
                            else {
                                const searchable = `${pkt.src || ''} ${pkt.dst || ''} ${pkt.protocol || ''} ${pkt.info || ''}`.toLowerCase();
                                matched = searchable.includes(val);
                            }
                        } else if (cond === 'tcp.analysis.flags' || cond.includes('tcp.analysis')) {
                            matched = (pkt.info && (pkt.info.toLowerCase().includes('retransmission') || pkt.info.toLowerCase().includes('dup ack') || pkt.info.toLowerCase().includes('out-of-order') || pkt.info.toLowerCase().includes('spurious')));
                        } else if (cond.includes('>=') || cond.includes('<=') || cond.includes('>') || cond.includes('<')) {
                            let op = cond.includes('>=') ? '>=' : (cond.includes('<=') ? '<=' : (cond.includes('>') ? '>' : '<'));
                            let parts = cond.split(op).map(s => s.trim());
                            let key = parts[0];
                            let val = Number(parts[1]);
                            
                            let fieldVal = 0;
                            if (key === 'frame.len' || key === 'frame.length' || key === 'length' || key === 'len') {
                                fieldVal = Number(pkt.length || 0);
                                if (op === '>') matched = fieldVal > val;
                                else if (op === '<') matched = fieldVal < val;
                                else if (op === '>=') matched = fieldVal >= val;
                                else if (op === '<=') matched = fieldVal <= val;
                            } else if (key === 'tcp.len') {
                                if (pkt.protocol && pkt.protocol.toLowerCase() === 'tcp') {
                                    fieldVal = Number(pkt.length || 0) - 54; // Approximation of TCP payload length
                                    if (fieldVal < 0) fieldVal = 0;
                                    if (op === '>') matched = fieldVal > val;
                                    else if (op === '<') matched = fieldVal < val;
                                    else if (op === '>=') matched = fieldVal >= val;
                                    else if (op === '<=') matched = fieldVal <= val;
                                }
                            }
                        }
                        
                        if (!matched) return false;
                    }
                    return true;
                } catch (e) {
                    return false;
                }
            });
        }

        const hasAnyFilter = Boolean(filterText) || hasProtocolFilter;

        if (packetSort.key) {
            filteredPackets = [...filteredPackets].sort((a, b) => comparePackets(a, b, packetSort.key, packetSort.direction));
        }

        if (filteredPackets.length === 0) {
            pageStartSpan.textContent = 0;
            pageEndSpan.textContent = 0;
            totalPacketsSpan.textContent = hasAnyFilter ? `0 (filtered out of ${allPackets.length})` : 0;
            pageNumberSpan.textContent = `Page 1`;
            btnPrev.disabled = true;
            btnNext.disabled = true;
            checkEmptyState(allPackets.length === 0 ? 0 : 1);
            return;
        }

        checkEmptyState(filteredPackets.length);

        const totalPages = Math.ceil(filteredPackets.length / itemsPerPage);
        if (currentPage > totalPages) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;

        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, filteredPackets.length);

        // Update pagination UI
        pageStartSpan.textContent = startIndex + 1;
        pageEndSpan.textContent = endIndex;
        totalPacketsSpan.textContent = hasAnyFilter ? `${filteredPackets.length} (filtered out of ${allPackets.length})` : allPackets.length;
        pageNumberSpan.textContent = `Page ${currentPage} of ${totalPages}`;

        btnPrev.disabled = currentPage === 1;
        btnNext.disabled = currentPage === totalPages;

        // Render rows
        const fragment = document.createDocumentFragment();
        for (let i = startIndex; i < endIndex; i++) {
            const pkt = filteredPackets[i];
            const tr = document.createElement('tr');
            tr.dataset.id = pkt.id;
            
            // If this is the currently selected packet, re-highlight it
            if (selectedPacketIdSpan.textContent === `#${pkt.id}`) {
                tr.classList.add('selected');
                selectedPacketRow = tr;
            }
            
            if (pkt.info && pkt.info.includes('[ALERT]')) {
                tr.classList.add('expert-error');
            } else if (pkt.info && (pkt.info.includes('[TCP Retransmission]') || pkt.info.includes('[TCP Dup ACK]') || pkt.info.includes('[TCP RST]') || pkt.info.includes('[NXDOMAIN]'))) {
                tr.classList.add('expert-warning');
            }
            
            tr.innerHTML = `
                <td>${pkt.id}</td>
                <td>${formatTime(pkt.timestamp)}</td>
                <td>${pkt.src}</td>
                <td>${pkt.dst}</td>
                <td class="${getProtocolClass(pkt.protocol)}">${pkt.protocol}</td>
                <td>${pkt.length}</td>
                <td>${pkt.info}</td>
            `;

            tr.addEventListener('click', () => selectPacket(tr, pkt.id));
            fragment.appendChild(tr);
        }
        
        packetList.appendChild(fragment);
    };

    const selectPacket = async (rowElement, id) => {
        if (selectedPacketRow) {
            selectedPacketRow.classList.remove('selected');
        }
        selectedPacketRow = rowElement;
        selectedPacketRow.classList.add('selected');
        selectedPacketIdSpan.textContent = `#${id}`;
        
        const btnFollowStream = document.getElementById('btn-follow-stream');
        const pkt = packetById.get(id) || allPackets.find(p => p.id === id);
        if (pkt && pkt.protocol === 'TCP') {
            btnFollowStream.style.display = 'inline-block';
            btnFollowStream.dataset.src = pkt.src;
            btnFollowStream.dataset.sport = pkt.sport;
            btnFollowStream.dataset.dst = pkt.dst;
            btnFollowStream.dataset.dport = pkt.dport;
        } else {
            btnFollowStream.style.display = 'none';
        }

        const detail = packetDetailsById.get(id);
        if (detail) {
            renderPacketDetails(detail);
            return;
        }

        detailsContent.innerHTML = '<div class="empty-selection"><p>No detailed data available for this packet.</p></div>';
    };

    const renderPacketDetails = (layers) => {
        detailsContent.innerHTML = '';
        if (!layers || layers.length === 0) {
            detailsContent.innerHTML = '<div class="empty-selection"><p>No detailed data available.</p></div>';
            return;
        }

        layers.forEach((layer, index) => {
            const section = document.createElement('div');
            section.className = 'layer-section';
            if (index === 0 || index === 1) section.classList.add('expanded'); // Auto-expand first few layers

            const header = document.createElement('div');
            header.className = 'layer-header';
            header.innerHTML = `<span class="layer-caret">▶</span> ${layer.layer}`;
            header.addEventListener('click', () => {
                section.classList.toggle('expanded');
            });

            const fieldsContainer = document.createElement('div');
            fieldsContainer.className = 'layer-fields';

            Object.entries(layer.fields).forEach(([key, value]) => {
                const row = document.createElement('div');
                row.className = 'field-row';
                row.innerHTML = `<span class="field-key">${key}:</span><span class="field-value">${value}</span>`;
                fieldsContainer.appendChild(row);
            });

            section.appendChild(header);
            section.appendChild(fieldsContainer);
            detailsContent.appendChild(section);
        });
    };

    const startCapture = async () => {
        const iface = interfaceSelect.value;
        if (!iface) return;

        try {
            const bodyData = { 
                interface: iface
            };

            const res = await fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyData)
            });
            
            const data = await res.json();
            if (data.status === 'started' || data.status === 'already capturing') {
                isCapturing = true;
                btnStart.disabled = true;
                btnStop.disabled = false;
                interfaceSelect.disabled = true;
                statusIndicator.classList.add('capturing');
                
                // Clear list on new capture
                allPackets = [];
                packetById.clear();
                packetDetailsById.clear();
                resetAnalysisData();
                resetStats();
                currentPage = 1;
                renderTable();
                
                detailsContent.innerHTML = '<div class="empty-selection"><p>Select a packet from the list to view detailed layers.</p></div>';
                selectedPacketIdSpan.textContent = 'None Selected';
                checkEmptyState();
                
                if (!ws || ws.readyState !== WebSocket.OPEN) {
                    connectWebSocket();
                }
            } else {
                alert(`Error starting capture: ${JSON.stringify(data)}`);
            }
        } catch (err) {
            console.error(err);
            alert('Error connecting to server');
        }
    };

    const stopCapture = async () => {
        try {
            await fetch('/api/capture/stop', { method: 'POST' });
            stopCaptureUI();
        } catch (err) {
            console.error(err);
            alert('Error connecting to server to stop capture');
            // Force UI stop anyway
            stopCaptureUI();
        }
    };

    const stopCaptureUI = () => {
        isCapturing = false;
        btnStart.disabled = false;
        btnStop.disabled = true;
        btnUpload.disabled = false;
        interfaceSelect.disabled = false;
        statusIndicator.classList.remove('capturing');
    };

    // Event Listeners
    btnStart.addEventListener('click', startCapture);
    btnStop.addEventListener('click', stopCapture);
    btnClear.addEventListener('click', () => {
        allPackets = [];
        packetById.clear();
        packetDetailsById.clear();
        resetAnalysisData();
        resetStats();
        currentPage = 1;
        renderTable();
        detailsContent.innerHTML = '<div class="empty-selection"><p>Select a packet from the list to view detailed layers.</p></div>';
        selectedPacketIdSpan.textContent = 'None Selected';
        selectedPacketRow = null;
    });

    // Premium custom glassmorphic toast notification
    const showToast = (message, title = 'NetScope AI', bg = '#a855f7') => {
        let toastContainer = document.getElementById('netscope-toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'netscope-toast-container';
            toastContainer.style.position = 'fixed';
            toastContainer.style.bottom = '20px';
            toastContainer.style.right = '20px';
            toastContainer.style.zIndex = '99999';
            toastContainer.style.display = 'flex';
            toastContainer.style.flexDirection = 'column';
            toastContainer.style.gap = '10px';
            document.body.appendChild(toastContainer);
        }

        const toast = document.createElement('div');
        toast.className = 'glass-panel';
        toast.style.background = 'rgba(16, 26, 46, 0.9)';
        toast.style.border = `1px solid ${bg}`;
        toast.style.borderRadius = '8px';
        toast.style.padding = '12px 16px';
        toast.style.boxShadow = '0 8px 32px 0 rgba(0, 0, 0, 0.5)';
        toast.style.backdropFilter = 'blur(8px)';
        toast.style.color = '#e2e8f0';
        toast.style.minWidth = '300px';
        toast.style.maxWidth = '420px';
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        toast.style.transition = 'all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)';

        toast.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="color: ${bg}; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">${title}</strong>
                <span style="font-size: 0.75rem; color: var(--text-muted); cursor: pointer;" onclick="this.parentElement.parentElement.remove()">✕</span>
            </div>
            <p style="margin: 0; font-size: 0.8rem; line-height: 1.4; color: #cbd5e1;">${message}</p>
        `;

        toastContainer.appendChild(toast);

        // Animate in
        setTimeout(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        }, 50);

        // Animate out
        setTimeout(() => {
            if (toast.parentElement) {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(-20px)';
                setTimeout(() => toast.remove(), 400);
            }
        }, 6000);
    };

    // -----------------------------------------------------------------------
    // AI / Natural Language Filter
    // -----------------------------------------------------------------------
    const btnAiFilter = document.getElementById('btn-ai-filter');
    const AI_PLACEHOLDER_DEFAULT = 'Nhập bộ lọc Wireshark hoặc mô tả bằng ngôn ngữ tự nhiên...';

    /** Source metadata for toast badges */
    const SOURCE_META = {
        local:          { label: '⚡ Local Rule',          color: '#10b981' },
        ai:             { label: '✨ AI Gemini',            color: '#a855f7' },
        fallback:       { label: '🔍 Heuristic',            color: '#f59e0b' },
        quota_exceeded: { label: '⚠️ AI Hết Quota',        color: '#ef4444' },
    };

    if (btnAiFilter) {
        btnAiFilter.addEventListener('click', async () => {
            let query = displayFilterInput.value.trim();

            // Cảnh báo nếu ô trống
            if (!query) {
                displayFilterInput.placeholder = '⚠️ Nhập mô tả bằng tiếng Việt hoặc tiếng Anh!';
                displayFilterInput.focus();
                setTimeout(() => { displayFilterInput.placeholder = AI_PLACEHOLDER_DEFAULT; }, 3000);
                return;
            }

            // Bóc tách filter fallback dạng contains "..." để tránh dịch lồng nhau
            const containsMatch = query.match(/^contains\s+"([^"]+)"$/i);
            if (containsMatch) query = containsMatch[1];

            // Loading state
            const originalHTML = btnAiFilter.innerHTML;
            btnAiFilter.innerHTML = '✨ Đang dịch…';
            btnAiFilter.disabled = true;
            btnAiFilter.style.opacity = '0.65';

            try {
                const res = await fetch('/api/translate-filter', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query }),
                });

                const data = await res.json();

                if (data && data.success && data.filter) {
                    displayFilterInput.value = data.filter;
                    currentPage = 1;
                    renderTable();

                    let meta;
                    if (data.source === 'local') {
                        meta = SOURCE_META.local;
                    } else if (data.source === 'ai') {
                        // Hiển thị tên provider thực tế (Gemini, OpenAI, v.v.)
                        const providerName = data.provider || 'AI';
                        meta = { label: `✨ ${providerName}`, color: '#a855f7' };
                    } else if (data.source === 'quota_exceeded') {
                        meta = SOURCE_META.quota_exceeded;
                    } else {
                        meta = SOURCE_META.fallback;
                    }
                    showToast(data.explanation || data.filter, meta.label, meta.color);
                } else {
                    const errMsg = data.error || 'Không dịch được query này.';
                    showToast(errMsg, 'Lỗi ❌', '#ef4444');
                }
            } catch (err) {
                console.error('[AI Filter]', err);
                showToast('Không kết nối được server.', 'Lỗi ❌', '#ef4444');
            } finally {
                btnAiFilter.innerHTML = originalHTML;
                btnAiFilter.disabled = false;
                btnAiFilter.style.opacity = '1';
            }
        });

        // Enter → lọc thường | Ctrl+Enter → lọc AI
        displayFilterInput.addEventListener('keydown', (e) => {
            if (e.key !== 'Enter') return;
            e.preventDefault();
            if (e.ctrlKey) {
                btnAiFilter.click();
            } else {
                const btnFilter = document.getElementById('btn-filter');
                if (btnFilter) btnFilter.click();
            }
        });
    }

    const btnFilter = document.getElementById('btn-filter');
    if (btnFilter) {
        btnFilter.addEventListener('click', () => {
            currentPage = 1;
            renderTable();
        });
    }

    if (protocolStatsList) {
        protocolStatsList.addEventListener('click', (event) => {
            const chip = event.target.closest('.protocol-stat-chip');
            if (!chip || !chip.dataset.protocol) return;

            const selectedProtocol = normalizeProtocolName(chip.dataset.protocol);
            if (selectedProtocolFilters.has(selectedProtocol)) {
                selectedProtocolFilters.delete(selectedProtocol);
            } else {
                selectedProtocolFilters.add(selectedProtocol);
            }

            currentPage = 1;
            updateStatsDisplay();
            renderTable();
        });
    }

    btnUpload.addEventListener('click', () => {
        pcapUpload.click();
    });

    pcapUpload.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        btnStart.disabled = true;
        btnUpload.disabled = true;
        btnUpload.textContent = "Uploading...";
        resetAnalysisData();

        try {
            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (res.ok) {
                // Prepare UI for playback
                isCapturing = true;
                btnStop.disabled = false;
                interfaceSelect.disabled = true;
                statusIndicator.classList.add('capturing');
                
                allPackets = [];
                packetById.clear();
                packetDetailsById.clear();
                resetAnalysisData();
                resetStats();
                currentPage = 1;
                renderTable();
                
                if (!ws || ws.readyState !== WebSocket.OPEN) {
                    connectWebSocket();
                }
            } else {
                alert(`Upload failed: ${data.detail || data.message}`);
                stopCaptureUI();
            }
        } catch (err) {
            console.error(err);
            alert('Error uploading file');
            stopCaptureUI();
        } finally {
            btnUpload.textContent = "Open PCAP";
            pcapUpload.value = ''; // Reset input
        }
    });

    btnPrev.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderTable();
        }
    });

    btnNext.addEventListener('click', () => {
        const totalPages = Math.ceil(allPackets.length / itemsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            renderTable();
        }
    });

    itemsPerPageSelect.addEventListener('change', (e) => {
        itemsPerPage = parseInt(e.target.value, 10);
        currentPage = 1; // Reset to page 1 on change
        renderTable();
    });

    // Tabs Logic
    const captureView = document.getElementById('capture-view');
    const overviewView = document.getElementById('overview-view');
    const securityView = document.getElementById('security-view');
    const dnsView = document.getElementById('dns-view');
    const timelineView = document.getElementById('timeline-view');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const target = btn.dataset.target;
            captureView.style.display = 'none';
            overviewView.style.display = 'none';
            securityView.style.display = 'none';
            dnsView.style.display = 'none';
            timelineView.style.display = 'none';

            if (target === 'capture-view') {
                captureView.style.display = 'grid';
            } else {
                const el = document.getElementById(target);
                if(el) el.style.display = 'flex';
            }
        });
    });

    // Analysis Logic
    const suspiciousList = document.getElementById('suspicious-list');
    const dnsList = document.getElementById('dns-list');
    const btnGlobalAnalysis = document.getElementById('btn-global-analysis');
    let ioChartInstance = null;

    if (btnExportAnalysis) {
        btnExportAnalysis.addEventListener('click', (event) => {
            event.stopPropagation();
            if (btnExportAnalysis.disabled) return;

            const isOpen = exportMenu ? exportMenu.classList.contains('open') : false;
            setExportMenuOpen(!isOpen);
        });
    }

    if (exportMenu) {
        exportMenu.addEventListener('click', (event) => {
            const optionBtn = event.target.closest('.export-option');
            if (!optionBtn) return;

            const format = optionBtn.dataset.format || 'html';
            if (!window.lastAnalysisData) {
                alert("Please run analysis first.");
                setExportMenuOpen(false);
                return;
            }

            downloadAnalysisReport(format, window.lastAnalysisData);
            setExportMenuOpen(false);
        });
    }

    document.addEventListener('click', (event) => {
        if (!exportMenu || !btnExportAnalysis) return;
        if (!exportMenu.classList.contains('open')) return;
        if (exportMenu.contains(event.target) || btnExportAnalysis.contains(event.target)) return;
        setExportMenuOpen(false);
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            setExportMenuOpen(false);
        }
    });

    if (btnGlobalAnalysis) {
        btnGlobalAnalysis.addEventListener('click', async () => {
            btnGlobalAnalysis.disabled = true;
            btnGlobalAnalysis.textContent = "Analyzing...";
            setAnalysisExportState(false);
            if(flowsList) flowsList.innerHTML = '<tr><td colspan="3" class="text-center">Loading...</td></tr>';
            if(credsList) credsList.innerHTML = '<tr><td colspan="5" class="text-center">Loading...</td></tr>';
            if(suspiciousList) suspiciousList.innerHTML = '<tr><td colspan="5" class="text-center">Loading...</td></tr>';
            if(dnsList) dnsList.innerHTML = '<tr><td colspan="4" class="text-center">Loading...</td></tr>';

            try {
                const res = await fetch('/api/analyze');
                const data = await res.json();

                if (data.error) {
                    if(flowsList) flowsList.innerHTML = `<tr><td colspan="3" class="text-center text-danger">${data.error}</td></tr>`;
                    return;
                }

                // Render Summary
                if (data.summary) {
                    const sum = data.summary;
                    document.getElementById('sum-duration').textContent = sum.duration || '-';
                    document.getElementById('sum-packets').textContent = sum.total_packets || '-';
                    document.getElementById('sum-hosts').textContent = sum.hosts_observed || '-';
                    document.getElementById('sum-external').textContent = sum.external_dests || '-';
                    document.getElementById('sum-longflows').textContent = sum.long_lived_flows || '-';
                    document.getElementById('sum-resets').textContent = sum.tcp_resets || '-';
                    document.getElementById('sum-nxdomain').textContent = sum.dns_nxdomain || '-';
                    document.getElementById('sum-suspicious-dns').textContent = sum.suspicious_names || '-';
                    document.getElementById('sum-protocols').textContent = sum.top_protocols || '-';
                    document.getElementById('sum-talkers').textContent = sum.top_talkers || '-';
                }

                // Render Top Flows
                if (flowsList) {
                    if (data.top_flows && data.top_flows.length > 0) {
                        flowsList.innerHTML = data.top_flows.map(f => `
                            <tr>
                                <td>${f.flow}</td>
                                <td>${f.packets}</td>
                                <td>${(f.bytes / 1024).toFixed(2)} KB</td>
                            </tr>
                        `).join('');
                    } else {
                        flowsList.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No flows detected.</td></tr>';
                    }
                }

                window.lastAnalysisData = data;
                setAnalysisExportState(true);

                // Render Suspicious Flows
                if (suspiciousList) {
                    if (data.suspicious_flows && data.suspicious_flows.length > 0) {
                        suspiciousList.innerHTML = data.suspicious_flows.map(f => `
                            <tr class="${f.risk_score >= 5 ? 'expert-error' : 'expert-warning'}">
                                <td>${f.flow}</td>
                                <td><span class="badge ${f.risk_score >= 5 ? 'badge-danger' : 'badge-warning'}">Risk: ${f.risk_score}</span></td>
                                <td>${f.evidence.join('<br>')}</td>
                                <td><small class="text-muted">${f.metadata}</small></td>
                                <td>
                                    <button class="btn copy-filter-btn" style="padding: 0.2rem 0.5rem; font-size: 0.8rem; background: var(--primary);" data-filter="${(f.wireshark_filter || '').replace(/"/g, '&quot;')}">Copy Filter</button>
                                    <button class="btn download-evidence-btn" style="padding: 0.2rem 0.5rem; font-size: 0.8rem; background: var(--success);" data-pkts="${(f.packet_nos || []).join(',')}">📥 PCAP</button>
                                </td>
                            </tr>
                        `).join('');
                    } else {
                        suspiciousList.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No suspicious flows detected.</td></tr>';
                    }
                }

                // Render DNS Anomalies
                if (dnsList) {
                    if (data.dns_anomalies && data.dns_anomalies.length > 0) {
                        dnsList.innerHTML = data.dns_anomalies.map(d => `
                            <tr class="${d.is_anomaly ? 'expert-warning' : ''}">
                                <td>${d.domain}</td>
                                <td>${d.count}</td>
                                <td>${d.nxdomain}</td>
                                <td><span class="${d.is_anomaly ? 'text-danger' : 'text-muted'}">${d.evidence.length > 0 ? d.evidence.join(', ') : '-'}</span></td>
                                <td>
                                    <button class="btn copy-filter-btn" style="padding: 0.2rem 0.5rem; font-size: 0.8rem; background: var(--primary);" data-filter="${(d.wireshark_filter || '').replace(/"/g, '&quot;')}">Copy Filter</button>
                                </td>
                            </tr>
                        `).join('');
                    } else {
                        dnsList.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No DNS queries found.</td></tr>';
                    }
                }

                // Render Credentials
                if (credsList) {
                    const clearTextRows = data.cleartext_fields || data.credentials || [];
                    if (clearTextRows.length > 0) {
                        credsList.innerHTML = clearTextRows.map(c => {
                            const packetNo = Number(c.packet_no);
                            const packetFilter = Number.isFinite(packetNo) ? `frame.number == ${packetNo}` : '';
                            const isDisabled = packetFilter ? '' : 'disabled';

                            return `
                            <tr>
                                <td>#${escapeHtml(c.packet_no ?? '-')}</td>
                                <td>${escapeHtml(c.source)} &rarr; ${escapeHtml(c.destination)}</td>
                                <td class="text-danger">${escapeHtml(c.field)}</td>
                                <td class="text-danger" style="font-weight:bold;">${escapeHtml(c.value)}</td>
                                <td>
                                    <button class="btn copy-filter-btn" style="padding: 0.2rem 0.5rem; font-size: 0.8rem; background: var(--primary);" data-filter="${escapeHtml(packetFilter)}" ${isDisabled}>Copy Packet Filter</button>
                                </td>
                            </tr>
                            `;
                        }).join('');
                    } else {
                        credsList.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No important clear-text fields found.</td></tr>';
                    }
                }
                // Render Timeline
                const timelineList = document.getElementById('timeline-list');
                if (timelineList && data.timeline) {
                    if (data.timeline.length > 0) {
                        timelineList.innerHTML = data.timeline.map(t => `<div style="margin-bottom: 0.5rem; border-left: 2px solid var(--primary); padding-left: 0.5rem;">${t}</div>`).join('');
                    } else {
                        timelineList.innerHTML = '<div class="text-center text-muted" style="margin-top: 100px;">No timeline events found.</div>';
                    }
                }

                // Render Chart
                if (data.io_graph && data.io_graph.length > 0) {
                const ctx = document.getElementById('io-chart').getContext('2d');
                if (ioChartInstance) ioChartInstance.destroy();
                Chart.defaults.color = '#cbd5e1';
                Chart.defaults.font.family = 'Inter';
                
                ioChartInstance = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: data.io_graph.map(d => d.time + 's'),
                        datasets: [{
                            label: 'Bytes/s',
                            data: data.io_graph.map(d => d.bytes),
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            fill: true,
                            yAxisID: 'y',
                            tension: 0.3
                        }, {
                            label: 'Packets/s',
                            data: data.io_graph.map(d => d.packets),
                            borderColor: '#10b981',
                            yAxisID: 'y1',
                            tension: 0.3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: { type: 'linear', display: true, position: 'left', title: {display: true, text: 'Bytes/s'}, grid: {color: 'rgba(255,255,255,0.05)'} },
                            y1: { type: 'linear', display: true, position: 'right', grid: { drawOnChartArea: false }, title: {display: true, text: 'Pkts/s'} }
                        }
                    }
                });
            }

        } catch (err) {
            console.error(err);
            if(flowsList) flowsList.innerHTML = '<tr><td colspan="3" class="text-center text-danger">Failed to fetch analysis data.</td></tr>';
        } finally {
            if (btnGlobalAnalysis) {
                btnGlobalAnalysis.disabled = false;
                btnGlobalAnalysis.textContent = "Run Analysis";
            }
        }
    });
    }

    // Analyst Action Event Delegation
    document.addEventListener('click', async (e) => {
        if (e.target.closest('.copy-filter-btn')) {
            const btn = e.target.closest('.copy-filter-btn');
            const filter = btn.dataset.filter;
            if (filter) {
                await navigator.clipboard.writeText(filter);
                const originalText = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> Copied';
                setTimeout(() => btn.innerHTML = originalText, 2000);
            }
        }
        
        if (e.target.closest('.download-evidence-btn')) {
            const btn = e.target.closest('.download-evidence-btn');
            const pkts = btn.dataset.pkts;
            if (!pkts) return;
            
            const originalText = btn.innerHTML;
            btn.innerHTML = 'Wait...';
            btn.disabled = true;
            
            try {
                const pktArray = pkts.split(',').map(Number);
                const res = await fetch('/api/download_evidence', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({packet_nos: pktArray})
                });
                if (res.ok) {
                    const blob = await res.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = 'evidence.pcap';
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                } else {
                    alert("Failed to download evidence.");
                }
            } catch(err) {
                console.error(err);
                alert("Error downloading evidence.");
            } finally {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        }
    });

    // Incident Brief Modal
    const btnIncidentBrief = document.getElementById('btn-incident-brief');
    const briefModal = document.getElementById('brief-modal');
    const btnCloseBrief = document.getElementById('btn-close-brief');
    const btnCopyBrief = document.getElementById('btn-copy-brief');
    const briefContent = document.getElementById('brief-content');

    if (btnIncidentBrief) {
        btnIncidentBrief.addEventListener('click', () => {
            if (!window.lastAnalysisData) {
                alert("Please run analysis first.");
                return;
            }
            
            const d = window.lastAnalysisData;
            let report = `# Incident Brief: Network Analysis Report\n\n`;
            
            if (d.summary) {
                report += `## Executive Summary\n`;
                report += `- **Duration:** ${d.summary.duration}\n`;
                report += `- **Total Packets:** ${d.summary.total_packets}\n`;
                report += `- **Hosts Observed:** ${d.summary.hosts_observed}\n`;
                report += `- **TCP Resets:** ${d.summary.tcp_resets}\n`;
                report += `- **DNS NXDOMAIN:** ${d.summary.dns_nxdomain}\n\n`;
            }
            
            if (d.suspicious_flows && d.suspicious_flows.length > 0) {
                report += `## Top Suspicious Flows\n`;
                d.suspicious_flows.slice(0, 5).forEach(f => {
                    report += `### Flow: ${f.flow} (Risk: ${f.risk_score})\n`;
                    report += `- **Evidence:** ${f.evidence.join('; ')}\n`;
                    report += `- **Metadata:** ${f.metadata}\n`;
                    report += `- **Wireshark Filter:** \`${f.wireshark_filter}\`\n\n`;
                });
            }
            
            if (d.dns_anomalies && d.dns_anomalies.length > 0) {
                report += `## DNS Anomalies\n`;
                d.dns_anomalies.slice(0, 5).forEach(a => {
                    if (a.is_anomaly) {
                        report += `- **Domain:** ${a.domain} (Queries: ${a.count}, NXDOMAIN: ${a.nxdomain})\n`;
                        report += `  - Evidence: ${a.evidence.join(', ')}\n`;
                        report += `  - Filter: \`${a.wireshark_filter}\`\n`;
                    }
                });
                report += `\n`;
            }
            
            if (briefContent) briefContent.value = report;
            if (briefModal) briefModal.style.display = 'flex';
        });
    }
    
    if (btnCloseBrief) {
        btnCloseBrief.addEventListener('click', () => {
            if (briefModal) briefModal.style.display = 'none';
        });
    }
    
    if (btnCopyBrief) {
        btnCopyBrief.addEventListener('click', async () => {
            await navigator.clipboard.writeText(briefContent.value);
            const orig = btnCopyBrief.textContent;
            btnCopyBrief.textContent = "Copied!";
            setTimeout(() => btnCopyBrief.textContent = orig, 2000);
        });
    }

    // Follow Stream Logic
    const btnFollowStream = document.getElementById('btn-follow-stream');
    const streamModal = document.getElementById('stream-modal');
    const btnCloseStream = document.getElementById('btn-close-stream');
    const streamContent = document.getElementById('stream-content');

    btnCloseStream.addEventListener('click', () => {
        streamModal.style.display = 'none';
    });

    btnFollowStream.addEventListener('click', async () => {
        const src = btnFollowStream.dataset.src;
        const sport = btnFollowStream.dataset.sport;
        const dst = btnFollowStream.dataset.dst;
        const dport = btnFollowStream.dataset.dport;

        btnFollowStream.textContent = "Loading...";
        btnFollowStream.disabled = true;

        try {
            const res = await fetch(`/api/stream?src_ip=${src}&src_port=${sport}&dst_ip=${dst}&dst_port=${dport}`);
            if (res.ok) {
                const data = await res.json();
                streamContent.innerHTML = '';
                if (data.stream && data.stream.length > 0) {
                    data.stream.forEach(chunk => {
                        const span = document.createElement('span');
                        span.textContent = chunk.payload;
                        span.style.color = chunk.direction === 'client_to_server' ? '#fbbf24' : '#60a5fa';
                        streamContent.appendChild(span);
                    });
                } else {
                    streamContent.innerHTML = 'No printable payload found in this stream.';
                }
                streamModal.style.display = 'flex';
            } else {
                alert("Failed to load stream");
            }
        } catch(e) {
            alert("Error loading stream");
        } finally {
            btnFollowStream.textContent = "Follow TCP Stream";
            btnFollowStream.disabled = false;
        }
    });

    // Start
    initPacketTableSort();
    initAnalysisTableSort('flows-table', [1, 2]);
    initAnalysisTableSort('suspicious-table', [1]);
    initAnalysisTableSort('creds-table', [0]);
    initAnalysisTableSort('dns-table', [1, 2]);
    init();
});
