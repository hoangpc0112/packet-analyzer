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

    const normalizeProtocolName = (proto) => {
        const p = String(proto || 'Unknown').trim().toUpperCase();
        return p || 'UNKNOWN';
    };

    const updateStatsDisplay = () => {
        document.getElementById('stat-total').textContent = packetStats.total;

        if (!protocolStatsList) return;

        const sortedProtocols = Object.entries(packetStats.byProtocol)
            .filter(([, count]) => count > 0)
            .sort((a, b) => b[1] - a[1]);

        if (sortedProtocols.length === 0) {
            protocolStatsList.innerHTML = '<span class="text-muted">No protocol data</span>';
            return;
        }

        protocolStatsList.innerHTML = sortedProtocols.map(([name, count]) => {
            const protoClass = getProtocolClass(name);
            return `<span class="protocol-stat-chip"><span class="${protoClass}">${name}</span><strong>${count}</strong></span>`;
        }).join('');
    };

    const resetStats = () => {
        packetStats = { total: 0, byProtocol: {} };
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

        if (filterText) {
            filteredPackets = allPackets.filter(pkt => {
                const lowerFilter = filterText; // Already lowered
                
                // Simple search fallback if no operators
                if (!lowerFilter.includes('==') && !lowerFilter.includes('!=') && !lowerFilter.includes('contains')) {
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
                        } else if (cond.includes('!=')) {
                            let parts = cond.split('!=').map(s => s.trim());
                            let key = parts[0];
                            let val = parts[1].replace(/"/g, '').replace(/'/g, '');
                            
                            if (key === 'ip.src') matched = (pkt.src && pkt.src.toLowerCase() !== val);
                            else if (key === 'ip.dst') matched = (pkt.dst && pkt.dst.toLowerCase() !== val);
                            else if (key === 'ip.addr') matched = (pkt.src && pkt.src.toLowerCase() !== val) && (pkt.dst && pkt.dst.toLowerCase() !== val);
                            else if (key === 'tcp.port' || key === 'udp.port') matched = (pkt.sport != val) && (pkt.dport != val);
                            else if (key === 'protocol') matched = (pkt.protocol && pkt.protocol.toLowerCase() !== val);
                        } else if (cond.includes('contains')) {
                            let parts = cond.split('contains').map(s => s.trim());
                            let key = parts[0];
                            let val = parts[1].replace(/"/g, '').replace(/'/g, '');
                            
                            if (key === 'dns.qry.name') matched = (pkt.info && pkt.info.toLowerCase().includes(val));
                            else {
                                const searchable = `${pkt.src || ''} ${pkt.dst || ''} ${pkt.protocol || ''} ${pkt.info || ''}`.toLowerCase();
                                matched = searchable.includes(val);
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

        if (packetSort.key) {
            filteredPackets = [...filteredPackets].sort((a, b) => comparePackets(a, b, packetSort.key, packetSort.direction));
        }

        if (filteredPackets.length === 0) {
            pageStartSpan.textContent = 0;
            pageEndSpan.textContent = 0;
            totalPacketsSpan.textContent = filterText ? `0 (filtered out of ${allPackets.length})` : 0;
            pageNumberSpan.textContent = `Page 1`;
            btnPrev.disabled = true;
            btnNext.disabled = true;
            checkEmptyState(0);
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
        totalPacketsSpan.textContent = filterText ? `${filteredPackets.length} (filtered out of ${allPackets.length})` : allPackets.length;
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
        resetStats();
        currentPage = 1;
        renderTable();
        detailsContent.innerHTML = '<div class="empty-selection"><p>Select a packet from the list to view detailed layers.</p></div>';
        selectedPacketIdSpan.textContent = 'None Selected';
        selectedPacketRow = null;
    });

    displayFilterInput.addEventListener('input', () => {
        currentPage = 1;
        renderTable();
    });

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
            btnUpload.textContent = "📂 Open PCAP";
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

    if (btnGlobalAnalysis) {
        btnGlobalAnalysis.addEventListener('click', async () => {
            btnGlobalAnalysis.disabled = true;
            btnGlobalAnalysis.textContent = "Analyzing...";
            if(flowsList) flowsList.innerHTML = '<tr><td colspan="3" class="text-center">Loading...</td></tr>';
            if(credsList) credsList.innerHTML = '<tr><td colspan="3" class="text-center">Loading...</td></tr>';
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
                        credsList.innerHTML = clearTextRows.map(c => `
                            <tr>
                                <td>${c.source} &rarr; ${c.destination}</td>
                                <td class="text-danger">${c.field}</td>
                                <td class="text-danger" style="font-weight:bold;">${c.value}</td>
                            </tr>
                        `).join('');
                    } else {
                        credsList.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No important clear-text fields found.</td></tr>';
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
    initAnalysisTableSort('creds-table');
    initAnalysisTableSort('dns-table', [1, 2]);
    init();
});
