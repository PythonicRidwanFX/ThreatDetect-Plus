(function () {
    "use strict";

    /* ============================================================
       DASHBOARD.JS
       Threat Detection System
       Professional Version
    ============================================================ */

    /* ============================================================
       DOM ELEMENTS
    ============================================================ */

    const sidebar = document.querySelector(".sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");

    const toastContainer = document.getElementById("toastContainer");

    const packetTable = document.getElementById("packet-table-body");
    const threatTable = document.getElementById("threat-table-body");
    const eventFeed = document.getElementById("eventFeed");

    const chartCanvas = document.getElementById("trafficChart");

    let trafficChart = null;

    /* ============================================================
       SIDEBAR TOGGLE
    ============================================================ */

    if (sidebar && sidebarToggle) {

        sidebarToggle.addEventListener("click", () => {

            sidebar.classList.toggle("show");

        });

    }

    /* ============================================================
       TOAST NOTIFICATION
    ============================================================ */

    function showToast(title, message, type = "primary") {

        if (!toastContainer) return;

        const id = "toast-" + Date.now();

        const html = `
            <div
                id="${id}"
                class="toast align-items-center text-bg-${type} border-0 mb-2"
                role="alert">

                <div class="d-flex">

                    <div class="toast-body">

                        <strong>${title}</strong><br>
                        ${message}

                    </div>

                    <button
                        type="button"
                        class="btn-close btn-close-white me-2 m-auto"
                        data-bs-dismiss="toast">
                    </button>

                </div>

            </div>
        `;

        toastContainer.insertAdjacentHTML("afterbegin", html);

        const toastElement = document.getElementById(id);

        const toast = new bootstrap.Toast(toastElement, {

            delay: 4000

        });

        toast.show();

        toastElement.addEventListener("hidden.bs.toast", () => {

            toastElement.remove();

        });

    }

    /* ============================================================
       COUNTER UPDATE
    ============================================================ */

    function updateCounter(id, value) {

        const element = document.getElementById(id);

        if (!element) return;

        element.innerText = value;

    }

    function increaseCounter(id, amount = 1) {

        const element = document.getElementById(id);

        if (!element) return;

        const current = parseInt(element.innerText || "0");

        element.innerText = current + amount;

    }

    /* ============================================================
       CHART INITIALIZATION
    ============================================================ */

    function initializeChart() {

        if (!chartCanvas) return;

        const labelsElement = document.getElementById("packet-labels");
        const valuesElement = document.getElementById("packet-values");

        if (!labelsElement || !valuesElement) return;

        const labels = JSON.parse(labelsElement.textContent);

        const values = JSON.parse(valuesElement.textContent);

        trafficChart = new Chart(chartCanvas, {

            type: "line",

            data: {

                labels: labels,

                datasets: [{

                    label: "Network Packets",

                    data: values,

                    borderWidth: 3,

                    fill: true,

                    tension: 0.4,

                    pointRadius: 3

                }]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                animation: {

                    duration: 700

                },

                interaction: {

                    intersect: false,

                    mode: "index"

                },

                plugins: {

                    legend: {

                        labels: {

                            color: "#edf6ff"

                        }

                    }

                },

                scales: {

                    x: {

                        ticks: {

                            color: "#9fb3ca"

                        },

                        grid: {

                            color: "rgba(255,255,255,.05)"

                        }

                    },

                    y: {

                        beginAtZero: true,

                        ticks: {

                            color: "#9fb3ca"

                        },

                        grid: {

                            color: "rgba(255,255,255,.05)"

                        }

                    }

                }

            }

        });

    }

    initializeChart();

    /* ============================================================
       CHART UPDATE
    ============================================================ */

    function updateTrafficChart(value) {

        if (!trafficChart) return;

        trafficChart.data.labels.push(

            new Date().toLocaleTimeString()

        );

        trafficChart.data.datasets[0].data.push(value);

        if (trafficChart.data.labels.length > 20) {

            trafficChart.data.labels.shift();

            trafficChart.data.datasets[0].data.shift();

        }

        trafficChart.update();

    }

    /* ============================================================
       BADGES
    ============================================================ */

    function packetBadge(protocol) {

        switch (protocol) {

            case "TCP":
                return '<span class="badge bg-primary">TCP</span>';

            case "UDP":
                return '<span class="badge bg-success">UDP</span>';

            case "ICMP":
                return '<span class="badge bg-warning text-dark">ICMP</span>';

            case "ARP":
                return '<span class="badge bg-info text-dark">ARP</span>';

            case "DNS":
                return '<span class="badge bg-secondary">DNS</span>';

            case "HTTP":
                return '<span class="badge bg-danger">HTTP</span>';

            case "HTTPS":
                return '<span class="badge bg-dark">HTTPS</span>';

            default:
                return `<span class="badge bg-light text-dark">${protocol}</span>`;

        }

    }

    function directionBadge(direction) {

        switch (direction) {

            case "Incoming":

                return `
                    <span class="badge bg-success">
                        <i class="bi bi-arrow-down-circle"></i>
                        Incoming
                    </span>
                `;

            case "Outgoing":

                return `
                    <span class="badge bg-warning text-dark">
                        <i class="bi bi-arrow-up-circle"></i>
                        Outgoing
                    </span>
                `;

            default:

                return `
                    <span class="badge bg-secondary">
                        Unknown
                    </span>
                `;

        }

    }

    function threatBadge(severity) {

        switch (severity) {

            case "Critical":
                return '<span class="badge bg-danger">Critical</span>';

            case "High":
                return '<span class="badge bg-warning text-dark">High</span>';

            case "Medium":
                return '<span class="badge bg-info">Medium</span>';

            default:
                return '<span class="badge bg-success">Low</span>';

        }

    }

    /* ============================================================
       PACKET TABLE
    ============================================================ */

    function addPacket(packet) {

        if (!packetTable) return;

        const empty = document.getElementById("packet-empty");

        if (empty) {
            empty.remove();
        }

        const row = document.createElement("tr");

        row.classList.add("packet-highlight");

        row.innerHTML = `
            <td>${packet.time || "--"}</td>

            <td>${packet.source_ip || "-"}</td>

            <td>${packet.destination_ip || "-"}</td>

            <td>
                ${packetBadge(packet.protocol || "OTHER")}
            </td>

            <td>
                ${packet.packet_length || packet.length || 0} Bytes
            </td>

            <td>
                ${directionBadge(packet.direction || "Unknown")}
            </td>
        `;

        packetTable.prepend(row);

        while (packetTable.rows.length > 50) {

            packetTable.deleteRow(50);

        }

        setTimeout(() => {

            row.classList.remove("packet-highlight");

        }, 2500);

    }

    /* ============================================================
       THREAT TABLE
    ============================================================ */

    function addThreat(threat) {

        if (!threatTable) return;

        const empty = document.getElementById("threat-empty");

        if (empty) {

            empty.remove();

        }

        const row = document.createElement("tr");

        row.classList.add("threat-highlight");

        row.innerHTML = `

            <td>${threat.time || "--"}</td>

            <td>

                <strong>

                    ${threat.name || "Unknown Threat"}

                </strong>

            </td>

            <td>

                ${threatBadge(threat.severity || "High")}

            </td>

            <td>

                <span class="badge bg-danger">

                    New

                </span>

            </td>

            <td>

                ${threat.description || threat.message || "-"}

            </td>

        `;

        threatTable.prepend(row);

        while (threatTable.rows.length > 25) {

            threatTable.deleteRow(25);

        }

        setTimeout(() => {

            row.classList.remove("threat-highlight");

        }, 3000);

    }

    /* ============================================================
       EVENT FEED
    ============================================================ */

    function addFeedItem(type, title, message) {

        if (!eventFeed) return;

        let dot = "info";

        switch (type) {

            case "packet":
                dot = "packet";
                break;

            case "threat":
                dot = "threat";
                break;

            case "alert":
                dot = "alert";
                break;

            case "success":
                dot = "success";
                break;

        }

        const item = document.createElement("div");

        item.className = "event-item feed-animation";

        item.innerHTML = `

            <span class="event-dot ${dot}"></span>

            <div>

                <strong>

                    ${title}

                </strong>

                <p>

                    ${message}

                </p>

                <small class="text-muted">

                    ${new Date().toLocaleTimeString()}

                </small>

            </div>

        `;

        eventFeed.prepend(item);

        while (eventFeed.children.length > 30) {

            eventFeed.removeChild(eventFeed.lastElementChild);

        }

    }

    /* ============================================================
       BROWSER NOTIFICATIONS
    ============================================================ */

    function requestNotificationPermission() {

        if (!("Notification" in window)) {

            return;

        }

        if (Notification.permission === "default") {

            Notification.requestPermission();

        }

    }

    requestNotificationPermission();

    function showBrowserNotification(title, body) {

        if (!("Notification" in window)) {

            return;

        }

        if (Notification.permission !== "granted") {

            return;

        }

        new Notification(title, {

            body: body,

            icon: "/static/images/logo.png"

        });

    }

    /* ============================================================
       TABLE HELPERS
    ============================================================ */

    function clearEmptyPacketMessage() {

        const empty = document.getElementById("packet-empty");

        if (empty) {

            empty.remove();

        }

    }

    function clearEmptyThreatMessage() {

        const empty = document.getElementById("threat-empty");

        if (empty) {

            empty.remove();

        }

    }

    /* ============================================================
       LIVE COUNTERS
    ============================================================ */

    function updateSecurityCounters(data) {

        if (data.total_packets !== undefined) {

            updateCounter(

                "totalPackets",

                data.total_packets

            );

        }

        if (data.total_threats !== undefined) {

            updateCounter(

                "totalThreats",

                data.total_threats

            );

        }

        if (data.total_alerts !== undefined) {

            updateCounter(

                "totalAlerts",

                data.total_alerts

            );

        }

        if (data.active_connections !== undefined) {

            updateCounter(

                "activeConnections",

                data.active_connections

            );

        }

    }

    /* ============================================================
       WEBSOCKET
    ============================================================ */

    let socket = null;

    function connectSocket() {

        const protocol = window.location.protocol === "https:"
            ? "wss"
            : "ws";

        socket = new WebSocket(
            `${protocol}://${window.location.host}/ws/dashboard/`
        );

        /* ==========================================
           CONNECTED
        ========================================== */

        socket.onopen = function () {

            console.log("Dashboard Connected");

            showToast(
                "Connected",
                "Real-time monitoring started.",
                "success"
            );

        };

        /* ==========================================
           RECEIVE MESSAGE
        ========================================== */

        socket.onmessage = function (event) {

            const data = JSON.parse(event.data);

            console.log(data);

            switch (data.event) {

                /* =====================================
                   LIVE PACKET
                ===================================== */

                case "packet":

                    addPacket(data);

                    addFeedItem(
                        "packet",
                        "Packet Captured",
                        `${data.source_ip} → ${data.destination_ip}`
                    );

                    increaseCounter("totalPackets");

                    updateTrafficChart(
                        data.total_packets ||
                        parseInt(
                            document.getElementById("totalPackets")?.innerText || 0
                        )
                    );

                    break;

                /* =====================================
                   THREAT DETECTED
                ===================================== */

                case "threat_detected":

                    addThreat(data);

                    addFeedItem(
                        "threat",
                        data.name || "Threat Detected",
                        data.description || data.message
                    );

                    updateSecurityCounters(data);

                    showToast(
                        "Threat Detected",
                        data.name || "Unknown Threat",
                        "danger"
                    );

                    showBrowserNotification(
                        "Threat Detected",
                        data.name || "Unknown Threat"
                    );

                    break;

                /* =====================================
                   ALERT
                ===================================== */

                case "alert":

                    increaseCounter("totalAlerts");

                    addFeedItem(
                        "alert",
                        "Security Alert",
                        data.message
                    );

                    showToast(
                        "Alert",
                        data.message,
                        "warning"
                    );

                    break;

                /* =====================================
                   SYSTEM STATUS
                ===================================== */

                case "status":

                    const status =
                        document.getElementById("systemStatus");

                    if (status) {

                        status.innerHTML = `
                            <span class="badge bg-success">
                                ${data.value}
                            </span>
                        `;

                    }

                    break;

                /* =====================================
                   SECURITY COUNTS
                ===================================== */

                case "counts":

                    updateSecurityCounters(data);

                    break;

                default:

                    console.log("Unknown event:", data);

            }

        };

        /* ==========================================
           CLOSED
        ========================================== */

        socket.onclose = function () {

            console.log("Dashboard Disconnected");

            showToast(
                "Disconnected",
                "Reconnecting in 3 seconds...",
                "warning"
            );

            setTimeout(connectSocket, 3000);

        };

        /* ==========================================
           ERROR
        ========================================== */

        socket.onerror = function (error) {

            console.error(error);

            showToast(
                "WebSocket Error",
                "Unable to connect to monitoring service.",
                "danger"
            );

        };

    }

    /* ============================================================
       START SOCKET
    ============================================================ */

    connectSocket();
        /* ============================================================
       PAGE VISIBILITY
    ============================================================ */

    document.addEventListener("visibilitychange", () => {

        if (document.hidden) {

            console.log("Dashboard hidden");

        } else {

            console.log("Dashboard visible");

            if (
                !socket ||
                socket.readyState === WebSocket.CLOSED
            ) {

                connectSocket();

            }

        }

    });

    /* ============================================================
       CONNECTION HEARTBEAT
    ============================================================ */

    setInterval(() => {

        if (!socket) return;

        if (socket.readyState === WebSocket.OPEN) {

            socket.send(JSON.stringify({

                event: "ping"

            }));

        }

    }, 30000);

    /* ============================================================
       LIVE CLOCK
    ============================================================ */

    function startClock() {

        const clock = document.getElementById("liveClock");

        if (!clock) return;

        setInterval(() => {

            clock.innerText =
                new Date().toLocaleTimeString();

        }, 1000);

    }

    startClock();

    /* ============================================================
       REFRESH LAST UPDATE
    ============================================================ */

    function updateLastRefresh() {

        const element =
            document.getElementById("lastRefresh");

        if (!element) return;

        element.innerText =
            new Date().toLocaleString();

    }

    setInterval(updateLastRefresh, 1000);

    updateLastRefresh();

    /* ============================================================
       SYSTEM HEALTH
    ============================================================ */

    function updateSystemHealth(status) {

        const badge =
            document.getElementById("systemStatus");

        if (!badge) return;

        let color = "success";

        switch (status) {

            case "Running":
                color = "success";
                break;

            case "Monitoring":
                color = "primary";
                break;

            case "Warning":
                color = "warning";
                break;

            case "Offline":
                color = "danger";
                break;

            default:
                color = "secondary";

        }

        badge.innerHTML = `
            <span class="badge bg-${color}">
                ${status}
            </span>
        `;

    }

    /* ============================================================
       MEMORY CLEANUP
    ============================================================ */

    window.addEventListener("beforeunload", () => {

        if (
            socket &&
            socket.readyState === WebSocket.OPEN
        ) {

            socket.close();

        }

    });

    /* ============================================================
       DEBUG MODE
    ============================================================ */

    const DEBUG = false;

    function log(...args) {

        if (DEBUG) {

            console.log(...args);

        }

    }

    log("Dashboard initialized successfully.");

    /* ============================================================
       INITIAL DASHBOARD STATE
    ============================================================ */

    updateSystemHealth("Monitoring");

    updateLastRefresh();

    /* ============================================================
       END OF DASHBOARD.JS
    ============================================================ */

})();