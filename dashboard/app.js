/* ============================================================
   SENTINELX - DASHBOARD JAVASCRIPT
   Cybersecurity Monitoring System
   ============================================================ */

let API_BASE;

if (window.SENTINELX_API_BASE) {

    API_BASE = window.SENTINELX_API_BASE;

} else if (
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1"
) {

    API_BASE = "http://127.0.0.1:5000";

} else {

    API_BASE = "https://sentinelx-os1m.onrender.com";

}


/* ============================================================
   DOM ELEMENTS
   ============================================================ */

// Overview
const systemStatus = document.getElementById("systemStatus");
const totalEvents = document.getElementById("totalEvents");
const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const securityAlerts = document.getElementById("securityAlerts");

// Statistics
const statTotalEvents = document.getElementById("statTotalEvents");
const statSecurityAlerts = document.getElementById("statSecurityAlerts");
const statProcesses = document.getElementById("statProcesses");
const statNetwork = document.getElementById("statNetwork");
const statCurrentRisk = document.getElementById("statCurrentRisk");
const statHighestRisk = document.getElementById("statHighestRisk");

// Alerts
const alertsContainer = document.getElementById("alertsContainer");
const alertCountBadge = document.getElementById("alertCountBadge");

// Risk
const riskNumber = document.getElementById("riskNumber");
const riskStatus = document.getElementById("riskStatus");

const riskSummaryCurrent =
    document.getElementById("riskSummaryCurrent");

const riskSummaryCurrentLevel =
    document.getElementById("riskSummaryCurrentLevel");

const riskSummaryHighest =
    document.getElementById("riskSummaryHighest");

const riskSummaryHighestLevel =
    document.getElementById("riskSummaryHighestLevel");

const riskSummaryTrend =
    document.getElementById("riskSummaryTrend");

const riskSummaryTrendDetail =
    document.getElementById("riskSummaryTrendDetail");

// Events
const eventsTableBody =
    document.getElementById("eventsTableBody");

// System information
const hostname =
    document.getElementById("hostname");

const operatingSystem =
    document.getElementById("operatingSystem");

const osVersion =
    document.getElementById("osVersion");

const username =
    document.getElementById("username");

// Processes
const processTableBody =
    document.getElementById("processTableBody");

const processCount =
    document.getElementById("processCount");

const processSearch =
    document.getElementById("processSearch");

// Network
const networkTableBody =
    document.getElementById("networkTableBody");

const networkCount =
    document.getElementById("networkCount");

const networkEstablished =
    document.getElementById("networkEstablished");

const networkListening =
    document.getElementById("networkListening");

const networkSearch =
    document.getElementById("networkSearch");

// Other
const lastUpdated =
    document.getElementById("lastUpdated");

const refreshBtn =
    document.getElementById("refreshBtn");

const reportBtn =
    document.getElementById("reportBtn");


/* ============================================================
   GLOBAL DATA
   ============================================================ */

let currentProcesses = [];
let currentNetworkConnections = [];
let currentEvents = [];
let currentAlerts = [];

let riskChart = null;


/* ============================================================
   API HELPER
   ============================================================ */

async function fetchAPI(endpoint) {

    try {

        const response = await fetch(
            `${API_BASE}${endpoint}`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status} - ${response.statusText}`
            );

        }

        return await response.json();

    } catch (error) {

        console.error(
            `SentinelX API Error: ${endpoint}`,
            error
        );

        return null;
    }
}


/* ============================================================
   STATUS
   ============================================================ */

async function loadStatus() {

    const data = await fetchAPI("/api/status");

    if (!data) {

        if (systemStatus) {
            systemStatus.textContent = "OFFLINE";
        }

        return;
    }


    if (systemStatus) {

        const status =
            String(data.status || "").toLowerCase();

        if (
            status === "online" ||
            status === "running"
        ) {

            systemStatus.textContent = "ONLINE";

        } else {

            systemStatus.textContent =
                String(data.status || "ONLINE").toUpperCase();

        }
    }


    if (totalEvents) {

        const total =
            Number(
                data.total_events ??
                data.event_count ??
                data.total ??
                0
            );

        totalEvents.textContent =
            total.toLocaleString();

    }
}


/* ============================================================
   SYSTEM INFORMATION
   ============================================================ */

async function loadSystemInfo() {

    const data = await fetchAPI("/api/system");

    if (!data) {
        return;
    }


    if (hostname) {

        hostname.textContent =
            data.hostname ??
            data.Hostname ??
            "Unknown";

    }


    if (operatingSystem) {

        operatingSystem.textContent =
            data.operating_system ??
            data.os ??
            data.OperatingSystem ??
            "Unknown";

    }


    if (osVersion) {

        osVersion.textContent =
            data.os_version ??
            data.version ??
            data.OSVersion ??
            "Unknown";

    }


    if (username) {

        username.textContent =
            data.username ??
            data.user ??
            data.Username ??
            "Unknown";

    }
}


/* ============================================================
   RISK LEVEL
   ============================================================ */

function getRiskLevel(score) {

    const value = Number(score) || 0;


    if (value >= 90) {
        return "CRITICAL";
    }

    if (value >= 70) {
        return "HIGH";
    }

    if (value >= 40) {
        return "MEDIUM";
    }

    if (value >= 20) {
        return "LOW";
    }

    return "NORMAL";
}


/* ============================================================
   LOAD RISK
   ============================================================ */

async function loadRisk() {

    const data = await fetchAPI("/api/risk");

    if (!data) {
        return;
    }


    const current =
        Number(
            data.current_risk ??
            data.current ??
            data.risk_score ??
            0
        );


    const highest =
        Number(
            data.highest_risk ??
            data.highest ??
            current
        );


    updateRiskDisplay(current);

    updateRiskSummary(
        current,
        highest
    );

}


/* ============================================================
   RISK DISPLAY
   ============================================================ */

function updateRiskDisplay(score) {

    const value =
        Math.max(
            0,
            Math.min(
                100,
                Number(score) || 0
            )
        );


    const level =
        getRiskLevel(value);


    if (riskScore) {

        riskScore.textContent =
            `${value}/100`;

    }


    if (riskLevel) {

        riskLevel.textContent =
            level;

    }


    if (riskNumber) {

        riskNumber.textContent =
            value;

    }


    if (riskStatus) {

        riskStatus.textContent =
            level;

    }


    if (statCurrentRisk) {

        statCurrentRisk.textContent =
            `${value}/100`;

    }
}


/* ============================================================
   RISK SUMMARY
   ============================================================ */

function updateRiskSummary(
    current,
    highest
) {

    const currentValue =
        Number(current) || 0;

    const highestValue =
        Number(highest) || 0;


    const currentLevel =
        getRiskLevel(currentValue);

    const highestLevel =
        getRiskLevel(highestValue);


    if (riskSummaryCurrent) {

        riskSummaryCurrent.textContent =
            `${currentValue}/100`;

    }


    if (riskSummaryCurrentLevel) {

        riskSummaryCurrentLevel.textContent =
            currentLevel;

    }


    if (riskSummaryHighest) {

        riskSummaryHighest.textContent =
            `${highestValue}/100`;

    }


    if (riskSummaryHighestLevel) {

        riskSummaryHighestLevel.textContent =
            highestLevel;

    }


    if (statCurrentRisk) {

        statCurrentRisk.textContent =
            `${currentValue}/100`;

    }


    if (statHighestRisk) {

        statHighestRisk.textContent =
            `${highestValue}/100`;

    }


    updateRiskTrend(
        currentValue
    );
}


/* ============================================================
   ALERTS
   ============================================================ */

async function loadAlerts() {

    const data =
        await fetchAPI("/api/alerts");


    let alerts = [];


    if (Array.isArray(data)) {

        alerts = data;

    } else if (
        data &&
        Array.isArray(data.alerts)
    ) {

        alerts = data.alerts;

    }


    currentAlerts = alerts;


    if (securityAlerts) {

        securityAlerts.textContent =
            alerts.length;

    }


    if (alertCountBadge) {

        alertCountBadge.textContent =
            `${alerts.length} ALERTS`;

    }


    renderAlerts(alerts);
}


/* ============================================================
   RENDER ALERTS
   ============================================================ */

function renderAlerts(alerts) {

    if (!alertsContainer) {
        return;
    }


    if (
        !Array.isArray(alerts) ||
        alerts.length === 0
    ) {

        alertsContainer.innerHTML = `
            <div class="empty-state">

                <div class="empty-icon">
                    ✓
                </div>

                <p>
                    No security alerts detected
                </p>

            </div>
        `;

        return;
    }


    const visibleAlerts =
        alerts.slice(0, 20);


    alertsContainer.innerHTML =
        visibleAlerts
            .map(createAlertHTML)
            .join("");
}


/* ============================================================
   CREATE ALERT HTML
   ============================================================ */

function createAlertHTML(alert) {

    let id = "N/A";
    let timestamp = "Unknown";
    let severity = "INFO";
    let process = "Unknown";
    let message = "No message";
    let risk = 0;


    if (Array.isArray(alert)) {

        id = alert[0] ?? "N/A";
        timestamp = alert[1] ?? "Unknown";
        severity = alert[2] ?? "INFO";
        process = alert[3] ?? "Unknown";
        message = alert[4] ?? "No message";
        risk = alert[5] ?? 0;

    } else if (
        alert &&
        typeof alert === "object"
    ) {

        id =
            alert.id ??
            alert.event_id ??
            "N/A";

        timestamp =
            alert.timestamp ??
            alert.time ??
            "Unknown";

        severity =
            alert.severity ??
            alert.level ??
            "INFO";

        process =
            alert.process ??
            alert.process_name ??
            "Unknown";

        message =
            alert.message ??
            "No message";

        risk =
            alert.risk_score ??
            alert.risk ??
            0;
    }


    const safeSeverity =
        String(severity).toUpperCase();


    return `
        <div
            class="alert-item"
            onclick="showThreatDetails(
                ${JSON.stringify(id)},
                ${JSON.stringify(timestamp)},
                ${JSON.stringify(safeSeverity)},
                ${JSON.stringify(process)},
                ${JSON.stringify(message)},
                ${Number(risk) || 0}
            )"
        >

            <div class="alert-header">

                <span class="severity-badge ${safeSeverity.toLowerCase()}">
                    ${escapeHTML(safeSeverity)}
                </span>

                <span class="alert-risk">
                    Risk: ${Number(risk) || 0}/100
                </span>

            </div>


            <div class="alert-process">
                ${escapeHTML(process)}
            </div>


            <div class="alert-message">
                ${escapeHTML(message)}
            </div>


            <div class="alert-footer">

                <span>
                    ${escapeHTML(String(timestamp))}
                </span>

                <span>
                    Event ID: ${escapeHTML(String(id))}
                </span>

            </div>

        </div>
    `;
}


/* ============================================================
   EVENTS
   ============================================================ */

async function loadEvents() {

    const data =
        await fetchAPI("/api/events");


    let events = [];


    if (Array.isArray(data)) {

        events = data;

    } else if (
        data &&
        Array.isArray(data.events)
    ) {

        events = data.events;

    }


    currentEvents = events;


    renderEvents(events);

    updateRiskHistory(events);

}


/* ============================================================
   RENDER EVENTS
   ============================================================ */

function renderEvents(events) {

    if (!eventsTableBody) {
        return;
    }


    if (
        !Array.isArray(events) ||
        events.length === 0
    ) {

        eventsTableBody.innerHTML = `
            <tr>
                <td colspan="6">
                    No events found.
                </td>
            </tr>
        `;

        return;
    }


    const visibleEvents =
        events.slice(0, 50);


    eventsTableBody.innerHTML =
        visibleEvents
            .map(createEventRow)
            .join("");
}


/* ============================================================
   CREATE EVENT ROW
   ============================================================ */

function createEventRow(event) {

    let id = "";
    let timestamp = "";
    let eventType = "";
    let severity = "INFO";
    let process = "—";
    let message = "";
    let risk = 0;


    if (Array.isArray(event)) {

        id = event[0] ?? "";
        timestamp = event[1] ?? "";
        eventType = event[2] ?? "";
        severity = event[3] ?? "INFO";
        process = event[4] ?? "—";
        message = event[5] ?? "";
        risk = event[6] ?? 0;

    } else if (
        event &&
        typeof event === "object"
    ) {

        id =
            event.id ??
            event.event_id ??
            "";

        timestamp =
            event.timestamp ??
            event.time ??
            "";

        eventType =
            event.event_type ??
            event.type ??
            event.event ??
            "";

        severity =
            event.severity ??
            "INFO";

        process =
            event.process ??
            "—";

        message =
            event.message ??
            "";

        risk =
            event.risk_score ??
            event.risk ??
            0;
    }


    const safeSeverity =
        String(severity).toUpperCase();


    return `
        <tr>

            <td>
                ${escapeHTML(String(timestamp))}
            </td>

            <td>
                ${escapeHTML(String(eventType))}
            </td>

            <td>
                <span class="severity-badge ${safeSeverity.toLowerCase()}">
                    ${escapeHTML(safeSeverity)}
                </span>
            </td>

            <td>
                ${escapeHTML(String(process))}
            </td>

            <td>
                ${escapeHTML(String(message))}
            </td>

            <td>
                ${Number(risk) || 0}/100
            </td>

        </tr>
    `;
}


/* ============================================================
   RISK CHART
   ============================================================ */

function getEventRisk(event) {

    if (Array.isArray(event)) {

        return Number(event[6]) || 0;

    }


    if (
        event &&
        typeof event === "object"
    ) {

        return Number(
            event.risk_score ??
            event.risk ??
            0
        );
    }


    return 0;
}


function getEventTimestamp(event) {

    if (Array.isArray(event)) {

        return event[1] ?? "";

    }


    if (
        event &&
        typeof event === "object"
    ) {

        return (
            event.timestamp ??
            event.time ??
            ""
        );
    }


    return "";
}


/* ============================================================
   UPDATE RISK HISTORY
   ============================================================ */

function updateRiskHistory(events) {

    const canvas =
        document.getElementById(
            "riskHistoryChart"
        );


    if (!canvas) {
        return;
    }


    const recent =
        Array.isArray(events)
            ? events.slice(0, 20).reverse()
            : [];


    const labels =
        recent.map(
            event => {

                const timestamp =
                    getEventTimestamp(event);

                if (!timestamp) {
                    return "";
                }

                return String(timestamp)
                    .split(" ")[1] || timestamp;
            }
        );


    const values =
        recent.map(
            getEventRisk
        );


    if (riskChart) {

        riskChart.destroy();

        riskChart = null;
    }


    if (
        typeof Chart === "undefined"
    ) {

        console.warn(
            "Chart.js is not loaded."
        );

        return;
    }


    riskChart =
        new Chart(
            canvas,
            {
                type: "line",

                data: {

                    labels: labels,

                    datasets: [
                        {
                            label: "Risk Score",

                            data: values,

                            tension: 0.35,

                            fill: false,

                            borderWidth: 2,

                            pointRadius: 3,

                            pointHoverRadius: 5
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    scales: {

                        y: {

                            beginAtZero: true,

                            max: 100,

                            ticks: {
                                stepSize: 20
                            }
                        }
                    },

                    plugins: {

                        legend: {
                            display: false
                        }
                    }
                }
            }
        );
}


/* ============================================================
   RISK TREND
   ============================================================ */

function updateRiskTrend(currentRisk) {

    const current =
        Number(currentRisk) || 0;


    let trend = "STABLE";
    let detail = "Risk remains stable";


    if (current >= 70) {

        trend = "ELEVATED";
        detail = "Higher security risk detected";

    } else if (current >= 40) {

        trend = "MODERATE";
        detail = "Moderate security risk detected";

    } else if (current >= 20) {

        trend = "LOW";
        detail = "Low-level security indicators detected";

    } else {

        trend = "STABLE";
        detail = "No significant change";
    }


    if (riskSummaryTrend) {

        riskSummaryTrend.textContent =
            trend;

    }


    if (riskSummaryTrendDetail) {

        riskSummaryTrendDetail.textContent =
            detail;

    }
}


/* ============================================================
   PROCESSES
   ============================================================ */

async function loadProcesses() {

    const data =
        await fetchAPI("/api/processes");


    let processes = [];


    if (Array.isArray(data)) {

        processes = data;

    } else if (
        data &&
        Array.isArray(data.processes)
    ) {

        processes = data.processes;

    }


    currentProcesses =
        processes;


    if (processCount) {

        processCount.textContent =
            `${processes.length} PROCESSES`;

    }


    renderProcesses(
        processes
    );
}


/* ============================================================
   RENDER PROCESSES
   ============================================================ */

function renderProcesses(processes) {

    if (!processTableBody) {
        return;
    }


    if (
        !Array.isArray(processes) ||
        processes.length === 0
    ) {

        processTableBody.innerHTML = `
            <tr>
                <td colspan="4">
                    No running processes found.
                </td>
            </tr>
        `;

        return;
    }


    const visibleProcesses =
        processes.slice(0, 100);


    processTableBody.innerHTML =
        visibleProcesses
            .map(
                process => {

                    let pid = "";
                    let name = "";
                    let memory = "";
                    let status = "running";


                    if (Array.isArray(process)) {

                        pid = process[0] ?? "";
                        name = process[1] ?? "";
                        memory = process[2] ?? "";
                        status = process[3] ?? "running";

                    } else if (
                        process &&
                        typeof process === "object"
                    ) {

                        pid =
                            process.pid ??
                            "";

                        name =
                            process.name ??
                            process.process ??
                            "";

                        memory =
                            process.memory ??
                            process.memory_usage ??
                            "";

                        status =
                            process.status ??
                            "running";
                    }


                    return `
                        <tr>

                            <td>
                                ${escapeHTML(String(pid))}
                            </td>

                            <td>
                                ${escapeHTML(String(name))}
                            </td>

                            <td>
                                ${escapeHTML(String(memory))}
                            </td>

                            <td>
                                ${escapeHTML(String(status))}
                            </td>

                        </tr>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   NETWORK
   ============================================================ */

async function loadNetwork() {

    const data =
        await fetchAPI("/api/network");


    let connections = [];


    if (Array.isArray(data)) {

        connections = data;

    } else if (
        data &&
        Array.isArray(data.network)
    ) {

        connections = data.network;

    } else if (
        data &&
        Array.isArray(data.connections)
    ) {

        connections = data.connections;

    }


    currentNetworkConnections =
        connections;


    updateNetworkStatistics(
        connections
    );


    renderNetwork(
        connections
    );
}


/* ============================================================
   NETWORK STATISTICS
   ============================================================ */

function updateNetworkStatistics(
    connections
) {

    if (!Array.isArray(connections)) {

        connections = [];

    }


    const total =
        connections.length;


    let established = 0;
    let listening = 0;


    connections.forEach(
        connection => {

            let state = "";


            if (Array.isArray(connection)) {

                /*
                 Expected API structure:

                 [protocol,
                  local_address,
                  foreign_address,
                  pid,
                  state]
                */

                state =
                    connection[4] ?? "";

            } else if (
                connection &&
                typeof connection === "object"
            ) {

                state =
                    connection.state ??
                    connection.status ??
                    connection.connection_state ??
                    "";
            }


            const normalizedState =
                String(state)
                    .trim()
                    .toUpperCase();


            if (
                normalizedState ===
                "ESTABLISHED"
            ) {

                established++;

            }


            if (
                normalizedState ===
                "LISTEN" ||

                normalizedState ===
                "LISTENING"
            ) {

                listening++;

            }
        }
    );


    if (networkCount) {

        networkCount.textContent =
            total.toLocaleString();

    }


    if (networkEstablished) {

        networkEstablished.textContent =
            established.toLocaleString();

    }


    if (networkListening) {

        networkListening.textContent =
            listening.toLocaleString();

    }


    if (statNetwork) {

        statNetwork.textContent =
            total.toLocaleString();

    }
}


/* ============================================================
   RENDER NETWORK
   ============================================================ */

function renderNetwork(
    connections
) {

    if (!networkTableBody) {
        return;
    }


    if (
        !Array.isArray(connections) ||
        connections.length === 0
    ) {

        networkTableBody.innerHTML = `
            <tr>
                <td colspan="5">
                    No network connections found.
                </td>
            </tr>
        `;

        return;
    }


    const visibleConnections =
        connections.slice(0, 100);


    networkTableBody.innerHTML =
        visibleConnections
            .map(
                connection => {

                    let protocol = "";
                    let localAddress = "";
                    let foreignAddress = "";
                    let pid = "";
                    let state = "";


                    if (Array.isArray(connection)) {

                        protocol =
                            connection[0] ?? "";

                        localAddress =
                            connection[1] ?? "";

                        foreignAddress =
                            connection[2] ?? "";

                        pid =
                            connection[3] ?? "";

                        state =
                            connection[4] ?? "";

                    } else if (
                        connection &&
                        typeof connection === "object"
                    ) {

                        protocol =
                            connection.protocol ??
                            "";

                        localAddress =
                            connection.local_address ??
                            connection.local ??
                            "";

                        foreignAddress =
                            connection.foreign_address ??
                            connection.foreign ??
                            "";

                        pid =
                            connection.pid ??
                            "";

                        state =
                            connection.state ??
                            connection.status ??
                            "";
                    }


                    return `
                        <tr>

                            <td>
                                ${escapeHTML(String(protocol))}
                            </td>

                            <td>
                                ${escapeHTML(String(localAddress))}
                            </td>

                            <td>
                                ${escapeHTML(String(foreignAddress))}
                            </td>

                            <td>
                                ${escapeHTML(String(pid))}
                            </td>

                            <td>
                                ${escapeHTML(String(state))}
                            </td>

                        </tr>
                    `;
                }
            )
            .join("");
}


/* ============================================================
   SECURITY STATISTICS
   ============================================================ */

async function updateSecurityStatistics() {

    const [
        status,
        alerts,
        processes,
        network,
        risk
    ] = await Promise.all(
        [
            fetchAPI("/api/status"),
            fetchAPI("/api/alerts"),
            fetchAPI("/api/processes"),
            fetchAPI("/api/network"),
            fetchAPI("/api/risk")
        ]
    );


    /* --------------------------------
       TOTAL EVENTS
       -------------------------------- */

    if (statTotalEvents) {

        /*
         IMPORTANT:

         /api/events returns only recent events.

         Therefore events.length must NOT
         be used for the total database count.

         /api/status contains the real total.
        */

        const totalEventsValue =
            Number(
                status?.total_events ??
                status?.event_count ??
                status?.total ??
                0
            );


        statTotalEvents.textContent =
            totalEventsValue.toLocaleString();
    }


    /* --------------------------------
       SECURITY ALERTS
       -------------------------------- */

    let alertList = [];


    if (Array.isArray(alerts)) {

        alertList = alerts;

    } else if (
        alerts &&
        Array.isArray(alerts.alerts)
    ) {

        alertList =
            alerts.alerts;
    }


    if (statSecurityAlerts) {

        statSecurityAlerts.textContent =
            alertList.length.toLocaleString();
    }


    /* --------------------------------
       PROCESSES
       -------------------------------- */

    let processList = [];


    if (Array.isArray(processes)) {

        processList = processes;

    } else if (
        processes &&
        Array.isArray(processes.processes)
    ) {

        processList =
            processes.processes;
    }


    if (statProcesses) {

        statProcesses.textContent =
            processList.length.toLocaleString();
    }


    /* --------------------------------
       NETWORK
       -------------------------------- */

    let networkList = [];


    if (Array.isArray(network)) {

        networkList = network;

    } else if (
        network &&
        Array.isArray(network.network)
    ) {

        networkList =
            network.network;

    } else if (
        network &&
        Array.isArray(network.connections)
    ) {

        networkList =
            network.connections;
    }


    /*
     Use the same network data to update
     all network counters.
    */

    updateNetworkStatistics(
        networkList
    );


    /* --------------------------------
       RISK
       -------------------------------- */

    if (risk) {

        const current =
            Number(
                risk.current_risk ??
                risk.current ??
                risk.risk_score ??
                0
            );


        const highest =
            Number(
                risk.highest_risk ??
                risk.highest ??
                current
            );


        if (statCurrentRisk) {

            statCurrentRisk.textContent =
                `${current}/100`;

        }


        if (statHighestRisk) {

            statHighestRisk.textContent =
                `${highest}/100`;

        }
    }
}


/* ============================================================
   REFRESH DASHBOARD
   ============================================================ */

async function refreshDashboard() {

    console.log(
        "Refreshing SentinelX dashboard..."
    );


    try {

        await Promise.all(
            [
                loadStatus(),
                loadSystemInfo(),
                loadRisk(),
                loadAlerts(),
                loadEvents(),
                loadProcesses(),
                loadNetwork(),
                updateSecurityStatistics()
            ]
        );


        updateLastUpdated();


        console.log(
            "SentinelX dashboard refreshed."
        );

    } catch (error) {

        console.error(
            "Dashboard refresh error:",
            error
        );
    }
}


/* ============================================================
   LAST UPDATED
   ============================================================ */

function updateLastUpdated() {

    if (!lastUpdated) {
        return;
    }


    const now =
        new Date();


    const time =
        now.toLocaleTimeString(
            [],
            {
                hour: "numeric",
                minute: "2-digit",
                second: "2-digit"
            }
        );


    lastUpdated.textContent =
        `Last updated: ${time}`;
}


/* ============================================================
   HTML ESCAPE
   ============================================================ */

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* ============================================================
   SEARCH - PROCESSES
   ============================================================ */

if (processSearch) {

    processSearch.addEventListener(
        "input",
        function () {

            const query =
                this.value
                    .trim()
                    .toLowerCase();


            if (!query) {

                renderProcesses(
                    currentProcesses
                );

                return;
            }


            const filtered =
                currentProcesses.filter(
                    process => {

                        let searchable = "";


                        if (
                            Array.isArray(process)
                        ) {

                            searchable =
                                process.join(" ");

                        } else if (
                            process &&
                            typeof process === "object"
                        ) {

                            searchable =
                                Object.values(process)
                                    .join(" ");
                        }


                        return searchable
                            .toLowerCase()
                            .includes(query);
                    }
                );


            renderProcesses(
                filtered
            );
        }
    );
}


/* ============================================================
   SEARCH - NETWORK
   ============================================================ */

if (networkSearch) {

    networkSearch.addEventListener(
        "input",
        function () {

            const query =
                this.value
                    .trim()
                    .toLowerCase();


            if (!query) {

                renderNetwork(
                    currentNetworkConnections
                );

                return;
            }


            const filtered =
                currentNetworkConnections.filter(
                    connection => {

                        let searchable = "";


                        if (
                            Array.isArray(connection)
                        ) {

                            searchable =
                                connection.join(" ");

                        } else if (
                            connection &&
                            typeof connection === "object"
                        ) {

                            searchable =
                                Object.values(connection)
                                    .join(" ");
                        }


                        return searchable
                            .toLowerCase()
                            .includes(query);
                    }
                );


            renderNetwork(
                filtered
            );
        }
    );
}


/* ============================================================
   REFRESH BUTTON
   ============================================================ */

if (refreshBtn) {

    refreshBtn.addEventListener(
        "click",
        async function () {

            refreshBtn.disabled = true;

            const originalText =
                refreshBtn.innerHTML;


            refreshBtn.innerHTML =
                "&#8635; Refreshing...";


            await refreshDashboard();


            refreshBtn.innerHTML =
                originalText;

            refreshBtn.disabled = false;
        }
    );
}


/* ============================================================
   REPORT BUTTON
   ============================================================ */

if (reportBtn) {

    reportBtn.href =
        `${API_BASE}/api/report`;

    reportBtn.target =
        "_blank";

}


/* ============================================================
   THREAT DETAILS
   ============================================================ */

function showThreatDetails(
    id,
    timestamp,
    severity,
    process,
    message,
    risk
) {

    /*
     The Threat Details popup is intentionally
     kept simple for now.

     This functionality can be polished later
     without affecting the monitoring system.
    */

    let popup =
        document.getElementById(
            "threatDetailsPopup"
        );


    if (!popup) {

        popup =
            document.createElement("div");

        popup.id =
            "threatDetailsPopup";

        popup.className =
            "threat-details-popup";


        popup.innerHTML = `
            <div class="threat-details-overlay"
                 onclick="closeThreatDetails()">

                <div class="threat-details-modal"
                     onclick="event.stopPropagation()">

                    <div class="threat-details-header">

                        <h3>
                            Threat Details
                        </h3>

                        <button
                            class="threat-close-btn"
                            onclick="closeThreatDetails()">

                            &times;

                        </button>

                    </div>


                    <div
                        id="threatDetailsContent"
                        class="threat-details-content">
                    </div>

                </div>

            </div>
        `;


        document.body.appendChild(
            popup
        );
    }


    const content =
        document.getElementById(
            "threatDetailsContent"
        );


    if (!content) {
        return;
    }


    const safeSeverity =
        String(severity || "INFO")
            .toUpperCase();


    const riskValue =
        Number(risk) || 0;


    content.innerHTML = `

        <div class="threat-detail-row">

            <span>
                Event ID
            </span>

            <strong>
                ${escapeHTML(String(id))}
            </strong>

        </div>


        <div class="threat-detail-row">

            <span>
                Timestamp
            </span>

            <strong>
                ${escapeHTML(String(timestamp))}
            </strong>

        </div>


        <div class="threat-detail-row">

            <span>
                Severity
            </span>

            <strong class="${safeSeverity.toLowerCase()}">
                ${escapeHTML(safeSeverity)}
            </strong>

        </div>


        <div class="threat-detail-row">

            <span>
                Process
            </span>

            <strong>
                ${escapeHTML(String(process))}
            </strong>

        </div>


        <div class="threat-detail-row">

            <span>
                Risk Score
            </span>

            <strong>
                ${riskValue}/100
            </strong>

        </div>


        <div class="threat-detail-message">

            <span>
                Detection Message
            </span>

            <p>
                ${escapeHTML(String(message))}
            </p>

        </div>

    `;


    popup.style.display =
        "block";
}


/* ============================================================
   CLOSE THREAT DETAILS
   ============================================================ */

function closeThreatDetails() {

    const popup =
        document.getElementById(
            "threatDetailsPopup"
        );


    if (popup) {

        popup.style.display =
            "none";
    }
}


/* ============================================================
   ESC KEY - CLOSE POPUP
   ============================================================ */

document.addEventListener(
    "keydown",
    function (event) {

        if (
            event.key === "Escape"
        ) {

            closeThreatDetails();
        }
    }
);


/* ============================================================
   INITIAL LOAD
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        console.log(
            "SentinelX dashboard starting..."
        );


        refreshDashboard();

    }
);


/* ============================================================
   AUTO REFRESH
   ============================================================ */

setInterval(
    refreshDashboard,
    10000
);


/* ============================================================
   SENTINELX READY
   ============================================================ */

console.log(
    "SentinelX dashboard JavaScript loaded."
);