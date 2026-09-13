const API_BASE =
    window.SENTINELX_API_BASE ||
    "http://127.0.0.1:5000";

// ===============================
// DOM ELEMENTS
// ===============================

const systemStatus = document.getElementById("systemStatus");
const totalEvents = document.getElementById("totalEvents");
const riskScore = document.getElementById("riskScore");
const statTotalEvents = document.getElementById("statTotalEvents");
const statSecurityAlerts = document.getElementById("statSecurityAlerts");
const statProcesses = document.getElementById("statProcesses");
const statNetwork = document.getElementById("statNetwork");
const statCurrentRisk = document.getElementById("statCurrentRisk");
const statHighestRisk = document.getElementById("statHighestRisk");
const riskLevel = document.getElementById("riskLevel");
const securityAlerts = document.getElementById("securityAlerts");

const riskCircle = document.getElementById("riskCircle");
const riskNumber = document.getElementById("riskNumber");
const riskStatus = document.getElementById("riskStatus");

const riskSummaryCurrent = document.getElementById("riskSummaryCurrent");
const riskSummaryHighest = document.getElementById("riskSummaryHighest");
const riskSummaryTrend = document.getElementById("riskSummaryTrend");
const riskSummaryCurrentLevel = document.getElementById("riskSummaryCurrentLevel");
const riskSummaryHighestLevel = document.getElementById("riskSummaryHighestLevel");
const riskSummaryTrendDetail = document.getElementById("riskSummaryTrendDetail");

const eventsTableBody = document.getElementById("eventsTableBody");
const processTableBody = document.getElementById("processTableBody");
const processSearch = document.getElementById("processSearch");
const networkTableBody = document.getElementById("networkTableBody");
const networkSearch = document.getElementById("networkSearch");

const processCount = document.getElementById("processCount");
const networkCount = document.getElementById("networkCount");
const lastUpdated = document.getElementById("lastUpdated");

const hostname = document.getElementById("hostname");
const operatingSystem = document.getElementById("operatingSystem");
const osVersion = document.getElementById("osVersion");
const username = document.getElementById("username");

const alertsContainer = document.getElementById("alertsContainer");
const alertCountBadge = document.getElementById("alertCountBadge");

// IMPORTANT:
// The HTML button uses id="refreshBtn"
const refreshButton = document.getElementById("refreshBtn");

// Risk History Chart
const riskHistoryCanvas = document.getElementById("riskHistoryChart");
let riskHistoryChart = null;


// ===============================
// API HELPER
// ===============================

async function fetchAPI(endpoint) {

    try {

        const response = await fetch(API_BASE + endpoint);

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status} while requesting ${endpoint}`
            );
        }

        return await response.json();

    } catch (error) {

        console.error(`API Error [${endpoint}]:`, error);

        return null;
    }
}


// ===============================
// SYSTEM STATUS
// ===============================

async function loadStatus() {

    const data = await fetchAPI("/api/status");

    if (!data) {
        return;
    }

    if (systemStatus) {

        const status =
            data.status ||
            data.system_status ||
            "UNKNOWN";

        systemStatus.textContent = String(status).toUpperCase();
    }

    if (totalEvents) {

        totalEvents.textContent =
            data.total_events ??
            data.event_count ??
            data.total ??
            0;
    }
}


// ===============================
// SYSTEM INFORMATION
// ===============================

async function loadSystemInfo() {

    const data = await fetchAPI("/api/system");

    if (!data) {
        return;
    }

    if (hostname) {
        hostname.textContent =
            data.hostname || "Unknown";
    }

    if (operatingSystem) {
        operatingSystem.textContent =
            data.operating_system ||
            data.os ||
            "Unknown";
    }

    if (osVersion) {
        osVersion.textContent =
            data.os_version ||
            data.version ||
            "Unknown";
    }

    if (username) {
        username.textContent =
            data.username ||
            "Unknown";
    }
}


// ===============================
// RISK
// ===============================

async function loadRisk() {

    const data = await fetchAPI("/api/risk");

    if (!data) {
        return;
    }

    const currentRisk =
        Number(data.current_risk ?? data.current ?? 0);

    const highestRisk =
        Number(data.highest_risk ?? data.highest ?? 0);

    updateRiskDisplay(currentRisk);

    updateRiskSummary(
        currentRisk,
        highestRisk
    );
}


// ===============================
// RISK LEVEL
// ===============================

function getRiskLevel(score) {

    score = Number(score) || 0;

    if (score >= 90) {
        return "CRITICAL";
    }

    if (score >= 70) {
        return "HIGH";
    }

    if (score >= 40) {
        return "MEDIUM";
    }

    if (score >= 20) {
        return "LOW";
    }

    return "NORMAL";
}


// ===============================
// RISK DISPLAY
// ===============================

function updateRiskDisplay(score) {

    score = Number(score) || 0;

    const level = getRiskLevel(score);

    if (riskScore) {
        riskScore.textContent = `${score}/100`;
    }

    if (riskLevel) {
        riskLevel.textContent = level;
    }

    if (riskNumber) {
        riskNumber.textContent = score;
    }

    if (riskStatus) {
        riskStatus.textContent = level;
    }

    if (riskCircle) {

        riskCircle.classList.remove(
            "normal",
            "low",
            "medium",
            "high",
            "critical"
        );

        riskCircle.classList.add(
            level.toLowerCase()
        );
    }
}


// ===============================
// RISK SUMMARY
// ===============================

function updateRiskSummary(
    currentRisk,
    highestRisk
) {

    currentRisk = Number(currentRisk) || 0;
    highestRisk = Number(highestRisk) || 0;

    const currentLevel =
        getRiskLevel(currentRisk);

    const highestLevel =
        getRiskLevel(highestRisk);

    if (riskSummaryCurrent) {

        riskSummaryCurrent.textContent =
            `${currentRisk}/100`;
    }

    if (riskSummaryHighest) {

        riskSummaryHighest.textContent =
            `${highestRisk}/100`;
    }

    if (riskSummaryCurrentLevel) {

        riskSummaryCurrentLevel.textContent =
            currentLevel;
    }

    if (riskSummaryHighestLevel) {

        riskSummaryHighestLevel.textContent =
            highestLevel;
    }
}


// ===============================
// SECURITY ALERTS
// ===============================

async function loadAlerts() {

    const data = await fetchAPI("/api/alerts");

    if (!data) {
        return;
    }

    let alerts = [];

    if (Array.isArray(data)) {

        alerts = data;

    } else if (Array.isArray(data.alerts)) {

        alerts = data.alerts;
    }

    // Main alert count
    if (securityAlerts) {

        securityAlerts.textContent =
            alerts.length;
    }

    // Visible badge
    if (alertCountBadge) {

        alertCountBadge.textContent =
            `${alerts.length} ALERT${alerts.length === 1 ? "" : "S"}`;
    }

    if (!alertsContainer) {
        return;
    }

    alertsContainer.innerHTML = "";

    if (alerts.length === 0) {

        alertsContainer.innerHTML = `
            <div class="empty-state">
                No security alerts detected.
            </div>
        `;

        return;
    }

    alerts
        .slice(0, 20)
        .forEach(alert => {

            alertsContainer.innerHTML +=
                createAlertHTML(alert);
        });
}


// ===============================
// CREATE ALERT HTML
// ===============================

function createAlertHTML(alert) {

    let id = "â€”";
    let timestamp = "â€”";
    let severity = "INFO";
    let process = "â€”";
    let message = "â€”";
    let risk = 0;

    if (Array.isArray(alert)) {

        id = alert[0] ?? "â€”";
        timestamp = alert[1] ?? "â€”";
        severity = alert[2] ?? "INFO";
        process = alert[3] ?? "â€”";
        message = alert[4] ?? "â€”";
        risk = Number(alert[5]) || 0;

    } else if (alert && typeof alert === "object") {

        id =
            alert.id ??
            alert.event_id ??
            "â€”";

        timestamp =
            alert.timestamp ??
            "â€”";

        severity =
            alert.severity ??
            "INFO";

        process =
            alert.process ??
            "â€”";

        message =
            alert.message ??
            "â€”";

        risk =
            Number(
                alert.risk_score ??
                alert.riskScore ??
                alert.risk ??
                0
            ) || 0;
    }

    const safeSeverity =
        String(severity).toUpperCase();

    return `
        <div
            class="alert-card ${safeSeverity.toLowerCase()}"
            onclick="showThreatDetails(
                ${JSON.stringify(String(id))},
                ${JSON.stringify(String(timestamp))},
                ${JSON.stringify(String(safeSeverity))},
                ${JSON.stringify(String(process))},
                ${JSON.stringify(String(message))},
                ${risk}
            )"
            style="cursor: pointer;"
        >

            <div class="alert-card-header">

                <span class="alert-severity">
                    ${escapeHTML(safeSeverity)}
                </span>

                <span class="alert-risk">
                    Risk: ${risk}/100
                </span>

            </div>

            <div class="alert-process">
                ${escapeHTML(String(process))}
            </div>

            <div class="alert-message">
                ${escapeHTML(String(message))}
            </div>

            <div class="alert-meta">

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


// ===============================
// EVENT HISTORY
// ===============================

async function loadEvents() {

    const data = await fetchAPI("/api/events");

    if (!data) {
        return;
    }

    let events = [];

    if (Array.isArray(data)) {

        events = data;

    } else if (Array.isArray(data.events)) {

        events = data.events;
    }

    if (!eventsTableBody) {
        return;
    }

    eventsTableBody.innerHTML = "";

    if (events.length === 0) {

        eventsTableBody.innerHTML = `
            <tr>
                <td colspan="7">
                    No events available.
                </td>
            </tr>
        `;

        return;
    }

    events
        .slice(0, 50)
        .forEach(event => {

            eventsTableBody.innerHTML +=
                createEventRow(event);
        });

    updateRiskHistory(events);

    updateRiskTrend(events);
}


// ===============================
// EVENT HELPERS
// ===============================

function getEventRisk(event) {

    if (Array.isArray(event)) {

        return Number(event[6]) || 0;
    }

    if (event && typeof event === "object") {

        return Number(
            event.risk_score ??
            event.riskScore ??
            event.risk ??
            0
        ) || 0;
    }

    return 0;
}


function getEventTimestamp(event) {

    if (Array.isArray(event)) {

        return event[1] || "";
    }

    if (event && typeof event === "object") {

        return event.timestamp || "";
    }

    return "";
}


// ===============================
// CREATE EVENT ROW
// ===============================

function createEventRow(event) {

    let id = "â€”";
    let timestamp = "â€”";
    let eventType = "â€”";
    let severity = "â€”";
    let process = "â€”";
    let message = "â€”";
    let risk = 0;

    if (Array.isArray(event)) {

        id = event[0] ?? "â€”";
        timestamp = event[1] ?? "â€”";
        eventType = event[2] ?? "â€”";
        severity = event[3] ?? "â€”";
        process = event[4] ?? "â€”";
        message = event[5] ?? "â€”";
        risk = Number(event[6]) || 0;

    } else if (event && typeof event === "object") {

        id =
            event.id ??
            event.event_id ??
            "â€”";

        timestamp =
            event.timestamp ??
            "â€”";

        eventType =
            event.event_type ??
            event.eventType ??
            "â€”";

        severity =
            event.severity ??
            "â€”";

        process =
            event.process ??
            "â€”";

        message =
            event.message ??
            "â€”";

        risk =
            Number(
                event.risk_score ??
                event.riskScore ??
                event.risk ??
                0
            ) || 0;
    }

    return `
        <tr>

            <td>
                ${escapeHTML(String(id))}
            </td>

            <td>
                ${escapeHTML(String(timestamp))}
            </td>

            <td>
                ${escapeHTML(String(eventType))}
            </td>

            <td>
                ${escapeHTML(String(severity))}
            </td>

            <td>
                ${escapeHTML(String(process ?? "â€”"))}
            </td>

            <td>
                ${escapeHTML(String(message))}
            </td>

            <td>
                ${risk}/100
            </td>

        </tr>
    `;
}


// ===============================
// RISK HISTORY CHART
// ===============================

function updateRiskHistory(events) {

    if (!riskHistoryCanvas) {

        console.warn(
            "Risk History canvas not found."
        );

        return;
    }

    // Chart.js is loaded in index.html
    if (typeof Chart === "undefined") {

        console.error(
            "Chart.js is not loaded."
        );

        return;
    }

    const points = events
        .map(event => {

            return {
                timestamp: getEventTimestamp(event),
                risk: getEventRisk(event)
            };

        })
        .filter(point => {

            return (
                point.timestamp &&
                Number.isFinite(point.risk)
            );

        })
        .slice(0, 30)
        .reverse();

    if (points.length === 0) {

        console.warn(
            "No risk history data available."
        );

        return;
    }

    const labels =
        points.map(point => point.timestamp);

    const values =
        points.map(point => {

            return Math.max(
                0,
                Math.min(
                    100,
                    point.risk
                )
            );

        });

    const chartData = {

        labels: labels,

        datasets: [

            {
                label: "Risk Score",

                data: values,

                borderColor: "#00e5a0",

                backgroundColor:
                    "rgba(0, 229, 160, 0.10)",

                borderWidth: 2,

                fill: true,

                tension: 0.35,

                pointRadius: 3,

                pointHoverRadius: 5
            }

        ]
    };


    const chartOptions = {

        responsive: true,

        maintainAspectRatio: false,

        animation: false,

        interaction: {

            intersect: false,

            mode: "index"
        },

        scales: {

            y: {

                min: 0,

                max: 100,

                ticks: {

                    stepSize: 20
                },

                title: {

                    display: true,

                    text: "Risk Score"
                }
            },

            x: {

                ticks: {

                    maxTicksLimit: 8,

                    autoSkip: true,

                    callback: function(value) {

                        const label =
                            this.getLabelForValue(value);

                        if (!label) {
                            return "";
                        }

                        // Show HH:MM:SS
                        if (label.length >= 19) {

                            return label.substring(
                                11,
                                19
                            );
                        }

                        return label;
                    }
                },

                title: {

                    display: true,

                    text: "Time"
                }
            }
        },

        plugins: {

            legend: {

                display: true
            },

            tooltip: {

                callbacks: {

                    title: function(items) {

                        if (!items.length) {
                            return "";
                        }

                        return items[0].label;
                    },

                    label: function(context) {

                        return `Risk: ${context.parsed.y}/100`;
                    }
                }
            }
        }
    };


    // Update existing chart
    if (riskHistoryChart) {

        riskHistoryChart.data =
            chartData;

        riskHistoryChart.options =
            chartOptions;

        riskHistoryChart.update("none");

        return;
    }


    // Create chart for first time
    riskHistoryChart =
        new Chart(
            riskHistoryCanvas,
            {
                type: "line",

                data: chartData,

                options: chartOptions
            }
        );
}


// ===============================
// RISK TREND
// ===============================

function updateRiskTrend(events) {

    if (!events || events.length === 0) {

        return;
    }

    const risks = events
        .map(event => getEventRisk(event))
        .filter(risk => Number.isFinite(risk));


    if (risks.length < 2) {

        return;
    }


    const recent =
        risks.slice(0, 5);

    const previous =
        risks.slice(5, 10);


    if (previous.length === 0) {

        return;
    }


    const recentAverage =
        recent.reduce(
            (sum, value) => sum + value,
            0
        ) / recent.length;


    const previousAverage =
        previous.reduce(
            (sum, value) => sum + value,
            0
        ) / previous.length;


    const difference =
        recentAverage - previousAverage;


    let trend = "STABLE";


    if (difference >= 10) {

        trend = "RISING";

    } else if (difference <= -10) {

        trend = "FALLING";
    }


    if (riskSummaryTrend) {

        riskSummaryTrend.textContent =
            trend;
    }


    if (riskSummaryTrendDetail) {

        if (trend === "RISING") {

            riskSummaryTrendDetail.textContent =
                `Risk increased by ${Math.abs(Math.round(difference))} points`;

        } else if (trend === "FALLING") {

            riskSummaryTrendDetail.textContent =
                `Risk decreased by ${Math.abs(Math.round(difference))} points`;

        } else {

            riskSummaryTrendDetail.textContent =
                "Risk remains stable";
        }
    }
}


// ===============================
// RUNNING PROCESSES
// ===============================

async function loadProcesses() {

    const data = await fetchAPI("/api/processes");

    if (!data) {
        return;
    }

    let processes = [];

    if (Array.isArray(data)) {

        processes = data;

    } else if (Array.isArray(data.processes)) {

        processes = data.processes;
    }


    if (processCount) {

        processCount.textContent =
            processes.length;
    }


    if (!processTableBody) {
        return;
    }


    processTableBody.innerHTML = "";


    if (processes.length === 0) {

        processTableBody.innerHTML = `
            <tr>
                <td colspan="4">
                    No process information available.
                </td>
            </tr>
        `;

        return;
    }


    processes
        .slice(0, 100)
        .forEach(process => {

            processTableBody.innerHTML +=
                createProcessRow(process);
        });
}


// ===============================
// PROCESS ROW
// ===============================

function createProcessRow(process) {

    let pid = "â€”";
    let name = "â€”";
    let memory = "â€”";
    let status = "â€”";


    if (Array.isArray(process)) {

        pid = process[0] ?? "â€”";
        name = process[1] ?? "â€”";
        memory = process[2] ?? "â€”";
        status = process[3] ?? "â€”";

    } else if (
        process &&
        typeof process === "object"
    ) {

        pid =
            process.pid ??
            "â€”";

        name =
            process.name ??
            process.process ??
            "â€”";

        memory =
            process.memory ??
            process.memory_usage ??
            "â€”";

        status =
            process.status ??
            "â€”";
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
                ${escapeHTML(formatMemory(memory))}
            </td>

            <td>
                ${escapeHTML(String(status))}
            </td>

        </tr>
    `;
}


// ===============================
// MEMORY FORMAT
// ===============================

function formatMemory(memory) {

    if (
        memory === null ||
        memory === undefined ||
        memory === ""
    ) {

        return "â€”";
    }


    if (!isNaN(memory)) {

        return `${memory} KB`;
    }


    return String(memory);
}


// ===============================
// NETWORK
// ===============================

async function loadNetwork() {

    const data = await fetchAPI("/api/network");

    if (!data) {
        return;
    }

    let connections = [];


    if (Array.isArray(data)) {

        connections = data;

    } else if (
        Array.isArray(data.connections)
    ) {

        connections = data.connections;
    }


    if (networkCount) {

        networkCount.textContent =
            connections.length;
    }


    if (!networkTableBody) {
        return;
    }


    networkTableBody.innerHTML = "";


    if (connections.length === 0) {

        networkTableBody.innerHTML = `
            <tr>
                <td colspan="5">
                    No network connections available.
                </td>
            </tr>
        `;

        return;
    }


    connections
        .slice(0, 100)
        .forEach(connection => {

            networkTableBody.innerHTML +=
                createNetworkRow(connection);
        });
}


// ===============================
// NETWORK ROW
// ===============================

function createNetworkRow(connection) {

    let protocol = "â€”";
    let localAddress = "â€”";
    let foreignAddress = "â€”";
    let pid = "â€”";
    let state = "â€”";


    if (Array.isArray(connection)) {

        protocol =
            connection[0] ?? "â€”";

        localAddress =
            connection[1] ?? "â€”";

        foreignAddress =
            connection[2] ?? "â€”";

        pid =
            connection[3] ?? "â€”";

        state =
            connection[4] ?? "â€”";

    } else if (
        connection &&
        typeof connection === "object"
    ) {

        protocol =
            connection.protocol ??
            "â€”";

        localAddress =
            connection.local_address ??
            connection.localAddress ??
            "â€”";

        foreignAddress =
            connection.foreign_address ??
            connection.foreignAddress ??
            "â€”";

        pid =
            connection.pid ??
            "â€”";

        state =
            connection.state ??
            "â€”";
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


// ===============================
// LAST UPDATED
// ===============================

function updateLastUpdated() {

    if (!lastUpdated) {
        return;
    }


    const now =
        new Date();


    lastUpdated.textContent =
        now.toLocaleTimeString();
}


// ===============================
// HTML SECURITY
// ===============================

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// ===============================
// REFRESH DASHBOARD
// ===============================

async function refreshDashboard() {

    console.log(
        "Refreshing SentinelX dashboard..."
    );


    await Promise.all([

        loadStatus(),

        loadSystemInfo(),

        loadRisk(),

        loadAlerts(),

        loadEvents(),

        loadProcesses(),

        loadNetwork()

    ]);


    updateLastUpdated();


    console.log(
        "SentinelX dashboard updated."
    );
}


// ===============================
// REFRESH BUTTON
// ===============================

if (refreshButton) {

    refreshButton.addEventListener(
        "click",
        refreshDashboard
    );
}


// ===============================
// INITIAL LOAD
// ===============================

// ===============================
// SECURITY STATISTICS
// ===============================

async function updateSecurityStatistics() {
    try {
        const [events, alerts, processes, network, risk] = await Promise.all([
            fetchAPI("/api/events"),
            fetchAPI("/api/alerts"),
            fetchAPI("/api/processes"),
            fetchAPI("/api/network"),
            fetchAPI("/api/risk")
        ]);

        // Total Events
        if (statTotalEvents) {
            statTotalEvents.textContent = Array.isArray(events)
                ? events.length
                : 0;
        }

        // Security Alerts
        if (statSecurityAlerts) {
            statSecurityAlerts.textContent = Array.isArray(alerts)
                ? alerts.length
                : 0;
        }

        // Running Processes
        const processList = Array.isArray(processes)
            ? processes
            : (processes?.processes || []);

        if (statProcesses) {
            statProcesses.textContent = processList.length;
        }

        // Network Connections
        const networkList = Array.isArray(network)
            ? network
            : (network?.connections || []);

        if (statNetwork) {
            statNetwork.textContent = networkList.length;
        }

        // Risk
        if (risk) {
            const currentRisk = Number(risk.current_risk ?? 0);
            const highestRisk = Number(risk.highest_risk ?? 0);

            if (statCurrentRisk) {
                statCurrentRisk.textContent = `${currentRisk}/100`;
            }

            if (statHighestRisk) {
                statHighestRisk.textContent = `${highestRisk}/100`;
            }
        }

    } catch (error) {
        console.error("Security statistics error:", error);
    }
}

// ===============================
// THREAT DETAILS POPUP
// ===============================

function showThreatDetails(
    id,
    timestamp,
    severity,
    process,
    message,
    risk
) {

    // Remove existing popup if one exists
    const existingPopup = document.getElementById("threatDetailsPopup");

    if (existingPopup) {
        existingPopup.remove();
    }

    const popup = document.createElement("div");

    popup.id = "threatDetailsPopup";

    popup.innerHTML = `
        <div class="threat-modal-overlay" onclick="closeThreatDetails(event)">

            <div class="threat-modal" onclick="event.stopPropagation()">

                <div class="threat-modal-header">

                    <div>
                        <h2>Threat Details</h2>
                        <p>SentinelX Security Alert</p>
                    </div>

                    <button
                        class="threat-close-btn"
                        onclick="closeThreatDetails()"
                    >
                        Ã—
                    </button>

                </div>

                <div class="threat-details-grid">

                    <div class="threat-detail-item">
                        <span>Severity</span>
                        <strong class="${String(severity).toLowerCase()}">
                            ${escapeHTML(String(severity))}
                        </strong>
                    </div>

                    <div class="threat-detail-item">
                        <span>Risk Score</span>
                        <strong>
                            ${Number(risk)}/100
                        </strong>
                    </div>

                    <div class="threat-detail-item">
                        <span>Process</span>
                        <strong>
                            ${escapeHTML(String(process))}
                        </strong>
                    </div>

                    <div class="threat-detail-item">
                        <span>Event ID</span>
                        <strong>
                            ${escapeHTML(String(id))}
                        </strong>
                    </div>

                    <div class="threat-detail-item full-width">
                        <span>Timestamp</span>
                        <strong>
                            ${escapeHTML(String(timestamp))}
                        </strong>
                    </div>

                    <div class="threat-detail-item full-width">
                        <span>Detection Message</span>
                        <strong>
                            ${escapeHTML(String(message))}
                        </strong>
                    </div>

                </div>

                <div class="threat-modal-footer">
                    <span class="threat-status">
                        â— Detected by SentinelX
                    </span>

                    <button
                        class="threat-ok-btn"
                        onclick="closeThreatDetails()"
                    >
                        Close
                    </button>
                </div>

            </div>

        </div>
    `;

    document.body.appendChild(popup);
}


function closeThreatDetails(event) {

    if (
        event &&
        event.target &&
        !event.target.classList.contains("threat-modal-overlay")
    ) {
        return;
    }

    const popup =
        document.getElementById("threatDetailsPopup");

    if (popup) {
        popup.remove();
    }
}

updateSecurityStatistics();

refreshDashboard();

// ===============================
// NETWORK SEARCH & FILTER
// ===============================

if (networkSearch) {
    networkSearch.addEventListener("input", function () {
        const searchText = this.value.toLowerCase().trim();

        const rows = networkTableBody.querySelectorAll("tr");

        rows.forEach(row => {
            const rowText = row.textContent.toLowerCase();

            if (rowText.includes(searchText)) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    });
}

// ===============================
// PROCESS SEARCH & FILTER
// ===============================

if (processSearch) {
    processSearch.addEventListener("input", function () {
        const searchText = this.value.toLowerCase().trim();

        const rows = processTableBody.querySelectorAll("tr");

        rows.forEach(row => {
            const rowText = row.textContent.toLowerCase();

            if (rowText.includes(searchText)) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    });
}

// ===============================
// AUTO REFRESH
// ===============================

setInterval(
    refreshDashboard,
    10000
);

// ===============================
// SECURITY REPORT
// ===============================

const reportButton =
    document.getElementById("reportBtn");

if (reportButton) {

    reportButton.href =
        API_BASE + "/api/report";

}

