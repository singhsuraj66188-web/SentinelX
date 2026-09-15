/* ============================================================
   SENTINELX DASHBOARD
   Cybersecurity Monitoring System
   ============================================================ */

"use strict";


/* ============================================================
   API CONFIGURATION
   ============================================================ */

const LOCAL_API = "http://127.0.0.1:5000";
const PRODUCTION_API = "https://sentinelx-os1m.onrender.com";

const isLocalEnvironment =
    window.location.protocol === "file:" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

let API_BASE =
    isLocalEnvironment
        ? LOCAL_API
        : PRODUCTION_API;


/* ============================================================
   GLOBAL STATE
   ============================================================ */

let currentProcesses = [];
let currentNetworkConnections = [];
let currentEvents = [];
let currentAlerts = [];

let currentRisk = 0;
let highestRisk = 0;

let totalEventCount = 0;

let riskChart = null;

let refreshInProgress = false;

let autoRefreshTimer = null;


/* ============================================================
   BASIC HELPERS
   ============================================================ */

function escapeHTML(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function firstDefined(...values) {

    for (const value of values) {

        if (
            value !== undefined &&
            value !== null &&
            value !== ""
        ) {
            return value;
        }
    }

    return "";
}


function toNumber(
    value,
    fallback = 0
) {

    if (
        typeof value === "number" &&
        Number.isFinite(value)
    ) {
        return value;
    }

    if (
        typeof value === "string"
    ) {

        const cleaned =
            value.replace(
                /[^\d.-]/g,
                ""
            );

        const parsed =
            Number(cleaned);

        if (
            Number.isFinite(parsed)
        ) {
            return parsed;
        }
    }

    return fallback;
}


function normalizeRisk(value) {

    const number =
        toNumber(
            value,
            0
        );

    return Math.max(
        0,
        Math.min(
            100,
            number
        )
    );
}


/* ============================================================
   API REQUEST
   ============================================================ */

async function requestAPI(
    baseURL,
    endpoint,
    options = {}
) {

    const response =
        await fetch(
            `${baseURL}${endpoint}`,
            {
                ...options,

                headers: {
                    "Accept":
                        "application/json, text/plain, */*",

                    ...(options.headers || {})
                }
            }
        );


    if (!response.ok) {

        throw new Error(
            `API request failed: ${response.status} ${response.statusText}`
        );
    }


    const contentType =
        response.headers.get(
            "content-type"
        ) || "";


    if (
        contentType.includes(
            "application/json"
        )
    ) {

        return await response.json();
    }


    const text =
        await response.text();


    try {

        return JSON.parse(text);

    } catch {

        return text;
    }
}


/* ============================================================
   API FETCH WITH AUTOMATIC FALLBACK
   ============================================================ */

async function fetchAPI(
    endpoint,
    options = {}
) {

    try {

        return await requestAPI(
            API_BASE,
            endpoint,
            options
        );

    } catch (primaryError) {

        console.warn(
            `Primary API failed: ${API_BASE}${endpoint}`,
            primaryError
        );


        if (
            API_BASE !== PRODUCTION_API
        ) {

            console.warn(
                "Switching to production API:",
                PRODUCTION_API
            );


            try {

                const data =
                    await requestAPI(
                        PRODUCTION_API,
                        endpoint,
                        options
                    );


                API_BASE =
                    PRODUCTION_API;


                console.log(
                    "SentinelX API fallback successful:",
                    API_BASE
                );


                return data;

            } catch (fallbackError) {

                console.error(
                    `Production API also failed: ${PRODUCTION_API}${endpoint}`,
                    fallbackError
                );


                throw fallbackError;
            }
        }


        throw primaryError;
    }
}


/* ============================================================
   ARRAY NORMALIZATION
   ============================================================ */

function normalizeArray(data) {

    if (
        Array.isArray(data)
    ) {
        return data;
    }


    if (
        !data ||
        typeof data !== "object"
    ) {
        return [];
    }


    if (
        Array.isArray(data.value)
    ) {
        return data.value;
    }


    if (
        Array.isArray(data.data)
    ) {
        return data.data;
    }


    if (
        Array.isArray(data.results)
    ) {
        return data.results;
    }


    if (
        Array.isArray(data.events)
    ) {
        return data.events;
    }


    if (
        Array.isArray(data.alerts)
    ) {
        return data.alerts;
    }


    if (
        Array.isArray(data.processes)
    ) {
        return data.processes;
    }


    if (
        Array.isArray(data.network)
    ) {
        return data.network;
    }


    if (
        Array.isArray(data.connections)
    ) {
        return data.connections;
    }


    return [];
}


/* ============================================================
   RISK LEVEL
   ============================================================ */

function getRiskLevel(score) {

    const risk =
        normalizeRisk(score);


    if (risk >= 90) {
        return "CRITICAL";
    }


    if (risk >= 75) {
        return "HIGH";
    }


    if (risk >= 50) {
        return "MEDIUM";
    }


    if (risk >= 20) {
        return "LOW";
    }


    return "INFO";
}


/* ============================================================
   RECOMMENDED ACTION
   ============================================================ */

function getRecommendedAction(alert) {

    const risk =
        normalizeRisk(
            alert?.risk_score
        );

    const severity =
        String(
            alert?.severity ||
            getRiskLevel(risk) ||
            "INFO"
        ).toUpperCase();

    const process =
        String(
            alert?.process ||
            ""
        ).toLowerCase();


    if (
        severity === "CRITICAL" ||
        risk >= 90
    ) {

        return {

            title:
                "Immediate Response Required",

            text:
                "Isolate the affected system if necessary and investigate the process, parent process, command line, and related network activity immediately."
        };
    }


    if (
        severity === "HIGH" ||
        risk >= 75
    ) {

        return {

            title:
                "Investigate Immediately",

            text:
                "Investigate this process and its parent process. Verify whether the execution was authorized and review related system and network activity."
        };
    }


    if (
        severity === "MEDIUM" ||
        risk >= 50
    ) {

        return {

            title:
                "Investigate Activity",

            text:
                "Review the process execution, parent process, command line, and recent events. Confirm whether the activity is expected."
        };
    }


    if (
        process === "rundll32.exe"
    ) {

        return {

            title:
                "Monitor & Verify",

            text:
                "Verify whether rundll32.exe was launched by a trusted application. If the activity repeats or becomes suspicious, investigate its parent process and command line."
        };
    }


    if (
        process === "wscript.exe" ||
        process === "cscript.exe" ||
        process === "mshta.exe" ||
        process === "regsvr32.exe"
    ) {

        return {

            title:
                "Monitor and Investigate",

            text:
                "Verify whether this process was intentionally launched. Review its parent process, command line, and recent security events for suspicious behavior."
        };
    }


    return {

        title:
            "Monitor & Verify",

        text:
            "Monitor this activity and verify that the detected process was initiated by a trusted application."
    };
}


/* ============================================================
   ALERT NORMALIZATION
   ============================================================ */

function normalizeAlertItem(item) {

    if (
        Array.isArray(item)
    ) {

        /*
            Normal alert:

            [
                id,
                timestamp,
                severity,
                process,
                message,
                risk
            ]

            Legacy alert:

            [
                timestamp,
                severity,
                process,
                message,
                risk
            ]
        */


        if (
            item.length >= 6
        ) {

            return {

                id:
                    item[0],

                timestamp:
                    item[1],

                severity:
                    item[2],

                process:
                    item[3],

                message:
                    item[4],

                risk_score:
                    normalizeRisk(
                        item[5]
                    )
            };
        }


        if (
            item.length === 5
        ) {

            return {

                id:
                    "",

                timestamp:
                    item[0],

                severity:
                    item[1],

                process:
                    item[2],

                message:
                    item[3],

                risk_score:
                    normalizeRisk(
                        item[4]
                    )
            };
        }


        return {

            id:
                item[0] || "",

            timestamp:
                item[1] || "",

            severity:
                item[2] || "INFO",

            process:
                item[3] || "",

            message:
                item[4] || "",

            risk_score:
                normalizeRisk(
                    item[5]
                )
        };
    }


    if (
        item &&
        typeof item === "object"
    ) {

        const risk =
            firstDefined(
                item.risk_score,
                item.risk,
                item.score,
                item.riskScore
            );


        return {

            id:
                firstDefined(
                    item.id,
                    item.event_id,
                    item.alert_id
                ),

            timestamp:
                firstDefined(
                    item.timestamp,
                    item.time,
                    item.created_at,
                    item.date
                ),

            severity:
                firstDefined(
                    item.severity,
                    item.level,
                    item.priority
                ) || "INFO",

            process:
                firstDefined(
                    item.process,
                    item.process_name,
                    item.processName,
                    item.name
                ),

            message:
                firstDefined(
                    item.message,
                    item.reason,
                    item.description,
                    item.alert_message
                ),

            risk_score:
                normalizeRisk(risk)
        };
    }


    return {

        id: "",

        timestamp: "",

        severity: "INFO",

        process: "",

        message: "",

        risk_score: 0
    };
}


/* ============================================================
   EVENT NORMALIZATION
   ============================================================ */

function normalizeEventItem(item) {

    if (
        Array.isArray(item)
    ) {

        if (
            item.length >= 7
        ) {

            return {

                id:
                    item[0],

                timestamp:
                    item[1],

                event_type:
                    item[2],

                severity:
                    item[3],

                process:
                    item[4],

                message:
                    item[5],

                risk_score:
                    normalizeRisk(
                        item[6]
                    )
            };
        }


        return {

            id:
                item[0] || "",

            timestamp:
                item[1] || "",

            event_type:
                item[2] || "EVENT",

            severity:
                item[3] || "INFO",

            process:
                item[4] || "",

            message:
                item[5] || "",

            risk_score:
                normalizeRisk(
                    item[6]
                )
        };
    }


    if (
        item &&
        typeof item === "object"
    ) {

        return {

            id:
                firstDefined(
                    item.id,
                    item.event_id
                ),

            timestamp:
                firstDefined(
                    item.timestamp,
                    item.time,
                    item.created_at,
                    item.date
                ),

            event_type:
                firstDefined(
                    item.event_type,
                    item.type,
                    item.event
                ) || "EVENT",

            severity:
                firstDefined(
                    item.severity,
                    item.level
                ) || "INFO",

            process:
                firstDefined(
                    item.process,
                    item.process_name,
                    item.processName
                ),

            message:
                firstDefined(
                    item.message,
                    item.description,
                    item.reason
                ),

            risk_score:
                normalizeRisk(
                    firstDefined(
                        item.risk_score,
                        item.risk,
                        item.score
                    )
                )
        };
    }


    return {

        id: "",

        timestamp: "",

        event_type: "EVENT",

        severity: "INFO",

        process: "",

        message: "",

        risk_score: 0
    };
}


/* ============================================================
   PROCESS NORMALIZATION
   ============================================================ */

function normalizeProcessItem(item) {

    if (
        Array.isArray(item)
    ) {

        return {

            pid:
                firstDefined(
                    item[0],
                    ""
                ),

            name:
                firstDefined(
                    item[1],
                    ""
                ),

            memory:
                firstDefined(
                    item[2],
                    ""
                ),

            status:
                firstDefined(
                    item[3],
                    ""
                )
        };
    }


    if (
        item &&
        typeof item === "object"
    ) {

        const processObject =
            item.process &&
            typeof item.process === "object"
                ? item.process
                : item;


        let memory =
            firstDefined(
                processObject.memory,
                processObject.memory_mb,
                processObject.memory_usage,
                processObject.memoryUsage,
                processObject.ram,
                processObject.rss
            );


        if (
            memory &&
            typeof memory === "object"
        ) {

            memory =
                firstDefined(
                    memory.mb,
                    memory.value,
                    memory.rss
                );
        }


        return {

            pid:
                firstDefined(
                    processObject.pid,
                    processObject.process_id,
                    processObject.processId,
                    processObject.id
                ),

            name:
                firstDefined(
                    processObject.name,
                    processObject.process,
                    processObject.process_name,
                    processObject.processName
                ),

            memory:
                memory,

            status:
                firstDefined(
                    processObject.status,
                    processObject.state
                )
        };
    }


    return {

        pid: "",

        name: "",

        memory: "",

        status: ""
    };
}


/* ============================================================
   NETWORK NORMALIZATION
   ============================================================ */

function normalizeNetworkItem(item) {

    if (
        Array.isArray(item)
    ) {

        return {

            protocol:
                firstDefined(
                    item[0],
                    ""
                ),

            local:
                firstDefined(
                    item[1],
                    ""
                ),

            foreign:
                firstDefined(
                    item[2],
                    ""
                ),

            pid:
                firstDefined(
                    item[3],
                    ""
                ),

            state:
                firstDefined(
                    item[4],
                    ""
                )
        };
    }


    if (
        item &&
        typeof item === "object"
    ) {

        return {

            protocol:
                firstDefined(
                    item.protocol,
                    item.proto
                ),

            local:
                firstDefined(
                    item.local,
                    item.local_address,
                    item.localAddress
                ),

            foreign:
                firstDefined(
                    item.foreign,
                    item.remote,
                    item.remote_address,
                    item.foreign_address,
                    item.foreignAddress
                ),

            pid:
                firstDefined(
                    item.pid,
                    item.process_id,
                    item.processId
                ),

            state:
                firstDefined(
                    item.state,
                    item.status
                )
        };
    }


    return {

        protocol: "",

        local: "",

        foreign: "",

        pid: "",

        state: ""
    };
}


/* ============================================================
   LOAD STATUS
   ============================================================ */

async function loadStatus() {

    try {

        const data =
            await fetchAPI(
                "/api/status"
            );


        const statusElement =
            document.getElementById(
                "systemStatus"
            );


        if (statusElement) {

            const statusValue =
                firstDefined(
                    data?.status,
                    data?.system_status,
                    data?.systemStatus
                );


            const online =
                data?.online === true ||
                String(
                    statusValue
                ).toLowerCase() ===
                "online";


            if (online) {

                statusElement.innerHTML = `
                    <span class="status-dot"></span>
                    <strong>ONLINE</strong>
                    <small>SentinelX monitoring engine</small>
                `;

            } else if (statusValue) {

                statusElement.innerHTML = `
                    <span class="status-dot"></span>
                    <strong>${escapeHTML(
                        String(
                            statusValue
                        ).toUpperCase()
                    )}</strong>
                `;
            }
        }


        const possibleTotal =
            firstDefined(
                data?.total_events,
                data?.totalEvents,
                data?.events_count,
                data?.event_count,
                data?.total_count
            );


        if (
            possibleTotal !== "" &&
            Number.isFinite(
                Number(
                    possibleTotal
                )
            )
        ) {

            totalEventCount =
                Number(
                    possibleTotal
                );
        }


        updateTotalEventDisplays();

    } catch (error) {

        console.error(
            "Status loading failed:",
            error
        );
    }
}


/* ============================================================
   TOTAL EVENT DISPLAY
   ============================================================ */

function updateTotalEventDisplays() {

    const total =
        totalEventCount > 0
            ? totalEventCount
            : currentEvents.length;


    const elements = [

        "totalEvents",

        "statTotalEvents"

    ];


    elements.forEach(
        id => {

            const element =
                document.getElementById(
                    id
                );


            if (element) {

                element.textContent =
                    total.toLocaleString();
            }
        }
    );
}


/* ============================================================
   SYSTEM INFORMATION
   ============================================================ */

async function loadSystemInfo() {

    try {

        const data =
            await fetchAPI(
                "/api/system"
            );


        const system =
            data?.system ||
            data?.data ||
            data ||
            {};


        const hostname =
            firstDefined(
                system.hostname,
                system.host,
                system.computer_name
            );


        const operatingSystem =
            firstDefined(
                system.operating_system,
                system.operatingSystem,
                system.os
            );


        const osVersion =
            firstDefined(
                system.os_version,
                system.osVersion,
                system.version
            );


        const username =
            firstDefined(
                system.username,
                system.user,
                system.user_name
            );


        const fields = {

            hostname,

            operatingSystem,

            osVersion,

            username
        };


        Object.entries(fields).forEach(
            ([id, value]) => {

                const element =
                    document.getElementById(
                        id
                    );


                if (
                    element &&
                    value !== ""
                ) {

                    element.textContent =
                        value;
                }
            }
        );

    } catch (error) {

        console.error(
            "System information loading failed:",
            error
        );
    }
}


/* ============================================================
   LOAD RISK
   ============================================================ */

async function loadRisk() {

    try {

        const data =
            await fetchAPI(
                "/api/risk"
            );


        const current =
            firstDefined(
                data?.current_risk,
                data?.currentRisk,
                data?.risk_score,
                data?.riskScore,
                data?.score
            );


        const highest =
            firstDefined(
                data?.highest_risk,
                data?.highestRisk,
                data?.max_risk,
                data?.maxRisk
            );


        if (
            current !== ""
        ) {

            currentRisk =
                normalizeRisk(
                    current
                );
        }


        if (
            highest !== ""
        ) {

            highestRisk =
                normalizeRisk(
                    highest
                );
        }


        if (
            highestRisk <
            currentRisk
        ) {

            highestRisk =
                currentRisk;
        }


        updateRiskDisplay();

    } catch (error) {

        console.error(
            "Risk loading failed:",
            error
        );


        const risks = [

            ...currentAlerts.map(
                alert =>
                    alert.risk_score
            ),

            ...currentEvents.map(
                event =>
                    event.risk_score
            )

        ];


        if (
            risks.length > 0
        ) {

            currentRisk =
                normalizeRisk(
                    risks[0]
                );


            highestRisk =
                Math.max(
                    currentRisk,
                    ...risks.map(
                        normalizeRisk
                    )
                );


            updateRiskDisplay();
        }
    }
}


/* ============================================================
   RISK DISPLAY
   ============================================================ */

function updateRiskDisplay() {

    const level =
        getRiskLevel(
            currentRisk
        );


    const highestLevel =
        getRiskLevel(
            highestRisk
        );


    const riskNumber =
        document.getElementById(
            "riskNumber"
        );


    if (riskNumber) {

        riskNumber.textContent =
            currentRisk;
    }


    const riskScore =
        document.getElementById(
            "riskScore"
        );


    if (riskScore) {

        riskScore.textContent =
            `${currentRisk}/100`;
    }


    const riskLevel =
        document.getElementById(
            "riskLevel"
        );


    if (riskLevel) {

        riskLevel.textContent =
            level;
    }


    const statCurrentRisk =
        document.getElementById(
            "statCurrentRisk"
        );


    if (statCurrentRisk) {

        statCurrentRisk.textContent =
            `${currentRisk}/100`;
    }


    const statHighestRisk =
        document.getElementById(
            "statHighestRisk"
        );


    if (statHighestRisk) {

        statHighestRisk.textContent =
            `${highestRisk}/100`;
    }


    const riskStatus =
        document.getElementById(
            "riskStatus"
        );


    if (riskStatus) {

        riskStatus.textContent =
            level;
    }


    const summaryCurrent =
        document.getElementById(
            "riskSummaryCurrent"
        );


    if (summaryCurrent) {

        summaryCurrent.textContent =
            `${currentRisk}/100`;
    }


    const summaryCurrentLevel =
        document.getElementById(
            "riskSummaryCurrentLevel"
        );


    if (summaryCurrentLevel) {

        summaryCurrentLevel.textContent =
            level;
    }


    const summaryHighest =
        document.getElementById(
            "riskSummaryHighest"
        );


    if (summaryHighest) {

        summaryHighest.textContent =
            `${highestRisk}/100`;
    }


    const summaryHighestLevel =
        document.getElementById(
            "riskSummaryHighestLevel"
        );


    if (summaryHighestLevel) {

        summaryHighestLevel.textContent =
            highestLevel;
    }


    updateRiskTrend();
}


/* ============================================================
   RISK TREND
   ============================================================ */

function updateRiskTrend() {

    const trendElement =
        document.getElementById(
            "riskSummaryTrend"
        );


    const detailElement =
        document.getElementById(
            "riskSummaryTrendDetail"
        );


    if (
        currentEvents.length < 2
    ) {

        if (trendElement) {

            trendElement.textContent =
                "STABLE";
        }


        if (detailElement) {

            detailElement.textContent =
                "Not enough history";
        }


        return;
    }


    const chronological =
        [
            ...currentEvents
        ].reverse();


    const latest =
        normalizeRisk(
            chronological[
                chronological.length - 1
            ].risk_score
        );


    const previous =
        normalizeRisk(
            chronological[
                chronological.length - 2
            ].risk_score
        );


    let trend =
        "STABLE";


    let detail =
        "No significant change";


    if (
        latest > previous
    ) {

        trend =
            "INCREASING";


        detail =
            `Risk increased from ${previous}/100 to ${latest}/100`;

    } else if (
        latest < previous
    ) {

        trend =
            "DECREASING";


        detail =
            `Risk decreased from ${previous}/100 to ${latest}/100`;
    }


    if (trendElement) {

        trendElement.textContent =
            trend;
    }


    if (detailElement) {

        detailElement.textContent =
            detail;
    }
}


/* ============================================================
   LOAD SECURITY ALERTS
   ============================================================ */

async function loadAlerts() {

    try {

        const data =
            await fetchAPI(
                "/api/alerts"
            );


        const rows =
            normalizeArray(
                data
            );


        currentAlerts =
            rows
                .map(
                    normalizeAlertItem
                )
                .filter(
                    alert =>
                        alert.message ||
                        alert.process ||
                        alert.timestamp
                );


        const alertCount =
            currentAlerts.length;


        const alertCountBadge =
            document.getElementById(
                "alertCountBadge"
            );


        const securityAlerts =
            document.getElementById(
                "securityAlerts"
            );


        const statSecurityAlerts =
            document.getElementById(
                "statSecurityAlerts"
            );


        if (alertCountBadge) {

            alertCountBadge.textContent =
                alertCount;
        }


        if (securityAlerts) {

            securityAlerts.textContent =
                alertCount;
        }


        if (statSecurityAlerts) {

            statSecurityAlerts.textContent =
                alertCount;
        }


        const container =
            document.getElementById(
                "alertsContainer"
            );


        if (!container) {

            console.error(
                "SentinelX: alertsContainer not found."
            );

            return;
        }


        if (
            currentAlerts.length === 0
        ) {

            container.innerHTML = `
                <div class="empty-state">
                    No security alerts detected.
                </div>
            `;

            return;
        }


        container.innerHTML =
            currentAlerts
                .map(
                    createAlertHTML
                )
                .join("");


        const detailButtons =
            container.querySelectorAll(
                ".alert-details-link"
            );


        console.log(
            "SentinelX: View Details buttons found:",
            detailButtons.length
        );


        detailButtons.forEach(
            button => {

                button.addEventListener(
                    "click",
                    event => {

                        event.preventDefault();

                        event.stopPropagation();


                        const index =
                            Number(
                                button.getAttribute(
                                    "data-alert-details"
                                )
                            );


                        console.log(
                            "SentinelX: View Details clicked:",
                            index
                        );


                        if (
                            Number.isNaN(index)
                        ) {

                            console.error(
                                "SentinelX: Invalid alert index:",
                                index
                            );

                            return;
                        }


                        const alert =
                            currentAlerts[index];


                        if (!alert) {

                            console.error(
                                "SentinelX: Alert not found:",
                                index
                            );

                            return;
                        }


                        console.log(
                            "SentinelX: Opening threat details:",
                            alert
                        );


                        showThreatDetails(
                            alert
                        );
                    }
                );
            }
        );

    } catch (error) {

        console.error(
            "Alerts loading failed:",
            error
        );
    }
}


/* ============================================================
   CREATE ALERT HTML
   ============================================================ */

function createAlertHTML(
    alert,
    index
) {

    const severity =
        String(
            alert.severity ||
            "INFO"
        ).toUpperCase();


    const risk =
        normalizeRisk(
            alert.risk_score
        );


    const process =
        alert.process ||
        "Unknown Process";


    const message =
        alert.message ||
        "Security alert detected";


    const timestamp =
        alert.timestamp ||
        "Unknown time";


    const severityClass =
        severity.toLowerCase();


    return `

        <div
            class="alert-item"
            data-alert-index="${index}"
            role="article"
        >

            <div class="alert-header">

                <span class="severity-badge ${escapeHTML(
                    severityClass
                )}">
                    ${escapeHTML(
                        severity
                    )}
                </span>

                <span class="alert-time">
                    ${escapeHTML(
                        timestamp
                    )}
                </span>

            </div>


            <div class="alert-process">
                ${escapeHTML(
                    process
                )}
            </div>


            <div class="alert-message">
                ${escapeHTML(
                    message
                )}
            </div>


            <div class="alert-footer">

                <span>
                    Risk: ${risk}/100
                </span>


                <button
                    type="button"
                    class="alert-details-link"
                    data-alert-details="${index}"
                    aria-label="View threat details for ${escapeHTML(process)}"
                >
                    View Details ›
                </button>

            </div>

        </div>

    `;
}


/* ============================================================
   THREAT DETAILS POPUP
   ============================================================ */

function showThreatDetails(
    alert
) {

    if (!alert) {
        return;
    }


    closeThreatDetails();


    const popup =
        document.createElement(
            "div"
        );


    popup.className =
        "threat-details-popup show";


    popup.id =
        "sentinelxThreatDetailsPopup";


    const severity =
        String(
            alert.severity ||
            "INFO"
        ).toUpperCase();


    const risk =
        normalizeRisk(
            alert.risk_score
        );


    const process =
        alert.process ||
        "Unknown Process";


    const timestamp =
        alert.timestamp ||
        "Unknown";


    const message =
        alert.message ||
        "No additional information available.";


    const id =
        alert.id !== undefined &&
        alert.id !== null &&
        alert.id !== ""
            ? alert.id
            : "N/A";


    const severityClass =
        severity.toLowerCase();


    const recommendedAction =
        getRecommendedAction(
            alert
        );


    popup.innerHTML = `

        <div
            class="threat-details-overlay"
            data-close-threat="true"
        >

            <div
                class="threat-details-content"
                role="dialog"
                aria-modal="true"
                aria-labelledby="threatDetailsTitle"
            >

                <button
                    type="button"
                    class="threat-details-close"
                    id="threatDetailsClose"
                    aria-label="Close threat details"
                >
                    ×
                </button>


                <div class="threat-details-header">

                    <div>

                        <div class="threat-details-label">
                            SECURITY ALERT
                        </div>

                        <h2 id="threatDetailsTitle">
                            Threat Details
                        </h2>

                    </div>


                    <div class="threat-details-severity ${escapeHTML(
                        severityClass
                    )}">
                        ${escapeHTML(
                            severity
                        )}
                    </div>

                </div>


                <div class="threat-details-grid">

                    <div class="threat-detail-card">

                        <span class="threat-detail-label">
                            Event ID
                        </span>

                        <strong>
                            ${escapeHTML(
                                id
                            )}
                        </strong>

                    </div>


                    <div class="threat-detail-card">

                        <span class="threat-detail-label">
                            Risk Score
                        </span>

                        <strong class="threat-risk ${escapeHTML(
                            severityClass
                        )}">
                            ${risk}/100
                        </strong>

                    </div>


                    <div class="threat-detail-card">

                        <span class="threat-detail-label">
                            Timestamp
                        </span>

                        <strong>
                            ${escapeHTML(
                                timestamp
                            )}
                        </strong>

                    </div>


                    <div class="threat-detail-card">

                        <span class="threat-detail-label">
                            Process
                        </span>

                        <strong class="threat-process">
                            ${escapeHTML(
                                process
                            )}
                        </strong>

                    </div>


                    <div class="threat-detail-message full-width">

                        <span class="threat-detail-label">
                            Detection Message
                        </span>

                        <p>
                            ${escapeHTML(
                                message
                            )}
                        </p>

                    </div>


                    <div class="threat-recommended-action full-width">

                        <span class="threat-detail-label">
                            Recommended Action
                        </span>

                        <strong class="recommended-action-title">
                            ${escapeHTML(
                                recommendedAction.title
                            )}
                        </strong>

                        <p>
                            ${escapeHTML(
                                recommendedAction.text
                            )}
                        </p>

                    </div>

                </div>


                <div class="threat-details-actions">

                    <button
                        type="button"
                        id="threatDetailsCloseButton"
                    >
                        Close
                    </button>

                </div>

            </div>

        </div>

    `;


    document.body.appendChild(
        popup
    );


    const closeButton =
        document.getElementById(
            "threatDetailsClose"
        );


    const closeButtonBottom =
        document.getElementById(
            "threatDetailsCloseButton"
        );


    if (closeButton) {

        closeButton.addEventListener(
            "click",
            closeThreatDetails
        );
    }


    if (closeButtonBottom) {

        closeButtonBottom.addEventListener(
            "click",
            closeThreatDetails
        );
    }


    const overlay =
        popup.querySelector(
            ".threat-details-overlay"
        );


    if (overlay) {

        overlay.addEventListener(
            "click",
            event => {

                if (
                    event.target === overlay
                ) {

                    closeThreatDetails();
                }
            }
        );
    }


    document.body.style.overflow =
        "hidden";


    document.body.classList.add(
        "threat-popup-open"
    );


    setTimeout(
        () => {

            if (closeButton) {

                closeButton.focus();
            }

        },
        50
    );
}


/* ============================================================
   CLOSE THREAT DETAILS
   ============================================================ */

function closeThreatDetails() {

    const popup =
        document.getElementById(
            "sentinelxThreatDetailsPopup"
        );


    if (popup) {

        popup.remove();
    }


    document.body.style.overflow =
        "";


    document.body.classList.remove(
        "threat-popup-open"
    );
}


window.showThreatDetails =
    showThreatDetails;


window.closeThreatDetails =
    closeThreatDetails;


/* ============================================================
   LOAD EVENTS
   ============================================================ */

async function loadEvents() {

    try {

        const data =
            await fetchAPI(
                "/api/events"
            );


        const rows =
            normalizeArray(
                data
            );


        currentEvents =
            rows
                .map(
                    normalizeEventItem
                )
                .filter(
                    event =>
                        event.timestamp ||
                        event.message ||
                        event.event_type
                );


        updateTotalEventDisplays();

        updateEventsDisplay();

        updateRiskTrend();

        updateRiskChart();


        const eventRisks =
            currentEvents.map(
                event =>
                    normalizeRisk(
                        event.risk_score
                    )
            );


        if (
            eventRisks.length > 0
        ) {

            const maximum =
                Math.max(
                    ...eventRisks
                );


            if (
                maximum >
                highestRisk
            ) {

                highestRisk =
                    maximum;
            }


            if (
                currentRisk === 0
            ) {

                currentRisk =
                    normalizeRisk(
                        eventRisks[0]
                    );
            }
        }


        updateRiskDisplay();

    } catch (error) {

        console.error(
            "Events loading failed:",
            error
        );
    }
}


/* ============================================================
   EVENTS DISPLAY
   ============================================================ */

function updateEventsDisplay() {

    const tbody =
        document.getElementById(
            "eventsTableBody"
        );


    if (!tbody) {
        return;
    }


    if (
        currentEvents.length === 0
    ) {

        tbody.innerHTML = `
            <tr>
                <td colspan="7">
                    No events available.
                </td>
            </tr>
        `;

        return;
    }


    tbody.innerHTML =
        currentEvents
            .map(
                event => {

                    const risk =
                        normalizeRisk(
                            event.risk_score
                        );


                    return `

                        <tr>

                            <td>
                                ${escapeHTML(
                                    event.id || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    event.timestamp || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    event.event_type || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    event.severity || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    event.process || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    event.message || "-"
                                )}
                            </td>

                            <td>
                                ${risk}
                            </td>

                        </tr>

                    `;
                }
            )
            .join("");
}


/* ============================================================
   RISK HISTORY
   ============================================================ */

async function loadRiskHistory() {

    updateRiskChart();
}


/* ============================================================
   UPDATE RISK CHART
   ============================================================ */

function updateRiskChart() {

    const canvas =
        document.getElementById(
            "riskHistoryChart"
        );


    if (!canvas) {
        return;
    }


    if (riskChart) {

        try {

            riskChart.destroy();

        } catch (error) {

            console.warn(
                "Chart destroy warning:",
                error
            );
        }


        riskChart =
            null;
    }


    if (
        typeof Chart === "undefined"
    ) {

        console.warn(
            "Chart.js is not loaded."
        );

        return;
    }


    const chartEvents =
        [
            ...currentEvents
        ]
        .filter(
            event =>
                event.timestamp &&
                Number.isFinite(
                    Number(
                        event.risk_score
                    )
                )
        )
        .reverse();


    if (
        chartEvents.length === 0
    ) {

        const context =
            canvas.getContext(
                "2d"
            );


        if (context) {

            context.clearRect(
                0,
                0,
                canvas.width,
                canvas.height
            );
        }


        return;
    }


    const labels =
        chartEvents.map(
            event =>
                event.timestamp
        );


    const values =
        chartEvents.map(
            event =>
                normalizeRisk(
                    event.risk_score
                )
        );


    riskChart =
        new Chart(
            canvas.getContext(
                "2d"
            ),
            {

                type: "line",

                data: {

                    labels,

                    datasets: [

                        {

                            label:
                                "Risk Score",

                            data:
                                values,

                            fill:
                                true,

                            tension:
                                0.35,

                            pointRadius:
                                3,

                            pointHoverRadius:
                                5
                        }

                    ]
                },


                options: {

                    responsive:
                        true,

                    maintainAspectRatio:
                        false,


                    interaction: {

                        intersect:
                            false,

                        mode:
                            "index"
                    },


                    plugins: {

                        legend: {

                            display:
                                false
                        },


                        tooltip: {

                            callbacks: {

                                label:
                                    context =>
                                        `Risk: ${context.parsed.y}/100`
                            }
                        }
                    },


                    scales: {

                        y: {

                            beginAtZero:
                                true,

                            min:
                                0,

                            max:
                                100,

                            ticks: {

                                stepSize:
                                    20
                            },

                            title: {

                                display:
                                    true,

                                text:
                                    "Risk Score"
                            }
                        },


                        x: {

                            ticks: {

                                maxTicksLimit:
                                    6,

                                callback:
                                    function(value) {

                                        const label =
                                            this.getLabelForValue(
                                                value
                                            );


                                        if (!label) {
                                            return "";
                                        }


                                        return label.length > 16
                                            ? label.substring(
                                                11,
                                                16
                                            )
                                            : label;
                                    }
                            }
                        }
                    }
                }
            }
        );
}


/* ============================================================
   LOAD PROCESSES
   ============================================================ */

async function loadProcesses() {

    try {

        const data =
            await fetchAPI(
                "/api/processes"
            );


        const rows =
            normalizeArray(
                data
            );


        currentProcesses =
            rows.map(
                normalizeProcessItem
            );


        updateProcessesDisplay();


        const statProcesses =
            document.getElementById(
                "statProcesses"
            );


        if (statProcesses) {

            statProcesses.textContent =
                currentProcesses.length;
        }

    } catch (error) {

        console.error(
            "Processes loading failed:",
            error
        );
    }
}


/* ============================================================
   FORMAT MEMORY
   ============================================================ */

function formatMemory(
    memory
) {

    if (
        memory === null ||
        memory === undefined ||
        memory === ""
    ) {

        return "0";
    }


    if (
        typeof memory === "number"
    ) {

        return Number.isInteger(
            memory
        )
            ? String(memory)
            : memory.toFixed(2);
    }


    if (
        typeof memory === "string"
    ) {

        return memory;
    }


    return String(memory);
}


/* ============================================================
   PROCESS DISPLAY
   ============================================================ */

function updateProcessesDisplay(
    filteredProcesses = null
) {

    const tbody =
        document.getElementById(
            "processTableBody"
        );


    const countElement =
        document.getElementById(
            "processCount"
        );


    if (!tbody) {
        return;
    }


    const processes =
        filteredProcesses ||
        currentProcesses;


    if (countElement) {

        countElement.textContent =
            `${processes.length} PROCESSES`;
    }


    if (
        processes.length === 0
    ) {

        tbody.innerHTML = `
            <tr>
                <td colspan="4">
                    No matching processes.
                </td>
            </tr>
        `;

        return;
    }


    tbody.innerHTML =
        processes
            .map(
                process => {

                    const pid =
                        process.pid ||
                        "-";


                    const name =
                        process.name ||
                        "Unknown Process";


                    const memory =
                        formatMemory(
                            process.memory
                        );


                    const status =
                        process.status ||
                        "unknown";


                    return `

                        <tr>

                            <td>
                                ${escapeHTML(
                                    pid
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    name
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    memory
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    status
                                )}
                            </td>

                        </tr>

                    `;
                }
            )
            .join("");
}


/* ============================================================
   PROCESS SEARCH
   ============================================================ */

function setupProcessSearch() {

    const search =
        document.getElementById(
            "processSearch"
        );


    if (!search) {
        return;
    }


    search.addEventListener(
        "input",
        () => {

            const query =
                search.value
                    .trim()
                    .toLowerCase();


            if (!query) {

                updateProcessesDisplay();

                return;
            }


            const filtered =
                currentProcesses.filter(
                    process => {

                        const text =
                            [

                                process.pid,

                                process.name,

                                process.memory,

                                process.status

                            ]
                                .join(" ")
                                .toLowerCase();


                        return text.includes(
                            query
                        );
                    }
                );


            updateProcessesDisplay(
                filtered
            );
        }
    );
}


/* ============================================================
   LOAD NETWORK
   ============================================================ */

async function loadNetwork() {

    try {

        const data =
            await fetchAPI(
                "/api/network"
            );


        const rows =
            normalizeArray(
                data
            );


        currentNetworkConnections =
            rows.map(
                normalizeNetworkItem
            );


        updateNetworkDisplay();


        const statNetwork =
            document.getElementById(
                "statNetwork"
            );


        if (statNetwork) {

            statNetwork.textContent =
                currentNetworkConnections.length;
        }

    } catch (error) {

        console.error(
            "Network loading failed:",
            error
        );
    }
}


/* ============================================================
   NETWORK DISPLAY
   ============================================================ */

function updateNetworkDisplay(
    filteredConnections = null
) {

    const tbody =
        document.getElementById(
            "networkTableBody"
        );


    const countElement =
        document.getElementById(
            "networkCount"
        );


    const establishedElement =
        document.getElementById(
            "networkEstablished"
        );


    const listeningElement =
        document.getElementById(
            "networkListening"
        );


    if (!tbody) {
        return;
    }


    const connections =
        filteredConnections ||
        currentNetworkConnections;


    if (countElement) {

        countElement.textContent =
            `${currentNetworkConnections.length} CONNECTIONS`;
    }


    const established =
        currentNetworkConnections.filter(
            connection =>
                String(
                    connection.state ||
                    ""
                ).toUpperCase() ===
                "ESTABLISHED"
        ).length;


    const listening =
        currentNetworkConnections.filter(
            connection =>
                String(
                    connection.state ||
                    ""
                ).toUpperCase() ===
                "LISTENING"
        ).length;


    if (establishedElement) {

        establishedElement.textContent =
            established;
    }


    if (listeningElement) {

        listeningElement.textContent =
            listening;
    }


    if (
        connections.length === 0
    ) {

        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    No matching network connections.
                </td>
            </tr>
        `;

        return;
    }


    tbody.innerHTML =
        connections
            .map(
                connection => {

                    return `

                        <tr>

                            <td>
                                ${escapeHTML(
                                    connection.protocol || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    connection.local || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    connection.foreign || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    connection.pid || "-"
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    connection.state || "-"
                                )}
                            </td>

                        </tr>

                    `;
                }
            )
            .join("");
}


/* ============================================================
   NETWORK SEARCH
   ============================================================ */

function setupNetworkSearch() {

    const search =
        document.getElementById(
            "networkSearch"
        );


    if (!search) {
        return;
    }


    search.addEventListener(
        "input",
        () => {

            const query =
                search.value
                    .trim()
                    .toLowerCase();


            if (!query) {

                updateNetworkDisplay();

                return;
            }


            const filtered =
                currentNetworkConnections.filter(
                    connection => {

                        const text =
                            [

                                connection.protocol,

                                connection.local,

                                connection.foreign,

                                connection.pid,

                                connection.state

                            ]
                                .join(" ")
                                .toLowerCase();


                        return text.includes(
                            query
                        );
                    }
                );


            updateNetworkDisplay(
                filtered
            );
        }
    );
}


/* ============================================================
   REPORT GENERATION
   ============================================================ */

async function generateReport() {

    const button =
        document.querySelector(
            "[data-report]"
        );


    if (button) {

        button.disabled =
            true;

        button.dataset.originalText =
            button.textContent;

        button.textContent =
            "Generating...";
    }


    try {

        let reportText =
            "";


        try {

            const data =
                await fetchAPI(
                    "/api/report"
                );


            if (
                typeof data ===
                "string"
            ) {

                reportText =
                    data;

            } else if (
                data &&
                typeof data ===
                "object"
            ) {

                reportText =
                    data.report ||
                    data.content ||
                    data.text ||
                    JSON.stringify(
                        data,
                        null,
                        2
                    );
            }

        } catch (apiError) {

            console.warn(
                "API report unavailable. Creating local report.",
                apiError
            );
        }


        if (!reportText) {

            reportText =
                createLocalReport();
        }


        const blob =
            new Blob(
                [reportText],
                {
                    type:
                        "text/plain;charset=utf-8"
                }
            );


        const url =
            URL.createObjectURL(
                blob
            );


        const link =
            document.createElement(
                "a"
            );


        const timestamp =
            new Date()
                .toISOString()
                .replace(
                    /[:.]/g,
                    "-"
                );


        link.href =
            url;


        link.download =
            `SentinelX-Security-Report-${timestamp}.txt`;


        document.body.appendChild(
            link
        );


        link.click();


        link.remove();


        URL.revokeObjectURL(
            url
        );

    } catch (error) {

        console.error(
            "Report generation failed:",
            error
        );


        alert(
            "Unable to generate the security report."
        );

    } finally {

        if (button) {

            button.disabled =
                false;

            button.textContent =
                button.dataset.originalText ||
                "Generate Security Report";
        }
    }
}


/* ============================================================
   LOCAL REPORT
   ============================================================ */

function createLocalReport() {

    const lines = [];


    lines.push(
        "============================================================"
    );


    lines.push(
        "                 SENTINELX SECURITY REPORT"
    );


    lines.push(
        "          Cybersecurity Monitoring System"
    );


    lines.push(
        "============================================================"
    );


    lines.push("");


    lines.push(
        `Generated: ${new Date().toLocaleString()}`
    );


    lines.push(
        `API: ${API_BASE}`
    );


    lines.push("");


    lines.push(
        "-------------------- SECURITY SUMMARY --------------------"
    );


    lines.push(
        `Total Events: ${totalEventCount || currentEvents.length}`
    );


    lines.push(
        `Security Alerts: ${currentAlerts.length}`
    );


    lines.push(
        `Current Risk: ${currentRisk}/100 (${getRiskLevel(currentRisk)})`
    );


    lines.push(
        `Highest Risk: ${highestRisk}/100 (${getRiskLevel(highestRisk)})`
    );


    lines.push(
        `Running Processes: ${currentProcesses.length}`
    );


    lines.push(
        `Network Connections: ${currentNetworkConnections.length}`
    );


    lines.push("");


    lines.push(
        "-------------------- SECURITY ALERTS ---------------------"
    );


    currentAlerts.forEach(
        (alert, index) => {

            lines.push(
                `${index + 1}. ${alert.timestamp || "Unknown"}`
            );


            lines.push(
                `   Severity: ${alert.severity || "INFO"}`
            );


            lines.push(
                `   Process: ${alert.process || "Unknown"}`
            );


            lines.push(
                `   Risk: ${normalizeRisk(alert.risk_score)}/100`
            );


            lines.push(
                `   Message: ${alert.message || "N/A"}`
            );


            const recommendation =
                getRecommendedAction(
                    alert
                );


            lines.push(
                `   Recommended Action: ${recommendation.title}`
            );


            lines.push(
                `   Action Details: ${recommendation.text}`
            );


            lines.push("");
        }
    );


    lines.push(
        "-------------------- RECENT EVENTS -----------------------"
    );


    currentEvents.forEach(
        event => {

            lines.push(
                `${event.id || "-"} | ` +
                `${event.timestamp || "-"} | ` +
                `${event.event_type || "-"} | ` +
                `${event.severity || "-"} | ` +
                `${event.message || "-"} | ` +
                `Risk: ${normalizeRisk(event.risk_score)}/100`
            );
        }
    );


    lines.push("");


    lines.push(
        "============================================================"
    );


    lines.push(
        "                 End of SentinelX Report"
    );


    lines.push(
        "============================================================"
    );


    return lines.join(
        "\n"
    );
}


/* ============================================================
   REPORT BUTTON SETUP
   ============================================================ */

function setupReportButton() {

    const button =
        document.querySelector(
            "[data-report]"
        ) ||
        document.querySelector(
            "#generateReport"
        ) ||
        Array.from(
            document.querySelectorAll(
                "button"
            )
        ).find(
            element =>
                element.textContent
                    .toLowerCase()
                    .includes(
                        "generate security report"
                    )
        );


    if (!button) {
        return;
    }


    button.dataset.report =
        "true";


    button.addEventListener(
        "click",
        event => {

            event.preventDefault();

            generateReport();
        }
    );
}


/* ============================================================
   REFRESH DASHBOARD
   ============================================================ */

async function refreshDashboard() {

    if (refreshInProgress) {
        return;
    }


    refreshInProgress =
        true;


    const refreshButton =
        document.querySelector(
            "[data-refresh]"
        ) ||
        document.querySelector(
            "#refreshButton"
        ) ||
        Array.from(
            document.querySelectorAll(
                "button"
            )
        ).find(
            element =>
                element.textContent
                    .toLowerCase()
                    .includes(
                        "refresh"
                    )
        );


    if (refreshButton) {

        refreshButton.disabled =
            true;

        refreshButton.classList.add(
            "loading"
        );
    }


    try {

        await loadStatus();


        await Promise.allSettled([

            loadSystemInfo(),

            loadAlerts(),

            loadEvents(),

            loadRisk(),

            loadProcesses(),

            loadNetwork()

        ]);


        updateRiskChart();

        updateRiskTrend();

        updateRiskDisplay();

        updateTotalEventDisplays();

    } catch (error) {

        console.error(
            "Dashboard refresh failed:",
            error
        );

    } finally {

        refreshInProgress =
            false;


        if (refreshButton) {

            refreshButton.disabled =
                false;

            refreshButton.classList.remove(
                "loading"
            );
        }


        const lastUpdated =
            document.getElementById(
                "lastUpdated"
            );


        if (lastUpdated) {

            lastUpdated.textContent =
                new Date()
                    .toLocaleTimeString();
        }
    }
}


/* ============================================================
   GLOBAL REFRESH
   ============================================================ */

window.refreshDashboard =
    refreshDashboard;


/* ============================================================
   REFRESH BUTTON SETUP
   ============================================================ */

function setupRefreshButton() {

    const button =
        document.querySelector(
            "[data-refresh]"
        ) ||
        document.querySelector(
            "#refreshButton"
        ) ||
        Array.from(
            document.querySelectorAll(
                "button"
            )
        ).find(
            element =>
                element.textContent
                    .toLowerCase()
                    .includes(
                        "refresh"
                    )
        );


    if (!button) {
        return;
    }


    button.dataset.refresh =
        "true";


    button.addEventListener(
        "click",
        event => {

            event.preventDefault();

            refreshDashboard();
        }
    );
}


/* ============================================================
   NAVIGATION
   ============================================================ */

function setupNavigation() {

    const navigationLinks =
        document.querySelectorAll(
            'a[href^="#"]'
        );


    navigationLinks.forEach(
        link => {

            link.addEventListener(
                "click",
                event => {

                    const href =
                        link.getAttribute(
                            "href"
                        );


                    if (
                        !href ||
                        href === "#"
                    ) {

                        event.preventDefault();


                        window.scrollTo({

                            top:
                                0,

                            behavior:
                                "smooth"
                        });


                        return;
                    }


                    const target =
                        document.querySelector(
                            href
                        );


                    if (target) {

                        event.preventDefault();


                        target.scrollIntoView({

                            behavior:
                                "smooth",

                            block:
                                "start"
                        });
                    }
                }
            );
        }
    );
}


/* ============================================================
   THREAT DETAILS KEYBOARD HANDLING
   ============================================================ */

document.addEventListener(
    "keydown",
    event => {

        if (
            event.key ===
            "Escape"
        ) {

            const popup =
                document.getElementById(
                    "sentinelxThreatDetailsPopup"
                );


            if (popup) {

                closeThreatDetails();
            }
        }
    }
);


/* ============================================================
   ALERT KEYBOARD ACCESSIBILITY
   ============================================================ */

function setupAlertKeyboardHandling() {

    const container =
        document.getElementById(
            "alertsContainer"
        );


    if (!container) {
        return;
    }


    container.addEventListener(
        "keydown",
        function(event) {

            const button =
                event.target.closest(
                    ".alert-details-link"
                );


            if (!button) {
                return;
            }


            if (
                event.key === "Enter" ||
                event.key === " "
            ) {

                event.preventDefault();

                event.stopPropagation();


                const index =
                    Number(
                        button.getAttribute(
                            "data-alert-details"
                        )
                    );


                if (
                    !Number.isNaN(index) &&
                    currentAlerts[index]
                ) {

                    showThreatDetails(
                        currentAlerts[index]
                    );
                }
            }
        }
    );
}


/* ============================================================
   AUTO REFRESH
   ============================================================ */

function startAutoRefresh() {

    if (autoRefreshTimer) {

        clearInterval(
            autoRefreshTimer
        );
    }


    autoRefreshTimer =
        setInterval(
            () => {

                refreshDashboard();

            },
            10000
        );
}


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        console.log(
            "========================================"
        );


        console.log(
            "SentinelX Dashboard initialized."
        );


        console.log(
            "Initial API:",
            API_BASE
        );


        console.log(
            "Local API:",
            LOCAL_API
        );


        console.log(
            "Production API:",
            PRODUCTION_API
        );


        console.log(
            "========================================"
        );


        setupProcessSearch();

        setupNetworkSearch();

        setupRefreshButton();

        setupReportButton();

        setupNavigation();

        setupAlertKeyboardHandling();


        await refreshDashboard();


        startAutoRefresh();
    }
);