# SentinelX - Risk Scoring Engine


SEVERITY_SCORES = {
    "INFO": 0,
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100
}


def calculate_risk_score(alerts):
    """
    Calculate an overall risk score from detected alerts.
    The highest individual severity is used as the base score.
    Multiple alerts can increase the score slightly.
    """

    if not alerts:
        return 0

    scores = []

    for alert in alerts:
        severity = alert.get("severity", "INFO").upper()
        score = SEVERITY_SCORES.get(severity, 0)
        scores.append(score)

    highest_score = max(scores)

    # Small increase when multiple indicators are detected.
    additional_score = max(0, len(alerts) - 1) * 5

    final_score = min(100, highest_score + additional_score)

    return final_score


def get_risk_level(score):

    if score == 0:
        return "NORMAL"

    if score <= 25:
        return "LOW"

    if score <= 50:
        return "MEDIUM"

    if score <= 75:
        return "HIGH"

    return "CRITICAL"


def display_risk_score(score):

    level = get_risk_level(score)

    print("\n========== RISK ASSESSMENT ==========")
    print(f"Risk Score : {score}/100")
    print(f"Risk Level : {level}")
    print("======================================")