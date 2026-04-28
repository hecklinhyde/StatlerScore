BAR_WIDTH = 20


def bar(pct):
    filled = round(pct / 100 * BAR_WIDTH)
    return "#" * filled + "-" * (BAR_WIDTH - filled)


def pillarLabel(pct):
    if pct >= 80: return "Strong"
    if pct >= 60: return "Fair"
    if pct >= 40: return "At Risk"
    return "Critical"


def overallLabel(score):
    if score >= 800: return "Resilient Posture"
    if score >= 740: return "Strong Posture"
    if score >= 670: return "Stable Posture"
    if score >= 580: return "Accumulating Technical Risk"
    return "Critical Remediation Required"


def generateReport(result, previousScore):
    score   = result["score"]
    pillars = result["pillars"]
    diff    = score - previousScore
    trend   = "↑" if diff > 0 else "↓" if diff < 0 else "→"
    label   = overallLabel(score)

    header = f"  Statler Score: {score}  {trend} ({diff:+d})  |  {label}"
    width  = max(60, len(header) + 2)
    rule   = "=" * width

    lines = [
        rule,
        header,
        rule,
        "  STATLER RATINGS",
        f"  {'Rating':<22}  {'Score':>5}   {'':^{BAR_WIDTH + 2}}  Status",
        "  " + "-" * (width - 2),
    ]

    for name, pct in sorted(pillars.items(), key=lambda x: (x[1] is None, x[1] or 0), reverse=True):
        if pct is None:
            lines.append(f"  {name:<22}   N/A   [{'—' * BAR_WIDTH}]  N/A")
        else:
            lines.append(f"  {name:<22}  {pct:>4}%   [{bar(pct)}]  {pillarLabel(pct)}")

    # Key factors — only shown when factors data is present
    factors = result.get("factors", {})
    hurting = factors.get("hurting", [])
    helping = factors.get("helping", [])
    if hurting or helping:
        lines += [
            rule,
            "  KEY FACTORS",
            "  " + "-" * (width - 2),
        ]
        if hurting:
            lines.append("  Hurting your score (worst first):")
            for f in hurting:
                lines.append(f"    - [{f.get('rating', f.get('pillar', ''))}] {f['check']:<40}  {f['score']:.0%}")
        if helping:
            lines.append("  Helping your score (best first):")
            for f in helping:
                lines.append(f"    + [{f.get('rating', f.get('pillar', ''))}] {f['check']:<40}  {f['score']:.0%}")

    # Bureau attestation block — only shown when result comes from the API
    if "attestation_id" in result:
        lines += [
            rule,
            "  STATLER ATTESTATION",
            "  " + "-" * (width - 2),
            f"  ID        {result['attestation_id']}",
            f"  Timestamp {result['timestamp']}",
            f"  Agent     {result['agent_hash'][:32]}...",
            f"  Sig       {result['signature'][:32]}...",
            f"  Verdict   {overallLabel(score)}",
        ]

    lines.append(rule)
    return "\n".join(lines)
