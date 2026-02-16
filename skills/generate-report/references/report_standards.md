# Report Generation Reference

## Confidence Language (ICD 203)

Always use these standardized terms:

| Term | Probability | Example Usage |
|------|-------------|---------------|
| Almost certain | >95% | "We assess with near certainty that..." |
| Highly likely | 80-95% | "We assess it is highly likely that..." |
| Likely | 60-80% | "We assess it is likely that..." |
| Roughly even chance | 40-60% | "We cannot determine with confidence..." |
| Unlikely | 20-40% | "We assess it is unlikely that..." |
| Highly unlikely | 5-20% | "We assess it is highly unlikely that..." |
| Remote possibility | <5% | "There is a remote possibility that..." |

**NEVER USE**: "We believe", "We think", "Probably" (without calibration)

## Source Reliability Ratings

| Rating | Description |
|--------|-------------|
| A | Reliable - Confirmed accuracy, established track record |
| B | Usually Reliable - Generally accurate, minor past errors |
| C | Fairly Reliable - Occasional inaccuracies |
| D | Not Usually Reliable - Significant past errors |
| E | Unreliable - Known inaccuracies |
| F | Cannot Be Judged - Insufficient track record |

## IOC Defanging Rules

Always defang IOCs to prevent accidental clicks:

- **Domains**: `evil.com` → `evil[.]com`
- **IPs**: `192.168.1.1` → `192[.]168[.]1[.]1`
- **URLs**: `https://evil.com` → `hxxps://evil[.]com`
- **Email**: `attacker@evil.com` → `attacker[@]evil[.]com`

## Detection Rule Quality Checklist

Before including Sigma/YARA rules:

- [ ] Rule has unique ID (UUID)
- [ ] Description explains what it detects
- [ ] References link to source intelligence
- [ ] Author and date included
- [ ] ATT&CK tags present
- [ ] False positive scenarios documented
- [ ] Severity level appropriate
- [ ] Detection logic validated

## Report Quality Checklist

Before finalizing any report:

- [ ] Executive summary is 2-3 sentences max
- [ ] Every judgment has confidence level
- [ ] All IOCs are defanged
- [ ] ATT&CK techniques have IDs (T####.###)
- [ ] Sources cited with reliability rating
- [ ] At least 3 defensive recommendations
- [ ] Key assumptions explicitly stated
- [ ] Intelligence gaps acknowledged
- [ ] No fabricated or unverified claims
- [ ] Reassessment triggers defined
