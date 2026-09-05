# auth-analyzer

A command-line tool that parses Linux `auth.log` files, classifies security events by severity, and detects brute-force login attempts by IP address.

Built and tested against a real, publicly-facing production server's authentication log (not synthetic sample data), so the detection logic has been validated against real attack traffic.

## What it does

- Parses SSH/sudo authentication log entries (ISO 8601 timestamp format)
- Classifies each event as `critical`, `high`, `medium`, or `low` severity based on keyword matching
- Detects brute-force patterns by grouping high-severity events per IP address and flagging any IP that crosses a configurable threshold
- Outputs either a human-readable report or structured JSON

## A real bug this project caught

The first version of the brute-force detector only counted log lines containing the literal phrase `"failed password"`. Running it against a real server's log returned:

```
Brute-force candidates (0 IPs flagged):
  None detected.
```

That looked wrong for a public-facing server with an open SSH port, so instead of assuming it was correct, I cross-checked with raw `grep`, independent of the Python entirely:

```bash
grep -c "Failed password" /var/log/auth.log
# → 1

grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" /var/log/auth.log | sort | uniq -c | sort -rn | head -10
#     794 27.155.92.28
#     680 95.173.161.147
#     455 195.178.110.218
#     ...
```

One IP had made **794 connection attempts** in under 25 minutes — a real, aggressive scan the tool had completely missed. The actual issue: most bots hitting this server never reach the "Failed password" step at all — they get rejected earlier (invalid usernames, connection resets during the handshake), which this server's log records under different message text entirely.

**The fix:** instead of matching one specific phrase, the detector now flags IPs by how many `critical`/`high`-severity events they generate overall — reusing the severity classifier that was already correctly categorizing this traffic, rather than duplicating separate matching logic. Re-running against the same log correctly flagged 26 IPs, including two distinct attacker behaviors: a fast scanner (792 attempts in 25 minutes) and a slow, patient one (680 attempts spread across 30+ hours).

## Usage

```bash
python3 auth_analyzer.py --log /var/log/auth.log
python3 auth_analyzer.py --log /var/log/auth.log --min-attempts 3 --json
python3 auth_analyzer.py --log /var/log/auth.log --output report.json
```

### Sample output

```
==================================================
AUTH LOG SECURITY REPORT
==================================================
Total events parsed: 5225

By severity:
  critical   3328
  high       1210
  medium     144
  low        543

Brute-force candidates (26 IPs flagged):
  27.155.92.28     792 failed attempts (first: 2026-08-30T07:51:21, last: 2026-08-30T08:14:25)
  95.173.161.147   680 failed attempts (first: 2026-08-30T00:20:48, last: 2026-08-31T06:06:50)
  ...
==================================================
```

## Requirements

Python 3.9+ (standard library only — no external dependencies)

## License

MIT


