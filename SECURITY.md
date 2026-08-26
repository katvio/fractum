# Security policy

## Reporting a vulnerability

Report privately, not in a public issue: **contact@katvio.com**, with
`SECURITY` in the subject line.

A dedicated `security@katvio.com` alias would be better, and does not exist
today; `contact@katvio.com` is the only address the project publishes.

Include the version, the platform, and the smallest set of steps that
reproduces the problem. A proof of concept helps but is not required.

What to expect:

| Step | Delay |
|---|---|
| Acknowledgement of receipt | 3 working days |
| First assessment, severity and whether it is accepted | 10 working days |
| Fix or documented mitigation for an accepted critical report | 90 days |

If you get no acknowledgement within the first delay, the address may be
failing; open a public issue saying only that you are trying to reach the
security contact, without any detail of the finding.

We ask for the usual restraint in return: no disclosure before a fix is
available or the 90 days have passed, whichever comes first, and no testing
against systems you do not own.

## Supported versions

Fixes land on the latest released minor version. Older versions receive nothing,
so an upgrade is part of any remediation.

## What this software does and does not claim

Fractum encrypts a file with AES-256-GCM and splits the encryption key into
shares using Shamir's Secret Sharing. It is a command line tool that runs
offline, by design.

Two limits are worth stating plainly, because they are the ones that surprise
people:

- **The share files are only as safe as where you put them.** The threshold
  protects against losing some of them, not against an attacker who collects
  enough of them. Storing several shares in one place removes the protection
  entirely.
- **The machine that runs the tool sees the key in memory.** Fractum is designed
  for an offline, trusted workstation. Running it on a shared or compromised
  host defeats the point.

Cryptographic export and import rules vary by country. Using or redistributing
this software is the user's responsibility in their own jurisdiction.
