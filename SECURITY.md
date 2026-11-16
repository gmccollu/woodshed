# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue:

1. Open the repository's **Security** tab and click **Report a vulnerability** (GitHub's private vulnerability
   reporting): <https://github.com/gmccollu/woodshed/security/advisories/new>.
2. Describe the problem, the version (`woodshed version`) and OS, and how to reproduce it. A proof of concept helps,
   but isn't required.

Only the maintainers see the report. You'll get an acknowledgement within a week, and we'll keep you updated in the
advisory as we confirm, fix and release. Once a fix is out, the advisory is published with credit to you, unless
you'd rather stay anonymous.

Please don't test against systems that aren't yours, and give us a reasonable time to release a fix before
disclosing.

## Supported versions

Security fixes go into the latest release. Upgrade in place with the newer installer; your config and logs are kept.

## What counts

Anything that lets someone do more than Woodshed's design allows, for example:

- reaching the UI or API from another machine while LAN mode is off, or without the password while it's on;
- reading, changing or deleting files outside Woodshed's data folder, or gaining the service account's or an
  administrator's rights through Woodshed, its installers or its service setup;
- crashing the service or making it lose data with crafted syslog traffic;
- Woodshed making any outbound network connection other than:
  - the opt-in update check: one HTTPS `GET` of `https://gmccollu.github.io/woodshed/releases.json` a day, made
    only after an administrator turns it on. A check while it's off or still asking, a request that sends more than
    that (a query string, a cookie, an identifier, the version), a connection anywhere else, or an update banner
    that links outside this repository's releases all count;
  - SNMP polls to devices you configure: SNMP `Get`, `GetNext` and `GetBulk` requests (and SNMPv3 engine
    discovery) sent only to the addresses and ports an administrator added under polling, for the OIDs configured
    there, at the configured interval, plus test polls an administrator starts. A request to any other address, a
    `Set` or any other PDU, a request before a target was configured, or a community or key sent to a device other
    than the one it was configured for all count.

A device on your network that can send syslog to Woodshed is expected to be able to fill its logs (within the disk
limits): that isn't a vulnerability, but a way to bypass the disk limits is.

## Verifying downloads

Every release lists SHA-256 checksums for all its files in `checksums.txt`, and, since the repository went public
(0.9.0-rc2 onwards), GitHub build provenance attestations: `gh attestation verify FILE --repo gmccollu/woodshed` shows that a file was built by this repository's
release workflow from the tagged source.
