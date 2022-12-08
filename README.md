
# Tholian® CVE Monitor

The Tholian® CVE Monitor is an attempt to unify downstream security tracker data with
the upstream CVE database entries for the intent of automating security audits.

The purpose of this database is to provide a merged dataset that can be used in a fully
automated manner in order to audit the security and potential attack surface of a system.


# Supported Security Trackers

- [x] [MITRE CVE](./updater/source/tracker/CVE.mjs)
- [x] [CISA Known Exploited Vulnerabilities](./updater/source/tracker/CISA.mjs)

- [ ] [Almalinux](./updater/source/tracker/Almalinux.mjs)
- [ ] Alpine Linux
- [ ] Amazon Linux
- [x] [Archlinux](./updater/source/tracker/Archlinux.mjs)
- [x] [Debian](./updater/source/tracker/Debian.mjs)
- [ ] Fedora
- [ ] [Microsoft MSRC](./updater/source/tracker/Microsoft.mjs)
- [ ] Photon
- [ ] Red Hat
- [ ] Rocky Linux
- [ ] Ubuntu


# Quickstart

The [updater/updater.mjs](./updater/updater.mjs) imports all upstream CVE entries, and
then incrementally updates all entries by scraping the downstream security trackers.

The vulnerabilities are exported into a separate folder, each time the tool is executed.
This folder contains merged vulnerabilities, identified by their origin (CVE, DSA, GHSA etc).

If a vulnerability has an `is_edited` (boolean) flag set to `true`, it will not be
overwritten with new information and will stay untouched by the updater tool.

```bash
# Update all security tracker data, and cache it in /tmp/database/cache
node updater/updater.mjs update /tmp/database;

# Merge all cached security tracker data with vulnerabilities in /tmp/database/vulnerabilities
node updater/updater.mjs export /tmp/database;
```


# Usage

The [updater/updater.mjs](./updater/updater.mjs) is used to scrape all supported security
trackers and to export all vulnerabilities to the [vulnerabilities](https://github.com/tholian-network/vulnerabilities)
repository on a regular basis.

1. Run the `update` action in order to download/scrape the security tracker data.
2. Run the `export` action which merges everything together.
3. Commit all changes in the message format `:package: YYYY-MM-DD".
4. Push all changes to the `vulnerabilities` repository.


# License

This tool is licensed via the [GNU Affero GPL 3.0](./AGPL-3.0.txt) license.

