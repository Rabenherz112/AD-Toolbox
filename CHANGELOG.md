# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),

## [unreleased]

- N/A

## [v0.2.0-alpha] - 2026-09-04

I swear it's always DNS. So here are some checks.

### New diagnostics

#### DC Locator / SRV Record Integrity

Verifies that the DC Locators actually exist and are resolvable. It also actually not only checks the presence but instead also checks the LDAP SRV target list against the live DC list in both directions. Duplicate A records get flagged too.
This should detect any possible issues that a DC might now get correctly found in the DNS.

#### DC DNS Client Settings

Checks on each DC the DNS client configuration and flags public resolver, empty lists, servers that can't be shown to serve the AD zones, and the classic DNS island.

#### DNS Forwarders Reachable

Has each DC resolve a known-good public name through every forwarder it is configured to use (by default this is `microsoft.com`) to check for dead resolvers or firewall issues.

#### DNS Conditional Forwarders

Same idea per forwarded zone, does each target actually serve the zone it is supposed to (SOA check include), and is an AD-integrated forwarder present on every DC?

#### DNS Zone Synchronization

Checks the zone inventory of every DC and finds replication mismatches.

### New actions

#### Re-register DC DNS Records *(LowImpact)*

Registers a DCs DNS entries back into the DNS and checks them via `nltest`.

#### Force Replication *(LowImpact)*

Performs a `repadmin /syncall /AdeP` to converge all partitions.

### Engine

- Prereqs and the module loader now share a single PowerShell module list instead of having the requirements hard-coded
- DC objects now carry `ObjectGuid` in the Context available for checks to use
- Addition of `Get-ADTDomainControllerSet` and `Invoke-ADTRemote` utilities to support the new checks and actions

### Fixes

- `enable-dns-scavenging` now sets the scavenging interval *alongside* the state
- `dns-configuration-hygiene` limits aging checks to zones that accept dynamic updates

### Other

- Add placeholder `utilities/` for later use (and for me as a reminder)

## [v0.1.0-alpha] - 2026-08-16

This alpha marks the **core of AD-Toolbox as complete**. The framework that discovers modules and runs diagnostics/actions should now be finished.
Going forward, development is mainly **implementing check and action modules**.

### This release includes

- Modular engine: discovery, context, logging, invocation
- Interactive menu and unattended CLI (`-FullTest`, `-Run`, `-Area`, `-List`)
- Findings model with severity ranking and exit-code mapping
- Reporting: Console, HTML, JSON, CSV
- Optional run persistence and drift compare (`-SaveRun`, `-CompareTo`)
- Risk-tier confirmation gate for write actions

[unreleased]: https://github.com/Rabenherz112/AD-Toolbox/compare/v0.2.0-alpha...HEAD
[v0.2.0-alpha]: https://github.com/Rabenherz112/AD-Toolbox/compare/v0.1.0-alpha...v0.2.0-alpha
[v0.1.0-alpha]: https://github.com/Rabenherz112/AD-Toolbox/releases/tag/v0.1.0-alpha
