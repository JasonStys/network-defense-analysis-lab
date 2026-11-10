# Network Defense Analysis Lab handbook

By Jason Stys.

Analyze bounded defensive network observations, correlate declared relationships and explain prioritization using reproducible fixtures. The lab does not scan external targets or perform traffic interception.

Filter captured events by exact UTC/protocol/rule/severity with snapshot/query-bound pagination and persistent visibility of capture gaps.

Makes defensive investigation manageable without presenting filtered or incomplete captures as clean traffic.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [release](release.md)
- [usage](usage.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)

## Historical results and reproduction

The reviewed source is [`6f474420416bd319f2384737c8764adf115c2861`](https://github.com/JasonStys/network-defense-analysis-lab/tree/6f474420416bd319f2384737c8764adf115c2861). The observed functional workflow baseline is `6f474420416bd319f2384737c8764adf115c2861`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/query-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/network-defense-analysis-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- The original 100-item detector evidence cap remains; a filtered event page does not include every related packet.
- Capture-quality issues lack reliable timestamps and remain visible outside event time filters.
- No live capture, blocking or attribution is supplied; no findings is not proof of safe traffic.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
