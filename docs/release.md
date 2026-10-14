# Release and maintenance checklist

Author: Jason Stys. This is a source-repository handoff, not a deployed network service or signed installer.

Before publishing: inspect staged inventory, exclude private evidence/secrets, run all local compiler/type/test/map/link gates, then inspect every hosted matrix/security/conformance job and CodeQL alerts on the exact pushed SHA. Do not infer a passing push from the prior commit's green badge.

Accepted implementation checks are recorded in [validation evidence](reports/validation.md). Documentation-only changes require the same final-main CI checks before handoff. Native builds are local; no binary release, capture driver, cloud resource, database migration or credential was provisioned.

If a regression appears, stop analysis, preserve input and incomplete output separately, and reproduce with a minimal synthetic fixture. Rebuild the last verified source in a separate checkout; never reset user changes or overwrite completed reviews. Retest supported operating systems and record current policy. Do not disable failed tests, checksum/length checks, dependency audits or secret scans.

For future Actions, check current artifact/cache bytes and available included-storage meter. Keep account-level evidence local. Ask Jason for fresh archive/delete approval if cleanup is needed; no recurring deletion or billing change is authorized. Maintain artifact/cache-free workflows unless explicitly approved otherwise.
