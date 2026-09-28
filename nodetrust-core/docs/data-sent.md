# What a CI run sends to NodeTrust (NT-018)

nodetrust-ci minimises the SBOM **before** it leaves the CI job, and the server stores only the fields below.
No source code, file contents or file paths are sent.

| Sent | Stored | Why |
|---|---|---|
| Git commit SHA, branch name, CI run id + attempt | yes | scan identity, drift baseline, one-run overrides |
| Root component: type, name, version, bom-ref | ref only | anchor for dependency paths |
| Per component: type, bom-ref, name, version, purl, scope | ref, purl, name, version, scope, status | exact-version matching |
| Dependency relations (`ref → dependsOn[]`) | yes | paths from root, blast radius, choke points |

Dropped by the client and ignored by the server: hashes, licences, authors, suppliers, CPEs, external
references, properties (including Syft file locations), evidence, services, compositions, and any
other CycloneDX field.

Repository names are not sent, apart from whatever the project admin chose as the NodeTrust project
name. The API key identifies the project. Maintainer e-mail addresses from the npm registry are
dropped at ingestion; only usernames are kept, to detect maintainer changes.
