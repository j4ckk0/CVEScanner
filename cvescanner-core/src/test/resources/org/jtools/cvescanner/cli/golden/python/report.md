# Dependency Vulnerability Report

- **Generated:** 2026-11-22 10:21 UTC
- **Scanned directory:** `<samples>/python-projects`
- **Database:** `pypi.zip` (OSV / GitHub advisories, 5 records (5 relevant), file dated 2026-11-22 10:19 UTC)
- **Files scanned:** 0 pom.xml, 0 Gradle build files, 0 version catalogs, 0 package.json, 9 Python project files
- **Dependencies analysed:** 18 (plus 6 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 4 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **11** (5 unique vulnerabilities in 8 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| CRITICAL | PyPI | `Django` | 3.1 ≈ | 3.1.13 | 1 | reqs/requirements.txt |
| CRITICAL | PyPI | `PyYAML` | 5.3.1 | 5.4 | 1 | reqs/requirements.txt |
| CRITICAL | PyPI | `django` | 3.1.0 | 3.1.13 | 1 | pipenv/Pipfile.lock |
| CRITICAL | PyPI | `pyyaml` | 5.3.1 | 5.4 | 1 | uv/uv.lock |
| HIGH | PyPI | `urllib3` | 1.26.4 | 1.26.5 | 1 | poetry/poetry.lock, uv/uv.lock |
| MEDIUM | PyPI | `jinja2` | 2.11.2 | 2.11.3 | 1 | pinned-pyproject/requirements.txt, poetry/poetry.lock |
| MEDIUM | PyPI | `requests` | 2.25.0 | 2.31.0 | 1 | poetry/poetry.lock, reqs/base.txt |
| MEDIUM | PyPI | `requests` | 2.25.1 | 2.31.0 | 1 | uv/uv.lock |

> ≈ = lowest version allowed by the range in package.json (no lockfile found). The installed version may be newer; add a lockfile for exact results.

## Findings by file

### `pinned-pyproject/requirements.txt`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | — | — | `jinja2` | 2.11.2 | requirements | [GHSA-g3rq-g295-4j3m](https://osv.dev/vulnerability/GHSA-g3rq-g295-4j3m) | Advisory | CVE-2020-28493 | 2.11.3 | Test vuln in Jinja2 |

### `pipenv/Pipfile.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `django` | 3.1.0 | direct | [GHSA-68w8-qjq3-2gfm](https://osv.dev/vulnerability/GHSA-68w8-qjq3-2gfm) | Advisory | CVE-2021-35042 | 3.1.13 | Test vuln in Django |

### `poetry/poetry.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `urllib3` | 1.26.4 | transitive | [GHSA-q2q7-5pp4-w6pg](https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg) | Advisory | CVE-2021-33503 | 1.26.5 | Test vuln in urllib3 |
| MEDIUM | — | — | `jinja2` | 2.11.2 | direct | [GHSA-g3rq-g295-4j3m](https://osv.dev/vulnerability/GHSA-g3rq-g295-4j3m) | Advisory | CVE-2020-28493 | 2.11.3 | Test vuln in Jinja2 |
| MEDIUM | — | — | `requests` | 2.25.0 | direct | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) | Advisory | CVE-2023-32681 | 2.31.0 | Test vuln in requests |

### `reqs/base.txt`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | — | — | `requests` | 2.25.0 | requirements | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) | Advisory | CVE-2023-32681 | 2.31.0 | Test vuln in requests |

### `reqs/requirements.txt`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `Django` | 3.1 | requirements | [GHSA-68w8-qjq3-2gfm](https://osv.dev/vulnerability/GHSA-68w8-qjq3-2gfm) | Advisory | CVE-2021-35042 | 3.1.13 | Test vuln in Django |
| CRITICAL | 9.8 (v3.1) | — | `PyYAML` | 5.3.1 | requirements | [GHSA-8q59-q68h-6hv4](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) | Advisory | CVE-2020-14343 | 5.4 | Test vuln in PyYAML |

### `uv/uv.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 9.8 (v3.1) | — | `pyyaml` | 5.3.1 | direct | [GHSA-8q59-q68h-6hv4](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) | Advisory | CVE-2020-14343 | 5.4 | Test vuln in PyYAML |
| HIGH | — | — | `urllib3` | 1.26.4 | transitive | [GHSA-q2q7-5pp4-w6pg](https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg) | Advisory | CVE-2021-33503 | 1.26.5 | Test vuln in urllib3 |
| MEDIUM | — | — | `requests` | 2.25.1 | direct | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) | Advisory | CVE-2023-32681 | 2.31.0 | Test vuln in requests |

## Dependencies that could not be checked (6)

| File | Ecosystem | Package | Declared | Reason |
|---|---|---|---|---|
| pinned-pyproject/pyproject.toml | PyPI | `requests` | — | unpinned version '\*' |
| pipenv/Pipfile.lock | PyPI | `localpkg` | — | non-registry source |
| reqs/requirements.txt | PyPI | `local` | -e ./local\#egg=local | non-registry source |
| reqs/requirements.txt | PyPI | `mypkg` | @ https://example.org/mypkg-1.0-py3-none-any.whl | non-registry source |
| reqs/requirements.txt | PyPI | `tool` | git+https://github.com/example/tool.git\#egg=tool | non-registry source |
| reqs/requirements.txt | PyPI | `urllib3` | \<2 | range has no lower bound |

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
