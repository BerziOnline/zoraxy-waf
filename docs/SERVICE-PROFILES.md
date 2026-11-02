# Service profile packages

## Official CRS packages

The official [registry](https://github.com/coreruleset/plugin-registry) currently lists these public rule-exclusion packages:

| Package | Bundled release | Host scoping |
| --- | --- | --- |
| Nextcloud | v1.7.1 | Entire plugin rule ID block gated before phase 1 |
| WordPress | v1.2.0 | Same |
| Drupal | v1.0.0 | Same |
| DokuWiki | v1.0.0 | Same |
| cPanel | v1.0.0 | Same |
| XenForo | v1.0.0 | Same |
| phpBB | v1.0.0 | Same |
| phpMyAdmin | Not bundled | Global `SecRuleUpdateTargetById` in its after file cannot be transaction-scoped |

Ghost is registered as official but its repository is private/unavailable. Roundcube, SOGo, Plausible and Plex are third-party, not official packages, and are not bundled.

The packages are unmodified Apache-2.0 sources; their licenses are retained and the manifest links to upstream documentation. The [manifest](../internal/crsplugins/manifest.json) records exact commits. Config, before, CRS and after files run in that order. An escaped, anchored `SERVER_NAME` match gates the whole package per canonical hostname. Aliases need their own approval. TRACE and CONNECT remain blocked even if an upstream package allows them.

Official packages can exclude more fields or methods than JSON profiles. Review their upstream rules before applying them. CrowdSec cannot execute these SecLang packages.

## Maintaining profiles

`tools/update-crs-plugins.sh --check` verifies all pinned upstream bytes. Without `--check` it restores those same commits, never upgrades releases. Review changes to pins, detection hints and exclusions together, and increment the profile version for changed behavior.

Applied JSON scopes remain materialised until explicitly updated. Update review shows the complete removed and added scopes. Applied CRS package commits are also pinned. If a previously approved commit is no longer bundled, the profile is labelled **inactive** and ordinary CRS runs until the admin reviews the new commit; the review links its exact upstream diff. This restores detection rather than silently enabling new exclusions. Removing a profile keeps method changes.

The JSON security gate uses `internal/engine/coraza/testdata/profile-attacks.json`, compares clean controls and real attacks at PL1 / threshold 5, and prints sibling-rule coverage per exception field. New attack-class blind spots require an explicit `accepted_blind_spot` reason. Detection needs three login-bearing observations per path: two distinct service paths, or one path plus a backend-port match. No header values, bodies or query values are stored for detection.
