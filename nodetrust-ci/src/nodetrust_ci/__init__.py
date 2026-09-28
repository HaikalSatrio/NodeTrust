"""nodetrust-ci: build/enrich an npm SBOM, submit it to NodeTrust, apply the verdict.

Standard library only, so it runs on any GitHub runner with python3 and adds no
dependencies to the build it is protecting.
"""

__version__ = "0.1.0.dev0"
# Contract version this client understands (must match nodetrust-core SCHEMA_VERSION).
SCHEMA_VERSION = "2026-09.draft1"

# Exit codes (contract shared with nodetrust-core, see docs in README):
EXIT_OK = 0            # pass or warn
EXIT_BLOCKED = 1       # gate, or held pending approval
EXIT_CONFIG = 2        # bad/missing credentials, bad payload, bad input: fails in BOTH modes
EXIT_UNAVAILABLE = 3   # assessment unavailable (API down/timeout/stale data) in ENFORCE mode
