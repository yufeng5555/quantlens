"""quantlens_schema — DSL v1.0 validation stack (schema -> semantic lint -> scope check).

Layers per 02 §4. All checks are deterministic; no network, no wall-clock.
"""

from .validator import (  # noqa: F401
    DSL_SCHEMA_VERSION,
    NAME_MAX_LENGTH,
    normalize_display_name,
    normalize_spec_names,
    load_schema,
    load_manifest_schema,
    load_dataset_manifest_schema,
    load_universe,
    universe_symbols,
    validate_schema,
    semantic_lint,
    scope_check,
    validate_full,
    default_spec,
    canonical_spec_json,
    spec_hash,
    restatement,
)
