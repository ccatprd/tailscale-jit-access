# =============================================================================
# Tailscale JIT Access: Profile & Approval Configuration
# =============================================================================
# This file is the canonical source for access profiles and default approval
# rules. Edit it and redeploy to change which profiles exist or who approves them.
#
# The Admin page (/admin) can override these rules at runtime without a redeploy.
# Those overrides live in the database and take precedence over what is defined
# here. Use the "Export to config.py" button on the Admin page to capture live
# overrides back into this file when you want to commit them to git.
#
# All profile IDs must start with "custom:" (Tailscale requirement).
# =============================================================================

# ---------------------------------------------------------------------------
# Access Profiles
# ---------------------------------------------------------------------------
# Each profile maps to a Tailscale custom posture attribute. When a request is
# approved, the app sets that attribute on the requesting device. Your ACL
# posture definitions then gate the actual network access.
#
# Add, rename, or remove profiles here. The profile ID must match the
# posture attribute name you define in your Tailscale ACL.
# ---------------------------------------------------------------------------
ACCESS_PROFILES = [
    {"id": "custom:prodDbAccess",       "name": "Production Database Access"},
    {"id": "custom:customerDataAccess", "name": "Customer Data Access"},
    {"id": "custom:cicdAdmin",          "name": "CI/CD Infrastructure Admin"},
]

# ---------------------------------------------------------------------------
# Default Approval Rules
# ---------------------------------------------------------------------------
# Controls how many approvals each profile requires and which users may approve.
# Profiles not listed here fall back to DEFAULT_REQUIRED_APPROVALS from .env.
#
# Structure per profile:
#   "required_approvals": int     - how many votes needed (1-3)
#   "authorized_approvers": list  - restrict who may approve (optional)
#     each entry: {"email": "user@example.com", "required": True/False}
#     "required": True means this person MUST vote even if quorum is already met
#     Leave list empty (or omit the key) to allow anyone with can_approve_requests
#
# These are DEFAULTS. The Admin page can override them without a redeploy.
# ---------------------------------------------------------------------------
APPROVAL_RULES = {
    # "custom:prodDbAccess": {
    #     "required_approvals": 2,
    #     "authorized_approvers": [
    #         {"email": "alice@example.com", "required": True},
    #         {"email": "bob@example.com",   "required": False},
    #     ],
    # },
    # "custom:cicdAdmin": {
    #     "required_approvals": 2,
    #     "authorized_approvers": [],
    # },
}
