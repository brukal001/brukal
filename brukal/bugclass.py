"""bugclass.py — canonical bug-class taxonomy that BOTH the human scope vocabulary and
the deterministic provers map into, so a program's allowed/forbidden classes gate which
confirm_* provers run. Deterministic; no LLM. The model's differential vocabulary
(_COMPARATORS in hypothesis.py) is a SEPARATE axis and is not touched here."""
from __future__ import annotations

# Superset — includes non-qualifying/hygiene classes so a program can explicitly
# FORBID them (e.g. "don't bother with rate-limit/user-enum noise on this program").
CANONICAL = frozenset({
    "sqli", "nosqli", "xss", "rce", "cmdi", "idor", "ssrf", "cors", "csrf",
    "open_redirect", "auth_bypass", "business_logic", "lfi", "rfi", "xxe", "ssti",
    "mass_assignment", "exposed_secrets", "unauth_access",
    "llm", "session", "user_enum", "rate_limit", "weak_password",
    "graphql_introspection", "missing_headers", "dos", "clickjacking",
})

# Human name (normalized: lowercased, spaces/hyphens -> underscore) -> canonical class.
_ALIASES = {
    "sql_injection": "sqli", "sqli": "sqli",
    "nosql_injection": "nosqli", "nosqli": "nosqli",
    "cross_site_scripting": "xss", "xss": "xss",
    "remote_code_execution": "rce", "rce": "rce",
    "os_command_injection": "cmdi", "command_injection": "cmdi", "cmdi": "cmdi",
    "insecure_direct_object_reference": "idor", "idor": "idor",
    "server_side_request_forgery": "ssrf", "ssrf": "ssrf", "xspa": "ssrf",
    "cross_origin_resource_sharing": "cors", "cors": "cors",
    "cross_site_request_forgery": "csrf", "csrf": "csrf",
    "open_redirect": "open_redirect",
    "authentication_bypass": "auth_bypass", "auth_bypass": "auth_bypass",
    "broken_authentication": "auth_bypass", "privilege_escalation": "auth_bypass",
    "business_logic": "business_logic", "business_logic_errors": "business_logic",
    "local_file_inclusion": "lfi", "lfi": "lfi", "file_inclusion": "lfi",
    "remote_file_inclusion": "rfi", "rfi": "rfi",
    "xxe": "xxe", "xml_external_entity": "xxe",
    "ssti": "ssti", "template_injection": "ssti",
    "mass_assignment": "mass_assignment",
    "exposed_secrets": "exposed_secrets", "exposed_credentials": "exposed_secrets",
    "sensitive_information": "exposed_secrets",
    "unauthenticated_access": "unauth_access", "unauth_access": "unauth_access",
    "denial_of_service": "dos", "dos": "dos",
    "clickjacking": "clickjacking",
    # --- P1 additions ---
    "session_fixation": "session", "session_management": "session",
    "no_session_revocation": "session",
    "user_enumeration": "user_enum", "account_enumeration": "user_enum",
    "rate_limiting": "rate_limit", "rate_limit": "rate_limit", "brute_force": "rate_limit",
    "weak_password_policy": "weak_password", "weak_password": "weak_password",
    "graphql_introspection": "graphql_introspection", "introspection": "graphql_introspection",
    "missing_security_headers": "missing_headers", "security_headers": "missing_headers",
    "missing_headers": "missing_headers",
    "prompt_injection": "llm", "llm": "llm", "chatbot": "llm",
}


def normalize_class(name: str) -> str | None:
    """Human vuln name -> canonical class, or None if unrecognized (fail-closed: an
    unknown name authorizes NOTHING and never invents a class)."""
    key = "_".join((name or "").strip().lower().replace("-", " ").split())
    return _ALIASES.get(key)


# confirm_* method name -> the canonical class(es) it TESTS. Source of "running this
# prover tests these classes". Kept in sync with _ConfirmMixin (brukal/assist_confirm.py)
# by test_registry_covers_every_confirm_method — that test fails if a confirm_* method
# is added there without a matching entry here.
#
# "_always" is a sentinel meaning "not a program-gated vuln test — always allowed to
# run" (orchestrators / identity probes). It is NOT a member of CANONICAL, so it can
# never be requested via a scope's allowed/forbidden lists.
PROVER_CLASSES: dict[str, frozenset[str]] = {
    # --- injection ---
    "confirm_sqli": frozenset({"sqli"}),
    "confirm_sqli_error": frozenset({"sqli"}),
    "confirm_sqli_status": frozenset({"sqli"}),
    "confirm_nosqli": frozenset({"nosqli"}),
    "confirm_nosqli_sinks": frozenset({"nosqli", "sqli"}),
    "confirm_xss": frozenset({"xss"}),
    "confirm_cmdi": frozenset({"cmdi"}),
    "confirm_blind_rce": frozenset({"cmdi", "rce"}),
    "confirm_deserialization_rce": frozenset({"rce"}),
    "confirm_lfi": frozenset({"lfi"}),
    "confirm_ssti": frozenset({"ssti", "rce"}),
    "confirm_open_redirect": frozenset({"open_redirect"}),
    "confirm_ssrf": frozenset({"ssrf"}),
    "confirm_blind_ssrf": frozenset({"ssrf"}),
    "confirm_ssrf_sinks": frozenset({"ssrf"}),
    # --- access control / authz ---
    "confirm_idor": frozenset({"idor"}),
    "confirm_bola": frozenset({"idor"}),
    "confirm_bola_from_collection": frozenset({"idor"}),
    "confirm_mass_assignment": frozenset({"mass_assignment"}),
    "confirm_object_mass_assignment": frozenset({"mass_assignment"}),
    "confirm_object_mass_assignment_sinks": frozenset({"mass_assignment"}),
    "confirm_privileged_route_via_signup": frozenset({"mass_assignment", "auth_bypass"}),
    "confirm_horizontal_takeover_via_form": frozenset({"auth_bypass"}),
    "confirm_bfla_password_takeover": frozenset({"auth_bypass"}),
    "confirm_destructive_endpoint_exposed": frozenset({"business_logic", "auth_bypass"}),
    # --- auth / session / creds ---
    "confirm_jwt_forgery": frozenset({"auth_bypass"}),
    "confirm_predictable_reset_token": frozenset({"auth_bypass"}),
    "confirm_session_fixation": frozenset({"session"}),
    "confirm_no_session_revocation": frozenset({"session"}),
    "confirm_default_credentials": frozenset({"auth_bypass", "exposed_secrets"}),
    "confirm_plaintext_password_storage": frozenset({"exposed_secrets"}),
    # --- info exposure ---
    "confirm_data_exposure": frozenset({"exposed_secrets", "unauth_access"}),
    "confirm_unauth_access": frozenset({"unauth_access"}),
    "confirm_debug_console": frozenset({"rce", "exposed_secrets"}),
    # --- cors / llm ---
    "confirm_cors": frozenset({"cors"}),
    "confirm_prompt_injection": frozenset({"llm"}),
    # --- non-qualifying / hygiene (classifiable so a program can forbid them) ---
    "confirm_user_enumeration": frozenset({"user_enum"}),
    "confirm_recovery_enumeration": frozenset({"user_enum"}),
    "confirm_missing_rate_limit": frozenset({"rate_limit"}),
    "confirm_unthrottled_registration": frozenset({"rate_limit"}),
    "confirm_weak_password_policy": frozenset({"weak_password"}),
    "confirm_security_headers": frozenset({"missing_headers"}),
    "confirm_graphql_introspection": frozenset({"graphql_introspection"}),
    "confirm_graphql_suggestions": frozenset({"graphql_introspection"}),
    "confirm_graphql_batching": frozenset({"graphql_introspection"}),
    # --- orchestrator / identity: NOT program-gated (always run) ---
    "confirm_surface": frozenset({"_always"}),
    "confirm_authentication": frozenset({"_always"}),
}


def active_classes(scope):
    """Allowed classes minus forbidden, or None when unrestricted (both allowed_classes
    and forbidden_classes empty)."""
    allowed = frozenset(getattr(scope, "allowed_classes", None) or ())
    forbidden = frozenset(getattr(scope, "forbidden_classes", None) or ())
    if not allowed and not forbidden:
        return None
    base = allowed if allowed else CANONICAL
    return frozenset(base) - forbidden


def prover_enabled(scope, method_name: str) -> bool:
    """True if this confirm_* prover may run under the scope's class policy.

    - A method mapped to the "_always" sentinel (orchestrator/identity probes) always
      runs, regardless of the scope's allowlist.
    - An unrestricted scope (empty allowed AND forbidden) => True for everything else.
    - An UNMAPPED method under an active (restricted) policy => False (fail-closed:
      never probe a class we can't classify).
    - Otherwise: True iff the method's class set intersects the active classes.
    """
    classes = PROVER_CLASSES.get(method_name)
    if classes and "_always" in classes:
        return True
    active = active_classes(scope)
    if active is None:
        return True
    if not classes:
        return False
    return bool(classes & active)
