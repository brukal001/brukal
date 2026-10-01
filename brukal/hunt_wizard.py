"""The guided `brukal hunt` wizard: gather -> draft -> plan -> show -> ONE
approval -> freeze + execute + verify -> dispatch. Deterministic; no LLM.
All side effects go through the injected runner / dispatch, so this module is
fully testable without Docker, a real key, or a network. It must never import
`brukal.kali`/`brukal.executor`/`brukal.agents.*` at module load — those only
come in (lazily) inside `_default_dispatch`, which is the one place that talks
to the real run engines."""
from __future__ import annotations

import os

from brukal import envprep
from brukal import keys as keys_mod
from brukal.cage import DockerCageRunner


def _ask(prompt, q, default=""):
    try:
        v = (prompt(q) or "").strip()
    except (EOFError, OSError):
        v = ""
    return v or default


def _default_dispatch(args):
    """Production dispatch: launch the real headless engine for the kind the
    plan picked.

    `run_auto` is `brukal.assist_cli.run_auto` (also re-exported via
    `brukal.assist`). `run_engagement` is `brukal.engagement.run` — imported
    under that alias, exactly as `cli.py` already does; there is no
    `run_engagement` in `assist_cli`. Both imports are lazy (inside this
    factory, not at module scope) so a test that injects its own `dispatch=`
    never pulls in the agent stack.

    `run_auto` has no top-level `web=`/`box=` flag; the web/box methodology is
    selected with `mode="web"` (it would otherwise auto-detect from whether
    `target` looks like a URL/hostname or an IP — see assist_cli.run_auto's
    `set_resolver`/`set_methodology` call). `run_auto` also has no free-text
    `context` parameter on this branch's base — the operator's one-line brief
    is shown at the approval gate and persisted into the frozen scope
    (`_context`) so the record carries it, but it is NOT fed into the
    engine's seeded objective here: that needs the `auto --context`/
    `_apply_context` feature, which is not committed to this branch's base,
    and assist_cli is out of scope for this module to touch."""
    from brukal.assist_cli import run_auto
    from brukal.engagement import run as run_engagement

    def _dispatch(plan):
        d = plan.dispatch
        if d.kind == "auto_web":
            hosts = tuple(plan.scope_draft.get("authorized_hosts") or ())
            return run_auto(
                d.target, fake=args.fake, yes_authorised=True,
                scope_path=plan.scope_path, audit_path=d.audit, vault_path=d.vault,
                container=args.container, model=d.model, provider=d.provider,
                base_url=args.base_url, hosts=hosts, mode="web")
        return run_engagement(
            d.target, fake=args.fake, yes_authorised=True,
            scope_path=plan.scope_path, audit_path=d.audit, vault_path=d.vault,
            container=args.container, model=d.model, provider=d.provider,
            base_url=args.base_url, tui=args.tui)
    return _dispatch


def run_hunt(args, *, prompt=input, runner=None, dispatch=None, resolve_key=None) -> int:
    resolve_key = resolve_key or keys_mod.resolve_key
    runner = runner or DockerCageRunner(container=args.container)
    # `dispatch` is resolved lazily, right before it is actually called — not here —
    # so an invalid --mode, a missing key, or a declined [y/N] never pays the cost of
    # importing assist_cli/engagement (the real run engines) for a run that never starts.

    # Coalesce ONCE, the same way the old _cmd_hunt did — args.provider defaults to
    # None on the `hunt` parser, and keys._env_var does provider.upper(), so a bare
    # `brukal hunt` with no --provider would otherwise crash with AttributeError
    # before anything else runs.
    provider = (args.provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()

    mode = (args.mode or _ask(prompt, "  Mode — web or vpn? ")).lower()
    if mode not in ("web", "vpn"):
        print("  unknown mode — choose web or vpn.")
        return 1

    key, _res = resolve_key(provider)
    if key is None:
        print("  no API key and none provided — aborting (set <PROVIDER>_API_KEY "
              "or use a local model).")
        return 1
    # A key resolved from runs/<provider>.env or an interactive prompt only lives in
    # KeyResolution/the local `key` so far — run_auto/run_engagement read it from
    # os.environ via LLMClient, so without this the wizard would report success,
    # bring up the cage, and then the dispatched run would fail for want of a key.
    if key:
        os.environ[f"{provider.upper()}_API_KEY"] = key

    if mode == "web":
        url = args.url or _ask(prompt, "  Target URL: ")
        context = args.context or _ask(prompt, "  One-line context (what to focus on): ")
        try:
            plan = envprep.plan_web(url, context, provider, args.model,
                                    args.scope, args.vault, args.audit)
        except ValueError as e:
            print(f"  cannot build web scope: {e}")
            return 1
    else:
        ovpn = args.ovpn or _ask(prompt, "  Path to .ovpn: ")
        targets = [t for t in _ask(prompt, "  Target IP/CIDR(s), comma-separated: ").split(",")
                   if t.strip()]
        try:
            plan = envprep.plan_vpn(ovpn, targets, provider, args.model,
                                    args.scope, args.vault, args.audit)
        except (ValueError, OSError) as e:
            print(f"  cannot build vpn scope: {e}")
            return 1

    print("\n  SCOPE (to be frozen on approval):")
    print(f"    {plan.scope_summary}")
    print("  BRING-UP PLAN:")
    print(f"    recreate cage on {plan.scope_path} · resolver {plan.resolver}"
          + (f" · stage {plan.vpn_file}" if plan.vpn_file else ""))
    print(f"    then verify: {', '.join(plan.verify_steps)}")
    print(f"  DISPATCH: {plan.dispatch.kind} -> {plan.dispatch.target}")
    if plan.dispatch.context:
        print(f"  CONTEXT: {plan.dispatch.context}")

    if _ask(prompt, "\n  Approve bring-up and start the run? [y/N] ").lower() not in ("y", "yes"):
        print("  aborted — nothing recreated.")
        return 1

    if plan.dispatch.context:
        # Record the operator's brief on the frozen scope itself (same "_note field"
        # idiom as plan_vpn's `_vpn_server`) so the run this launches carries it, even
        # though run_auto has no kwarg to receive it yet (see _default_dispatch).
        plan.scope_draft["_context"] = plan.dispatch.context
    envprep.freeze_scope(plan.scope_path, plan.scope_draft, approver="operator")

    ex = envprep.execute(plan, runner)
    if not ex.ok:
        bad = next((s.name for s in ex.steps if not s.ok), "?")
        print(f"  bring-up failed at: {bad} — not dispatching.")
        return 1

    vf = envprep.verify(plan, runner)
    if not vf.ok:
        bad = next((s.name for s in vf.steps if not s.ok), "?")
        print(f"  verification failed at: {bad} — not dispatching.")
        return 1

    dispatch = dispatch or _default_dispatch(args)
    return dispatch(plan)
