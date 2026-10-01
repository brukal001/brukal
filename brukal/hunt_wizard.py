"""The guided `brukal hunt` wizard: gather -> draft -> plan -> show -> ONE
approval -> freeze + execute + verify -> dispatch. Deterministic; no LLM.
All side effects go through the injected runner / dispatch, so this module is
fully testable without Docker, a real key, or a network. It must never import
`brukal.kali`/`brukal.executor`/`brukal.agents.*` at module load — those only
come in (lazily) inside `_default_dispatch`, which is the one place that talks
to the real run engines."""
from __future__ import annotations

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
    `context` parameter — the operator's one-line brief is shown/logged by the
    wizard but is not currently plumbed into the engine's seeded objective;
    that would need a separate change to `run_auto`'s signature."""
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
    dispatch = dispatch or _default_dispatch(args)

    mode = (args.mode or _ask(prompt, "  Mode — web or vpn? ")).lower()
    if mode not in ("web", "vpn"):
        print("  unknown mode — choose web or vpn.")
        return 1

    key, _res = resolve_key(args.provider)
    if key is None:
        print("  no API key and none provided — aborting (set <PROVIDER>_API_KEY "
              "or use a local model).")
        return 1

    if mode == "web":
        url = args.url or _ask(prompt, "  Target URL: ")
        context = args.context or _ask(prompt, "  One-line context (what to focus on): ")
        try:
            plan = envprep.plan_web(url, context, args.provider, args.model,
                                    args.scope, args.vault, args.audit)
        except ValueError as e:
            print(f"  cannot build web scope: {e}")
            return 1
    else:
        ovpn = args.ovpn or _ask(prompt, "  Path to .ovpn: ")
        targets = [t for t in _ask(prompt, "  Target IP/CIDR(s), comma-separated: ").split(",")
                   if t.strip()]
        try:
            plan = envprep.plan_vpn(ovpn, targets, args.provider, args.model,
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

    if _ask(prompt, "\n  Approve bring-up and start the run? [y/N] ").lower() not in ("y", "yes"):
        print("  aborted — nothing recreated.")
        return 1

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

    return dispatch(plan)
