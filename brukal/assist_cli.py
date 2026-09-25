"""
assist_cli.py — the interactive/entry layer for assist: the wizard, the rich and
plain menu loops, approvers, host/vhost authorisation prompts and the run_solve /
run_auto entry points. Extracted verbatim from assist.py (no logic change); the
testable session logic stays in AssistSession.
"""
from __future__ import annotations

from .assist import AssistSession
from .audit import AuditLog
from .executor import Executor
from .gate import Gate
from .kali import DockerKali
from .kali import FakeKali
from .scope import load_scope
from .trust import TrustModel
from pathlib import Path
import getpass
import os
import re
import sys
import time
from .assist_util import (
    _AGENT_ICON,
    _PHASE_COLOUR,
    _VERDICT_COLOUR,
    _explain_run_error,
    record_engagement_stop,
)








def _show_tool_policy(console, vhost=""):
    """Show which tools run automatically vs which pause for a human — the broad
    Kali policy: safe enumeration auto-runs, attack/irreversible/unknown ask you."""
    from .risk import _ATTACK_TOOLS, _READ_ONLY_TOOLS
    auto = ", ".join(sorted(_READ_ONLY_TOOLS)[:26]) + " …"
    human = ", ".join(sorted(_ATTACK_TOOLS)[:24]) + " …"
    if console is not None:
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        t = Table.grid(padding=(0, 2))
        t.add_column(); t.add_column()
        t.add_row(Text("✅ AUTO-RUN", style="bold green"),
                  Text("safe read-only enumeration\n" + auto, style="grey70"))
        t.add_row(Text("🔒 ASKS YOU", style="bold yellow"),
                  Text("attack / irreversible / unknown tools — you approve (y/N)\n" + human,
                       style="grey70"))
        t.add_row(Text("🚫 DENIED", style="bold red"),
                  Text("anything outside the authorised scope — always, by construction",
                       style="grey70"))
        console.print(Panel(t, title="[bold]tool policy — broad Kali mode[/]",
                            border_style="cyan"))
    else:
        print("  AUTO-RUN (safe enum):", auto)
        print("  ASKS YOU (attack/unknown):", human)
        print("  DENIED: anything out of scope")


def run_wizard(fake: bool = False, container: str = "brukal-kali") -> int:
    """The guided `brukal` experience: ask the target, pick the brain, show the
    tool policy + loaded playbooks, choose auto/manual, then hunt — all governed."""
    import ipaddress
    import json

    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    _emit(console, "\n  Let's set up a governed hunt — a few quick questions.\n",
          "\n  [bold cyan]Let's set up a governed hunt[/] — a few quick questions.\n")

    # 1) target
    target = _ask(console, "  1) Target IP you are AUTHORISED to test").strip()
    if not target:
        print("  no target — bye."); return 1
    try:
        net = ipaddress.ip_network(f"{target}/32", strict=False)
    except ValueError:
        print(f"  '{target}' is not a valid IP."); return 1

    # 2) optional web vhost (HTB boxes often route by hostname)
    vhost = _ask(console, "  2) Known web vhost, e.g. nexus.htb (blank to skip)", "").strip()

    # 3) the brain — all options (Claude / Ollama / Groq / OpenAI-compatible)
    _emit(console, "  3) Choose the brain:")
    provider, model, base_url = choose_brain(console)

    # build a broad-mode scope for just this host (all tools; dangerous -> human)
    Path("runs").mkdir(parents=True, exist_ok=True)
    scope_path = "runs/wizard_scope.json"
    Path(scope_path).write_text(json.dumps({
        "engagement": f"brukal-hunt-{target}",
        "authorized_cidrs": [str(net)],
        "authorized_hosts": [vhost.lower()] if vhost else [],
        "allowlisted_tools": "all",
        "rate_limit_per_min": 60,
    }, indent=2), encoding="utf-8")

    # 4) show the tool policy (auto vs human) + the skill library
    _emit(console, "\n  4) Tool policy for this hunt:")
    _show_tool_policy(console, vhost)
    try:
        from .skills import SkillLibrary
        lib = SkillLibrary()
        hits = lib.retrieve(vhost or target, 3)
        rel = ("; relevant: " + ", ".join(s.name for s in hits)) if hits else ""
        _emit(console, f"  📚 {len(lib)} red-team playbooks loaded{rel} "
                       f"(used automatically while hunting).")
    except Exception:
        pass

    # 5) auto or manual
    _emit(console, "\n  5) How should Brukal work?")
    auto = choose_run_mode(console)

    if not fake and not _confirm(console, f"\n  Ready. Confirm you are AUTHORISED to "
                                          f"test {target}?"):
        print("  aborted — authorisation not confirmed."); return 1

    _emit(console, f"\n  🚀 hunting {target} — {'AUTO' if auto else 'MANUAL'} mode. "
                   f"Dangerous steps will pause for your OK.\n",
          f"\n  [bold green]🚀 hunting {target}[/] — {'AUTO' if auto else 'MANUAL'} mode. "
          f"Dangerous steps will pause for your OK.\n")

    common = dict(yes_authorised=True, scope_path=scope_path, fake=fake,
                  container=container, provider=provider, model=model, base_url=base_url,
                  vault_path="runs/vault")
    if auto:
        return run_auto(target, **common)
    return run_solve(target, auto=False, **common)


def _auto_approver(decision) -> bool:
    """Auto-mode approver: keep the hunt moving on REVERSIBLE escalations (an
    aggressive-but-read-only scan like `nmap -T4 --top-ports`), but PAUSE on
    anything IRREVERSIBLE or unclassified — reverse shells, credential attacks,
    `sqlmap --dump`, writes, unknown tools. That is 'safe/aggressive-but-reversible
    runs itself; dangerous asks a human', which the operator approves in `brukal
    solve`. Scope + audit are untouched; this only tunes the soft escalation."""
    return getattr(decision, "reversibility", None) == "reversible"


def _full_send_approver(decision) -> bool:
    """'Full send' auto-mode approver: approve EVERY escalation the gate routed here —
    including irreversible, attack-grade actions (credential attacks, sqlmap --dump,
    reverse shells). It is only ever called on decisions the HARD gate already let
    through (in scope, allowlisted, parsed, not smuggling a host): the approver is
    invoked on ESCALATE, never on DENY, so an out-of-scope command is still refused
    before it can reach here. This unleashes maximum autonomy WITHIN your authorised
    scope; it does not — and cannot — widen scope. Enabled by `--full-send` /
    BRUKAL_FULL_SEND=1, and only on an authorised live run."""
    return True


class _AutoLiveView:
    """A live, animated terminal view of the autonomous hunt: a spinner that shows
    what Brukal is doing right now (thinking / running a tool / rendering a site),
    running tallies, and a scrolling step log with colour-coded verdicts. Uses rich
    Live's background refresh so the spinner keeps moving during a blocking scan."""

    def __init__(self, console, target, cage, budget, objective=""):
        self.con = console
        self.target = target
        self.cage = cage
        self.budget = budget
        self.objective = objective
        self.status = "starting…"
        self.steps: list = []                 # (idx, phase, verdict, action, summary)
        self.tally = {"ran": 0, "blocked": 0, "escalated": 0, "web": 0}
        self._live = None

    def set_status(self, text):
        self.status = text
        if self._live is not None:
            self._live.update(self._render())

    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.spinner import Spinner
        from rich.table import Table
        from rich.text import Text

        t = self.tally
        header = Text.assemble(
            ("🎯 ", ""), (self.target, "bold cyan"), (f"  ({self.cage})   ", "grey50"),
            (f"{t['ran']} ran", "green"), (" · ", "grey42"),
            (f"{t['escalated']} escalated", "yellow"), (" · ", "grey42"),
            (f"{t['blocked']} blocked", "red"), (" · ", "grey42"),
            (f"{t['web']} web", "magenta"),
            (f"   step {len(self.steps)}/{self.budget}", "grey62"))
        obj = Text(f"🏁 {self.objective}", style="grey58") if self.objective else Text("")
        spin = Spinner("dots", text=Text(self.status, style="bold yellow"))

        log = Table.grid(padding=(0, 1))
        log.add_column(justify="right"); log.add_column(); log.add_column(); log.add_column()
        for idx, phase, verdict, action, summ in self.steps[-9:]:
            c = _VERDICT_COLOUR.get(verdict, "grey50")
            log.add_row(Text(f"{idx}", style="grey42"),
                        Text((phase or "").upper()[:5], style="cyan"),
                        Text(f"{verdict:<9}", style=f"bold {c}"),
                        Text(action[:58], style="white"))
        body = Group(header, obj, Text(""), spin, Text(""), log)
        return Panel(body, title="[bold cyan]brukal — governed autonomous hunt[/]",
                     border_style="cyan")

    def on(self, kind, payload):
        if kind == "thinking":
            ag = payload.get("agent")
            if ag:                            # the phase's specialist is composing its command
                self.status = (f"{_AGENT_ICON.get(ag, '🧠')} {ag} agent — "
                               f"{(payload.get('goal') or 'planning')[:44]}")
            else:
                self.status = "🧠 thinking… (planning the next move)"
        elif kind == "running":
            a = payload.get("action", "")
            ag = payload.get("agent")
            if payload.get("web"):
                self.status = f"🌐 browser: {a[:56]}"
            else:
                tool = (a.split() or [""])[0]
                icon = _AGENT_ICON.get(ag, "⚙")
                who = f"{ag}: " if ag else ""
                self.status = f"{icon}  {who}running {tool} …  ({a[:44]})"
        elif kind == "crawling":
            self.status = "🕸  crawling — mapping the web attack surface…"
        elif kind == "crawl":
            self.status = (f"🕸  crawling {str(payload.get('url', ''))[:48]}  "
                           f"(page {payload.get('found', '?')})")
        elif kind == "learning":
            self.status = f"📚 learning — researching {str(payload.get('query', ''))[:40]}…"
        elif kind == "step":
            s = payload["step"]
            v = s.verdict or "-"
            if s.executed:
                self.tally["ran"] += 1
                if (s.command or "").startswith("WEB:"):
                    self.tally["web"] += 1
            elif v == "ESCALATE":
                self.tally["escalated"] += 1
            else:
                self.tally["blocked"] += 1
            self.steps.append((s.index, s.phase, v, s.command or "", s.summary))
            self.status = "observing the result…"
        elif kind == "stop":
            self.status = f"⏹ stopped: {payload.get('reason', '')}"
        if self._live is not None:
            self._live.update(self._render())

    def start(self):
        from rich.live import Live
        self._live = Live(self._render(), console=self.con, refresh_per_second=10,
                          transient=False)
        return self._live


class _PlainAutoView:
    """Live feedback for `brukal auto` when rich is NOT installed. The old plain path
    only printed a line when a STEP finished, so during the model call and a long scan
    the screen sat silent and looked frozen. This prints what Brukal is doing right now
    (🧠 thinking / ⚙ running <cmd>) and runs a background heartbeat that ticks the
    elapsed seconds in place, so a 2-minute scan visibly shows it's still working."""

    def __init__(self):
        import threading
        self._threading = threading
        self._stop = threading.Event()
        self._thread = None

    def _beat(self, label):
        start = time.time()
        while not self._stop.wait(5):        # tick every 5s
            el = int(time.time() - start)
            sys.stdout.write(f"\r     … {label} — {el}s   ")
            sys.stdout.flush()

    def _start_beat(self, label):
        self._stop_beat()
        self._stop = self._threading.Event()
        self._thread = self._threading.Thread(target=self._beat, args=(label,), daemon=True)
        self._thread.start()

    def _stop_beat(self):
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=1)
            self._thread = None
            sys.stdout.write("\r" + " " * 64 + "\r")   # clear the heartbeat line
            sys.stdout.flush()

    def set_status(self, text):
        print(f"  {text}")

    def on(self, kind, payload):
        if kind == "thinking":
            self._stop_beat()
            ag = payload.get("agent")
            if ag:                            # the phase's specialist is composing its command
                print(f"  {_AGENT_ICON.get(ag, '🧠')} {ag} agent — "
                      f"{(payload.get('goal') or 'planning')[:70]}")
                self._start_beat(f"{ag} thinking")
            else:
                print("  🧠 thinking…"); self._start_beat("thinking")
        elif kind == "running":
            self._stop_beat()
            action = (payload.get("action") or "")[:90]
            ag = payload.get("agent")
            tag = "🌐" if payload.get("web") else _AGENT_ICON.get(ag, "⚙")
            who = f"{ag}: " if ag else ""
            print(f"  {tag} {who}running: {action}")
            tool = (action.split() or [""])[0]
            self._start_beat(f"running {tool} (killed at 180s if it runs long)")
        elif kind == "crawling":
            self._stop_beat()
            print("  🕸 crawling — mapping the web attack surface…")
            self._start_beat("crawling the site")
        elif kind == "learning":
            self._stop_beat()
            print(f"  📚 learning — researching {payload.get('query', '')}")
            self._start_beat("researching (control-plane)")
        elif kind == "coached":
            self._stop_beat(); print(f"  ↩ {(payload.get('note') or '')[:110]}")
        elif kind == "solved":
            self._stop_beat(); print("  🎯 SOLVED — verified from real output")
        elif kind == "step":
            self._stop_beat()
            st = payload["step"]
            print(f"  [{st.index}] {(st.phase or '').upper():<12} {st.verdict or '-':<9} "
                  f"{(st.command or '')[:70]}\n        {st.summary[:110]}")
        elif kind == "stop":
            self._stop_beat()


def _rich_approver(con, holder):
    """Escalation sign-off that pauses the live spinner, prompts, then resumes."""
    from rich.panel import Panel
    from rich.text import Text

    def approve(decision) -> bool:
        st = holder.get("status")
        if st is not None:
            st.stop()
        con.print(Panel(Text.assemble(
            ("ESCALATION — human sign-off required\n", "bold yellow"),
            (f"action : {decision.action}\n", "white"),
            (f"target : {decision.target}   agent: {decision.agent}\n", "white"),
            (f"risk   : {decision.risk_band}  ({decision.reason})", "grey62")),
            border_style="yellow"))
        try:
            ans = (con.input("  approve this action? [y/N] ").strip().lower()
                   if con.file.isatty() else "")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if st is not None:
            st.start()
        return ans in ("y", "yes")

    return approve


def _show_highlights(con, Panel, Text, hits, title):
    if not hits:
        return
    body = Text()
    for i, (tag, line) in enumerate(hits):
        if i:
            body.append("\n")
        body.append(f"{tag:>11} ", style="bold yellow")
        body.append(line, style="white")
    con.print(Panel(body, title=f"[bold yellow]★ {title}[/]", border_style="yellow"))


_AUTO_CAP = 20   # in auto mode, hand back to the human after this many auto-runs


def _menu_loop(session, audit, target, cage, con, holder, auto=False):
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text

    flags = {"auto": auto}
    auto_steps = 0

    con.print(Panel(Text.assemble(("BRUKAL — pentest companion   ", "bold cyan"),
                                   (f"target={target}   cage={cage}   "
                                    f"mode={'AUTO' if auto else 'MANUAL'}", "white")),
                    border_style="cyan"))

    if session.resumed:
        con.print(f"[green]↻ resumed[/] — loaded [bold]{session.resumed}[/] prior "
                  f"finding(s) for {target}; picking up where we left off.")

    # Ask up front what the box wants (HTB task questions) — this steers everything.
    con.print("[grey62]What is the box asking you to find? (HTB task questions, one per "
              "line — e.g. \"How many open TCP ports?\"). Enter blank to skip / finish.[/]")
    while True:
        try:
            obj = Prompt.ask("  objective", default="")
        except (EOFError, KeyboardInterrupt):
            break
        if not obj:
            break
        session.add_objective(obj)

    # Lay out the shortest-path plan up front so the operator sees the route.
    if not session.plan:
        with con.status("[cyan]companion planning the route…", spinner="dots"):
            session.make_plan()

    def show_plan():
        pt = session._plan_text()
        if pt:
            con.print(Panel(pt, title="[bold]plan — shortest path[/]", border_style="blue"))

    def run_and_show(command):
        with con.status(f"[cyan]running:[/] {command}", spinner="dots") as st:
            holder["status"] = st
            d, r, new_hl = session.run(command)
            holder["status"] = None
        colour = _VERDICT_COLOUR.get(d.verdict, "white")
        con.print(Text.assemble(("  → ", ""), (d.verdict, f"bold {colour}"),
                                 (f"   {d.layer}", "grey50")))
        if r is not None and (r.stdout or "").strip():
            con.print(Panel(r.stdout.strip()[:1800], title="raw output", border_style="grey23"))
            _show_highlights(con, Panel, Text, new_hl, "key results")
        elif r is None:
            con.print(f"  [grey50]{d.reason}[/]")
        session.last = None   # regenerate advice from the new findings

    while True:
        # objectives tracker + the plan, shown every turn
        if session.objectives:
            ot = Text()
            for o in session.objectives:
                ot.append("? ", style="bold yellow"); ot.append(o + "\n")
            con.print(Panel(ot, title="objectives", border_style="yellow"))
        show_plan()

        # AUTO: take the single top move itself, pausing on manual/escalation/cap.
        if flags["auto"]:
            if session.last is None:
                with con.status("[cyan]companion thinking…", spinner="dots"):
                    session.advise()
            s = session.last
            if s.command and auto_steps < _AUTO_CAP:
                con.print(f"[grey62]▶ auto — running:[/] {s.command} [grey62](Ctrl-C to pause)[/]")
                try:
                    run_and_show(s.command); session.option_list = []
                    auto_steps += 1
                    continue
                except KeyboardInterrupt:
                    con.print("\n[yellow]paused — back to manual.[/]")
                    flags["auto"] = False
            else:
                why = ("hit the auto-step limit" if auto_steps >= _AUTO_CAP
                       else "the next step is yours (manual)" if s.manual
                       else "no safe command to run")
                con.print(f"[yellow]⏸ auto paused — {why}. Over to you.[/]")
                flags["auto"] = False

        # MANUAL: present a RANKED list of moves — pick one, run your own, or steer.
        if not session.option_list:
            with con.status("[cyan]companion weighing the best moves…", spinner="dots"):
                session.advise_options(n=3)
        opts = session.option_list

        read = getattr(session.strategist, "last_read", "") if session.strategist else ""
        if read:
            con.print(Text.assemble(("  🧠 Brukal: ", "bold cyan"), (read, "white")))

        body = Text()
        for i, o in enumerate(opts, 1):
            pc = _PHASE_COLOUR.get((o.phase or "").lower(), "cyan")
            body.append(f"[{i}] ", style="bold cyan")
            if o.phase:
                body.append(f"{o.phase.upper()}  ", style=f"bold {pc}")
            body.append(o.goal or (o.rationale or "")[:60] or "next move", style="white")
            if o.command:
                body.append(f"\n     RUN: {o.command}", style="green")
            elif o.manual:
                body.append(f"\n     MANUAL: {o.manual}", style="yellow")
            if i < len(opts):
                body.append("\n")
        con.print(Panel(body, title="[bold]next moves — pick a number, or type your own[/]",
                        border_style="cyan"))
        if session.highlights:
            _show_highlights(con, Panel, Text, session.highlights[-8:], "what we know so far")

        actions = [("c", "type your own command (gated)"),
                   ("?", "ask Brukal about the hunt (what did you find? why?)"),
                   ("i", "give an instruction / re-plan the options"),
                   ("p", "run all the SAFE options in PARALLEL"),
                   ("a", f"switch to {'MANUAL' if flags['auto'] else 'AUTO'} mode"),
                   ("t", "add a note"), ("m", "record a manual step you did"),
                   ("o", "add an objective"), ("k", "search skill playbooks"),
                   ("v", "verify audit chain"), ("q", "quit")]
        grid = Table.grid(padding=(0, 2))
        for key, label in actions:
            grid.add_row(Text(f"[{key}]", style="bold cyan"), Text(label))
        con.print(grid)

        nums = [str(i) for i in range(1, len(opts) + 1)]
        try:
            choice = Prompt.ask("  pick a number or action",
                                choices=nums + [k for k, _ in actions], default="1")
        except (EOFError, KeyboardInterrupt):
            break

        if choice in nums:
            opt = opts[int(choice) - 1]
            if opt.command:
                run_and_show(opt.command)
            elif opt.manual:
                session.manual(opt.manual)
                con.print(f"  [yellow]recorded manual:[/] {opt.manual}")
            session.option_list = []
        elif choice == "c":
            run_and_show(Prompt.ask("  your command")); session.option_list = []
        elif choice == "?":
            q = Prompt.ask("  your question about the hunt", default="")
            if q.strip():
                with con.status("[cyan]Brukal is reviewing the findings…", spinner="dots"):
                    ans = session.ask(q.strip())
                con.print(Panel(ans, title="[bold cyan]🧠 Brukal[/]", border_style="cyan"))
        elif choice == "i":
            instr = Prompt.ask("  your instruction (what should we try / focus on?)",
                               default="")
            with con.status("[cyan]re-planning the options…", spinner="dots"):
                session.advise_options(instr, n=3)
        elif choice == "p":
            with con.status("[cyan]running the safe options in parallel…", spinner="dots") as st:
                holder["status"] = st
                batch = session.run_options_parallel(session.option_list)
                holder["status"] = None
            for label, d, r, _hl in batch:
                v = d.verdict if d is not None else "SKIP"
                colour = _VERDICT_COLOUR.get(v, "grey50")
                con.print(Text.assemble(("  → ", ""), (v, f"bold {colour}"), (f"  {label}", "white")))
        elif choice == "a":
            flags["auto"] = not flags["auto"]; auto_steps = 0
            con.print(f"  mode → [bold]{'AUTO' if flags['auto'] else 'MANUAL'}[/]")
        elif choice == "t":
            session.note(Prompt.ask("  note / paste output")); session.option_list = []
        elif choice == "m":
            session.manual(Prompt.ask("  what you did")); session.option_list = []
        elif choice == "o":
            session.add_objective(Prompt.ask("  objective")); session.option_list = []
        elif choice == "k":
            for sk in (session.skills.retrieve(Prompt.ask("  topic"), 4)
                       if session.skills else []):
                con.print(f"    [magenta]\\[{sk.category}][/] {sk.name}")
        elif choice == "v":
            con.print(f"  audit chain intact: [green]{audit.verify()}[/]")
        elif choice == "q":
            break


_HELP = """  pick a NUMBER to take that move, or type your own:
    <cmd>  run any command (through the gate)      <instruction>  steer the options
    ask <question>   ask Brukal about the hunt (e.g. "what did you find?", "why ssh?")
    p  run all the SAFE options in PARALLEL        note <text>   manual <text>
    host <name>  authorise a vhost (e.g. host nexus.htb) so web/Host-header hits pass
    plan   auto   manual-mode   skills <topic>   verify   quit
    (a question — ending in '?' or starting with what/why/how… — is answered, not run;
     `auto` runs the safe steps itself; risky/irreversible moves still pause for y/N)"""


def _looks_like_command(text: str) -> bool:
    """Heuristic: does the operator's free text look like a command to RUN (vs an
    instruction to steer with)? First token is a known/allowlisted-ish tool name."""
    first = (text.split() or [""])[0].lower()
    return bool(re.match(r"^[a-z][a-z0-9._-]*$", first)) and first in _COMMON_TOOLS


_QUESTION_WORDS = frozenset({
    "what", "whats", "why", "how", "where", "when", "which", "who", "whose",
    "is", "are", "was", "were", "did", "does", "do", "can", "could", "should",
    "would", "will", "has", "have", "tell", "explain", "show", "describe",
    "summarise", "summarize", "recap"})


def _looks_like_question(text: str) -> bool:
    """Is the operator ASKING about the hunt (answer it) rather than instructing a
    re-plan? A trailing '?' or a leading interrogative word means a question."""
    t = (text or "").strip()
    if not t:
        return False
    if t.endswith("?"):
        return True
    first = re.sub(r"[^a-z]", "", t.split()[0].lower())
    return first in _QUESTION_WORDS


_COMMON_TOOLS = frozenset({
    "nmap", "masscan", "gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz", "nikto",
    "whatweb", "wafw00f", "nuclei", "curl", "wget", "dig", "host", "dnsrecon",
    "sslscan", "smbclient", "smbmap", "enum4linux", "enum4linux-ng", "nbtscan",
    "snmpwalk", "ldapsearch", "redis-cli", "hydra", "medusa", "ncrack", "sqlmap",
    "wpscan", "john", "hashcat", "searchsploit", "crackmapexec", "netexec", "nxc",
    "kerbrute", "evil-winrm", "nc", "ncat", "netcat", "socat", "ssh", "ping"})


def _show_highlights_plain(hits, title="what Brukal found"):
    """Plain-text version of the rich highlights panel — the 'what did that command
    tell us' line, so a run visibly produces knowledge, not just raw text."""
    if not hits:
        return
    print(f"  ★ {title}:")
    for tag, line in hits:
        print(f"      {tag:>11}  {line}")


def _print_options(opts):
    print("\n  NEXT MOVES — pick a number, or type your own command/instruction:")
    for i, o in enumerate(opts, 1):
        tag = f"[{o.phase}] " if o.phase else ""
        # next(iter(...), "") is empty-safe: an option with no goal AND no rationale
        # (a weak/misbehaving model) must not IndexError on ""splitlines()[0].
        first_line = next(iter((o.rationale or "").splitlines()), "")
        label = o.goal or first_line[:70] or "next move"
        print(f"    [{i}] {tag}{label}")
        # Show WHY (the strategist's reasoning) so the operator sees Brukal thinking
        # about the findings, not just a bare command list.
        why = (o.rationale or "").strip()
        if why and why != label:
            print(f"         why: {why.splitlines()[0][:110]}")
        if o.command:
            print(f"         RUN: {o.command}")
        elif o.web:
            print(f"         WEB: {o.web}")
        elif o.manual:
            print(f"         MANUAL (you): {o.manual}")
    print("    [type a command to run it · type an instruction to re-plan · "
          "host <name> to authorise a vhost · help · quit]")


def _report(d, r):
    # Make the OUTCOME of a run visible, not just a raw dump: a timed-out command
    # (returncode 124 / "timed out") otherwise prints only its startup banner and
    # looks like it "did nothing". Always tell the operator what actually happened.
    if r is None:
        print(f"  -> {d.verdict}  ({d.layer}: {d.reason})")
        return
    rc = getattr(r, "returncode", 0)
    out = (getattr(r, "stdout", "") or "").rstrip()
    stderr = (getattr(r, "stderr", "") or "")
    if rc == 124 or "timed out" in stderr.lower():
        print(f"  -> {d.verdict}  ⏱ TIMED OUT — killed before it finished, so NO usable "
              f"result. Re-run narrower: a small wordlist (not rockyou), fewer ports, "
              f"or a single service.")
    elif rc not in (0, None):
        print(f"  -> {d.verdict}  (exit {rc})")
    else:
        print(f"  -> {d.verdict}")
    if out:
        for line in out.splitlines():
            print(f"     {line}")
    # On a failure/empty run, show stderr so the reason is visible (e.g. a wordlist
    # that doesn't exist prints "no such file" to stderr — otherwise it looks silent).
    err = stderr.rstrip()
    if err and (not out or rc not in (0, None)):
        for line in err.splitlines()[:8]:
            print(f"     ! {line}")
    elif not out and rc == 0:
        print("     (ran, no output)")


def _deny_hint(d):
    """After a DENY, tell the operator how to unblock it when it's a fixable case
    (an out-of-scope vhost they can authorise, or shell metacharacters to drop)."""
    reason = (getattr(d, "reason", "") or "").lower()
    if "out of scope" in reason or "out-of-scope host" in reason:
        print("     ↪ if that host is a real vhost of your target, authorise it: "
              "type  host <name>  (e.g.  host nexus.htb)")
    elif "metacharacter" in reason or "injection" in reason:
        print("     ↪ drop shell operators (| > 2>/dev/null && ;) — send the bare "
              "command; output is captured for you.")


def _authorise_vhost(session, name: str) -> bool:
    """Operator authorises a virtual host (e.g. nexus.htb) for this session — a
    deliberate scope-TIME act (same as `brukal target`/`brukal web --host`), NOT a
    runtime widen by an agent. Installs a new Scope (with the vhost added) on both the
    shell gate and the web browser, so subsequent web renders and Host-header requests
    to that vhost pass the gate. Returns False if nothing to update."""
    name = (name or "").strip().lower()
    if not name:
        return False
    # Authorise the host AND, for a bare domain, its vhosts (*.domain) — so vhost
    # fuzzing (Host: FUZZ.domain against the in-scope IP) is not blocked. A wildcard
    # only widens the *hostname* set; the network destination is still the in-scope
    # IP (URL/CIDR check + nftables), so this cannot reach an out-of-scope host.
    names = _vhost_names(name)
    updated = False
    gate = getattr(session.executor, "_gate", None)
    for n in names:
        if gate is not None:
            gate.scope = gate.scope.with_host(n)
            updated = True
        if getattr(session, "browser", None) is not None:
            session.browser._scope = session.browser._scope.with_host(n)
            updated = True
    # Also map the concrete vhost -> the target IP in the cage's /etc/hosts, so it
    # actually RESOLVES for the browser/curl (the wildcard can't be an /etc/hosts
    # entry, so only the concrete name is mapped).
    if getattr(session, "cage_container", None):
        from .web import map_cage_host
        map_cage_host(name, session.target, session.cage_container)
    return updated


def _vhost_names(name: str) -> list[str]:
    """A host to authorise, plus its `*.domain` wildcard when it's a bare domain
    (has a dot, isn't already a wildcard, isn't an IP) — so its vhosts are in scope."""
    name = (name or "").strip().lower()
    if not name:
        return []
    names = [name]
    if "." in name and not name.startswith("*.") and not name.replace(".", "").isdigit():
        names.append("*." + name)
    return names


def _take_option(session, opt):
    """Execute a chosen option: a RUN/WEB goes through the gate; a MANUAL is recorded.
    Narrate the result so the operator sees Brukal *hunt* — run, learn, react."""
    if opt.command:
        d, r, hl = session.run(opt.command)
        _report(d, r); _deny_hint(d); _show_highlights_plain(hl)
    elif opt.web:
        d, r, hl = session.run_web(opt.web)
        _report(d, r); _deny_hint(d); _show_highlights_plain(hl)
    elif opt.manual:
        session.manual(opt.manual)
        print(f"  recorded manual step: {opt.manual}")
    session.option_list = []          # regenerate from the new findings next turn


def _show_plan_plain(session):
    pt = session._plan_text()
    if pt:
        print("\n  PLAN (shortest path):")
        for line in pt.splitlines():
            print(f"    {line}")
        print()


def _plain_loop(session, audit, target, cage, auto=False):
    print(f"\n  brukal solve — target {target}   cage={cage}   "
          f"mode={'AUTO' if auto else 'MANUAL'}")
    if session.resumed:
        print(f"  ↻ resumed — loaded {session.resumed} prior finding(s) for {target}.")
    print(_HELP)
    if not session.plan:
        print("  planning the route…")
        session.make_plan()
    _show_plan_plain(session)
    flags = {"auto": auto}
    auto_steps = 0
    if flags["auto"]:
        session.advise()                    # seed the top move for the auto branch
    while True:
        # AUTO: run the safe top move itself, pausing on manual/cap/Ctrl-C.
        if flags["auto"]:
            s = session.last
            if s and s.command and auto_steps < _AUTO_CAP:
                print(f"  [auto] running: {s.command}")
                try:
                    d, r, _ = session.run(s.command)
                    _report(d, r)
                    auto_steps += 1
                    session.advise()
                    continue
                except KeyboardInterrupt:
                    print("\n  paused — manual mode.")
                    flags["auto"] = False
            else:
                print("  [auto] paused — over to you (type `auto` to resume).")
                flags["auto"] = False

        # MANUAL: present a ranked list of moves; the operator picks one, runs their
        # own command, or gives an instruction to re-plan the options.
        if not session.option_list:
            print("  thinking…")
            session.advise_options(n=3)
        read = getattr(session.strategist, "last_read", "") if session.strategist else ""
        if read:
            print(f"\n  🧠 Brukal: {read}")     # conversational take on the last result
        _print_options(session.option_list)
        try:
            raw = input("  brukal> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if raw.isdigit() and 1 <= int(raw) <= len(session.option_list):
            _take_option(session, session.option_list[int(raw) - 1])
        elif raw == "" and session.option_list:
            _take_option(session, session.option_list[0])       # enter = top move
        elif raw in ("quit", "exit", "q"):
            break
        elif raw in ("help", "?"):
            print(_HELP)
        elif raw == "auto":
            flags["auto"] = True; auto_steps = 0; session.advise(); print("  mode → AUTO")
        elif raw in ("manual-mode", "manual_mode"):
            flags["auto"] = False; print("  mode → MANUAL")
        elif raw == "verify":
            print("  audit chain intact:", audit.verify())
        elif raw in ("p", "par", "parallel"):
            print("  running the safe options in parallel…")
            for label, d, r, _hl in session.run_options_parallel(session.option_list):
                v = d.verdict if d is not None else "SKIP"
                print(f"    [{v}] {label}")
                if r is not None and (r.stdout if hasattr(r, 'stdout') else getattr(r, 'body', '')):
                    body = getattr(r, 'stdout', None) or getattr(r, 'body', '') or ''
                    print(f"        {body.strip()[:120]}")
        elif raw == "plan":
            print("  re-planning the route…")
            session.make_plan(); _show_plan_plain(session); session.option_list = []
        elif raw.split(None, 1)[0] in ("host", "scope", "authorise", "authorize") \
                and len(raw.split(None, 1)) == 2:
            name = raw.split(None, 1)[1].strip()
            if _authorise_vhost(session, name):
                print(f"  ✓ authorised vhost {name} (scope-time). It's now in scope for "
                      f"web + shell against this target.")
            session.option_list = []
        elif raw.startswith("note "):
            session.note(raw[5:].strip()); session.option_list = []; print("  noted.")
        elif raw.startswith("manual "):
            session.manual(raw[7:].strip()); session.option_list = []; print("  recorded.")
        elif raw.startswith("skills "):
            for s in (session.skills.retrieve(raw[7:].strip(), 4) if session.skills else []):
                print(f"    [{s.category}] {s.name}")
        elif raw.startswith("run "):
            d, r, hl = session.run(raw[4:].strip())
            _report(d, r); _deny_hint(d); _show_highlights_plain(hl); session.option_list = []
        elif raw.startswith("ask ") or raw.startswith("? "):
            q = raw.split(None, 1)[1].strip()                    # explicit question
            print(f"\n  🧠 Brukal: {session.ask(q)}\n")
        elif _looks_like_command(raw):
            d, r, hl = session.run(raw)                          # custom command
            _report(d, r); _deny_hint(d); _show_highlights_plain(hl); session.option_list = []
        elif _looks_like_question(raw):
            # a question about the hunt -> answer it conversationally (runs nothing)
            print(f"\n  🧠 Brukal: {session.ask(raw)}\n")
        else:
            print("  re-planning around that…")
            session.advise_options(raw, n=3)     # free text = an instruction to steer


def _print_suggestion(s):
    tag = f"[{s.phase.upper()}] " if s.phase else ""
    if s.goal:
        print(f"\n  {tag}GOAL: {s.goal}")
    print(f"  [companion] {s.rationale}")
    if s.command:
        print(f"  suggested (gated):  {s.command}")
    if s.manual:
        print(f"  manual step (you):  {s.manual}")
    print()


def _ask(console, prompt: str, default: str = "") -> str:
    """One-line prompt that works with or without rich; fail-closed on EOF."""
    try:
        if console is not None:
            from rich.prompt import Prompt
            return Prompt.ask(prompt, default=default)
        return input(f"{prompt} ").strip() or default
    except (EOFError, KeyboardInterrupt, OSError):
        return default


def _confirm(console, prompt: str) -> bool:
    """Yes/No confirmation, fail-closed (default No, No on EOF/non-tty)."""
    ans = _ask(console, f"{prompt} [y/N]", "").strip().lower()
    return ans in ("y", "yes")


def _emit(console, plain: str, markup: str | None = None):
    if console is not None:
        console.print(markup if markup is not None else plain)
    else:
        print(plain)


def _spend_line(session) -> str:
    """One-line LLM token/cost tally for a finished hunt, read from the strategist's
    client meter. Reachable because the strategist is the only thing that calls the
    model, so its meter is the whole engagement's spend."""
    try:
        meter = session.strategist._llm.usage
    except AttributeError:
        return ""
    if not meter.calls:
        return "  brain: no model calls (fully deterministic run)"
    return f"  brain spend — {meter.summary()}"


def _spend_detail(session) -> dict:
    """The same tally as `_spend_line`, structured, for the interchange export.

    A cost comparison between tools is only worth reading if it cites measured tokens
    rather than an estimate, so every run persists its own meter alongside its
    findings."""
    try:
        return session.strategist._llm.usage.as_dict()
    except AttributeError:
        return {}


def _ensure_key_env(var: str, label: str) -> bool:
    """Ensure an API-key env var is set; prompt (hidden) if interactive."""
    if os.environ.get(var):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        val = getpass.getpass(f"  {label} (input hidden, blank to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        val = ""
    if val:
        os.environ[var] = val
        return True
    return False


def choose_brain(console):
    """Ask the operator HOW to run Brukal's brain and return (provider, model,
    base_url), ensuring any needed API key is set. Returns (None, None, None) when
    non-interactive (fall back to defaults/env)."""
    from .llm import _ANTHROPIC_DEFAULT, _PRESETS
    if not sys.stdin.isatty():
        return None, None, None

    _emit(console, "\n  How should Brukal think? Pick the model it runs on:",
          "\n  [bold]How should Brukal think? Pick the model it runs on:[/]")
    for k, label in (
        ("1", "Claude API (Anthropic) — best quality, needs an API key"),
        ("2", "Local model via Ollama — free, private, no key (e.g. qwen2.5)"),
        ("3", "Groq — FREE api key, very fast, strong models (e.g. llama-3.3-70b)"),
        ("4", "Other OpenAI-compatible — OpenAI / OpenRouter / DeepSeek / GLM / LM Studio"),
        ("5", "Advanced — type provider / model / base-url yourself"),
    ):
        _emit(console, f"    [{k}] {label}", f"    [cyan]\\[{k}][/] {label}")
    choice = (_ask(console, "  choose", "1") or "1").strip()

    if choice == "2":                                        # free local Ollama
        model = (_ask(console, "  Ollama model", "qwen2.5") or "qwen2.5").strip()
        base = (_ask(console, "  Ollama base URL", "http://localhost:11434/v1") or "").strip()
        _emit(console, "  (WSL note: if Ollama runs on Windows, use the Windows host IP, "
              "e.g. http://172.x.x.x:11434/v1, and start Ollama with OLLAMA_HOST=0.0.0.0)")
        return "ollama", model, base or None

    if choice == "3":                                        # Groq (free, fast)
        _emit(console, "  Get a free key at console.groq.com/keys (starts with gsk_).")
        default_model = "llama-3.3-70b-versatile"
        model = (_ask(console, "  Groq model", default_model) or default_model).strip()
        if not _ensure_key_env("GROQ_API_KEY", "Groq API key (GROQ_API_KEY)"):
            _emit(console, "  ⚠ no GROQ_API_KEY set — calls will fail until you provide it.")
        return "groq", model, None

    if choice == "4":                                        # other OpenAI-compatible preset
        prov = (_ask(console, "  provider (openai/openrouter/deepseek/glm/lmstudio)",
                     "openai") or "openai").strip().lower()
        if prov not in _PRESETS:
            _emit(console, f"  unknown provider '{prov}', using openai.")
            prov = "openai"
        _, key_env, default_model = _PRESETS[prov]
        model = (_ask(console, "  model", default_model or "") or "").strip() or default_model
        if prov != "lmstudio" and not _ensure_key_env(key_env, f"{prov} API key ({key_env})"):
            _emit(console, f"  ⚠ no {key_env} set — calls will fail until you export it.")
        return prov, model, None

    if choice == "5":                                        # advanced
        prov = (_ask(console, "  provider", "openai") or "openai").strip().lower()
        model = (_ask(console, "  model (blank = provider default)", "") or "").strip() or None
        base = (_ask(console, "  base URL (blank = preset)", "") or "").strip() or None
        return prov, model, base

    # default: Claude API
    if not _ensure_key_env("ANTHROPIC_API_KEY", "Anthropic API key"):
        _emit(console, "  ⚠ no ANTHROPIC_API_KEY — Claude calls will fail. "
              "Tip: option 2 runs a free local model instead.")
    model = (_ask(console, "  Claude model", _ANTHROPIC_DEFAULT) or _ANTHROPIC_DEFAULT).strip()
    return "anthropic", model, None


def choose_run_mode(console) -> bool:
    """Ask how to work the plan. Returns True for AUTO, False for MANUAL."""
    if not sys.stdin.isatty():
        return False
    _emit(console, "\n  How should I work through the plan?",
          "\n  [bold]How should I work through the plan?[/]")
    _emit(console, "    [1] Manual — you approve each step (recommended)",
          "    [cyan]\\[1][/] Manual — you approve each step (recommended)")
    _emit(console, "    [2] Auto — I run the safe (ALLOW) steps myself, and pause for "
                   "anything risky or manual",
          "    [cyan]\\[2][/] Auto — I run the safe (ALLOW) steps myself, and pause for "
          "anything risky or manual")
    return (_ask(console, "  choose", "1") or "1").strip() == "2"


def _authorise_host(scope, target: str):
    """Build a session Scope narrowed to a single /32 host, reusing the loaded
    scope's tool allowlist and rate limit. This SETS scope before the engagement
    (like `brukal target`) — it does not widen a running scope (invariant 5)."""
    import ipaddress

    from .scope import Scope
    net = ipaddress.ip_network(f"{target.strip()}/32", strict=False)
    return Scope(engagement=f"{scope.engagement}-solve",
                 authorized_networks=(net,),
                 allowlisted_tools=scope.allowlisted_tools,
                 rate_limit_per_min=scope.rate_limit_per_min,
                 authorization=scope.authorization,
                 expires=scope.expires)


# A curated set of the tools a pentest planner commonly reaches for. We ask the cage
# which are actually present so the model proposes real invocations. Read-only probe.
_TOOL_CANDIDATES = (
    "nmap masscan curl wget ffuf gobuster feroxbuster dirb dirsearch nikto whatweb "
    "wafw00f nuclei wpscan sqlmap dalfox commix gau katana hakrawler waybackurls httpx "
    "git git-dumper gitdumper dnsrecon dnsx dnsenum subfinder amass assetfinder "
    "theharvester smbclient smbmap enum4linux enum4linux-ng crackmapexec netexec nxc "
    "rpcclient snmpwalk onesixtyone ldapsearch hydra medusa john hashcat searchsploit "
    "msfconsole nc ncat socat jq python3 ssh sslscan wpscan"
).split()


# Tools whose stdout IS a raw HTTP response body (or a fetched file) — the only
# output the content-signature exposure detector should read. A scanner's report is
# not a response body, so it is deliberately excluded (avoids technique-name FPs).
def _probe_cage_tools(kali) -> list[str]:
    """Ask the cage which of the candidate tools are installed (one read-only `which`),
    so the planner is grounded in reality instead of guessing tool/script paths that
    don't exist. This introspects OUR cage, not the target — the agent still never
    receives the kali, only the resulting list of names. Best-effort: any failure
    returns [] and the planner simply runs without the hint."""
    seen = set()
    try:
        res = kali.run("which " + " ".join(sorted(set(_TOOL_CANDIDATES))))
    except Exception:
        return []
    for line in (getattr(res, "stdout", "") or "").splitlines():
        base = line.strip().rsplit("/", 1)[-1]
        if base in _TOOL_CANDIDATES and base not in seen:
            seen.add(base)
    return [t for t in _TOOL_CANDIDATES if t in seen]


def _vault_for(vault_root, target: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target.strip()) or "target"
    return Path(vault_root) / safe


def _prepare_session(target, *, fake, yes_authorised, scope_path, audit_path,
                     vault_path, container, model, provider, base_url, lessons_path=None,
                     console, holder, hosts=(), login=None):
    """Shared setup for `solve` and `auto`: resolve the target, authorise scope,
    take the live-run sign-off, pick the brain, and build a grounded
    AssistSession wired to the governed executor + per-target vault.

    Returns (session, audit, target, cage) on success, or an int exit code."""
    try:
        from .agents import ExploitAgent, ReconAgent, VerifyAgent
        from .agents.strategist import StrategistAgent
        from .blackboard import Blackboard
        from .engagement import (enforce_authorization, interactive_approver,
                                  warn_if_unkeyed_audit)
        from .llm import LLMClient
        from .skills import SkillLibrary
    except ImportError as e:
        print(f"Agent dependencies missing ({e}). Install: pip install \"brukal[agents]\"")
        return 2

    # 1) The target — ask for it if it wasn't given on the command line.
    if not target:
        target = _ask(console, "  target IP to work on").strip()
    if not target:
        print("No target given.")
        return 2

    # 2) Scope — use the file if it already authorises this host, else offer to
    #    authorise just this one host for the session (a deliberate, confirmed act).
    scope = load_scope(scope_path)
    if scope.contains_ip(target):
        session_scope = scope
    else:
        msg = (f"  ⚠ {target} is not in {scope_path}. Authorise this single host "
               f"({target}/32) for this session?")
        if not _confirm(console, msg):
            print(f"Refused: {target} is out of scope.  (or run: brukal target {target})")
            return 2
        session_scope = _authorise_host(scope, target)
        yes_authorised = True          # explicitly authorising the host is the sign-off

    # 2b) Pre-authorise any vhosts the operator named (--host nexus.htb). A deliberate
    #     scope-time act: it lets auto-mode render vhost-gated web apps and Host-header
    #     requests without a mid-hunt `host` command, and ensure_cage_vhosts (below)
    #     maps each to the target IP in the cage so it actually resolves.
    for h in hosts or ():
        for n in _vhost_names(h):              # the host + its *.domain (vhost fuzzing)
            if n and n not in session_scope.authorized_hosts:
                session_scope = session_scope.with_host(n)
                _emit(console, f"  ✓ authorised vhost {n} (scope-time).")

    # 3) Live-run sign-off (fake cage needs none). Confirm interactively if a
    #    tty is available; otherwise the --yes-authorised flag is required.
    if not fake and not yes_authorised:
        if not _confirm(console, f"  LIVE run against {target}. Confirm you are "
                                 f"authorised to test it?"):
            print("Refused: a live run needs your authorisation (--yes-authorised).")
            return 2

    # 4) The brain — ask how to run the model, unless it was set on the CLI/env.
    if provider is None and not os.environ.get("BRUKAL_PROVIDER"):
        provider, model, base_url = choose_brain(console)

    audit = AuditLog(audit_path)

    # Authorization artifact (Phase 5): pin the authorising (session) scope into the
    # ledger and refuse a stale engagement before building the executor.
    if not enforce_authorization(session_scope, audit, target):
        return 2
    warn_if_unkeyed_audit(audit, fake)

    approver = _rich_approver(console, holder) if console is not None else interactive_approver

    trust = TrustModel()
    kali = FakeKali() if fake else DockerKali(container=container)
    executor = Executor(Gate(session_scope, trust=trust), kali, audit, approver=approver)
    try:
        llm = LLMClient(model=model, provider=provider, base_url=base_url)
    except Exception as e:
        print(f"Could not initialise the model client: {e}")
        print("Set a key, or choose Ollama (free, local) when asked.")
        return 2
    strategist = StrategistAgent(llm)

    # Per-target Obsidian vault → persistence + resume across sessions.
    vault_dir = _vault_for(vault_path, target)
    blackboard = Blackboard(vault_dir, session_scope)
    # Cross-session lessons live at the VAULT ROOT (shared across every target), so
    # Brukal carries what it learned from one box to the next.
    #
    # GAP #24: that only holds while the vault root is REUSED, and a measurement run must
    # use a FRESH vault to be reproducible. Those two needs were the same flag, so 87 runs
    # each started with an empty store and the whole corpus is 75 lessons -- 73 of them
    # pitfalls, and the SAME THREE re-learned from scratch ("nuclei times out",
    # "shell metacharacters are rejected"). The harness was re-discovering its own cage
    # every run and carrying nothing about any application forward.
    #
    # `lessons_path` separates them: a fresh vault for a clean measurement, a persistent
    # store for accumulated knowledge. Default is unchanged, so nothing existing moves.
    from .lessons import LessonStore
    lessons = LessonStore(Path(lessons_path or vault_path) / "lessons.jsonl")

    # A GOVERNED BROWSER for WEB actions (same scope gate + audit). Fake cage in
    # test mode; else render via headless Chromium + craft requests, both in-cage.
    from .web import GovernedBrowser
    if fake:
        from .web import FakeWebCage
        web_cage = FakeWebCage()
    else:
        from .chrome import DockerChromeCage
        from .web import CompositeWebCage, DockerHttpWebCage, ensure_cage_vhosts
        # Map authorised vhosts -> the TARGET IP in the cage so nexus.htb (and any
        # authorised subdomain) resolves for the browser/curl regardless of how broad
        # the scope is (not only for a single-/32 scope).
        ensure_cage_vhosts(session_scope, container, target_ip=target)
        web_cage = CompositeWebCage(DockerChromeCage(container=container),
                                    DockerHttpWebCage(container=container))
    browser = GovernedBrowser(session_scope, web_cage, audit)

    # On-demand research (control-plane egress only; disabled unless
    # BRUKAL_RESEARCH_SOURCES names allowlisted sources). Never touches the cage.
    from .research import ResearchProvider
    research = ResearchProvider()
    session = AssistSession(target, executor, strategist, skills=SkillLibrary(),
                            blackboard=blackboard, lessons=lessons, browser=browser,
                            research=research if research.enabled else None)
    session.cage_container = None if fake else container   # for mid-session vhost mapping
    if not fake:
        # Ground the planner in the cage's real toolset (one read-only `which`), so it
        # proposes installed tools instead of guessing script paths. Best-effort.
        session.cage_tools = _probe_cage_tools(kali)
    # Specialist agents for multi-agent auto ("planner + role executors"). Built on
    # the SAME executor (one door) and the SAME model as the strategist. The auto
    # loop uses them only when multi-agent mode is on; they are inert otherwise. The
    # shared TrustModel is the one the gate reads, so a specialist's outcomes modulate
    # its own future soft-risk scoring.
    session.trust = trust
    # Vault-backed findings ledger (append-only JSONL) — survives across sessions and
    # feeds `brukal report`.
    from .findings import FindingStore
    session.findings = FindingStore(Path(vault_dir) / "findings.jsonl")
    session.agents = {
        "recon": ReconAgent(llm, executor),
        "exploit": ExploitAgent(llm, executor),
        "verify": VerifyAgent(llm, executor),
    }
    cage = "fake" if fake else "docker:" + container
    # Authenticated scanning: if the operator supplied login credentials, authenticate
    # NOW (through the governed browser) so the crawl and every later web action run
    # WITH the session and can reach pages behind the login.
    if login and login.get("url") and session.browser is not None:
        ok = session.login(login["url"], login.get("user", ""), login.get("password", ""),
                           user_field=login.get("user_field", "username"),
                           pass_field=login.get("pass_field", "password"),
                           login_type=login.get("type", "form"))
        _emit(console, f"  {'✓ authenticated' if ok else '⚠ login failed'} at {login['url']}")
        # A login that was ASKED FOR and did not happen changes what the whole run
        # means, so it has to travel as far as the findings do. Brukal learned this by
        # producing a DVNA report that listed three low-severity header findings and
        # looked exactly like a clean authenticated assessment — the credentials had
        # been rejected, the crawl never left the login page, and the only trace was
        # one line in the engagement log nobody reads next to a report. An unreached
        # surface is the same failure mode as an unreached CHECK: silence that looks
        # like a result.
        session.login_status = ("authenticated" if ok else "failed", login["url"])
    session.reachable = _preflight(session, console)
    return session, audit, target, cage


def _preflight(session, console=None) -> bool:
    """One gated request, before anything is spent, to prove the target is reachable
    THROUGH THE PATH THE RUN WILL ACTUALLY USE.

    A run once spent $0.46 and thirty-two model calls against a target it could not
    touch: the cage had failed to start on a stale bind mount, so every web request died
    at the source. The health monitor said so honestly in the report — "none of 13
    requests were answered, nothing was actually assessed" — but only afterwards, once
    the budget was gone. Reachability is cheap to establish and expensive to assume, and
    checking the cage separately would not do: what matters is the whole path, cage and
    scope gate and browser together, which is exactly what one real request exercises."""
    browser = getattr(session, "browser", None)
    if browser is None:
        return True                       # no web layer in this engagement; nothing to check
    from .web import WebAction

    # Probe the ORIGIN THE RUN WILL USE, which is rarely port 80. The first version of
    # this check assumed `http://{target}/` and promptly blocked a healthy engagement:
    # the login had just succeeded at :9090 on the line above, and the preflight then
    # declared the target unreachable because nothing was listening on 80. A guard that
    # fails closed is right; a guard that fails closed for the wrong reason costs a run
    # and teaches the operator to ignore it.
    #
    # The login URL is authoritative when the operator gave one — it is a place we have
    # already reached. Otherwise fall back to the bare target.
    from urllib.parse import urlsplit
    url = f"http://{session.target}/"
    login_url = getattr(session, "_login_url", "") or ""
    if login_url:
        sp = urlsplit(login_url)
        if sp.scheme and sp.netloc:
            url = f"{sp.scheme}://{sp.netloc}/"
    try:
        _d, result = browser.run(WebAction("request", url=url, method="GET"))
    except Exception as exc:
        result = None
        session.notes.append(f"[preflight] {url} raised {type(exc).__name__}")
    if result is not None and getattr(result, "status", None) is not None:
        return True
    # A failure is only EVIDENCE of a dead target when we knew where to knock. Without
    # an operator-supplied login URL there is no port to use but 80, and recon has not
    # run yet to discover the real one — so a silent port 80 is the normal case for an
    # application on :3000, :5013 or :8080, not a reason to abort.
    #
    # This guard has now blocked two healthy engagements. It was added because a run
    # spent $0.46 assessing nothing, and it has since cost more runs than it saved. A
    # guard that fails closed for the WRONG REASON is worse than no guard: it burns the
    # run and teaches the operator to ignore the warning, so the day it fires correctly
    # nobody listens. Certainty about the origin is what licenses a hard stop.
    if not login_url:
        note = (f"⚠ preflight could not reach {url}, but no target URL was supplied and "
                f"recon has not yet found the open ports — continuing, since an "
                f"application on a non-default port answers nothing on 80. Target "
                f"health will report honestly if nothing is reachable.")
        session.notes.append(f"[preflight] {note}")
        _emit(console, f"  {note}")
        return True
    msg = (f"⚠ PREFLIGHT FAILED: {url} returned nothing through the governed browser. "
           f"The target, the cage, or the route between them is down — a run started "
           f"now would assess nothing and still cost a full budget. Check that the cage "
           f"container is up and can reach the target.")
    session.notes.append(f"[preflight] {msg}")
    _emit(console, f"  {msg}")
    return False


def run_solve(target=None, *, fake=False, yes_authorised=False, scope_path="scope.json",
              audit_path="runs/audit.jsonl", vault_path="runs/vault", lessons_path=None,
              container="brukal-kali", model=None, provider=None, base_url=None,
              auto=None, hosts=(), login=None) -> int:
    # A rich console (menu UI + spinner-aware approver), or plain fallback.
    holder: dict = {"status": None}
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    prep = _prepare_session(
        target, fake=fake, yes_authorised=yes_authorised, scope_path=scope_path,
        audit_path=audit_path, vault_path=vault_path, container=container,
        model=model, provider=provider, base_url=base_url,
        lessons_path=lessons_path,
        console=console, holder=holder, hosts=hosts, login=login)
    if isinstance(prep, int):
        return prep
    session, audit, target, cage = prep

    # How to work the plan — manual (approve each step) or auto (run safe steps).
    if auto is None:
        auto = choose_run_mode(console)

    try:
        if console is not None:
            _menu_loop(session, audit, target, cage, console, holder, auto=auto)
        else:
            _plain_loop(session, audit, target, cage, auto=auto)
    except KeyboardInterrupt:
        print()
    except Exception as e:
        if os.environ.get("BRUKAL_DEBUG"):
            raise
        _head, _advice = _explain_run_error(e)
        print(f"\n  ⚠ {_head}")
        print(f"  {_advice}")
        return 1

    print(f"\n  session recorded to {audit_path}  ·  notes in {_session_vault(session)}"
          f"  ·  chain intact: {audit.verify()}\n")
    return 0


def _session_vault(session):
    """The vault directory a session persists to (for the closing summary line)."""
    return getattr(getattr(session, "blackboard", None), "root", "runs/vault")


# What the operator is told, per stop reason. `report.md` prints the RAW reason, so these
# two surfaces must name the same event: a reason with no entry here falls through to its
# bare identifier, which reads as a different ending from the one the report describes.
# `tests/test_unreadable_reply.py` scans loop.py for every `_finish()` reason and fails if
# one has no sentence — the guard that keeps this table from going stale silently.
_STOP_LABELS = {
    "solved": "SOLVED — success verified from real gated output",
    "manual": "the next step is yours (intrusive/interactive exploitation)",
    "escalation": "a step needs your sign-off (ESCALATE)",
    "stalled": "no safe next step — over to you",
    "exhausted": "hit the step budget",
    "aborted": "STOPPED by kill switch",
    "budget": "hit an engagement budget cap",
    "done": "nothing left to safely automate",
    "truncated": "the model's reply was cut off before it named an action — "
                 "retried once and still incomplete, so this is NOT 'nothing left to do'",
    "unreadable": "the model's reply finished but could not be parsed into an action — "
                  "retried once and still unreadable, so this is NOT 'nothing left to do'",
    # Found by the scan this table now has, not by a run: `target-unhealthy` has been
    # emittable since the health monitor landed and had no sentence, so run 2C2 ended
    # with the operator reading the bare identifier.
    "target-unhealthy": "the TARGET stopped answering healthily — stopped to avoid "
                        "hammering it; findings so far are kept",
}


def _write_session_report(session, result, cage, audit, spend=""):
    """Build engagement metadata from the live session and write report.md + .json
    to the vault. Best-effort — a report failure must never fail the hunt."""
    try:
        from .report import write_reports
        sc = getattr(getattr(session.executor, "_gate", None), "_scope", None)
        hosts = list(getattr(sc, "authorized_hosts", []) or [])
        meta = {
            "engagement": getattr(sc, "engagement", "-"),
            "target": session.target,
            "scope": ", ".join([session.target] + hosts) if hosts else session.target,
            "cage": cage,
            "steps": len(result.steps),
            "executed": result.executed,
            "blocked": result.blocked,
            "stop_reason": result.stop_reason,
            "audit_intact": bool(audit.verify()) if audit is not None else False,
            # Same fact under the name the interchange formats use: a result is worth
            # only as much as the evidence it was obtained in scope, so governance
            # travels WITH the findings rather than staying in the human report.
            "audit_chain_intact": bool(audit.verify()) if audit is not None else False,
            "audit_log": str(getattr(audit, "path", "")) if audit is not None else "",
            "spend": spend,
            "spend_detail": _spend_detail(session),
            "coverage": (session.coverage_summary()
                         if hasattr(session, "coverage_summary") else []),
            # Findings whose title maps to no coverage class — flagged in the report so it
            # cannot silently contradict itself (see coverage_contradictions).
            "contradictions": (session.coverage_contradictions()
                               if hasattr(session, "coverage_contradictions") else []),
            "target_health": (getattr(getattr(session, "browser", None), "health", None)
                              .summary()
                              if getattr(getattr(session, "browser", None), "health", None)
                              else ""),
            "login_status": list(getattr(session, "login_status", ()) or ()),
            "surface": session.surface.summary() if session.surface else "",
            # THE FUNNEL, computed from the audit log rather than from the notes. Run CM5
            # rendered `notes[-40:]` and evicted every `[experiment]` line, so a published
            # count rested on lines no longer in the bundle. One function, one source.
            "funnel": (__import__("brukal.hypothesis", fromlist=["x"])
                       .funnel_from_log(getattr(audit, "path", ""))
                       if audit is not None else {}),
        }
        return write_reports(session.findings, meta, _session_vault(session))
    except Exception:
        return {}


def run_auto(target=None, *, fake=False, yes_authorised=False, scope_path="scope.json",
             audit_path="runs/audit.jsonl", vault_path="runs/vault", lessons_path=None,
             container="brukal-kali", model=None, provider=None, base_url=None,
             max_steps=20, handoff_to_menu=True, hosts=(), single_agent=False,
             full_send=False, mode=None, no_research=False,
             packs_dir=None, source_dir=None, capture_path=None, fail_on=None,
             max_cost=None, max_research=None, max_time=None, resume=True,
             login=None) -> int:
    """Headless grounded agentic loop: Brukal autonomously drives the SAFE,
    in-scope enumeration. When it hands back (manual/escalation/stall/budget), and
    a human is present at a terminal, it drops straight into the interactive menu on
    the SAME session — no state lost, no need to re-launch `brukal solve`. Every
    command still goes through the gate; nothing out of scope runs. Set
    handoff_to_menu=False (or BRUKAL_NO_HANDOFF=1) to keep the old stop-and-exit
    behaviour. This is the engine `solve --auto` wraps, plus the live view."""
    from .loop import GroundedLoop

    holder: dict = {"status": None}
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    prep = _prepare_session(
        target, fake=fake, yes_authorised=yes_authorised, scope_path=scope_path,
        audit_path=audit_path, vault_path=vault_path, container=container,
        model=model, provider=provider, base_url=base_url,
        lessons_path=lessons_path,
        console=console, holder=holder, hosts=hosts, login=login)
    if isinstance(prep, int):
        return prep
    session, audit, target, cage = prep
    if not getattr(session, "reachable", True):
        # Refuse to start rather than spend a budget assessing nothing. The report would
        # have said so honestly afterwards; saying so BEFORE costs one request.
        _emit(console, "  stopping: the target is not reachable through the governed "
                       "browser. Nothing was assessed and nothing was spent.")
        return 2
    if no_research:                            # opt out of all control-plane research egress
        session.research = None

    # -- Phase 3 robustness: budget caps, kill switch, resumable checkpoint ---- #
    from . import checkpoint as _ckpt
    from .budget import EngagementBudget
    from .killswitch import KillSwitch

    def _envf(name, cast):
        v = os.environ.get(name)
        try:
            return cast(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None

    max_cost = max_cost if max_cost is not None else _envf("BRUKAL_MAX_COST", float)
    max_research = max_research if max_research is not None else _envf("BRUKAL_MAX_RESEARCH", int)
    max_time = max_time if max_time is not None else _envf("BRUKAL_MAX_TIME", float)
    if max_research is not None and session.research is not None:
        session.research.max_fetches = max_research   # cap control-plane egress this run
    budget = EngagementBudget(max_cost=max_cost, max_steps=max_steps,
                              max_research_fetches=max_research,
                              max_wall_seconds=max_time).start()

    kill = KillSwitch()
    # Trap SIGINT/SIGTERM so an interrupt (or an external `kill`) stops at the next safe
    # boundary and closes sessions, instead of tearing the process down mid-action.
    import signal
    _prev_handlers = {}

    def _on_signal(signum, _frame):
        kill.trip(f"signal {signum}")
    try:
        for _sig in (signal.SIGINT, signal.SIGTERM):
            _prev_handlers[_sig] = signal.signal(_sig, _on_signal)
    except (ValueError, OSError):
        _prev_handlers = {}                    # not on the main thread — skip signal traps

    def _restore_signals():
        for _sig, _h in _prev_handlers.items():
            try:
                signal.signal(_sig, _h)        # give Ctrl-C back after the autonomous phase
            except (ValueError, OSError):
                pass
        _prev_handlers.clear()

    # Resumable engagement: reload loop-progress (executed cmds / learned / cursor) from
    # the last checkpoint so a dead run continues instead of restarting.
    ckpt_path = _vault_for(vault_path, target) / "checkpoint.json"
    if resume and not os.environ.get("BRUKAL_NO_RESUME"):
        prior = _ckpt.load(ckpt_path)
        if prior is not None:
            done = _ckpt.restore(session, prior)
            if done:
                _emit(console, f"  ↻ resumed from checkpoint — {done} step(s) already "
                               f"spent, {len(session.executed_cmds)} command(s) known.")

    def _save_checkpoint(steps_done, stop_reason):
        _ckpt.save(ckpt_path, session, steps_done=steps_done, stop_reason=stop_reason)
    # In headless auto, an ESCALATE cleanly PAUSES the hunt (the loop hands back)
    # rather than prompting mid-live-view: dangerous/irreversible moves are approved
    # interactively in `brukal solve`. Fail-closed keeps the invariant intact.
    # Governance dial (SOFT layer only — the hard scope gate is never affected).
    #   default    : pause on irreversible/attack in-scope moves for your sign-off.
    #   full-send  : auto-approve EVERY in-scope action; only DENY (out of scope /
    #                hard-check failure) still stops it. Maximum autonomy inside the
    #                authorised scope; it cannot widen scope.
    full = bool(full_send or os.environ.get("BRUKAL_FULL_SEND"))
    session.executor._approver = _full_send_approver if full else _auto_approver
    # Some proofs can only be made by CREATING state on the target (a mass-assignment
    # test needs an account carrying the injected field, plus a control account without
    # it). The web door has no risk layer to escalate through, so that stays behind the
    # operator's explicit "unleash" rather than running by default.
    session.allow_intrusive = full
    # CAPTURED TRAFFIC, if the operator handed over a HAR from Burp / ZAP / mitmproxy /
    # DevTools. Ingested BEFORE the crawl so the surface the model first sees is built
    # from requests that actually happened, not from the path wishlist that produced 19
    # guesses out of 30 URLs on the first cold target. Scope-filtered and
    # credential-stripped inside `capture.parse_har` — see brukal/capture.py.
    if capture_path:
        from . import capture as _capture
        try:
            _caps, _rep = _capture.parse_har(
                Path(capture_path).read_text(errors="replace"),
                session.executor._gate.scope)
            # PARSE now (a bad path or an empty capture must be visible before the run
            # spends anything), APPLY when the surface exists. `session.surface` is None
            # until the crawl builds it.
            _capture.hold_for_surface(session, _caps)
            line = (f"[capture] {Path(capture_path).name}: {_rep.summary()}; "
                    f"held for the surface")
            session.notes.append(line)
            print(f"  {line}")
            if not _caps:
                print(f"  ⚠ --capture {capture_path} yielded no in-scope requests — "
                      f"the surface is unchanged")
        except FileNotFoundError:
            print(f"  ⚠ --capture {capture_path} not found — ignored")
        except Exception as exc:
            print(f"  ⚠ --capture {capture_path} could not be read "
                  f"({type(exc).__name__}: {str(exc)[:80]}) — ignored")

    # Source leads, if the operator pointed at the target's tree. Mined once, up front,
    # so a bad path is visible at start-up — and kept strictly as leads: they select what
    # the dynamic provers try, and never appear as findings on their own.
    if source_dir:
        from . import sourcemap as _sourcemap
        try:
            session.source_leads = _sourcemap.scan(source_dir)
            line = _sourcemap.summarise(session.source_leads)
            if line:
                session.notes.append(line)
                print(f"  {line}")
            elif not Path(source_dir).is_dir():
                print(f"  ⚠ --source {source_dir} is not a directory — ignored")
        except Exception:
            pass

    # Contributed detections, if the operator pointed at a pack directory. Loaded here so
    # a malformed pack is visible at start-up rather than mid-engagement.
    if packs_dir:
        from . import packs as _packs
        session.signature_packs = _packs.load_dir(packs_dir)
        _emit(console, f"  signature packs: {len(session.signature_packs)} contributed "
                       f"detection(s) from {packs_dir}")
    if full:
        _emit(console,
              "  ⚠ FULL-SEND — auto-approving ALL in-scope actions (incl. irreversible "
              "/ attack). Scope wall stays: out-of-scope is still DENIED.",
              "  [bold red]⚠ FULL-SEND[/] — auto-approving [bold]all in-scope[/] actions "
              "(incl. irreversible/attack). Scope wall stays: out-of-scope still DENIED.")

    # Multi-agent mode (default): strategist plans, specialists (recon/exploit/verify)
    # execute — one door, per-agent trust. Opt out with BRUKAL_SINGLE_AGENT=1.
    multi = not (single_agent or os.environ.get("BRUKAL_SINGLE_AGENT"))
    # NOTE: this is the banner's DISPLAY string only. It must not be called `mode` —
    # that is the caller's web/box methodology selector, and assigning to it here made
    # --web/--box silently do nothing (set_methodology then saw "multi-agent … ·
    # full-send", matched neither, and fell back to target detection: an IP is a box).
    agent_mode = "multi-agent (planner+recon/exploit/verify)" if multi else "single-strategist"
    agent_mode += " · full-send" if full else " · governed"

    _emit(console, f"\n  brukal auto — target {target}   cage={cage}   "
                   f"budget={max_steps} steps   mode={agent_mode}",
          f"\n  [bold cyan]brukal auto[/] — target [bold]{target}[/]   "
          f"cage={cage}   budget={max_steps} steps   [magenta]{agent_mode}[/]")
    if session.resumed:
        _emit(console, f"  resumed — loaded {session.resumed} prior finding(s).")

    # Pick the methodology (web=OWASP WSTG / box=enum→foothold→privesc→loot). It grounds
    # every plan/decision and seeds the objective if none was set. `mode` forces it;
    # otherwise it's detected from the target (URL/hostname → web, IP → box).
    meth = session.set_methodology(mode)
    _emit(console, f"  methodology: {meth.kind} "
                   f"({'OWASP WSTG' if meth.kind == 'web' else 'box enum→privesc→loot'})")

    view = _AutoLiveView(console, target, cage, max_steps,
                         session.objectives[0] if session.objectives else "") \
        if console is not None else None
    # No rich? Use the plain live view so 'thinking' / 'running <cmd>' + an elapsed
    # heartbeat are still shown — a long scan must never look frozen.
    plain_view = _PlainAutoView() if view is None else None

    def observer(kind, payload):
        if view is not None:
            view.on(kind, payload)
        elif plain_view is not None:
            plain_view.on(kind, payload)

    from .verify import Verifier
    # `multi` computed above. Multi-agent: the strategist PLANS and the phase's
    # specialist generates each command, through the same one door with per-agent
    # trust. Single-agent: the classic single-strategist loop.
    loop = GroundedLoop(session, max_steps=max_steps, observer=observer,
                        # The target is handed to the verifier so a foothold claim can
                        # be ATTRIBUTED: cage-local output proves nothing about the
                        # target, and without the target there is nothing to attribute to.
                        verifier=Verifier(target=getattr(session, "target", "")),
                        agents=getattr(session, "agents", None) if multi else None,
                        trust=getattr(session, "trust", None) if multi else None,
                        kill=kill, budget=budget, on_checkpoint=_save_checkpoint,
                        # --full-send is a request to run WITHOUT a human, so a manual
                        # suggestion must not end the engagement. See GroundedLoop.
                        autonomous=bool(full_send))
    if budget.any_cap:
        _emit(console, f"  budget: {budget.status(cost=0, steps=0, fetches=0)}")

    try:
        if not session.plan:
            if view is not None:
                view.set_status("🗺  planning the route…")
            elif plain_view is not None:
                plain_view.set_status("🗺  planning the route…")
                plain_view._start_beat("planning")
            session.make_plan()             # lay out the route before driving it
        if view is not None:
            with view.start():
                result = loop.run()
        else:
            try:
                result = loop.run()
            finally:
                if plain_view is not None:
                    plain_view._stop_beat()
    except KeyboardInterrupt:
        if plain_view is not None:
            plain_view._stop_beat()
        _restore_signals()
        session.close_sessions()             # no orphaned live shells on an interrupt
        print("\n  paused.")
        return 0
    except Exception as e:
        _restore_signals()
        session.close_sessions()
        if os.environ.get("BRUKAL_DEBUG"):
            raise
        _head, _advice = _explain_run_error(e)
        # THE LEDGER FIRST, then the deliverable. A run that dies mid-engagement still
        # holds everything it proved up to that point — CR1's abort left a confirmed
        # cross-account result reachable only as raw audit rows — so the ending is
        # recorded and the report is written from what the session has.
        _steps = len(getattr(loop, "steps", []) or [])
        record_engagement_stop(audit, "aborted", _head, steps=_steps)
        try:
            from .loop import LoopResult
            _partial = LoopResult(steps=getattr(loop, "steps", []) or [],
                                  stop_reason="aborted", stop_detail=_head)
            _reports = _write_session_report(session, _partial, cage, audit,
                                             _spend_line(session))
            if _reports.get("md"):
                print(f"\n  📄 partial report ({len(session.findings)} finding(s)): "
                      f"{_reports['md']}")
        except Exception:
            pass
        print(f"\n  ⚠ {_head}")
        print(f"  {_advice}")
        return 1
    _restore_signals()                       # autonomous phase done — Ctrl-C back to normal

    handoff = _STOP_LABELS.get(result.stop_reason, result.stop_reason)
    spend = _spend_line(session)

    # Write the deliverable report (findings + engagement metadata) to the vault.
    reports = _write_session_report(session, result, cage, audit, spend)
    if reports.get("md"):
        n = len(session.findings)
        _emit(console,
              f"  📄 report ({n} finding(s)): {reports['md']}",
              f"  [bold]📄 report[/] ({n} finding(s)): {reports['md']}")

    # Hand the wheel to the operator IN THE SAME SESSION when a human is present.
    # Auto stops because it ran out of *safe autonomous* moves — not because the
    # engagement is over. Dropping into the menu keeps every note/highlight/plan and
    # lets the human supply the next insight (the vhost leap, an exploit) without
    # re-launching. Skip only when non-interactive (piped/CI) or explicitly opted out.
    # A kill-switch abort means STOP — don't drop into the interactive menu.
    to_menu = (handoff_to_menu and not os.environ.get("BRUKAL_NO_HANDOFF")
               and sys.stdin.isatty() and result.stop_reason != "aborted")
    if to_menu:
        _emit(console,
              f"\n  ⏹ auto handed back: {handoff}\n     {result.stop_detail}\n"
              f"  ran {result.executed} command(s), {result.blocked} blocked · "
              f"{spend}\n  ↪ switching to MANUAL — you drive now (same session; "
              f"'q' to quit).\n",
              f"\n  [bold yellow]⏹ auto handed back:[/] {handoff}\n"
              f"     [grey70]{result.stop_detail}[/]\n"
              f"  ran [bold]{result.executed}[/] command(s), {result.blocked} blocked · "
              f"{spend}\n  [bold cyan]↪ switching to MANUAL[/] — you drive now "
              f"(same session; 'q' to quit).\n")
        # Restore the interactive approver (auto swapped in the auto one), so an
        # ESCALATE the operator picks prompts y/N instead of auto-deciding.
        from .engagement import interactive_approver
        session.executor._approver = _rich_approver(console, holder) if console \
            else interactive_approver
        try:
            if console is not None:
                _menu_loop(session, audit, target, cage, console, holder, auto=False)
            else:
                _plain_loop(session, audit, target, cage, auto=False)
        except KeyboardInterrupt:
            print()
        except Exception as e:
            if os.environ.get("BRUKAL_DEBUG"):
                raise
            _head, _advice = _explain_run_error(e)
            print(f"\n  ⚠ {_head}")
            print(f"  {_advice}")
            return 1
        session.close_sessions()             # operator done — tear the live shells down
        print(f"\n  session recorded to {audit_path} · chain intact: {audit.verify()}\n")
        return 0

    session.close_sessions()                 # non-interactive stop — no orphaned shells
    _emit(console,
          f"\n  ⏹ stopped: {handoff}\n     {result.stop_detail}\n"
          f"  ran {result.executed} command(s), {result.blocked} blocked · "
          f"continue in: brukal solve {target}\n"
          f"  session recorded to {audit_path} · chain intact: {audit.verify()}\n"
          f"{spend}\n",
          f"\n  [bold yellow]⏹ stopped:[/] {handoff}\n     [grey70]{result.stop_detail}[/]\n"
          f"  ran [bold]{result.executed}[/] command(s), {result.blocked} blocked · "
          f"continue in: [cyan]brukal solve {target}[/]\n"
          f"  session recorded to {audit_path} · chain intact: "
          f"[green]{audit.verify()}[/]\n{spend}\n")
    if fail_on:
        # A pipeline gate, deliberately CONFIRMED-only: a build should break on
        # something Brukal proved, not on a lead nobody has triaged — a gate that cries
        # wolf gets switched off within a week, and then it protects nothing.
        from . import export
        code = export.exit_code(session.findings.all(), fail_on=fail_on)
        if code:
            _emit(console, f"  ✖ CI gate: a confirmed finding at or above "
                           f"'{fail_on}' was recorded — exiting non-zero.")
        return code
    return 0
