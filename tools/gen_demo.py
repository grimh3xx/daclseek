#!/usr/bin/env python3
"""Render the animated terminal demo for mycroft into docs/demo.svg.

Same "filmstrip" model as the pe-binaries / SecureArchSetup demos: every frame
is a full snapshot of the screen, stacked vertically, and a CSS keyframe
animation steps the strip through them to play back a typed session. Font
embedding (JBM) is reused from the sibling github-profile brand toolchain so the
art matches the rest of grimh3xx's repos.

Usage: python3 tools/gen_demo.py [--static N]   (--static dumps frame N, no anim)
"""
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

BRAND = Path.home() / "github-profile" / "scripts"
sys.path.insert(0, str(BRAND))
try:
    from brand import finish  # type: ignore
except Exception:
    def finish(svg, faces=None):
        return svg

MONO = "'JBM','JetBrains Mono',ui-monospace,Consolas,Menlo,monospace"

# CentralTech palette
C = {
    "user": "#22D3EE", "punct": "#D5DDE8", "path": "#60A5FA", "cmd": "#F1F5FB",
    "text": "#C5CFDD", "muted": "#8B98AD", "cyan": "#22D3EE",
    "red": "#F87171", "amber": "#FBBF24", "green": "#34D399", "white": "#F1F5FB",
}

CW = 8.4          # JBM advance width at font-size 14
FS = 14
LH = 23           # line height
Y0 = 18           # first baseline inside the viewport
VIEW_W, VIEW_H = 874, 576
MAXLINES = (VIEW_H - Y0) // LH
W, H = 910, 652

# timing weights (ticks)
TYPE, OUT, PAUSE, HOLD = 1, 2, 7, 44


def seg(t, color="text", bold=False):
    return (t, color, bold)


def prompt():
    return [seg("grimh3xx@centraltech", "user"), seg(":", "punct"),
            seg("~/mycroft", "path"), seg("$ ", "punct")]


class Session:
    def __init__(self):
        self.history = []      # committed lines
        self.active = None     # current input line (list of segs) or None
        self.frames = []       # list of (lines snapshot)
        self.durs = []

    def _snap(self, dur):
        lines = [l[:] for l in self.history]
        if self.active is not None:
            lines.append(self.active[:])
        self.frames.append(lines)
        self.durs.append(dur)

    def type(self, text):
        self.active = prompt() + [seg("", "cmd")]
        for ch in text:
            s = self.active[-1]
            self.active[-1] = seg(s[0] + ch, "cmd")
            self._snap(TYPE)
        self._snap(PAUSE)

    def enter(self):
        if self.active is not None:
            self.history.append(self.active)
            self.active = None

    def out(self, line, dur=OUT):
        self.history.append(line if isinstance(line, list) else [seg(line)])
        self._snap(dur)

    def blank(self):
        self.out([seg("")], dur=1)

    def cursor_hold(self):
        self.active = prompt() + [seg("█", "cyan")]
        self._snap(HOLD)


def rule():
    return seg("─" * 56, "muted")


def finding(tag, tagcolor, cat, title):
    return [seg(f"[{tag}] ", tagcolor, True), seg(f"({cat}) ", "muted"),
            seg(title, "white", True)]


def detail(text):
    return [seg("       " + text, "muted")]


def evidence(text):
    return [seg("       · ", "muted"), seg(text, "text")]


def fix(text):
    return [seg("       → " + text, "muted")]


def build():
    s = Session()
    s.type("./mycroft.exe")
    s.enter()
    s.out([seg("mycroft", "cyan", True), seg(" — windows privesc enumeration", "muted")], dur=OUT)
    s.out([rule()], dur=1)
    s.out([seg("  Host     : "), seg("Windows 11 Pro (build 22631.4317)", "white")])
    s.out([seg("  Version  : "), seg("23H2 (AMD64)", "text")])
    s.out([seg("  User     : "), seg("CORP\\jdoe", "cyan")])
    s.out([seg("  Integrity: "), seg("Medium", "amber")])
    s.out([rule()], dur=1)
    s.blank()

    s.out(finding("CRIT", "red", "policy", "AlwaysInstallElevated enabled (HKLM + HKCU)"))
    s.out(detail("Installer packages apply with elevated privileges for all users."))
    s.out(evidence("HKLM\\...\\Installer\\AlwaysInstallElevated = 1"))
    s.out(evidence("HKCU\\...\\Installer\\AlwaysInstallElevated = 1"))
    s.out(fix("Set both values to 0 via GPO."))
    s.blank()

    s.out(finding("HIGH", "red", "privileges", "SeImpersonatePrivilege"))
    s.out(detail("Impersonate a client after authentication."))
    s.out(evidence("token holds SeImpersonatePrivilege — enabled"))
    s.out(fix("Remove this privilege from accounts that don't need it."))
    s.blank()

    s.out(finding("HIGH", "red", "services", "Writable service binary — 'UpdaterSvc'"))
    s.out(evidence("binary: C:\\ProgramData\\Updater\\updater.exe"))
    s.out(fix("Restrict write access to administrators / SYSTEM."))
    s.blank()

    s.out(finding("HIGH", "red", "path", "Writable directory on PATH"))
    s.out(evidence("writable PATH entry: C:\\tools\\bin"))
    s.blank()

    s.out(finding("MED ", "amber", "services", "Unquoted service path — 'LegacyAgent'"))
    s.out(evidence("ImagePath: C:\\Program Files\\Legacy Agent\\agent.exe"))
    s.out(evidence("hijack binary: C:\\Program.exe"))
    s.blank()

    s.out(finding("LOW ", "path", "uac", "UAC secure desktop disabled"))
    s.out(evidence("HKLM\\...\\PromptOnSecureDesktop = 0"))
    s.blank()

    s.out([seg("summary:", "muted"), seg(" 1 critical · 3 high · 1 medium · 1 low · 0 info", "text")])
    s.cursor_hold()
    return s


def render_rows(frames):
    """Emit <g id="rN"> defs — one full-screen snapshot each."""
    out = []
    for n, lines in enumerate(frames):
        window = lines[-MAXLINES:] if len(lines) > MAXLINES else lines
        parts = [f'<g id="r{n}">']
        for j, line in enumerate(window):
            y = Y0 + j * LH
            x = 0.0
            for text, color, bold in line:
                if text:
                    wt = ' font-weight="700"' if bold else ""
                    tl = len(text) * CW
                    parts.append(
                        f'<text x="{x:.1f}" y="{y}" fill="{C[color]}"{wt} '
                        f'textLength="{tl:.1f}" lengthAdjust="spacingAndGlyphs">'
                        f'{escape(text)}</text>')
                x += len(text) * CW
        parts.append("</g>")
        out.append("".join(parts))
    return "".join(out)


def keyframes(durs):
    total = sum(durs)
    cum, stops = 0, []
    for i, d in enumerate(durs):
        pct = cum / total * 100
        stops.append(f"{pct:.3f}%{{transform:translateY(-{i * VIEW_H}px)}}")
        cum += d
    stops.append(f"100%{{transform:translateY(-{(len(durs) - 1) * VIEW_H}px)}}")
    dur_s = max(10, round(total * 0.09))
    css = ("@keyframes play{" + "".join(stops) + "}"
           f".strip{{animation:play {dur_s}s steps(1,end) infinite}}"
           "@media(prefers-reduced-motion){.strip{animation:none;"
           f"transform:translateY(-{(len(durs) - 1) * VIEW_H}px)}}}}")
    return css


def render(static_frame=None):
    s = build()
    rows = render_rows(s.frames)
    nframes = len(s.frames)

    strip_items = "".join(
        f'<g transform="translate(0,{i * VIEW_H})"><use href="#r{i}"/></g>'
        for i in range(nframes))

    if static_frame is None:
        css = keyframes(s.durs)
        strip_open = '<g class="strip" '
    else:
        f = min(static_frame, nframes - 1)
        css = ""
        strip_open = f'<g transform="translate(0,{-f * VIEW_H})" '

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" aria-label="mycroft privesc scan demo">'
        f'<style>{css}</style>'
        f'<defs>{rows}</defs>'
        f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="12" fill="#111826" stroke="#1E2A3D"/>'
        f'<path d="M0 40H{W}" stroke="#1E2A3D"/>'
        '<circle cx="24" cy="20" r="6" fill="#FF5F57"/>'
        '<circle cx="44" cy="20" r="6" fill="#FEBC2E"/>'
        '<circle cx="64" cy="20" r="6" fill="#28C840"/>'
        f'<text x="{W/2:.0f}" y="25" text-anchor="middle" fill="#8B98AD" '
        f'font-family="{MONO}" font-size="13">mycroft — privesc audit</text>'
        f'<svg x="18" y="58" width="{VIEW_W}" height="{VIEW_H}" '
        f'viewBox="0 0 {VIEW_W} {VIEW_H}" overflow="hidden">'
        f'{strip_open}font-family="{MONO}" font-size="{FS}" xml:space="preserve">'
        f'{strip_items}</g></svg></svg>\n')
    return finish(svg, {("JBM", 400), ("JBM", 700)})


if __name__ == "__main__":
    DOCS.mkdir(exist_ok=True)
    if len(sys.argv) >= 3 and sys.argv[1] == "--static":
        out = render(static_frame=int(sys.argv[2]))
        p = Path("/tmp/demo-static.svg")
        p.write_text(out, encoding="utf-8")
        print("wrote", p)
    else:
        p = DOCS / "demo.svg"
        p.write_text(render(), encoding="utf-8")
        print("wrote", p, f"({len(render())//1024} KB,", "animated)")
