"""
Hermian in 5 minutes - a Manim Community Edition presentation.

Render:
    manim -pql manim_hermian.py HermianOverview
    manim -pqk manim_hermian.py HermianOverview
"""

from manim import (
    BLUE,
    BLUE_B,
    BLUE_D,
    DOWN,
    GREEN,
    LEFT,
    ORANGE,
    RED,
    RIGHT,
    UP,
    YELLOW,
    WHITE,
    BLACK,
    Arc,
    Arrow,
    Circle,
    Dot,
    ImageMobject,
    Line,
    RoundedRectangle,
    Scene,
    Text,
    VGroup,
    DashedLine,
    FadeIn,
    FadeOut,
    GrowArrow,
    Create,
    Write,
    Transform,
    Succession,
)


def heading(text, color=WHITE, font_size=42):
    return Text(text, weight=BOLD, font_size=font_size, color=color)


def body(text, font_size=26, color=WHITE):
    return Text(text, font_size=font_size, color=color)


def bullet(text, font_size=23, color=WHITE):
    dot = Dot(radius=0.055, color=YELLOW)
    label = body(text, font_size=font_size, color=color)
    label.scale(max(0.001, min(1.0, 8.8 / max(1.0, len(text) / 9))))
    return VGroup(dot, label).arrange(RIGHT, buff=0.18, aligned_edge=UP)


def card(title, lines, color=BLUE_B, width=3.7, height=2.2):
    box = RoundedRectangle(
        width=width,
        height=height,
        corner_radius=0.16,
        fill_color=BLACK,
        fill_opacity=0.82,
        stroke_color=color,
        stroke_width=3,
    )
    title_m = body(title, font_size=25, color=color)
    title_m.move_to(box.get_top() + DOWN * 0.38)

    content = VGroup(*[body(line, font_size=16) for line in lines])
    content.arrange(DOWN, buff=0.12, aligned_edge=LEFT)
    content.move_to(box.get_center() + DOWN * 0.22)
    content.scale(min(1.0, (width - 0.35) / max([content.width, 1.0])))

    return VGroup(box, title_m, content)


class HermianOverview(Scene):
    def construct(self):
        self.camera.background_color = "#080D18"

        self.show_intro()
        self.show_how_it_works()
        self.show_detection_families()
        self.show_context_and_process_chain()
        self.show_collector_limits()
        self.show_java4shell()
        self.show_response_and_positioning()
        self.show_closing()

    def show_intro(self):
        title = heading("HERMIAN", YELLOW, 72)
        subtitle = body("Behavioral Linux host detection", 34, BLUE_B)
        subtitle.next_to(title, DOWN, buff=0.28)

        shield = RoundedRectangle(
            width=2.2,
            height=2.2,
            corner_radius=0.35,
            fill_color=BLUE_D,
            fill_opacity=0.18,
            stroke_color=BLUE_B,
            stroke_width=6,
        )
        shield.shift(UP * 0.15)
        check = Text("✓", font_size=108, color=YELLOW)
        check.move_to(shield)

        mark = VGroup(title, subtitle)
        mark.move_to(UP * 2.15)

        promise = body("Silent by default. Loud when it matters.", 29, GREEN)
        promise.next_to(subtitle, DOWN, buff=0.55)

        self.play(FadeIn(shield), Write(check), run_time=1)
        self.play(Write(title), FadeIn(subtitle), FadeIn(promise))
        self.wait(1.2)

        layer = body(
            "A Linux server daemon that connects process context, "
            "network activity, accounts, and file changes",
            25,
        )
        layer.next_to(promise, DOWN, buff=0.55)
        self.play(FadeIn(layer))
        self.wait(1.5)
        self.play(FadeOut(VGroup(mark, shield, check, promise, layer)))

    def show_how_it_works(self):
        heading_m = heading("How Hermian works", YELLOW)
        heading_m.to_edge(UP * 1.35)

        collectors = VGroup(
            card("COLLECT", ["eBPF execution", "connect + ptrace", "inotify file changes", "SSH / PAM", "/proc listeners"], BLUE_B, 3.15, 3.45),
        )
        engine = card(
            "ENGINE",
            ["Process tree", "24 h baseline", "D1 - D5 rules", "Allowlists", "Context"],
            GREEN,
            3.15,
            3.45,
        )
        outputs = card(
            "OUTPUT",
            ["Deduplicated finding", "Evidence chain", "Risk + actions", "Log / webhook", "Block or isolate"],
            ORANGE,
            3.15,
            3.45,
        )

        collectors.move_to(LEFT * 4.2)
        engine.move_to(ORIGIN)
        outputs.move_to(RIGHT * 4.2)

        arrow1 = Arrow(
            collectors.get_right(),
            engine.get_left(),
            buff=0.12,
            color=YELLOW,
            stroke_width=5,
        )
        arrow2 = Arrow(
            engine.get_right(),
            outputs.get_left(),
            buff=0.12,
            color=YELLOW,
            stroke_width=5,
        )

        self.play(Write(heading_m))
        self.play(FadeIn(collectors), GrowArrow(arrow1), FadeIn(engine), run_time=1.2)
        self.play(GrowArrow(arrow2), FadeIn(outputs), run_time=1)
        self.wait(1.4)

        bottom = body(
            "Deterministic rules, not a score: \"who started it, from where, and what happened nearby\"",
            22,
            YELLOW,
        )
        bottom.next_to(engine, DOWN, buff=0.62)
        self.play(FadeIn(bottom))
        self.wait(1.8)
        self.play(FadeOut(VGroup(heading_m, collectors, engine, outputs, arrow1, arrow2, bottom)))

    def show_detection_families(self):
        heading_m = heading("Five detection families", YELLOW)
        heading_m.to_edge(UP)

        d1 = card("D1  PROCESS CHAINS", ["Web / database shells", "Downloader + relay tools", "/tmp or deleted execution", "Download-and-run", "Memfd execution"], RED, 3.65, 3.0)
        d2 = card("D2  SSH + ACCOUNTS", ["Failed-login bursts", "Root / new-source login", "Hidden SSH keys", "SSH configuration", "Account changes"], ORANGE, 3.65, 3.0)
        d3 = card("D3  PERSISTENCE", ["Cron / at / systemd", "Profiles + rc.local", "Authorized keys", "LD loader config", "PAM / udev / modules"], YELLOW, 3.65, 3.0)
        d4 = card("D4  PRIVILEGES", ["Setuid + capabilities", "Ptrace attachment", "LD_PRELOAD / LD_AUDIT", "Sudoers / shadow writes"], GREEN, 3.65, 3.0)
        d5 = card("D5  NETWORK", ["C2 from a flagged chain", "New external destinations", "First network program", "Suspicious listeners"], BLUE_B, 3.65, 3.0)

        top = VGroup(d1, d2, d3).arrange(RIGHT, buff=0.25).shift(UP * 0.85)
        bottom = VGroup(d4, d5).arrange(RIGHT, buff=0.25).shift(DOWN * 2.05)

        self.play(Write(heading_m))
        self.play(LaggedStart(*[FadeIn(c) for c in top], lag_ratio=0.18), run_time=1.5)
        self.play(LaggedStart(*[FadeIn(c) for c in bottom], lag_ratio=0.18), run_time=1.2)
        self.wait(2.2)
        self.play(FadeOut(VGroup(heading_m, top, bottom)))

    def show_context_and_process_chain(self):
        heading_m = heading("Why context matters", YELLOW)
        heading_m.to_edge(UP)

        nginx = body("nginx", 25, GREEN)
        nginx_box = RoundedRectangle(width=1.8, height=0.8, corner_radius=0.15, stroke_color=GREEN)
        nginx_box.move_to(LEFT * 4.8)
        nginx.move_to(nginx_box)

        curl = body("curl", 25, ORANGE)
        curl_box = RoundedRectangle(width=1.6, height=0.8, corner_radius=0.15, stroke_color=ORANGE)
        curl_box.move_to(LEFT * 1.6)
        curl.move_to(curl_box)

        bash = body("bash", 25, RED)
        bash_box = RoundedRectangle(width=1.6, height=0.8, corner_radius=0.15, stroke_color=RED)
        bash_box.move_to(RIGHT * 1.6)
        bash.move_to(bash_box)

        beacon = body("10.4.2.19:443", 20, RED)
        beacon_box = RoundedRectangle(width=2.2, height=0.8, corner_radius=0.15, stroke_color=RED)
        beacon_box.move_to(RIGHT * 4.8)
        beacon.move_to(beacon_box)

        arrows = VGroup(
            Arrow(nginx_box.get_right(), curl_box.get_left(), buff=0.12, color=YELLOW),
            Arrow(curl_box.get_right(), bash_box.get_left(), buff=0.12, color=YELLOW),
            Arrow(bash_box.get_right(), beacon_box.get_left(), buff=0.12, color=YELLOW),
        )

        labels = VGroup(
            body("service", 15, GREEN),
            body("download", 15, ORANGE),
            body("shell", 15, RED),
            body("outbound", 15, RED),
        )
        labels[0].next_to(nginx_box, DOWN)
        labels[1].next_to(curl_box, DOWN)
        labels[2].next_to(bash_box, DOWN)
        labels[3].next_to(beacon_box, DOWN)

        severity = body("D1: download-and-run  →  CRITICAL", 28, RED)
        severity.next_to(labels, DOWN, buff=0.55)
        hint = body("The shell chain, payload location, destination, timing, and ancestry are correlated.", 20)
        hint.next_to(severity, DOWN, buff=0.28)

        no_context = body("A shell in an SSH session is not treated as suspicious in the same way.", 23, YELLOW)
        no_context.to_edge(DOWN * 1.45)

        self.play(Write(heading_m))
        chain = VGroup(nginx_box, nginx, arrows[0], curl_box, curl, arrows[1], bash_box, bash, arrows[2], beacon_box, beacon)
        self.play(FadeIn(chain), run_time=1.6)
        self.play(FadeIn(labels))
        self.play(FadeIn(severity), FadeIn(hint))
        self.wait(0.8)
        self.play(FadeIn(no_context))
        self.wait(2)
        self.play(FadeOut(VGroup(heading_m, chain, labels, severity, hint, no_context)))

    def show_collector_limits(self):
        heading_m = heading("Coverage and limits", YELLOW)
        heading_m.to_edge(UP)

        seen = card(
            "SEEN",
            ["New processes", "Process ancestry", "Network attempts", "Ptrace attempts", "File writes", "New listeners"],
            GREEN,
            4.2,
            4.2,
        )
        missed = card(
            "NOT SEEN",
            ["Code inside an existing process", "Unnewed 32-bit syscalls", "UDP sends", "io_uring connects", "Containers from the host", "Short-lived polling gaps"],
            RED,
            4.2,
            4.2,
        )
        seen.move_to(LEFT * 3.25)
        missed.move_to(RIGHT * 3.25)

        note = body("Hermian watches the Linux host - not application memory or every network protocol.", 21, YELLOW)
        note.next_to(seen, DOWN, buff=0.8)
        note.shift(RIGHT * 3.25)

        self.play(Write(heading_m))
        self.play(FadeIn(seen), FadeIn(missed), run_time=1.2)
        self.play(FadeIn(note))
        self.wait(2.2)
        self.play(FadeOut(VGroup(heading_m, seen, missed, note)))

    def show_java4shell(self):
        heading_m = heading("Where Java4Shell fits", YELLOW)
        heading_m.to_edge(UP)

        runtime = card(
            "JVM MEMORY",
            ["Attacker-controlled Base64", "Malformed input reaches decoder", "Heap corruption", "Existing Java process"],
            BLUE_B,
            4.2,
            3.4,
        )
        aftermath = card(
            "POST-EXPLOITATION",
            ["Shell / interpreter starts", "Payload in /tmp", "Downloader executes", "Suspicious outbound link", "Persistence created"],
            GREEN,
            4.2,
            3.4,
        )
        runtime.move_to(LEFT * 3.25)
        aftermath.move_to(RIGHT * 3.25)

        gap = Arrow(runtime.get_right(), aftermath.get_left(), buff=0.18, color=RED)
        gap_label = body("Hermian cannot see this first step", 20, RED)
        gap_label.next_to(gap, UP)

        verdict = body("Hermian detects some consequences - not the CVE trigger or patched runtime state.", 24, YELLOW)
        verdict.next_to(runtime, DOWN, buff=0.85).shift(RIGHT * 3.25)

        self.play(Write(heading_m))
        self.play(FadeIn(runtime))
        self.play(GrowArrow(gap), FadeIn(gap_label))
        self.play(FadeIn(aftermath))
        self.play(FadeIn(verdict))
        self.wait(2.8)
        self.play(FadeOut(VGroup(heading_m, runtime, aftermath, gap, gap_label, verdict)))

    def show_response_and_positioning(self):
        heading_m = heading("Response and deployment", YELLOW)
        heading_m.to_edge(UP)

        left = card(
            "DETECTION",
            ["INFO: context only", "LOW: worth a look", "HIGH: investigate", "CRITICAL: urgent"],
            ORANGE,
            4.1,
            3.4,
        )
        right = card(
            "ACTION",
            ["Log / Telegram / email", "Webhook / Slack / Discord", "Block source", "Disconnect SSH", "Isolate host"],
            RED,
            4.1,
            3.4,
        )
        left.move_to(LEFT * 3.25)
        right.move_to(RIGHT * 3.25)

        baseline = body("Learns normal behavior for 24 hours, then judges novelty.", 22, BLUE_B)
        baseline.next_to(left, DOWN, buff=0.9).shift(RIGHT * 3.25)

        self.play(Write(heading_m))
        self.play(FadeIn(left), FadeIn(right))
        self.play(FadeIn(baseline))
        self.wait(2.2)

        positioning = VGroup(
            heading("One host. One daemon.", YELLOW, 42),
            body("No dashboard or central account.", 25),
            body("It is an EDR-style detector - not a vulnerability scanner or SIEM replacement.", 22, GREEN),
        ).arrange(DOWN, buff=0.25)

        self.play(FadeOut(VGroup(left, right, baseline)))
        self.play(FadeIn(positioning))
        self.wait(2.5)
        self.play(FadeOut(VGroup(heading_m, positioning)))

    def show_closing(self):
        title = heading("Hermian + patching", YELLOW, 58)

        stack = VGroup(
            card("PREVENT", ["Patch Java", "Inventory runtimes", "Harden encoders"], GREEN, 3.7, 2.3),
            card("DETECT", ["Behavioral alerts", "Post-exploit chains", "Anomaly context"], BLUE_B, 3.7, 2.3),
            card("RESPOND", ["Investigate", "Block", "Disconnect", "Isolate"], RED, 3.7, 2.3),
        ).arrange(RIGHT, buff=0.32)
        stack.next_to(title, DOWN, buff=0.75)

        slogan = body("You need both prevention and detection.", 30, YELLOW)
        slogan.next_to(stack, DOWN, buff=0.65)

        self.play(Write(title))
        self.play(LaggedStart(*[FadeIn(c) for c in stack], lag_ratio=0.25), run_time=1.8)
        self.play(FadeIn(slogan))
        self.wait(3)
