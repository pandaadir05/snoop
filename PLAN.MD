The project: snoop (working name)
Tagline: "strace, but you actually want to use it."
One-line pitch: A modern syscall tracer for Linux, written in Rust, built on eBPF, with a beautiful TUI, smart filters, flamegraphs, and an "explain this" mode that tells you in plain English what a process is doing.
Why this wins

Every Linux developer has suffered strace. The output is a wall of text, it's slow because it uses ptrace, it can't easily attach to an already-running process tree, filtering is arcane (-e trace=...), and there's no UI. Any dev who has debugged "why is this container slow to start" has a bad strace memory.
eBPF makes the technical story sexy. "I rewrote strace on eBPF and it's 10x faster and doesn't slow down your program" is a Hacker News front-page headline on its own. Jvns-style blog post writes itself.
The TUI is the viral vehicle. A 20-second GIF of a real-time, colored, grouped, filterable syscall view — with a flamegraph panel updating live — is the kind of thing that gets retweeted 2000 times. None of the existing tools has this.
The "explain" mode is the moat. Every other tool dumps raw syscalls. snoop groups them: instead of 200 lines of openat, read, close, it says "Loaded config from /etc/nginx/nginx.conf (3ms)". Instead of a connect + 15 sendtos, "HTTP GET to api.github.com/users/x — 180 bytes sent, 4KB received". This is the feature nobody else has because it requires taste, not just eBPF knowledge. And it's the feature that makes non-experts star it.
It's security-relevant without being security-niche. Every malware analyst, reverse engineer, and incident responder uses strace. They'll love it too. You get dev tool audience and sec audience.

Scope: v0.1 (what you ship on launch day — target 2–3 months)
Minimum to put on HN and not get dunked on:

Attach modes: snoop <cmd> (spawn), snoop -p <pid> (attach), snoop -p <pid> --follow (+ children).
Core tracing via eBPF tracepoints (raw_syscalls/sys_enter + sys_exit). Use aya — pure Rust, no C toolchain, fast builds. That's a selling point in the README.
Argument decoding for the top ~40 syscalls that matter (openat, read, write, connect, sendto, recvfrom, execve, mmap, close, stat family, futex, clone, wait4, etc). strace handles 300+ — don't try to match that, handle the ones people actually care about brilliantly.
Two output modes:

--raw: strace-compatible line output (so people can drop it in).
Default: TUI (ratatui) with: live syscall stream, per-syscall counts, per-fd activity view, filterable by pid/syscall/fd.


Filtering that doesn't suck: snoop --files (only file ops), --net (only network), --slow 10ms (only syscalls taking >10ms).
One killer feature for v0.1 — pick one of:

Flamegraph export (--flamegraph out.svg) — trivial once you have timing data, gives you a shareable artifact.
"Explain" mode — the higher-level grouping. Harder but way more differentiating.

My strong pick: ship v0.1 with flamegraph, ship v0.2 with explain mode. Flamegraph is easier and still demo-worthy.

What goes in v0.2+ (your roadmap, teased in the README)

Explain mode (the grouping/semantic layer).
Record & replay: snoop record ./mybinary > trace.snoop, then snoop view trace.snoop later. Now it's also a debugging artifact people share in bug reports.
Diff mode: snoop diff good.snoop bad.snoop — shows what's different between a working and broken run. Nobody has this. It alone will get stars.
Container-aware: snoop --docker <container>, snoop --pod <pod>. Plugs you into the Kubernetes crowd.
Library-call tracing via uprobes — absorbs ltrace too.
TLS decryption via uprobes on SSL_write/SSL_read — now you can see HTTP bodies inside encrypted connections without a MITM. This is the feature that brings security researchers running.

Technical reality-check (the hard parts)

Syscall argument decoding is tedious. Each syscall has its own argument layout and many take pointers into userspace memory that you need to read via bpf_probe_read_user. Strings are variable-length (path names), structures have versions. This is the actual work of the project. Budget ~60% of your time on this, not on the TUI.
eBPF stack is 512 bytes. You'll hit this constantly when trying to copy argument data. Design the event structure carefully; for big strings, copy into a per-CPU map first.
Kernel version portability. Use CO-RE (via aya or libbpf-rs). aya is pure Rust (nicer toolchain), libbpf-rs has more mature CO-RE (safer for portability). Recommendation: start with aya, because "I built it in pure Rust, no C toolchain, 3-second builds" is part of your story. If you hit CO-RE walls, you can switch later.
Root / CAP_BPF. You need privileges. Handle this gracefully, document it, offer a setuid wrapper pattern.
Performance claims. Before you write the README, benchmark against strace on something real (a make, a git clone). If you're not actually faster, don't claim to be — people will check.

The launch mechanics (this part matters more than the code)
Stars don't come from code, they come from a good launch. Plan it from day 1:

README is the product. Top of it: an animated GIF of the TUI. Then a comparison table vs strace. Then a one-command install (curl | sh + cargo install + homebrew tap on day 1). Then "how it works" with an architecture diagram. Check out how bottom, bandwhich, and uv do their READMEs.
The blog post is half the project. "I rewrote strace in Rust with eBPF" — ~3000 words, Julia Evans style, screenshots everywhere, explain the eBPF verifier, explain the argument decoding, explain the tradeoffs. Post it the same day you launch.
Where to launch: Hacker News (Tuesday or Wednesday, ~9am ET), r/rust, r/linux, r/netsec, lobste.rs, This Week in Rust. Not all at once — HN first, then the rest 24–48h later once you have social proof.
Don't launch at v0.0.1. Launch when there's a clean binary that installs in one command and the GIF looks good. A bad first impression is permanent.

The honest risks

You burn out on syscall arg decoding in month 2. Mitigation: only commit to the top 40 syscalls, mark others as "raw args shown" in v0.1.
Someone else ships it first. Possible but unlikely at polish level — the half-built blog-post prototypes have been sitting there for years. Speed matters though; don't spend 6 months on v0.1.
The TUI eats all your time. Mitigation: ratatui + a couple of reference apps (bottom, gitui) and don't try to be pretty in week 1. Function first, polish in the last two weeks before launch.
It only works on Linux. That's fine — so does strace. Don't waste time on macOS until after launch.

