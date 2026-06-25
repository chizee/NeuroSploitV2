<h1 align="center">🧠 NeuroSploit v3.5.1</h1>

<p align="center">
  <a href="https://github.com/JoasASantos/NeuroSploit/stargazers"><img src="https://img.shields.io/github/stars/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=8b5cf6" alt="Stars"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/network/members"><img src="https://img.shields.io/github/forks/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=a855f7" alt="Forks"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/issues"><img src="https://img.shields.io/github/issues/JoasASantos/NeuroSploit?style=for-the-badge&color=22d3ee" alt="Issues"></a>
  <img src="https://img.shields.io/github/last-commit/JoasASantos/NeuroSploit?style=for-the-badge&color=34d399" alt="Last commit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.5.1-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Harness-Rust%20%7C%20tokio-e6b673?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/MD%20Agents-303-red?style=flat-square">
  <img src="https://img.shields.io/badge/Models-12%20providers-success?style=flat-square">
  <img src="https://img.shields.io/badge/Auth-API%20key%20%7C%20Subscription-orange?style=flat-square">
</p>

<p align="center"><b>Autonomous, multi-model penetration-testing harness — Rust, CLI-only.</b><br>
<i>by Joas A Santos &amp; Red Team Leaders</i></p>

> ⭐ If this is useful, **star the repo** — it helps a lot.

---

## 🆕 v3.5.1 — POMDP belief & grounded anti-hallucination

The target is only **partially observable**, so v3.5.1 stops treating findings as
booleans and tracks a **belief**:

- **Belief world model** (`belief.rs`) — a property graph whose nodes
  (host / service / vuln / exploit / credential) each carry a *probability*, not a
  boolean. Observations update them with a Bayesian step; per-node **Shannon
  entropy** measures how diffuse the belief still is.
- **Value-of-information planner** (`pomdp.rs`) — "scan more vs exploit now" is
  not a heuristic: when a node's belief is diffuse, the expected value of an
  observation (recon) exceeds the risk-adjusted value of an exploit. The
  `may_assert` gate is the **mathematical anti-hallucination rule** — the agent
  may not claim exploitability while the belief is diffuse; it must observe first.
- **Grounding / verification engine** (`grounding.rs`) — a hard rule: **no claim
  enters the world model without a tool receipt** (raw tool output, not the LLM's
  paraphrase). Black-box grounding is *empirical* (a real HTTP response / OOB
  callback / error oracle); white-box is *symbolic* (a `file:line` into the
  reviewed source). Ungrounded claims are demoted and flagged `receipt_missing`.
- **Regimes** — black-box runs a true POMDP (diffuse priors that sharpen with
  observation); white-box collapses toward a near-deterministic MDP (the world
  model is built from SAST/dataflow, so uncertainty migrates to *path
  reachability*, not state).

> Roadmap (in progress on this branch): infra targets (IP + SSH/Windows/AD) with
> Linux/Windows/AD host agents, a contextual-bandit tool router, and
> value-of-information reward shaping.

---

**Autonomous, multi-model penetration-testing harness — Rust, CLI-only.**

This branch is the **slim, Rust-only** distribution: the `neurosploit-rs/` workspace
plus the `agents_md/` agent library. It turns a URL (black-box) or a code
repository (white-box) into an autonomous engagement that drives a pool of LLMs
— via **API key** or local **subscription** (Claude Code / Codex / Gemini / Grok)
— recons the target, **intelligently selects only the agents matching the
discovered surface**, runs them in parallel, then validates every finding by
**cross-model voting** before reporting.

> The full project (Python engine, web GUIs, history) lives on the `main` branch.

---

## 📦 Install (one line)

```bash
curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
```

The installer auto-installs Rust if needed, clones the repo to `~/.neurosploit`,
builds the release binary, and links `neurosploit` into `~/.local/bin`. Re-run it
any time to update. Tweak with env vars: `NEUROSPLOIT_REF` (branch/tag),
`NEUROSPLOIT_DIR`, `PREFIX`.

Prefer to build by hand?

```bash
git clone https://github.com/JoasASantos/NeuroSploit && cd NeuroSploit/neurosploit-rs
cargo build --release      # → target/release/neurosploit
```

## ⚡ Quick start (60 seconds)

```bash
# easiest path — just run it; the interactive session asks everything:
neurosploit

# or one-liner (subscription login, no API key needed):
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v

# 🛰  Mission Control TUI — live panels (header/feed/findings/targets) + a composer
#    you can type in WHILE the run streams (summary · pause · errors · notes):
neurosploit tui http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp
```

No login? Use an **API key** instead — see [Authentication](#authentication--run-via-api-key-or-subscription).

---

## Build

```bash
cd neurosploit-rs
cargo build --release        # → target/release/neurosploit
```

Requires a Rust toolchain (`rustup`). **Recommended: run on Kali Linux** (or the
Kali Docker image) so the offensive tools the agents use are already present:

```bash
docker run -it --rm kalilinux/kali-rolling
apt update && apt install -y curl nmap ffuf nodejs npm
# rustscan (faster port scan): cargo install rustscan   (or grab a release from GitHub)
```

The agents degrade gracefully: if `rustscan` isn't installed they use `nmap`; if
neither, they probe with `curl`. If a Playwright MCP browser is available they use
it for JS-heavy pages, otherwise they fall back to `curl`.

---

## Usage

Run with **no arguments** for an interactive wizard:

```bash
./target/release/neurosploit
```

Or drive it directly:

```bash
# Black-box — subscription (no API key), Opus, browser via Playwright if present, verbose
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --subscription --model anthropic:claude-opus-4-8 --mcp -v

# Black-box — API keys, multi-model voting panel (1st finds, others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3

# White-box — clone a vulnerable app and review its source
git clone https://github.com/digininja/DVWA /tmp/DVWA
./target/release/neurosploit whitebox /tmp/DVWA \
    --subscription --model anthropic:claude-opus-4-8 -v

# Offline pipeline self-test (no keys/login needed)
./target/release/neurosploit run http://testphp.vulnweb.com/ --offline

# Utilities
./target/release/neurosploit agents     # library counts
./target/release/neurosploit models      # providers & models
./target/release/neurosploit --help        # full help with examples
```

### Options (`run` / `whitebox`)

| Flag | Meaning |
|------|---------|
| `--model provider:model` | Repeatable. First = primary; the rest fail over **and** form the voting jury. |
| `--subscription` | Use the local CLI login (Claude/Codex/Gemini/Grok) instead of an API key. |
| `--mcp` | Enable Playwright MCP (auto-provisioned via `npx`; backends without MCP use built-in tools). |
| `--vote-n N` | How many models must agree a finding is real (default 3 / 2 for whitebox). |
| `--max-agents N` | Cap agents run (`0` = all matching the recon). |
| `--offline` | Exercise the full pipeline without calling any model. |
| `-v, --verbose` | Log each agent as it launches, recon, and votes. |

### Authentication — run via API key *or* subscription

You can run NeuroSploit two ways. They're independent: pick per run.

#### 1) Via API (provider API key)

Export the key(s) for the providers in your model panel, then run **without**
`--subscription`. Any OpenAI-compatible provider works.

```bash
# pick one or more, depending on the models you select
export ANTHROPIC_API_KEY=sk-ant-...        # anthropic:claude-*
export OPENAI_API_KEY=sk-...               # openai:gpt-*
export GEMINI_API_KEY=AIza...              # gemini:gemini-*
export XAI_API_KEY=xai-...                 # xai:grok-*
export NVIDIA_NIM_API_KEY=nvapi-...        # nvidia_nim:*
export DEEPSEEK_API_KEY=...                # deepseek:*
export MISTRAL_API_KEY=...                 # mistral:*
export DASHSCOPE_API_KEY=...               # qwen:*  (Alibaba DashScope)
export GROQ_API_KEY=...                    # groq:*
export TOGETHER_API_KEY=...                # together:*
export OPENROUTER_API_KEY=...              # openrouter:*
# ollama needs no key (local)

# then run via API (note: NO --subscription)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --vote-n 3 -v

# multi-provider voting panel via API (1st finds, the others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --model gemini:gemini-2.5-pro
```

Or put the keys in a `.env` and source it (`cp .env.example .env`; edit; `set -a; . ./.env; set +a`).

**Provider → env var → endpoint** (all OpenAI-compatible):

| `--model` prefix | Env var | Base URL |
|------------------|---------|----------|
| `anthropic:` | `ANTHROPIC_API_KEY` | api.anthropic.com |
| `openai:` | `OPENAI_API_KEY` | api.openai.com |
| `gemini:` | `GEMINI_API_KEY` | generativelanguage.googleapis.com |
| `xai:` | `XAI_API_KEY` | api.x.ai |
| `nvidia_nim:` | `NVIDIA_NIM_API_KEY` | integrate.api.nvidia.com |
| `deepseek:` | `DEEPSEEK_API_KEY` | api.deepseek.com |
| `mistral:` | `MISTRAL_API_KEY` | api.mistral.ai |
| `qwen:` | `DASHSCOPE_API_KEY` | dashscope-intl.aliyuncs.com |
| `groq:` | `GROQ_API_KEY` | api.groq.com |
| `together:` | `TOGETHER_API_KEY` | api.together.xyz |
| `openrouter:` | `OPENROUTER_API_KEY` | openrouter.ai |
| `ollama:` | _(none)_ | localhost:11434 |

Run `./target/release/neurosploit models` for the full provider/model list.

#### 2) Via subscription (no API key)

`--subscription` drives your local agentic-CLI login instead of an API key —
install and log into one of the CLIs first:

| `--model` prefix | CLI used | Login |
|------------------|----------|-------|
| `anthropic:` | `claude` (Claude Code) | `claude` then `/login` |
| `openai:` | `codex` | `codex` login |
| `gemini:` | `gemini` | `gemini` login |
| `xai:` | `grok` | `grok` login |

```bash
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --subscription --model anthropic:claude-opus-4-8 --mcp -v
```

---

## How it works

```
target ─▶ recon (curl/nmap/…) ─▶ INTELLIGENT agent selection (recon-aware)
       ─▶ parallel exploitation ─▶ cross-model validation vote
       ─▶ severity/score ─▶ report (HTML + Typst PDF) ─▶ RL reward update
```

Every run writes a self-contained folder `runs/ns-<ts>-<target>/`:

| File | Contents |
|------|----------|
| `status.json` | `running` → `complete` with a summary |
| `recon.json` / `recon.md` | mapped attack surface |
| `exploitation.md` | raw per-agent transcript |
| `findings.json` / `findings.md` | validated findings (reuse by other tools/AIs) |
| `report.html`, `report.typ`, `report.pdf` | final report (PDF via the Typst engine) |

A reinforcement-learning reward store (`data/rl_state_rs.json`) biases agent
selection on future runs.

## Agent library — `agents_md/` (303)

| Category | Count | Purpose |
|----------|-------|---------|
| `vulns/` | 196 | Exploit a specific vulnerability class |
| `recon/` | 12 | Information gathering / attack surface |
| `code/` | 78 | White-box source-code (SAST) review |
| `meta/` | 17 | Orchestrator, validator, scorers, reporter, RL |

Each agent is a self-contained markdown playbook (`## User Prompt` methodology +
`## System Prompt` strict anti-false-positive rules). Drop a new `.md` into the
matching folder and the harness picks it up.

---

## Safety

For **authorized** testing only. Agents are instructed to stay in scope, never run
destructive/DoS actions, and require proof-of-exploitation. You are responsible for
having permission for any target.

## Credits

**Joas A Santos** & **Red Team Leaders**.

## License

MIT.
