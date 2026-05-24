# AI / LLM features

WPSecScan supports OpenAI, Anthropic, and Ollama. **You bring your own
key** — the project ships no inference cost.

## Privacy + safety guards

- Every LLM call is preceded by **PII masking** (email / IP / card / SSN /
  AWS-key / Stripe-key / GitHub PAT → `[REDACTED]`)
- Every LLM call is preceded by a **prompt-injection guard** that strips
  known instruction-overrider patterns from finding evidence
- **Hard disable**: `WPSECSCAN_NO_AI=1` short-circuits every LLM call
- **Cost tracking**: per-backend $-spend tallied in `~/.wpsecscan/ai_cost.json`
- **Hallucination check**: optional re-prompt verifies LLM claims

## Configure a backend

Pick one (or several — last-configured wins by Anthropic → OpenAI → Ollama):

**Anthropic** (recommended for accuracy):
```
export WPSECSCAN_ANTHROPIC_API_KEY=sk-ant-...
```

**OpenAI**:
```
export WPSECSCAN_OPENAI_API_KEY=sk-...
```

**Ollama** (local — GDPR-safe):
```
ollama serve &
ollama pull llama3
export WPSECSCAN_OLLAMA_URL=http://localhost:11434
```

**llama.cpp** (local — alternative to Ollama):
```
./server -m model.gguf --host 0.0.0.0 --port 8080
export WPSECSCAN_LLAMA_CPP_URL=http://localhost:8080
```

## Features that use the LLM

| Feature | What it does |
|---------|--------------|
| `remediation_augment` | Adds 3 concrete commands/configs to each finding |
| `executive_summary` | Plain-English C-suite summary |
| `query(question)` | Ask natural-language questions of the report |
| `chain_explanation` | "How an attacker would chain these findings" |
| `fix_pr_body` | Auto-write a GitHub PR description for the fix |
| `replacement_plugin_recommender` | Suggests alternatives to vulnerable plugins |
| `verify_claim` | Yes/no LLM fact-check of a claim |

## Cost transparency

```
wpsecscan ai-cost
```

Prints token + USD usage per backend. The cost log is append-only and
never sent anywhere.

## Switching off mid-scan

If a scan starts misbehaving (rate limits, weird outputs), kill the AI
without aborting the scan:

```
export WPSECSCAN_NO_AI=1
```

Set this in the same shell and re-run. All AI helpers return `""`
immediately; everything else proceeds normally.
