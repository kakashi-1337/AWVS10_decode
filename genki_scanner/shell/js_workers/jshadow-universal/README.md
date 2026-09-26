# 🥷 J-Shadow Universal

One command. Recon-first, auto-routing JavaScript deobfuscator that merges every
proven engine from the J-Shadow lineage.

## Run
```bash
npm install
node index.js <obfuscated.js> -o clean.js -v
```

## How it works
1. **Recon** (`patterns.json` + AST) → builds a decode plan: family, decoder,
   rotation, anti-debug, required files.
2. **Route** to the best engine per family (obfuscator.io RC4 / JScrambler /
   webpack / packers / esoteric).
3. **Escalate** static → dynamic sandbox (instrument + hook the file's own
   decoders, proven on RC4 + rotation + self-defending) → AI (only if leftovers;
   notifies when an API key/Ollama is needed).
4. **Guardrails** — if the output balloons (>3x, wrong decode) or an anti-debug
   trap blocks execution, it STOPS instead of shipping garbage.
5. **Learn** the result back into `patterns.json`.

## Honest about limits
- **VM / virtualization** (JScrambler VM, control-flow flattening) is a different
  problem class — the logic lives in bytecode + an interpreter, not a decoder.
  J-Shadow **detects** it, does **partial** extraction (strings/urls/keys), and
  reports honestly that full recovery needs opcode mapping + CFG reconstruction —
  it never fabricates a fake de-virtualized output.

## Modules (superiority-merged)
- `jshadow-core` — RC4/rotation/self-defending + proxy/const-object + fold/rename (proven)
- `JScramblerUniversal` / `JShadow_V11` — JScrambler XOR + JSDOM
- `smart-renamer` — semantic renaming
- `recon-ast` + `patterns.json` — fingerprint + self-learning DB
- (pluggable) crypto-tracer, ai-deobfuscator
