"""
JS Workers for genki-shell.

Bundled Node.js analysis engines from the old AWVS10 scanning pipeline:

  genki-prober/  - IAST engine, JS static analyzer, deobfuscator,
                   taint planter, script harvester, source extractor,
                   crawler, gadget finder, security scanner (.cjs)

  kiseichu/      - DOM invader, mutation engine, sink tracker,
                   fuzzer core, IAST engine (.js)

  jshadow-universal/ - JScrambler / JS-obfuscator corpus generator
                       and universal deobfuscation patterns

Use runner.run_js_worker() to execute any worker via Node.js subprocess.
"""
