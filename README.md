# npm-ws-gate

CI/CD infection gate for the **npm-ws / PolinRider** npm supply-chain implant
(OX Security · Apiiro · CISA · Microsoft · Sonatype/Amazon — campaign documented
Nov 2026). Blocks any build/push carrying the implant's signatures.

Companion to `npm-ws-remediate.sh` + `npm-ws-agent-instructions.md`
(the machine-side kit lives in `navidRashik/popular-travels-audit`).

## What it detects

| Family | Signatures |
|---|---|
| npm hook | `M260630A`, `npm-ws` in any `cli.js` / content |
| Variant 1/2/3 caches | `parseInt(0x`, `VcIjEMuK`, `oUjdMfbQcGFkunf`, `bx = '-11381-2'`, bare `-11381-2` |
| Family B — active C2-resolver loader | `uG$O_YLJZRJdet`, `daIQfX`, `}(global,require)` scaffold |
| Family C — live loader (R-dash) | `global['!']='9-4349'`, `var _$_1e42=`, `var n=2667686`, `Tgw(2509)` |
| Font loader | `EWKyMvkJkykfdVCH` (obfuscator inside fake `.ttf`) |
| Payload files | `init`, `*.orc`, `config.bat` (name+content/size heuristics) |
| Persistence triggers | `.vscode/tasks.json` running fonts / hidden `isBackground` tasks |
| Secret-steal prep | `.gitignore` un-ignoring `.env` / `.vscode` |
| Script hijack | `package.json` `"dev"/"build": "node init && …"` |

Plus optional **pickaxe mode**: `--base <ref>` scans every commit the push
adds (`git log -S` per marker family) so payload-carrying pushes are blocked
at the gate.

## Use as a GitHub Action (composite — no workflow file needed in THIS repo)

```yaml
# in YOUR repo's .github/workflows/gate.yml
name: npm-ws gate
on: [push, pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # pickaxe needs history
      - uses: navidRashik/npm-ws-gate@main
        with:
          base-ref: ${{ github.event.pull_request.base.sha || github.event.repository.default_branch }}
```

> NOTE: pushing `.github/workflows/*.yml` requires a token with **workflow**
> scope. This repo ships only a composite `action.yml` + shell script, which
> plain `repo` scope can push — the caller workflow lives in the repos being
> protected.

## Use as a local gate

```bash
./npm-ws-ci-gate.sh .                      # working tree
./npm-ws-ci-gate.sh . --base origin/main   # + pickaxe the added commits
./install-prepush-hooks.sh                 # every git repo under ~/src, ~/Documents:
                                           # pre-push hook refuses marker-carrying pushes
```

## Exit codes

`0` clean · `1` FINDINGS (block) · `2` setup/usage gap — **a gate that could
not run is never clean.**

## Field lessons baked in

- `git grep` rejects `--binary-files=text` on many builds (exit 129 = silent
  zero hits) — the portable flag is `-a`; the gate asserts its grep ran.
- Payloads hide behind binary NAMES (`fa-solid-600.ttf` is text) — raw bytes
  are scanned, never `-I`.
- `git ls-tree --name-only` strips the blob sha and silently no-ops filename
  checks — full `-r -z` entries only.
- `init` filename alone is not proof (legit vendored packaging, e.g. Odoo
  `debian/init`) — name + marker-content or dropper-size heuristic.
- A benign `tasks.json` is normal; its `label/command/args/runOptions` are
  what matter.

Optional dependency-vuln scanning (osv-scanner) is staged in `npm-ws-gate.yml`
as a reusable-workflow variant.
