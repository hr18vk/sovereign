# Raw evidence for the 1,000-process runs

This directory contains the per-node final-state tables, archive manifests, complete
gate and hook logs, and selected console extracts for three clean convergence runs
and three fault drills on 6 November 2026. Each run used 1,000 node processes on
30 machines in three AWS regions.

| Run | Per-node table | Archive manifest | Gate log | Hook log | Console extract |
|:--|:--|:--|:--|:--|:--|
| Clean run 1 | [fingerprints](clean-run-1.fingerprints.tsv) | [SHA-256 manifest](clean-run-1.manifest.sha256) | [gate](clean-run-1.gate.log) | — | [console](clean-run-1.console.txt) |
| Clean run 2 | [fingerprints](clean-run-2.fingerprints.tsv) | [SHA-256 manifest](clean-run-2.manifest.sha256) | [gate](clean-run-2.gate.log) | — | [console](clean-run-2.console.txt) |
| Clean run 3 | [fingerprints](clean-run-3.fingerprints.tsv) | [SHA-256 manifest](clean-run-3.manifest.sha256) | [gate](clean-run-3.gate.log) | — | [console](clean-run-3.console.txt) |
| Packet-drop drill | [fingerprints](packet-drop-drill.fingerprints.tsv) | [SHA-256 manifest](packet-drop-drill.manifest.sha256) | [gate](packet-drop-drill.gate.log) | [during-gate hook](packet-drop-drill.during-gate-hook.log) | [console and hook](packet-drop-drill.console.txt) |
| Kill drill | [fingerprints](kill-drill.fingerprints.tsv) | [SHA-256 manifest](kill-drill.manifest.sha256) | [gate](kill-drill.gate.log) | [during-gate hook](kill-drill.during-gate-hook.log) | [console and hook](kill-drill.console.txt) |
| Impostor-identity drill | [fingerprints](impostor-identity-drill.fingerprints.tsv) | [SHA-256 manifest](impostor-identity-drill.manifest.sha256) | [gate](impostor-identity-drill.gate.log) | [pre-gate hook](impostor-identity-drill.pre-gate-hook.log) | [console, impostor output, and hook](impostor-identity-drill.console.txt) |

All six final-state tables, all six archive manifests, all nine gate and hook logs,
and all six console extracts are verified and published in this directory: 27 unique
files in total.

## Per-node tables

Each tab-separated table has 1,000 data rows and one header row. Its columns are:

- `global_idx`: the node's zero-based index in the run.
- `region`: the AWS region recorded for the node.
- `box_id`: the deterministic machine placeholder for this run.
- `ip`: the node address, redacted as `[address]`.
- `port`: the service port recorded for the node.
- `keys`: the key count recorded at the final harvest.
- `state_fp`: the state fingerprint returned by the node at the final sweep.
- `xor_root`: the XOR root recorded for the node. This is a separate value, not the
  Merkle root used by the convergence check. The common Merkle root appears in the
  console extracts and gate logs.

All non-redacted fields and the original row order are retained. In particular,
`state_fp` and `xor_root` keep their source meanings; neither column has been renamed or
derived from the other.

## Redaction

Within each run, `[machine-NN]` consistently replaces one source machine identifier.
The mapping is deterministic for that run, and the archive labels use the same machine
placeholders. Node addresses in the tables are `[address]`; console extracts disclose
their own labelled address placeholders. These placeholders preserve row and archive
correspondence without publishing host addresses or instance identifiers.

## Archive manifests

Each manifest has 30 per-machine archive entries followed by one self-entry. The archive
entries retain their original SHA-256 digests and entry order; private paths are reduced
to basenames with machine placeholders. The final self-entry is labelled
`archive-manifest.sha256`, the redacted basename of the original manifest. Its digest is
unchanged.

The 180 original per-machine `.tgz` archives for the six final runs were not preserved
after 6 November 2026 and cannot be restored. Their per-node log members are unavailable,
and no archive digest can be rechecked against live tarballs. The manifests preserve the
recorded archive names and SHA-256 digests; they do not establish current archive
availability, and the manifest entries are not links to downloadable archives.

## Console-extract limits

The console files are selected extracts, not complete consoles. Their headers identify
the source and gate-log hashes, selected source lines, redactions, and omissions. Lines
that would expose private paths, host identifiers, or source-runner and configuration
names are omitted rather than rewritten. Result and verdict lines carrying such names
are summarized in the extract metadata instead of being quoted. Retained raw lines are
otherwise verbatim.

The drill extracts also include selected hook-log or impostor-output lines under separate
headings. Those lines are not console lines. Read each extract together with its per-node
table and manifest; the extract alone is not the complete run record.

## Gate and hook logs

The nine gate and hook logs are published verbatim with only the approved redactions
(addresses, instance identifiers, private filesystem tokens, and blocked source-run
labels replaced by bracketed placeholders or public aliases). Every source line, its
order, timestamps, measurements, roots, fingerprints, and verdicts are preserved. See
each log's header for its source SHA-256 and the substitution classes applied.
