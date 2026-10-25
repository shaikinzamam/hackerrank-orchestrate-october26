# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Step 4: Identity and As-of Timeline Modules

`code/identity_timeline.py` provides independent identity resolution and case
timeline reconstruction. It consumes the current identity rows, audit rows, and
the existing normalized `EvidenceFact` objects; it does not apply deletion
policy, determine deletion status, or generate remediation steps.

```python
from evidence_ingestion import ingest_evidence
from identity_timeline import (
    load_activity_events,
    load_identity_resolver,
    reconstruct_timeline,
)

evidence = ingest_evidence(dataset / "evidence_files.csv")
resolver = load_identity_resolver(
    dataset / "user_identities.csv",
    dataset / "user_audit_log.csv",
    evidence_facts=evidence.facts,
)
activity = load_activity_events(dataset / "system_activity.csv")
timeline = reconstruct_timeline(
    request_row,
    resolver,
    activity_events=activity,
)
```

Email matching trims surrounding whitespace and ignores case without changing
provider-specific spelling; phone matching removes whitespace but preserves
punctuation; email hashes are case-insensitive, and stable IDs are exact after
trimming surrounding whitespace.
Audit and evidence provenance is retained on identity links and timeline events.
Identifiers with more than one possible stable owner remain ambiguous unless a
temporal query disambiguates them. Each timeline event carries an
`identity_status` so ambiguous activity or evidence is not silently merged.

The supplied CSV timestamp columns use ISO-8601 UTC `Z` values. Offset-aware
timestamps are compared as instants; naive timestamps are interpreted as UTC.
Evidence capture time, source event time, and ingestion time are separate
fields. Known future evidence, audit changes, and process activity are excluded
at the request's `audit_at`; records with missing relevant timestamps remain
explicitly marked `unknown_time` and cannot establish a historical absence.
The supplied schemas do not provide ingestion timestamps, so those remain
unset. Current identity values use their row's `updated_at` as the observation
time, which cannot establish their exact start time; incomplete audit history
may therefore leave earlier identity state unresolved.

## Step 5: Lineage and Resurrection-Path Analysis

`code/lineage_graph.py` represents directed, provenance-bearing flow evidence
and analyzes paths independently of deletion-policy or final-status decisions.
Its main interfaces are `build_lineage_graph`, `resource_evidence_from_facts`,
`analyze_resurrection_paths`, and `simulate_edge_removals`. The graph builder
uses the request's as-of timeline to retain only relevant activity events and
filters evidence captured or observed after the cutoff. Activity time,
evidence capture time, and ingestion time are not conflated; the supplied
schemas do not provide an ingestion timestamp.

The supplied activity schema provides `activity_id`, `event_time`, `event_type`,
`source_system`, `target_system`, `resource_id`, `reported_result`, and
`details`. Transfer-like activity rows are retained as observed operations,
not persistent active flows: `reported_result` is an asserted outcome and
cannot by itself prove that a process remains enabled. The evidence manifest
provides `file_id`, `file_path`, `origin`, and `captured_at`. Inspected
`DATA_FLOW` evidence provides `resource_id`, `destination`, `subject_selector`,
`enabled`, and `mode`, but does not provide a source system. These incomplete
configurations are kept as unresolved edges; a source is never inferred from a
connector name or from unrelated activity. A matching `DISABLE_DATA_FLOW`
event is retained as a timeline observation and makes an otherwise active
configuration ambiguous; it does not itself prove that the disable succeeded.

Only an explicitly directed, active, user-applicable flow with source-resource
evidence can produce a confirmed path. A configuration observed earlier than
the cutoff without a validity interval is treated as a possible, not confirmed,
active path. Multi-hop traversal also requires evidence that the subject's
relevant data is present at each intermediate source. `ResourceEvidence` leaves
`contains_prohibited_data` unset unless a caller supplies a separately
established policy-stage judgment; graph analysis does not decide what data is
prohibited, whether deletion is complete, or what remediation to perform.
Hypothetical edge-removal simulation only compares graph analyses and does not
apply a change or verify deletion.

Known limitation: the supplied connector configuration examples lack a source
endpoint, while activity rows are point-in-time process claims rather than
authoritative ongoing-flow state. Consequently, the supplied evidence may
support unresolved or possible candidates but cannot, by itself, confirm a
user-specific active recreation path where those links are missing.

## Step 6: Policy Evaluation and Remediation Planning

`code/policy_engine.py` loads every action and condition from
`dataset/deletion_rules.csv`, evaluates identity-scoped evidence at each
request's `audit_at`, and returns `COMPLETE`, `INCOMPLETE`, or
`NOT_APPLICABLE`. It treats reported workflow states as claims, requires
inventory completeness and lineage analysis before declaring completion, and
keeps ambiguous identity, missing evidence, and uncertain flow candidates
unresolved rather than turning them into confirmed findings.

`code/remediation_planner.py` produces deterministic seven-field audit steps.
It emits only supported evidence-backed findings, sorts each phase by the
contract operation order and resource identifiers, and uses empty evidence
references for proposed remediation and future verification. A retained
backup is verified both as present and as unavailable to restore when restore
access is blocked.

Conditional policy rules do not define an alternative action when their
condition is false. The policy engine therefore leaves those cases unresolved
instead of inventing retention or deletion behavior. A required retained
record that is missing also cannot be safely reconstructed using the allowed
step operations, so planning reports that limitation rather than suggesting
unsupported remediation.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.

## Step 7: End-to-End Pipeline

`code/main.py` connects manifest-backed evidence ingestion, historical identity
resolution, as-of timeline reconstruction, lineage analysis, the 15 supplied
policy rules, remediation planning, and output contract validation. Requests
are processed in sorted `case_id` order. Structured JSON progress messages are
written to stderr; they include counts and case IDs, not request emails or
request text.

Run the full pipeline from the repository root after you intend to create the
submission output:

```powershell
python code/main.py
```

On success, the pipeline atomically writes the validated result to the
repository-root `output.csv`. To exercise the public sample without changing
either dataset output file:

```powershell
python code/main.py --requests dataset/sample_deletion_requests.csv --expected-cases 32 --output "$env:TEMP\ghost-sample-output.csv"
```

Use `--dataset`, `--requests`, `--expected-cases`, and `--output` to select
other fixtures or destinations. The pipeline refuses to overwrite
`dataset/output.csv` and `dataset/sample_output.csv`.

Evidence files are parsed locally; the pipeline makes no network or paid API
calls. PDF extraction requires `pdfplumber` or `PyPDF2`, and image validation
requires Pillow. OCR is optional. If OCR is unavailable or any manifest item
cannot be parsed, the evidence inventory is marked incomplete. Such cases
cannot be marked `COMPLETE` based on the remaining files. Per-file and
per-case failures are logged explicitly; valid rows are contract-checked, but
the output destination is left untouched if any case cannot be represented
safely.

Explicit `data_store` evidence is used as the system target when a record has
no more specific system field. Known inventory collection labels are mapped
to matching supplied policy categories; unrecognized labels and connector
configurations without explicit flow fields remain unresolved rather than
being guessed.
