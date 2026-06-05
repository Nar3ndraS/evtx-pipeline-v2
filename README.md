# evtx-pipeline

A fast, single-pass Bash + jq pipeline that converts raw Windows Event Log JSON exports into clean, SIEM-ready NDJSON — with human-readable event descriptions and placeholder code resolution enriched from a multi-tier lookup system.

## What it does

Windows Event Log JSON exports are deeply nested and inconsistent — different Event IDs carry different fields, producing noisy output when flattened naively.

This pipeline:

1. **Flattens** all System-level fields into a single-level object
2. **Preserves** `EventData` as a nested JSON object (query it in ADX/KQL after ingestion)
3. **Enriches** every record with a human-readable `EventDescription` via a two-tier lookup:
   - **Master file** (first priority) — official Microsoft documentation + Sysmon IDs
   - **Fallback file** (second priority, optional) — generated from your environment via `generate_lookup.ps1`
4. **Resolves** `%%` placeholder codes inside `EventData` fields using `msobjs_lookup.json`
5. **Packs** low-value metadata fields into `AdditionalFields` to keep the schema clean
6. **Normalizes** field names — e.g. `TimeCreated_SystemTime` → `TimeGenerated`
7. **Drops** noise columns — e.g. `xmlns`
8. **Logs warnings** for records missing the `.Event` field
9. Outputs clean **NDJSON** ready for Sentinel, Splunk, Elastic, or any SIEM

---

## Project structure

```
evtx-pipeline/
├── evtx_pipeline.sh                              # Main pipeline script
├── master_security_auditing_index_micosoft.json  # Master EventID lookup (required)
├── msobjs_lookup.json                            # %% code lookup (required)
├── generate_lookup.ps1                           # Generates fallback EventID lookup
├── generate_msobjs_lookup.ps1                    # Generates msobjs_lookup.json
├── soc_event_lookup.json                         # Fallback EventID lookup (optional)
└── NOTES.md                                      # Project decisions and future work
```

> `master_security_auditing_index_micosoft.json` and `msobjs_lookup.json` must always be in the same directory as `evtx_pipeline.sh`. The script will error out if either is missing.

---

## Requirements

- [`evtx_dump`](https://github.com/omerbenamram/evtx) — to convert raw `.evtx` files to JSON
- `bash` >= 4
- `jq` >= 1.6

---

## Workflow

### Step 0 — Generate lookup files (once)

#### msobjs lookup (required)

Run `generate_msobjs_lookup.ps1` on a **Windows DC or Server** to extract `%%` code descriptions from `msobjs.dll`:

```powershell
.\generate_msobjs_lookup.ps1
```

Produces `msobjs_lookup.json` — copy to the same directory as `evtx_pipeline.sh`.

#### Fallback EventID lookup (optional)

Run `generate_lookup.ps1` on a **Windows DC** for the widest provider coverage:

```powershell
.\generate_lookup.ps1
```

Produces `soc_event_lookup.json` — copy to the same directory as `evtx_pipeline.sh`.

> The fallback lookup is optional. The pipeline works with the master file alone for EventDescription. The fallback fills in EventIDs not covered by the master.

---

### Step 1 — Convert raw `.evtx` to JSON

#### Single file

```bash
evtx_dump -o jsonl -t 1 /path/to/Security.evtx > Security.json
```

#### Multiple files (combine into one)

Use `find` with `evtx_dump` to merge multiple `.evtx` files matching a pattern into a single JSON file:

```bash
find . -name '*Sysmon*.evtx' -exec evtx_dump -o jsonl -t 2 {} \; > SysmonLogs.json
```

| Flag | Meaning |
|---|---|
| `-o jsonl` | Output format: JSONL (one JSON object per line) |
| `-t 1` | Use 1 thread (keeps output order stable) |
| `-t 2` | Use 2 threads (faster for multiple files, minor ordering trade-off) |

---

### Step 2 — Run the pipeline

```bash
chmod +x evtx_pipeline.sh

# Master + msobjs only
./evtx_pipeline.sh Security.json out.ndjson

# Master + msobjs + fallback lookup
./evtx_pipeline.sh Security.json out.ndjson --lookup soc_event_lookup.json

# With custom warnings path
./evtx_pipeline.sh Security.json out.ndjson --lookup soc_event_lookup.json --warnings w.log
```

---

### Step 3 — Ingest into your SIEM

The output `out.ndjson` is one JSON object per line — ready to ingest into Sentinel, Splunk, Elastic, or any NDJSON pipeline.

> ⚠️ **ADX / Azure Data Explorer ingestion warning**
>
> When ingesting into ADX using the **Get data** wizard, you will see a **Nested levels** spinner on the Inspect step.
> **Always keep Nested levels set to 1.**
>
> Increasing it will cause ADX to automatically expand `EventData` into separate flat columns, breaking the schema and making KQL queries against `EventData` impossible.
> At level 1, `EventData` is correctly stored as a single dynamic JSON column and can be queried using `todynamic()`.

---

## Options

| Flag | Default | Description |
|---|---|---|
| *(none)* | — | Master and msobjs lookups always loaded automatically from script directory |
| `--lookup <file>` | *(not set)* | Optional fallback EventID lookup for EventIDs not in master |
| `--warnings <file>` | `warnings.log` | Path to write skipped-record warnings |

---

## EventDescription resolution

For each event, the pipeline builds a lookup key: `Provider_Name + "_" + EventID`

Resolution order:
1. **Master file** — `master_security_auditing_index_micosoft.json` (official Microsoft + Sysmon)
2. **Fallback file** — `soc_event_lookup.json` via `--lookup` (environment-generated)
3. **`null`** — if not found in either

---

## %% code resolution

Windows Security logs contain `%%` placeholder codes in fields like `AccessList`, `AccessReason`, `UserAccountControl`, and `GroupMembership`. These are normally resolved by the Windows Event Viewer message DLL at display time.

The pipeline resolves them using `msobjs_lookup.json` with **Option B** — the original code is kept and the description is appended in parentheses:

```
"%%1538\r\n\t\t%%1541"
→
"%%1538 (READ_CONTROL)\r\n\t\t%%1541 (SYNCHRONIZE)"
```

This preserves the original code for reference while making the value human-readable. The `\r\n\t` delimiters are left intact for KQL parsing at query time.

---

## Output format

```json
{
  "TimeGenerated": "2026-05-25T20:43:10.511558Z",
  "EventID": 5145,
  "EventDescription": "A network share object was checked to see whether client can be granted desired access.",
  "Computer": "DC1.blues.lab",
  "Provider_Name": "Microsoft-Windows-Security-Auditing",
  "Channel": "Security",
  "AdditionalFields": {
    "Provider_Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
    "Version": 0,
    "Level": 0,
    "Task": 12811,
    "Opcode": 0,
    "Keywords": "0x8020000000000000",
    "EventRecordID": 655588,
    "Execution_ProcessID": 4,
    "Execution_ThreadID": 52
  },
  "EventData": {
    "SubjectUserName": "Administrator",
    "AccessList": "%%1538 (READ_CONTROL)\r\n\t\t\t\t%%1541 (SYNCHRONIZE)",
    "AccessReason": "%%1538 (READ_CONTROL):\t%%1801 (Granted by)\r\n\t\t\t\t%%1541 (SYNCHRONIZE):\t%%1801 (Granted by)",
    "ShareName": "\\\\*\\Tools"
  }
}
```

**Field order:** `TimeGenerated → EventID → EventDescription → Computer → remaining flat fields → AdditionalFields → EventData`

| Field | Notes |
|---|---|
| `TimeGenerated` | Renamed from `TimeCreated_SystemTime` — Sentinel/ADX compatible |
| `EventDescription` | Human-readable description, `null` if not found in either lookup |
| `AdditionalFields` | Low-value metadata — `null` if all packed fields are absent |
| `EventData` | Nested object, always last — query with `todynamic()` in KQL |

### Fields packed into AdditionalFields

| Field | Reason |
|---|---|
| `Provider_Guid` | Redundant — `Provider_Name` is sufficient |
| `Version` | Event schema version, rarely queried |
| `Level` | Numeric severity code, rarely queried directly |
| `Task` | Numeric subcategory code |
| `Opcode` | Numeric operation code |
| `Keywords` | Audit success/failure bitmask |
| `EventRecordID` | Record sequence number |
| `Execution_ProcessID` | Process that logged the event |
| `Execution_ThreadID` | Thread that logged the event |

---

## Key naming

| Raw nested path | Output key |
|---|---|
| `System.EventID` | `EventID` |
| `System.Channel` | `Channel` |
| `System.Computer` | `Computer` |
| `System.TimeCreated.#attributes.SystemTime` | `TimeGenerated` |
| `System.Provider.#attributes.Name` | `Provider_Name` |
| `System.Correlation.#attributes.ActivityID` | `Correlation_ActivityID` |
| `System.Execution.#attributes.ProcessID` | `Execution_ProcessID` (→ AdditionalFields) |
| `EventData.*` | `EventData.*` (nested) |

---

## Querying in KQL (Sentinel / ADX)

### EventData fields

```kql
MyTable_CL
| extend ED = todynamic(EventData)
| where ED.LogonType == "3"
| project TimeGenerated, Computer, EventDescription, ED.TargetUserName, ED.LogonType
```

### AdditionalFields

```kql
MyTable_CL
| extend AF = todynamic(AdditionalFields)
| where AF.Level == 0
| project TimeGenerated, Computer, EventDescription, AF.Keywords
```

### Splitting %% delimited fields

```kql
// AccessList — tab+newline delimited
| extend AccessRights = split(tostring(todynamic(EventData).AccessList), "\r\n\t\t\t\t")

// GroupMembership — newline+tab delimited
| extend Groups = split(tostring(todynamic(EventData).GroupMembership), "\r\n\t\t")
```

---

## Pipeline internals

```
Security.evtx  (raw Windows Event Log)
        │
        │  evtx_dump -o jsonl -t 1 Security.evtx > Security.json
        ▼
Security.json  (NDJSON — one event per line)
        │
        ▼
┌──────────────────────────────────────────────┐
│  STAGE 1: Flatten                            │  Single jq pass via [inputs]
│                                              │  System fields → flat top-level
│                                              │  EventData → preserved as nested object
│                                              │  Tags bad records as { "__warn": N }
└──────────────────────────────────────────────┘
        │
        ├──── warnings filtered → warnings.log
        │
        ▼
┌──────────────────────────────────────────────┐
│  STAGE 2: Enrich + Normalize                 │  Single jq pass
│                                              │  Master lookup (first priority)
│                                              │  Fallback lookup (second priority)
│                                              │  %% replacement via msobjs_lookup.json
│                                              │  Pack metadata → AdditionalFields
│                                              │  Rename TimeCreated_SystemTime → TimeGenerated
│                                              │  Drop xmlns
└──────────────────────────────────────────────┘
        │
        ▼
   out.ndjson
```

---

## Warnings

Records missing a top-level `.Event` field are skipped and logged:

```
[WARN] Line 4821 is missing .Event field — skipped.
```

---

## Limitations

- True key collisions (same base name under two different `.Event` sections) — last write wins. Does not occur in standard Windows Security logs.
- Stage 2 loads all records into memory via `[inputs]`. For very large files (millions of records), consider splitting first.
- `EventDescription` coverage depends on the master file and which providers were included in `generate_lookup.ps1`.
- `%%` code coverage depends on the Windows version and patch level of the machine where `generate_msobjs_lookup.ps1` was run.

## Reference
https://claude.ai/chat/2e87535e-e946-465a-bec9-e2eaa87624b9

---

## License

MIT
