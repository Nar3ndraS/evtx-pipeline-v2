# Project Notes

Running list of decisions, findings, and future improvements.

---

## Pending Implementations

### 1. Additional Lookup Tables
The following lookup tables are planned for future implementation.
All follow the same pattern as `msobjs_lookup.json` — auto-detected from script directory.

#### Logon Types
Numeric `LogonType` field in Events 4624, 4625, 4648 etc.
| Value | Description |
|-------|-------------|
| 2 | Interactive |
| 3 | Network |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials |
| 10 | RemoteInteractive |
| 11 | CachedInteractive |

#### Kerberos Error Codes
`Status` field in Event 4771 (Kerberos pre-auth failure).
Common codes: `0x6` (bad username), `0x12` (account disabled), `0x17` (password expired), `0x18` (bad password).
Full list: https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9

#### Kerberos Ticket Options
Bitmask flags in `TicketOptions` field in Events 4768, 4769, 4770.
Requires bitwise decoding — not a simple key-value lookup.

#### LSASS / SAM Object Access Types
`ObjectType` field in Event 4661.
Values like `SAM_USER`, `SAM_DOMAIN`, `SAM_GROUP` etc.

#### Logon Failure Status / SubStatus Codes
`Status` and `SubStatus` fields in Event 4625.
Common codes: `0xC000006A` (wrong password), `0xC0000064` (no such user), `0xC0000234` (account locked).

---

### 2. AdditionalFields — Schema Review Needed

Currently packing these fields into `AdditionalFields` in the pipeline (Security logs confirmed):

```json
"Provider_Guid", "Version", "Level", "Task", "Opcode",
"Keywords", "EventRecordID", "Execution_ProcessID", "Execution_ThreadID"
```

**TODO:** Review System/Application log schemas to check if they have additional
fields beyond these that also belong in `AdditionalFields`. Only Security logs
have been reviewed so far.

Fields confirmed to stay flat (top-level):
- `TimeGenerated`, `EventID`, `EventDescription`, `Computer`
- `Channel`, `Provider_Name`

Fields to investigate for other log sources:
- `Correlation_ActivityID` — almost always null in Security logs, may be populated in System/Application
- `Correlation_RequestID` — same as above
- `Security` — almost always null, verify across log sources

---

### 3. `\r\n\t` Handling in EventData

Fields like `AccessList`, `AccessReason`, `GroupMembership`, `UserAccountControl`
contain `\r\n\t` delimited values and `%%` placeholder codes.

**Decision:** Do NOT strip in pipeline — handle in KQL at query time.
`%%` codes are resolved in-place via msobjs_lookup.json (Option B — code kept, description appended).
The `\r\n\t` delimiters are preserved as natural separators for KQL `split()`.

Example KQL to split `GroupMembership`:
```kql
| extend Groups = split(tostring(todynamic(EventData).GroupMembership), "\r\n\t\t")
```

Example KQL to split `AccessList`:
```kql
| extend AccessRights = split(tostring(todynamic(EventData).AccessList), "\r\n\t\t\t\t")
```

---

## Decisions Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-05 | Keep `EventData` as nested object | Query via `todynamic()` in ADX/KQL after ingestion |
| 2026-05 | ADX ingestion — keep Nested levels at 1 | Increasing it breaks EventData schema |
| 2026-05 | Drop `xmlns` field | XML namespace string, no analytical value |
| 2026-05 | Rename `TimeCreated_SystemTime` → `TimeGenerated` | Sentinel/ADX naming convention |
| 2026-05 | Master lookup required, not optional | Ensures descriptions always resolve from official Microsoft source |
| 2026-05 | `msobjs_lookup.json` required, not optional | Ensures `%%` codes always resolve |
| 2026-05 | Do not strip `\r\n\t` in pipeline | Preserves delimiter structure for KQL parsing |
| 2026-05 | `%%` replacement — Option B (keep code + append description) | Preserves original code for reference while adding human-readable description |
| 2026-05 | Pack metadata fields into `AdditionalFields` | Keeps top-level schema clean for SOC queries; low-value fields still accessible |
| 2026-05 | `AdditionalFields` → `null` if all packed fields absent | Avoids empty objects in schema |
| 2026-05 | Field order: TimeGenerated, EventID, EventDescription, Computer → rest → AdditionalFields → EventData | Priority fields visible first in ADX/Sentinel; EventData always last |
