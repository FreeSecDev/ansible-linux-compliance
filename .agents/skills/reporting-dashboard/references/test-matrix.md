# Required test matrix

| Area | Cases |
|---|---|
| Formats | A valid fixture for every format in the formats reference |
| Missing and corrupt | Absent file, empty file, truncated file, wrong encoding, wrong format version |
| Unexpected XML | Unknown root element, DTD, entity expansion, external entity, deep nesting |
| Large sets | Size limit rejection and a large valid set within time and memory bounds |
| Summary math | Counts, denominators, scope labels, empty sets, no averages across scopes |
| Waivers | Active, expired, not yet valid, wrong scope; waived never counted as pass |
| Severity | Aggregation, unknown severity, ordering |
| Deduplication | Same rule across standards keeps all identifiers; different benchmark versions stay separate |
| Sanitization | Rule text containing markup, `</script>`, quotes, `&`; output contains no executable injection and no innerHTML of report data |
| Accessibility | Tab roles and keyboard navigation, contrast tokens for both themes, labels, focus visibility |
| Offline | No external URLs, no network access attempted, CSP meta present |
| Determinism | Byte-identical output for identical inputs, stable ordering, no generated timestamps |
| Raw artifacts | Originals preserved with matching checksums |
