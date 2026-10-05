# Security findings

| Id | Severity | Status | Notes |
| --- | --- | --- | --- |
| `symlink_windows_detection_limit` | MEDIUM | Waived (SYM-WIN) | On Windows without Developer Mode / `SeCreateSymbolicLinkPrivilege`, CI cannot reliably create symlink escape fixtures. Product mitigation: `ConfigPathResolver` rejects reparse points and final paths outside `Sav:ConfigRoot` via `GetFinalPathNameByHandle` when the path exists. Non-symlink `..` / absolute escapes remain hard-fail tested. |
