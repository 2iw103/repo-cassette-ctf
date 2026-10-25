# Repo Cassette transport diagnostics

This is a disposable repository for testing GitHub response transports used by
the authorized Repo Cassette CTF analysis. The workflow is manual-only. It does
not contact the challenge, and it stores no challenge token, account
credential, signed storage URL, or flag.

The required response must preserve an exact attacker-chosen JSON body and
return `Content-Type: application/json` followed by raw byte `85`. GitHub's
live behavior on 2026-10-25 blocks every tested construction:

| Transport | Exact body | Public REST Content-Type / result |
| --- | --- | --- |
| Artifact v7 with normal JSON MIME | yes | `application/json` |
| Artifact v7 with NEL, C0 separators, empty/omitted MIME, or percent forms | n/a | `CreateArtifact` rejects the MIME |
| Artifact v4-v6 with NEL or omitted MIME | no raw mode | `application/zip` |
| Artifact v8 | n/a | rejected; maximum version is 7 |
| Current job-log blob with normal or NEL blob metadata | yes | forced to `text/plain` |
| Synthetic step-log blob | uploaded and registered | public step-log endpoint returned 404 |

The decisive job-log check is run `40172308403`, job `121105553577`, commit
`6e9c39d26a001dfea4765b21d19b3f31dc71d727`. Both variants returned the exact
1024-byte body with SHA-256
`eb9ba03b297329d8aeb8cfe48ded6f5753e148723a01ac29f0733819a51aa2dc`, but both
returned `text/plain` (`746578742f706c61696e`). The MIME validation matrix is
in run `40171628612` (job `121103486695`), and the percent-encoding matrix is
in run `40171869462` (job `121104207199`).

Git history retains the MIME matrices. `artifact-action/index.js` retains the
dependency-free job-log probe and original raw artifact prototype for review.
The checked-in workflow runs only the conclusive job-log control/NEL comparison
when explicitly dispatched. It rewrites its own disposable job log, so it
should not be copied to a production repository.
