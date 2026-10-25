# Repo Cassette artifact fixture

This disposable repository runs a dependency-free JavaScript action that
creates and verifies the raw GitHub Actions artifact required by the authorized
Repo Cassette CTF challenge.

The workflow starts on a push to `main`. Its log prints the artifact ID,
repository path, payload hash, and a `live_check` value. No challenge token,
account credential, or flag is stored in this repository.
