# Contributing

Run the complete non-destructive test suite before submitting changes:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q isopropyl tests
desktop-file-validate data/io.github.codebooker.isopropyl.desktop
appstreamcli validate --no-net data/io.github.codebooker.isopropyl.metainfo.xml
```

Tests must never write to a real `/dev` node or Windows PhysicalDrive. Mock
privileged processes and use regular files or byte streams on every platform.
Native platform tests and the supported host matrix are in [CROSS_PLATFORM.md](CROSS_PLATFORM.md).

New destructive workflows need an immutable plan,
explicit whole-disk validation, target identity rechecks, exact confirmation,
cancellation, bounded diagnostics, and tests proving that preflight failures run
no unmount or write command.

Do not add downloaded executable code or boot payloads without documented
upstream provenance, license review, exact hashes, independent signature policy,
cache revalidation, and explicit user consent.
