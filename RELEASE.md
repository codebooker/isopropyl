# Preparing an ISOpropyl release

Releases support Linux x86-64 and ARM64 (Debian/Ubuntu packages), macOS13 or newer on Apple silicon, and Windows10 version1903 or newer on x86-64 and ARM64 (offline portable ZIPs).

1. Change `version` in `pyproject.toml` and `__version__` in `isopropyl/__init__.py` to the same stable `MAJOR.MINOR.PATCH` version. Keep the existing native PyQt6/Qt upper bound: Qt6.12 requires newer macOS than our macOS13 minimum.
2. Run the test workflow successfully for that commit on all five supported targets. Create and push the corresponding `vMAJOR.MINOR.PATCH` tag.
3. Run **prepare release** manually from Actions, entering that tag. With **Attach verified assets to a new draft GitHub release** disabled, this only uploads workflow artifacts. Enable it to create a draft release after every build and manifest check succeeds. The workflow never publishes a live release and does not overwrite an existing release.
4. Review the `complete-release` artifact, test offline installation/update on each target, and review the draft release assets. Publish the draft manually when ready. The in-app checker ignores drafts and prereleases; a repository without published releases reports no update.

Each release contains five primary versioned assets, a universal application wheel for existing dependency-compatible Linux virtual environments, and `isopropyl-update.json`. The schema1 manifest records exact asset names, target operating systems/architectures, kinds, byte sizes and SHA-256 hashes. Download URLs are derived from the official release tag and the GitHub API asset listing. Hashes provide consistency with the release metadata; trust remains in the official repository and release permissions.

Windows ZIPs include the pinned CPython3.13 embedded runtime, Qt, application and all Python dependencies. macOS update ZIPs contain `macos-update.json` and a complete offline `wheelhouse/` for Python3.12 and3.13, resolved for macOS13 ARM64. The managed updater builds a fresh versioned runtime from the existing durable base Python before switching the app pointer. It does not require PyPI during an update. Linux DEBs preserve package-manager ownership and declare their system dependencies; missing system packages may need installation through the OS package manager.

The workflow checks both version declarations against the tag, resolves native offline dependencies, validates matching wheel tags and requirements, and runs real native helper image tests without physical-drive writes. Build metadata and native helper provenance remain inside the artifacts. `tools/release_manifest.py --tag vVERSION --assets DIRECTORY` can regenerate the outer manifest from the five completed primary assets (plus the application wheel when present) without network access.

Linux wheel updates only support an existing managed virtual environment with already-compatible dependencies. They do not replace system package installations or install new dependencies; use the DEB or update that environment manually when requirements change.
