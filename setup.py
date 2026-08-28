from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Small build hook that prevents retired package data leaking from build/.

Setuptools incrementally refreshes ``build/lib`` and otherwise leaves removed
package-data files behind.  A wheel must be assembled from the current source
package, not that stale merged tree.
"""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class CleanPackageBuild(_build_py):
    def run(self) -> None:
        package_output = Path(self.build_lib) / "isopropyl"
        if package_output.exists():
            shutil.rmtree(package_output)
        super().run()


setup(cmdclass={"build_py": CleanPackageBuild})
