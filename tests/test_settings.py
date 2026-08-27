from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from PyQt6.QtCore import QSettings

from isopropyl.settings import (
    PortableSettings, application_settings, parse_application_arguments,
    portable_settings_path, settings_sync_error, settings_sync_was_committed,
)


class ArgumentTests(unittest.TestCase):
    def test_parses_portable_and_one_image(self):
        parsed = parse_application_arguments([
            "isopropyl", "--portable", "linux.iso",
        ])
        self.assertTrue(parsed.portable)
        self.assertEqual(parsed.image, Path("linux.iso"))

    def test_double_dash_allows_a_dash_prefixed_image(self):
        parsed = parse_application_arguments(["isopropyl", "--", "--portable"])
        self.assertFalse(parsed.portable)
        self.assertEqual(parsed.image, Path("--portable"))

    def test_unknown_options_and_extra_images_fail(self):
        with self.assertRaisesRegex(ValueError, "Unknown option"):
            parse_application_arguments(["isopropyl", "--portabl"])
        with self.assertRaisesRegex(ValueError, "at most one"):
            parse_application_arguments(["isopropyl", "one.iso", "two.iso"])


class PortableSettingsTests(unittest.TestCase):
    def test_explicit_unchanged_launch_creates_reusable_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "isopropyl"
            launcher.write_bytes(b"launcher")
            marker = Path(directory) / "isopropyl.ini"
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            self.assertIsInstance(settings, PortableSettings)
            self.assertTrue(marker.is_file())
            settings.close()

            reopened = application_settings(
                [str(launcher)], environment={}, executable=str(launcher),
            )
            self.assertIsInstance(reopened, PortableSettings)
            reopened.close()

    def test_values_round_trip_through_bound_store(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            settings.setValue("appearance", "light")
            self.assertEqual(settings_sync_error(settings), "")
            settings.close()
            reopened = application_settings(
                [str(launcher)], environment={}, executable=str(launcher),
            )
            self.assertEqual(reopened.value("appearance"), "light")
            reopened.close()

    def test_default_mode_has_no_adjacent_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "isopropyl"
            launcher.write_bytes(b"launcher")
            self.assertIsNone(portable_settings_path(
                [str(launcher)], environment={}, executable=str(launcher),
            ))
            self.assertFalse((Path(directory) / "isopropyl.ini").exists())

    def test_appimage_config_convention_creates_marker_without_switch(self):
        with tempfile.TemporaryDirectory() as directory:
            appimage = Path(directory) / "ISOpropyl.AppImage"
            appimage.write_bytes(b"appimage")
            config = Path(f"{appimage}.config")
            config.mkdir()
            settings = application_settings(
                ["internal-isopropyl"],
                environment={"APPIMAGE": str(appimage)},
                executable="/tmp/.mount/isopropyl",
            )
            self.assertIsInstance(settings, PortableSettings)
            self.assertTrue((config / "isopropyl.ini").is_file())
            settings.close()

    def test_invocation_symlink_uses_the_invoked_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_dir = root / "installed"
            media_dir = root / "portable"
            target_dir.mkdir()
            media_dir.mkdir()
            target = target_dir / "isopropyl"
            target.write_bytes(b"launcher")
            launcher = media_dir / "isopropyl"
            launcher.symlink_to(target)
            self.assertEqual(
                portable_settings_path(
                    [str(launcher), "--portable"],
                    environment={}, executable=str(launcher),
                ),
                media_dir / "isopropyl.ini",
            )

    def test_existing_link_and_hardlink_markers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            target = root / "target.ini"
            target.write_text("[General]\n", encoding="utf-8")
            marker = root / "isopropyl.ini"
            marker.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                application_settings(
                    [str(launcher)], environment={}, executable=str(launcher),
                )
            marker.unlink()
            os.link(target, marker)
            with self.assertRaisesRegex(ValueError, "singly linked"):
                application_settings(
                    [str(launcher)], environment={}, executable=str(launcher),
                )

    def test_swapping_path_for_symlink_cannot_redirect_save(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            marker = root / "isopropyl.ini"
            displaced = root / "original.ini"
            marker.rename(displaced)
            victim = root / "victim"
            victim.write_text("do not overwrite", encoding="utf-8")
            marker.symlink_to(victim)
            settings.setValue("appearance", "light")
            error = settings_sync_error(settings)
            self.assertIn("link", error)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not overwrite")
            settings.close()

    def test_write_and_data_fsync_failures_preserve_live_bytes_and_clean_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            settings.setValue("appearance", "dark")
            self.assertEqual(settings_sync_error(settings), "")
            marker = root / "isopropyl.ini"
            original = marker.read_bytes()

            settings.setValue("appearance", "light")
            with patch("isopropyl.settings.os.write", side_effect=OSError("disk full")):
                self.assertIn("disk full", settings_sync_error(settings))
            self.assertEqual(marker.read_bytes(), original)
            self.assertEqual(list(root.glob(".isopropyl.ini.tmp-*")), [])

            with patch("isopropyl.settings.os.fsync", side_effect=OSError("fsync failed")):
                self.assertIn("fsync failed", settings_sync_error(settings))
            self.assertEqual(marker.read_bytes(), original)
            self.assertEqual(list(root.glob(".isopropyl.ini.tmp-*")), [])
            settings.close()

    def test_directory_fsync_failure_reports_committed_and_keeps_store_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            settings.setValue("appearance", "dark")
            self.assertEqual(settings_sync_error(settings), "")
            settings.setValue("appearance", "light")
            real_fsync = os.fsync

            def fail_directory_fsync(descriptor):
                if descriptor == settings._directory_fd:
                    raise OSError("directory fsync failed")
                return real_fsync(descriptor)

            with patch(
                "isopropyl.settings.os.fsync", side_effect=fail_directory_fsync,
            ):
                error = settings_sync_error(settings)

            self.assertIn("was committed", error)
            self.assertIn("might not survive", error)
            self.assertTrue(settings_sync_was_committed(settings))
            self.assertIn(
                "appearance=light",
                (root / "isopropyl.ini").read_text(encoding="utf-8"),
            )
            self.assertEqual(list(root.glob(".isopropyl.ini.tmp-*")), [])

            # The store must be rebound to the published inode even though the
            # post-commit durability check failed.
            settings.setValue("appearance", "dark")
            self.assertEqual(settings_sync_error(settings), "")
            self.assertFalse(settings_sync_was_committed(settings))
            self.assertIn(
                "appearance=dark",
                (root / "isopropyl.ini").read_text(encoding="utf-8"),
            )
            settings.close()

    def test_short_writes_are_completed_before_atomic_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            real_write = os.write

            def short_write(descriptor, value):
                return real_write(descriptor, value[:3])

            settings.setValue("appearance", "light")
            with patch("isopropyl.settings.os.write", side_effect=short_write):
                self.assertEqual(settings_sync_error(settings), "")
            settings.close()
            reopened = application_settings(
                [str(launcher)], environment={}, executable=str(launcher),
            )
            self.assertEqual(reopened.value("appearance"), "light")
            reopened.close()

    def test_second_portable_writer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            first = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            try:
                with self.assertRaisesRegex(ValueError, "already in use"):
                    application_settings(
                        [str(launcher)], environment={}, executable=str(launcher),
                    )
            finally:
                first.close()

    def test_directory_lock_cannot_be_bypassed_at_publish_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            settings.setValue("appearance", "dark")
            self.assertEqual(settings_sync_error(settings), "")
            marker = root / "isopropyl.ini"
            settings.setValue("appearance", "light")
            real_replace = os.replace
            probes = []

            def probe_then_replace(*args, **kwargs):
                with self.assertRaisesRegex(ValueError, "already in use"):
                    application_settings(
                        [str(launcher)], environment={}, executable=str(launcher),
                    )
                probes.append(True)
                return real_replace(*args, **kwargs)

            with patch(
                "isopropyl.settings.os.replace", side_effect=probe_then_replace,
            ):
                error = settings_sync_error(settings)

            self.assertEqual(error, "")
            self.assertEqual(probes, [True])
            self.assertFalse(settings_sync_was_committed(settings))
            self.assertIn("appearance=light", marker.read_text(encoding="utf-8"))
            settings.close()

    def test_temp_close_failure_cannot_escape_precommit_save_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            settings = application_settings(
                [str(launcher), "--portable"],
                environment={}, executable=str(launcher),
            )
            marker = root / "isopropyl.ini"
            original = marker.read_bytes()
            settings.setValue("appearance", "light")
            real_close = os.close

            def close_then_fail(descriptor):
                real_close(descriptor)
                if descriptor not in (settings._file_fd, settings._directory_fd):
                    raise OSError("temporary close failed")

            with (
                patch(
                    "isopropyl.settings.os.replace",
                    side_effect=OSError("publish failed"),
                ),
                patch("isopropyl.settings.os.close", side_effect=close_then_fail),
            ):
                error = settings_sync_error(settings)

            self.assertIn("publish failed", error)
            self.assertFalse(settings_sync_was_committed(settings))
            self.assertEqual(marker.read_bytes(), original)
            self.assertEqual(list(root.glob(".isopropyl.ini.tmp-*")), [])
            settings.close()

    def test_creation_and_existing_write_errors_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "isopropyl"
            launcher.write_bytes(b"launcher")
            real_open = os.open

            def refuse_create(path, flags, mode=0o777, *, dir_fd=None):
                if (
                    isinstance(path, str)
                    and path.startswith(".isopropyl.ini.tmp-")
                    and flags & os.O_CREAT
                ):
                    raise PermissionError("read-only portable directory")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch("isopropyl.settings.os.open", side_effect=refuse_create):
                with self.assertRaisesRegex(ValueError, "read-only"):
                    application_settings(
                        [str(launcher), "--portable"],
                        environment={}, executable=str(launcher),
                    )

            marker = root / "isopropyl.ini"
            marker.write_text("[General]\n", encoding="utf-8")

            def refuse_existing(path, flags, mode=0o777, *, dir_fd=None):
                if path == "isopropyl.ini" and not flags & os.O_CREAT:
                    raise PermissionError("existing marker is not writable")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch("isopropyl.settings.os.open", side_effect=refuse_existing):
                with self.assertRaisesRegex(ValueError, "not writable"):
                    application_settings(
                        [str(launcher)], environment={}, executable=str(launcher),
                    )

    def test_appimage_path_must_be_absolute(self):
        with self.assertRaisesRegex(ValueError, "APPIMAGE"):
            portable_settings_path(
                ["isopropyl", "--portable"],
                environment={"APPIMAGE": "ISOpropyl.AppImage"},
                executable="isopropyl",
            )

    def test_settings_sync_error_reports_qsettings_failure(self):
        settings = Mock()
        settings.status.return_value = QSettings.Status.AccessError
        self.assertIn("could not save", settings_sync_error(settings))
        settings.sync.assert_called_once_with()
        self.assertFalse(settings_sync_was_committed(settings))
