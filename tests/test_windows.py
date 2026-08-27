# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path

from isopropyl.wim import WimEdition, WimSelection
from isopropyl.windows import (
    UNATTEND_NS, WCM_NS, WindowsCustomization, add_autounattend_to_staging,
    answer_file_install_index, generate_autounattend,
    validate_input_locale, validate_language_tag, validate_timezone,
    validate_username, windows_architecture,
)

NS = {"u": UNATTEND_NS}


def install_selection(architecture: str = "amd64") -> WimSelection:
    edition = WimEdition(
        index=6, name="Windows 11 Pro", description="Professional desktop",
        edition_id="Professional", architecture=architecture,
        major_version=10, minor_version=0, build=26100, service_pack_build=2454,
    )
    return WimSelection("sources/install.wim", 1234, (edition,), 6)


class WindowsCustomizationTests(unittest.TestCase):
    def test_answer_file_is_added_without_overwriting_existing_media_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xml = generate_autounattend(WindowsCustomization(hide_online_account=True))
            target = add_autounattend_to_staging(root, xml)
            self.assertEqual(target.name, "autounattend.xml")
            self.assertEqual(ET.fromstring(target.read_text()).tag, f"{{{UNATTEND_NS}}}unattend")
            with self.assertRaisesRegex(ValueError, "will not overwrite"):
                add_autounattend_to_staging(root, xml)

    def test_answer_file_commit_rejects_non_unattend_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "unexpected root"):
                add_autounattend_to_staging(root, "<not-unattend/>")
            self.assertFalse((root / "autounattend.xml").exists())

    def test_generates_a_parseable_profile_with_requested_options(self):
        xml = generate_autounattend(WindowsCustomization(
            bypass_hardware_requirements=True,
            hide_online_account=True,
            local_username="Jack",
            reduce_data_collection=True,
            disable_automatic_bitlocker=True,
        ))
        root = ET.fromstring(xml)
        self.assertIn("BypassTPMCheck", xml)
        self.assertIsNotNone(root.find(".//u:HideOnlineAccountScreens", NS))
        self.assertIsNotNone(root.find(".//u:HideWirelessSetupInOOBE", NS))
        self.assertEqual(root.findtext(".//u:ProtectYourPC", namespaces=NS), "3")
        self.assertIsNotNone(root.find(".//u:HideOEMRegistrationScreen", NS))
        self.assertEqual(root.findtext(".//u:PreventDeviceEncryption", namespaces=NS), "true")
        self.assertEqual(root.findtext(".//u:TCGSecurityActivationDisabled", namespaces=NS), "1")
        self.assertEqual(root.findtext(".//u:Name", namespaces=NS), "Jack")

    def test_emits_one_settings_element_per_pass(self):
        root = ET.fromstring(generate_autounattend(WindowsCustomization(
            bypass_hardware_requirements=True,
            input_locale="0409:00000409",
            user_locale="en-US",
            reduce_data_collection=True,
            disable_automatic_bitlocker=True,
        )))
        passes = [element.attrib["pass"] for element in root.findall("u:settings", NS)]
        self.assertEqual(passes.count("windowsPE"), 1)
        self.assertEqual(passes.count("oobeSystem"), 1)
        self.assertEqual(len(passes), len(set(passes)))

    def test_selected_image_index_is_explicit_and_does_not_select_a_disk(self):
        options = WindowsCustomization(
            bypass_hardware_requirements=True,
            install_image=install_selection(),
        )
        self.assertTrue(options.enabled)
        xml = generate_autounattend(options, "amd64")
        root = ET.fromstring(xml)
        self.assertEqual(answer_file_install_index(xml), 6)
        self.assertEqual(
            root.findtext(".//u:InstallFrom/u:MetaData/u:Key", namespaces=NS),
            "/IMAGE/INDEX",
        )
        self.assertEqual(
            root.findtext(".//u:InstallFrom/u:MetaData/u:Value", namespaces=NS),
            "6",
        )
        setup_components = [
            item for item in root.findall(".//u:component", NS)
            if item.attrib.get("name") == "Microsoft-Windows-Setup"
        ]
        self.assertEqual(len(setup_components), 1)
        self.assertIsNone(root.find(".//u:InstallTo", NS))
        self.assertIsNone(root.find(".//u:WillWipeDisk", NS))

    def test_selected_image_architecture_and_answer_index_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            generate_autounattend(
                WindowsCustomization(install_image=install_selection("arm64")),
                "amd64",
            )
        xml = generate_autounattend(
            WindowsCustomization(install_image=install_selection()), "amd64",
        )
        duplicate = xml.replace(
            "</InstallFrom>",
            '<MetaData xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" '
            'wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>2</Value></MetaData>'
            "</InstallFrom>",
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            answer_file_install_index(duplicate)
        with self.assertRaisesRegex(ValueError, "uppercase"):
            answer_file_install_index(xml.replace("/IMAGE/INDEX", "/image/index"))
        with self.assertRaisesRegex(ValueError, "wcm:action"):
            answer_file_install_index(
                xml.replace(' wcm:action="add"', "", 1)
            )
        with self.assertRaisesRegex(ValueError, "misplaced"):
            answer_file_install_index(
                xml.replace("<InstallFrom>", "</OSImage><InstallFrom>", 1)
                .replace("</InstallFrom>", "</InstallFrom><OSImage>", 1)
            )
        with self.assertRaisesRegex(ValueError, "windowsPE"):
            answer_file_install_index(
                xml.replace('pass="windowsPE"', 'pass="offlineServicing"', 1)
            )
        with self.assertRaisesRegex(ValueError, "Microsoft-Windows-Setup"):
            answer_file_install_index(
                xml.replace("Microsoft-Windows-Setup", "Microsoft-Windows-Forged", 1)
            )
        with self.assertRaisesRegex(ValueError, "architecture"):
            answer_file_install_index(
                xml.replace(
                    'processorArchitecture="amd64"',
                    'processorArchitecture="arm64"',
                    1,
                ),
                "amd64",
            )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            answer_file_install_index(
                xml.replace(
                    "<Value>6</Value>",
                    "<Value>6</Value><Value>6</Value>",
                    1,
                )
            )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            answer_file_install_index(
                xml.replace(
                    "<Key>/IMAGE/INDEX</Key>",
                    "<Key>/IMAGE/INDEX</Key><Key>/IMAGE/INDEX</Key>",
                    1,
                )
            )

    def test_applies_regional_settings_to_setup_and_oobe(self):
        root = ET.fromstring(generate_autounattend(WindowsCustomization(
            input_locale="0409:00000409;fr-FR",
            system_locale="en-US",
            ui_language="en-US",
            user_locale="en-CA",
            timezone="Eastern Standard Time",
        )))
        components = {
            component.attrib["name"]: component
            for component in root.findall(".//u:component", NS)
        }
        for name in (
            "Microsoft-Windows-International-Core-WinPE",
            "Microsoft-Windows-International-Core",
        ):
            self.assertEqual(
                components[name].findtext("u:InputLocale", namespaces=NS),
                "0409:00000409;fr-FR",
            )
            self.assertEqual(
                components[name].findtext("u:UserLocale", namespaces=NS), "en-CA",
            )
        self.assertEqual(root.findtext(".//u:TimeZone", namespaces=NS), "Eastern Standard Time")

    def test_local_account_uses_hidden_blank_and_scoped_account_policy(self):
        root = ET.fromstring(generate_autounattend(WindowsCustomization(
            local_username="O'Brien & Co",
        )))
        self.assertEqual(
            root.findtext(".//u:Password/u:Value", namespaces=NS),
            "UABhAHMAcwB3AG8AcgBkAA==",
        )
        self.assertEqual(root.findtext(".//u:Password/u:PlainText", namespaces=NS), "false")
        commands = root.findall(".//u:FirstLogonCommands/u:SynchronousCommand", NS)
        self.assertEqual(len(commands), 1)
        self.assertEqual(
            [command.attrib[f"{{{WCM_NS}}}action"] for command in commands],
            ["add"],
        )
        command_lines = [
            command.findtext("u:CommandLine", namespaces=NS) for command in commands
        ]
        self.assertIn("O''Brien & Co,user", command_lines[0])
        self.assertIn("PasswordExpired", command_lines[0])
        self.assertIn("PasswordNeverExpires", command_lines[0])
        self.assertNotIn("net accounts", " ".join(command_lines))

    def test_local_account_mandates_password_change_policy(self):
        with self.assertRaisesRegex(ValueError, "mandatory"):
            generate_autounattend(WindowsCustomization(
                local_username="Jack",
                require_local_password_change=False,
                local_password_never_expires=False,
            ))
        root = ET.fromstring(generate_autounattend(WindowsCustomization(
            local_username="Jack",
            require_local_password_change=True,
            local_password_never_expires=False,
        )))
        commands = root.findall(".//u:FirstLogonCommands/u:SynchronousCommand", NS)
        self.assertEqual(len(commands), 1)
        self.assertIn(
            "PasswordExpired", commands[0].findtext("u:CommandLine", namespaces=NS),
        )

    def test_all_serialized_elements_use_the_unattend_namespace(self):
        root = ET.fromstring(generate_autounattend(WindowsCustomization(
            input_locale="en-US", local_username="Jack", reduce_data_collection=True,
        )))
        for element in root.iter():
            self.assertTrue(element.tag.startswith(f"{{{UNATTEND_NS}}}"), element.tag)

    def test_empty_profile_is_not_enabled_and_has_no_settings(self):
        options = WindowsCustomization()
        self.assertFalse(options.enabled)
        root = ET.fromstring(generate_autounattend(options))
        self.assertEqual(root.tag, f"{{{UNATTEND_NS}}}unattend")
        self.assertEqual(root.findall("u:settings", NS), [])

    def test_regional_fields_enable_profile(self):
        self.assertTrue(WindowsCustomization(user_locale="en-US").enabled)
        self.assertTrue(WindowsCustomization(timezone="UTC").enabled)

    def test_rejects_reserved_or_invalid_usernames(self):
        for username in (
            "Administrator", "SYSTEM", "bad/name", 'bad"name', "trailing.",
            "bad\x00name", "x" * 21,
        ):
            with self.subTest(username=username), self.assertRaises(ValueError):
                validate_username(username)

    def test_validates_and_normalizes_regional_fields(self):
        self.assertEqual(validate_input_locale(" en-US ; 0409:00000409 "), "en-US;0409:00000409")
        self.assertEqual(validate_language_tag(" sr-Latn-RS "), "sr-Latn-RS")
        self.assertEqual(validate_timezone(" Eastern Standard Time "), "Eastern Standard Time")
        for invalid in ("en_US", "en-US;<bad>", "en-US;;fr-FR"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                if ";" in invalid:
                    validate_input_locale(invalid)
                else:
                    validate_language_tag(invalid)
        with self.assertRaises(ValueError):
            validate_timezone("bad\ntimezone")

    def test_rejects_unsupported_answer_file_architecture(self):
        with self.assertRaises(ValueError):
            generate_autounattend(WindowsCustomization(user_locale="en-US"), "riscv64")

    def test_maps_detected_architecture(self):
        self.assertEqual(windows_architecture(("ARM64",)), "arm64")
        self.assertEqual(windows_architecture(("x64",)), "amd64")


if __name__ == "__main__":
    unittest.main()
