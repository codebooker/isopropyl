# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import os
import re
import stat
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .wim import WimSelection, WimValidationError, validate_wim_selection
from .windows_paths import validate_install_image_member_path

UNATTEND_NS = "urn:schemas-microsoft-com:unattend"
WCM_NS = "http://schemas.microsoft.com/WMIConfig/2002/State"
ET.register_namespace("", UNATTEND_NS)
ET.register_namespace("wcm", WCM_NS)

# Microsoft documents these characters as invalid for LocalAccount/Name.  The
# quote is included too: it is invalid for the equivalent `net user` account
# name and must never reach one of the generated first-logon command lines.
INVALID_USERNAME = re.compile(r'[/\\\[\]:|<>+=;,?*%@`"]|[. ]+$')
RESERVED_USERNAMES = {
    "none", "administrator", "defaultaccount", "guest", "wdagutilityaccount",
    "helpassistant", "krbtgt", "local", "system",
}
LANGUAGE_TAG = re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*")
KEYBOARD_LAYOUT = re.compile(r"[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
ONLINE_ACCOUNT_BYPASS_BUILDS = frozenset({22000, 22621, 22631, 26100})
ONLINE_ACCOUNT_BYPASS_EDITIONS = frozenset({
    "education",
    "educationn",
    "enterprise",
    "enterprisen",
    "enterprises",
    "enterprisesn",
    "iotenterprise",
    "iotenterprises",
    "professional",
    "professionaleducation",
    "professionaleducationn",
    "professionaln",
    "professionalworkstation",
    "professionalworkstationn",
})


@dataclass(frozen=True)
class WindowsCustomization:
    """Opt-in settings for an exported Windows unattended-setup profile.

    ISOpropyl only exports this profile today.  Merely constructing this object
    does not modify an ISO, a Windows image, or the host system.
    """

    bypass_hardware_requirements: bool = False
    hide_online_account: bool = False
    local_username: str = ""
    reduce_data_collection: bool = False
    disable_automatic_bitlocker: bool = False
    input_locale: str = ""
    system_locale: str = ""
    ui_language: str = ""
    user_locale: str = ""
    timezone: str = ""
    require_local_password_change: bool = True
    local_password_never_expires: bool = True
    install_image: WimSelection | None = None
    install_image_path: str = ""
    bypass_online_account_requirement: bool = False
    acknowledge_online_account_limitations: bool = False
    # Appended to retain the positional argument order of the public dataclass.
    disable_fast_startup: bool = False

    @property
    def enabled(self) -> bool:
        return any((
            self.bypass_hardware_requirements, self.hide_online_account,
            self.bypass_online_account_requirement,
            bool(self.local_username), self.reduce_data_collection,
            self.disable_automatic_bitlocker, self.disable_fast_startup,
            bool(self.input_locale),
            bool(self.system_locale), bool(self.ui_language),
            bool(self.user_locale), bool(self.timezone), self.install_image is not None,
            bool(self.install_image_path),
        ))


def validate_username(username: str) -> str:
    value = username.strip()
    if not value:
        return ""
    # `net user`, which is used for the opt-in post-creation account policy,
    # documents a 20-character maximum even though the unattend Name element
    # itself accepts a longer string.
    if len(value) > 20:
        raise ValueError("Local account names must be 20 characters or fewer")
    if CONTROL_CHARACTER.search(value) or INVALID_USERNAME.search(value):
        raise ValueError("The local account name contains a character Windows does not allow")
    if value.casefold() in RESERVED_USERNAMES:
        raise ValueError("That local account name is reserved by Windows")
    return value


def validate_language_tag(value: str, field_name: str = "locale") -> str:
    normalized = value.strip()
    if not normalized:
        return ""
    if len(normalized) > 85 or not LANGUAGE_TAG.fullmatch(normalized):
        raise ValueError(
            f"{field_name} must be a Windows language tag such as en-US or sr-Latn-RS"
        )
    return normalized


def validate_input_locale(value: str) -> str:
    """Validate and normalize a semicolon-separated Windows keyboard list."""

    normalized = value.strip()
    if not normalized:
        return ""
    layouts = [layout.strip() for layout in normalized.split(";")]
    if not layouts or any(not layout for layout in layouts):
        raise ValueError("Input locale contains an empty keyboard layout")
    for layout in layouts:
        if not (LANGUAGE_TAG.fullmatch(layout) or KEYBOARD_LAYOUT.fullmatch(layout)):
            raise ValueError(
                "Input locale entries must be language tags or values such as 0409:00000409"
            )
    return ";".join(layouts)


def validate_timezone(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        return ""
    if len(normalized) > 256:
        raise ValueError("Windows time-zone names must be 256 characters or fewer")
    if CONTROL_CHARACTER.search(normalized):
        raise ValueError("The Windows time-zone name contains a control character")
    return normalized


def validate_install_wim_path(value: str) -> str:
    """Validate a canonical, media-relative install.wim member path.

    Catalog member names use forward slashes.  Keeping one accepted spelling
    avoids Windows drive, UNC, alternate-data-stream, and traversal semantics;
    the answer-file generator converts separators only when serializing Path.
    """

    if not isinstance(value, str):
        raise ValueError("The Windows image path must be text")
    if value == "":
        return ""
    try:
        validated = validate_install_image_member_path(value)
    except ValueError as error:
        raise ValueError("The Windows image path is not a safe catalog member path") from error
    if validated.image_format != "wim":
        raise ValueError("The selected Windows image path must name install.wim")
    return validated.path


def online_account_bypass_compatibility(
    selection: WimSelection | None,
) -> tuple[bool, str]:
    """Return the conservative compatibility policy for the fixed BypassNRO tweak."""

    if selection is None:
        return False, "Inspect and select a Windows 11 edition before enabling this option"
    try:
        validate_wim_selection(selection)
    except WimValidationError:
        return False, "The selected Windows edition metadata is not valid"
    edition = selection.edition
    if (
        edition.major_version != 10
        or edition.minor_version != 0
        or edition.build not in ONLINE_ACCOUNT_BYPASS_BUILDS
    ):
        return False, (
            "The offline-account registry method is limited to known Windows 11 "
            "21H2–24H2 builds 22000, 22621, 22631, and 26100"
        )
    if edition.architecture not in {"amd64", "arm64"}:
        return False, "The offline-account registry method requires x64 or ARM64 Windows 11"
    edition_text = unicodedata.normalize("NFKC", " ".join((
        edition.name, edition.description, edition.edition_id,
    ))).casefold()
    compact_edition_text = "".join(
        character for character in edition_text if character.isalnum()
    )
    if "smode" in compact_edition_text or "cloud" in compact_edition_text:
        return False, (
            "The offline-account registry method is disabled because the edition "
            "contains an obvious S-mode or cloud marker"
        )
    if edition.edition_id.casefold() not in ONLINE_ACCOUNT_BYPASS_EDITIONS:
        return False, (
            "The offline-account registry method is disabled for Home/S-mode or "
            "unrecognized Windows editions"
        )
    return True, (
        "Uses the fixed BypassNRO registry value for a recognized non-Home Windows 11 "
        "21H2–24H2 edition. Disconnect networking during OOBE; later builds are not "
        "assumed compatible, and WIM metadata cannot rule out offline-serviced S mode."
    )


def _settings(root: ET.Element, passes: dict[str, ET.Element], name: str) -> ET.Element:
    settings = passes.get(name)
    if settings is None:
        settings = ET.SubElement(root, "settings", {"pass": name})
        passes[name] = settings
    return settings


def _component(settings: ET.Element, name: str, architecture: str) -> ET.Element:
    return ET.SubElement(settings, "component", {
        "name": name,
        "processorArchitecture": architecture,
        "publicKeyToken": "31bf3856ad364e35",
        "language": "neutral",
        "versionScope": "nonSxS",
    })


def _command(parent: ET.Element, order: int, description: str, command: str) -> None:
    item = ET.SubElement(parent, "RunSynchronousCommand", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(item, "Order").text = str(order)
    ET.SubElement(item, "Description").text = description
    ET.SubElement(item, "Path").text = command


def _first_logon_command(
    parent: ET.Element, order: int, description: str, command: str,
) -> None:
    item = ET.SubElement(parent, "SynchronousCommand", {f"{{{WCM_NS}}}action": "add"})
    ET.SubElement(item, "Order").text = str(order)
    ET.SubElement(item, "Description").text = description
    ET.SubElement(item, "CommandLine").text = command


def _hidden_blank_local_password() -> str:
    # Windows SIM hides a LocalAccount password by appending the setting name
    # "Password", encoding as UTF-16LE and then Base64 encoding it.  This is
    # obfuscation, not encryption; the profile deliberately contains no secret.
    return base64.b64encode("Password".encode("utf-16-le")).decode("ascii")


def generate_autounattend(options: WindowsCustomization, architecture: str = "amd64") -> str:
    username = validate_username(options.local_username)
    input_locale = validate_input_locale(options.input_locale)
    system_locale = validate_language_tag(options.system_locale, "System locale")
    ui_language = validate_language_tag(options.ui_language, "UI language")
    user_locale = validate_language_tag(options.user_locale, "User locale")
    timezone = validate_timezone(options.timezone)
    install_image_path = validate_install_wim_path(options.install_image_path)
    if architecture not in {"amd64", "arm64", "x86"}:
        raise ValueError(f"Unsupported Windows architecture: {architecture}")
    if username and not options.require_local_password_change:
        raise ValueError(
            "A local administrator may not be created unless the mandatory "
            "post-setup password-change policy is enabled"
        )
    if options.install_image is not None:
        validate_wim_selection(options.install_image)
        if options.install_image.edition.architecture != architecture:
            raise ValueError(
                "The selected Windows image architecture does not match Windows Setup"
            )
        if install_image_path and install_image_path != options.install_image.source_name:
            raise ValueError(
                "The Windows image path does not match the selected WIM source"
            )
    elif install_image_path:
        raise ValueError("A Windows image path requires an explicitly selected image index")
    if options.bypass_online_account_requirement:
        if not options.acknowledge_online_account_limitations:
            raise ValueError(
                "Acknowledge that WIM metadata cannot prove S mode is absent and "
                "that Microsoft may change the offline-account path"
            )
        compatible, reason = online_account_bypass_compatibility(options.install_image)
        if not compatible:
            raise ValueError(reason)

    root = ET.Element(f"{{{UNATTEND_NS}}}unattend")
    passes: dict[str, ET.Element] = {}
    components: dict[tuple[str, str], ET.Element] = {}

    def component(pass_name: str, name: str) -> ET.Element:
        key = (pass_name, name)
        found = components.get(key)
        if found is None:
            found = _component(_settings(root, passes, pass_name), name, architecture)
            components[key] = found
        return found

    if options.bypass_hardware_requirements:
        setup = component("windowsPE", "Microsoft-Windows-Setup")
        synchronous = ET.SubElement(setup, "RunSynchronous")
        checks = (
            ("TPM", "BypassTPMCheck"), ("Secure Boot", "BypassSecureBootCheck"),
            ("RAM", "BypassRAMCheck"),
        )
        for order, (label, value) in enumerate(checks, 1):
            _command(
                synchronous, order, f"Bypass Windows 11 {label} requirement",
                f'reg add "HKLM\\SYSTEM\\Setup\\LabConfig" /v {value} /t REG_DWORD /d 1 /f',
            )

    if options.install_image is not None:
        setup = component("windowsPE", "Microsoft-Windows-Setup")
        image_install = ET.SubElement(setup, "ImageInstall")
        os_image = ET.SubElement(image_install, "OSImage")
        install_from = ET.SubElement(os_image, "InstallFrom")
        if install_image_path:
            ET.SubElement(install_from, "Path").text = install_image_path.replace("/", "\\")
        metadata = ET.SubElement(install_from, "MetaData", {
            f"{{{WCM_NS}}}action": "add",
        })
        ET.SubElement(metadata, "Key").text = "/IMAGE/INDEX"
        ET.SubElement(metadata, "Value").text = str(options.install_image.selected_index)

    specialize_commands: list[tuple[str, str]] = []
    if options.bypass_online_account_requirement:
        specialize_commands.append((
            "Enable the Windows 11 offline-account setup path",
            'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\OOBE" '
            "/v BypassNRO /t REG_DWORD /d 1 /f",
        ))
    if options.disable_fast_startup:
        specialize_commands.append((
            "Disable Windows Fast Startup",
            'reg add "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Power" '
            "/v HiberbootEnabled /t REG_DWORD /d 0 /f",
        ))
    if specialize_commands:
        deployment = component("specialize", "Microsoft-Windows-Deployment")
        synchronous = ET.SubElement(deployment, "RunSynchronous")
        for order, (description, command) in enumerate(specialize_commands, 1):
            _command(synchronous, order, description, command)

    international_values = (
        ("InputLocale", input_locale),
        ("SystemLocale", system_locale),
        ("UILanguage", ui_language),
        ("UserLocale", user_locale),
    )
    if any(value for _, value in international_values):
        # Apply the same explicit choices to Windows Setup and to the installed
        # system.  Microsoft assigns these components to different passes.
        for pass_name, component_name in (
            ("windowsPE", "Microsoft-Windows-International-Core-WinPE"),
            ("oobeSystem", "Microsoft-Windows-International-Core"),
        ):
            international = component(pass_name, component_name)
            for element_name, value in international_values:
                if value:
                    ET.SubElement(international, element_name).text = value

    needs_shell = any((
        options.hide_online_account, options.bypass_online_account_requirement,
        username, options.reduce_data_collection, timezone,
    ))
    if needs_shell:
        shell = component("oobeSystem", "Microsoft-Windows-Shell-Setup")

        if (
            options.hide_online_account
            or options.bypass_online_account_requirement
            or options.reduce_data_collection
        ):
            oobe = ET.SubElement(shell, "OOBE")
            if (
                options.hide_online_account
                or options.bypass_online_account_requirement
            ):
                ET.SubElement(oobe, "HideOnlineAccountScreens").text = "true"
                ET.SubElement(oobe, "HideWirelessSetupInOOBE").text = "true"
            if options.reduce_data_collection:
                # Value 3 turns off Microsoft's documented "Express settings".
                ET.SubElement(oobe, "ProtectYourPC").text = "3"
                ET.SubElement(oobe, "HideOEMRegistrationScreen").text = "true"

        if timezone:
            ET.SubElement(shell, "TimeZone").text = timezone

        if username:
            accounts = ET.SubElement(shell, "UserAccounts")
            local_accounts = ET.SubElement(accounts, "LocalAccounts")
            account = ET.SubElement(local_accounts, "LocalAccount", {
                f"{{{WCM_NS}}}action": "add",
            })
            password = ET.SubElement(account, "Password")
            ET.SubElement(password, "Value").text = _hidden_blank_local_password()
            ET.SubElement(password, "PlainText").text = "false"
            ET.SubElement(account, "Description").text = "Local administrator created by ISOpropyl"
            ET.SubElement(account, "DisplayName").text = username
            # Built-in group names in unattend files are language neutral and
            # must be written in English.
            ET.SubElement(account, "Group").text = "Administrators"
            ET.SubElement(account, "Name").text = username

            first_logon_commands: list[tuple[str, str]] = []
            if options.require_local_password_change:
                ps_username = username.replace("'", "''")
                account_policy = (
                    '"$u=[ADSI](\'WinNT://\'+$env:COMPUTERNAME+\'/'
                    f"{ps_username},user\');$u.Put(\'PasswordExpired\',[int]1);"
                    "$u.SetInfo()"
                )
                if options.local_password_never_expires:
                    account_policy += (
                        f";Set-LocalUser -Name '{ps_username}' "
                        "-PasswordNeverExpires $true"
                    )
                account_policy += '"'
                first_logon_commands.append((
                    "Apply the local-account password policy",
                    "powershell.exe -NoLogo -NoProfile -NonInteractive -Command "
                    + account_policy,
                ))
            if first_logon_commands:
                commands = ET.SubElement(shell, "FirstLogonCommands")
                for order, (description, command) in enumerate(first_logon_commands, 1):
                    _first_logon_command(commands, order, description, command)

    if options.disable_automatic_bitlocker:
        secure_startup = component(
            "oobeSystem", "Microsoft-Windows-SecureStartup-FilterDriver",
        )
        ET.SubElement(secure_startup, "PreventDeviceEncryption").text = "true"
        enhanced_storage = component("oobeSystem", "Microsoft-Windows-EnhancedStorage-Adm")
        ET.SubElement(enhanced_storage, "TCGSecurityActivationDisabled").text = "1"

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def answer_file_install_index(
    xml: str, expected_architecture: str | None = None,
) -> int | None:
    """Return the exact Windows Setup /IMAGE/INDEX choice, if present."""

    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, ValueError) as error:
        raise ValueError("The Windows answer file is not valid XML") from error
    if root.tag != f"{{{UNATTEND_NS}}}unattend":
        raise ValueError("The Windows answer file has an unexpected root element")
    all_index_metadata: list[ET.Element] = []
    for metadata in root.iter(f"{{{UNATTEND_NS}}}MetaData"):
        key = metadata.findtext(f"{{{UNATTEND_NS}}}Key", default="").strip()
        if key.casefold() == "/image/index":
            if key != "/IMAGE/INDEX":
                raise ValueError("The Windows image-index key must be uppercase")
            all_index_metadata.append(metadata)
    if not all_index_metadata:
        return None

    windows_pe = [
        settings for settings in root.findall(f"{{{UNATTEND_NS}}}settings")
        if settings.attrib.get("pass") == "windowsPE"
    ]
    if len(windows_pe) != 1:
        raise ValueError("The Windows image index is outside one windowsPE pass")
    setup_components = [
        component
        for component in windows_pe[0].findall(f"{{{UNATTEND_NS}}}component")
        if component.attrib.get("name") == "Microsoft-Windows-Setup"
    ]
    if len(setup_components) != 1:
        raise ValueError(
            "The Windows image index is outside one Microsoft-Windows-Setup component"
        )
    setup_architecture = setup_components[0].attrib.get("processorArchitecture")
    if expected_architecture is not None and setup_architecture != expected_architecture:
        raise ValueError(
            "The Windows Setup architecture does not match the selected image"
        )
    correct = setup_components[0].findall(
        f"{{{UNATTEND_NS}}}ImageInstall/"
        f"{{{UNATTEND_NS}}}OSImage/"
        f"{{{UNATTEND_NS}}}InstallFrom/"
        f"{{{UNATTEND_NS}}}MetaData"
    )
    if (
        len(correct) != 1
        or len(all_index_metadata) != 1
        or correct[0] is not all_index_metadata[0]
    ):
        raise ValueError("The Windows image index is misplaced or ambiguous")
    metadata = correct[0]
    if metadata.attrib.get(f"{{{WCM_NS}}}action") != "add":
        raise ValueError("The Windows image index metadata must use wcm:action=add")
    key_elements = metadata.findall(f"{{{UNATTEND_NS}}}Key")
    value_elements = metadata.findall(f"{{{UNATTEND_NS}}}Value")
    if (
        len(metadata) != 2
        or len(key_elements) != 1
        or len(value_elements) != 1
        or list(metadata) != [key_elements[0], value_elements[0]]
    ):
        raise ValueError(
            "The Windows image index metadata has ambiguous or unexpected children"
        )
    value = (value_elements[0].text or "").strip()
    if not value.isascii() or not value.isdecimal():
        raise ValueError("The Windows answer file has an ambiguous image index")
    index = int(value)
    if index <= 0:
        raise ValueError("The Windows answer file has an invalid image index")
    return index


def answer_file_install_path(
    xml: str, expected_architecture: str | None = None,
) -> str | None:
    """Return and strictly validate the optional source-specific WIM path."""

    index = answer_file_install_index(xml, expected_architecture)
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, ValueError) as error:
        raise ValueError("The Windows answer file is not valid XML") from error
    install_from_nodes = list(root.iter(f"{{{UNATTEND_NS}}}InstallFrom"))
    if index is None:
        if install_from_nodes:
            raise ValueError("The Windows image source path has no image index")
        return None
    if len(install_from_nodes) != 1:
        raise ValueError("The Windows image source binding is ambiguous")
    install_from = install_from_nodes[0]
    paths = install_from.findall(f"{{{UNATTEND_NS}}}Path")
    metadata = install_from.findall(f"{{{UNATTEND_NS}}}MetaData")
    if not paths:
        if len(metadata) != 1 or list(install_from) != [metadata[0]]:
            raise ValueError("The Windows image source binding has unexpected children")
        return None
    if (
        len(paths) != 1
        or len(metadata) != 1
        or list(install_from) != [paths[0], metadata[0]]
    ):
        raise ValueError("The Windows image source path is misplaced or ambiguous")
    serialized = paths[0].text or ""
    if not serialized or "/" in serialized:
        raise ValueError("The Windows image source path is not canonical")
    catalog_path = serialized.replace("\\", "/")
    validated = validate_install_wim_path(catalog_path)
    if validated.replace("/", "\\") != serialized:
        raise ValueError("The Windows image source path is not canonical")
    return validated


def windows_architecture(architectures: tuple[str, ...]) -> str:
    for detected, answer_file in (("x64", "amd64"), ("ARM64", "arm64"), ("x86", "x86")):
        if detected in architectures:
            return answer_file
    return "amd64"


def add_autounattend_to_staging(root: Path, xml: str) -> Path:
    """Add a new validated answer file without replacing existing media content."""
    directory = root.resolve(strict=True)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("The Windows media staging root is not a directory")
    try:
        parsed = ET.fromstring(xml)
    except (ET.ParseError, ValueError) as error:
        raise ValueError("The Windows answer file is not valid XML") from error
    if parsed.tag != f"{{{UNATTEND_NS}}}unattend":
        raise ValueError("The Windows answer file has an unexpected root element")
    target = directory / "autounattend.xml"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as error:
        raise ValueError(
            "The media already contains autounattend.xml; ISOpropyl will not overwrite it"
        ) from error
    try:
        payload = xml.encode("utf-8")
        with os.fdopen(descriptor, "wb", buffering=0) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target
