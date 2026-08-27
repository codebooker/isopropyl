# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import os
import re
import stat
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

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

    @property
    def enabled(self) -> bool:
        return any((
            self.bypass_hardware_requirements, self.hide_online_account,
            bool(self.local_username), self.reduce_data_collection,
            self.disable_automatic_bitlocker, bool(self.input_locale),
            bool(self.system_locale), bool(self.ui_language),
            bool(self.user_locale), bool(self.timezone),
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
    if architecture not in {"amd64", "arm64", "x86"}:
        raise ValueError(f"Unsupported Windows architecture: {architecture}")

    root = ET.Element(f"{{{UNATTEND_NS}}}unattend")
    passes: dict[str, ET.Element] = {}

    if options.bypass_hardware_requirements:
        settings = _settings(root, passes, "windowsPE")
        setup = _component(settings, "Microsoft-Windows-Setup", architecture)
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
            component = _component(
                _settings(root, passes, pass_name), component_name, architecture,
            )
            for element_name, value in international_values:
                if value:
                    ET.SubElement(component, element_name).text = value

    needs_shell = any((
        options.hide_online_account, username, options.reduce_data_collection, timezone,
    ))
    if needs_shell:
        settings = _settings(root, passes, "oobeSystem")
        shell = _component(settings, "Microsoft-Windows-Shell-Setup", architecture)

        if options.hide_online_account or options.reduce_data_collection:
            oobe = ET.SubElement(shell, "OOBE")
            if options.hide_online_account:
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
                first_logon_commands.append((
                    "Require a password change after initial setup",
                    "powershell.exe -NoLogo -NoProfile -NonInteractive -Command "
                    '"$u=[ADSI](\'WinNT://\'+$env:COMPUTERNAME+\'/'
                    f"{ps_username},user\');$u.Put(\'PasswordExpired\',[int]1);$u.SetInfo()\"",
                ))
            if options.local_password_never_expires:
                ps_username = username.replace("'", "''")
                first_logon_commands.append((
                    "Keep the replacement password from expiring",
                    "powershell.exe -NoLogo -NoProfile -NonInteractive -Command "
                    f'"Set-LocalUser -Name \'{ps_username}\' -PasswordNeverExpires $true"',
                ))
            if first_logon_commands:
                commands = ET.SubElement(shell, "FirstLogonCommands")
                for order, (description, command) in enumerate(first_logon_commands, 1):
                    _first_logon_command(commands, order, description, command)

    if options.disable_automatic_bitlocker:
        settings = _settings(root, passes, "oobeSystem")
        secure_startup = _component(
            settings, "Microsoft-Windows-SecureStartup-FilterDriver", architecture,
        )
        ET.SubElement(secure_startup, "PreventDeviceEncryption").text = "true"
        enhanced_storage = _component(
            settings, "Microsoft-Windows-EnhancedStorage-Adm", architecture,
        )
        ET.SubElement(enhanced_storage, "TCGSecurityActivationDisabled").text = "1"

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


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
