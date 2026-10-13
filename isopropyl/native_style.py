# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared visual language and compact geometry for every platform."""

import re

MAIN_SIZE = (660, 570)
MINIMUM_SIZE = (560, 460)
WINDOWS_OPTIONS_SIZE = (680, 540)

STYLE = """
QWidget { font-family: "SF Pro Text", "Segoe UI", sans-serif; font-size: 12px; color: #f5f6f8; }
QMainWindow, QDialog, QScrollArea, QWidget#canvas, QWidget#root, QWidget#workflowContent, QWidget#workflowFooter { background: #111318; }
QFrame#card { background: #1b1e25; border: 1px solid #2d313b; border-radius: 10px; }
QLabel { background: transparent; }
QLabel#title { font-size: 20px; font-weight: 700; }
QLabel#sectionTitle, QLabel#cardTitle { font-size: 14px; font-weight: 600; }
QLabel#muted, QLabel#subtitle, QLabel#status { color: #a9adb7; }
QLabel#eyebrow { color: #ff9f43; font-size: 11px; font-weight: 700; }
QLineEdit, QComboBox, QPlainTextEdit, QSpinBox, QDoubleSpinBox { background: #14171d; border: 1px solid #3a3f4b; border-radius: 7px; padding: 6px; selection-background-color: #b96416; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border: 1px solid #ff9f43; }
QPushButton { background: #272b34; border: 1px solid #3a3f4b; border-radius: 7px; padding: 7px 12px; font-weight: 600; }
QPushButton:hover { background: #323743; }
QPushButton#primary { background: #f28c28; border: none; color: #16120d; padding: 8px 16px; }
QPushButton#primary:hover { background: #ffa347; }
QPushButton:disabled { color: #70747d; background: #20232a; border-color: #343945; }
QCheckBox { spacing: 7px; padding: 2px 0; }
QCheckBox:disabled { color: #70747d; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #3a3f4b; border-radius: 3px; background: #14171d; }
QCheckBox::indicator:checked { background: #f28c28; border-color: #f28c28; }
QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button, QDoubleSpinBox::down-button { background: #272b34; border-left: 1px solid #3a3f4b; }
QMenu { background: #1b1e25; color: #f5f6f8; border: 1px solid #3a3f4b; }
QMenu::item:selected { background: #b96416; }
QListWidget, QComboBox QAbstractItemView { background: #14171d; color: #f5f6f8; border: 1px solid #3a3f4b; selection-background-color: #b96416; }
QProgressBar { background: #292d35; border: none; border-radius: 3px; height: 6px; max-height: 6px; }
QProgressBar::chunk { background: #f28c28; border-radius: 3px; }
QTabWidget::pane { border: 1px solid #343945; border-radius: 8px; padding: 7px; background: #1b1e25; }
QTabBar::tab { background: #272b34; padding: 7px 9px; color: #a9adb7; }
QTabBar::tab:selected { background: #3a3f4b; color: #ffffff; }
QScrollArea { border: none; }
QScrollArea > QWidget > QWidget { background: #1b1e25; }
QToolTip { background: #272b34; color: #f5f6f8; border: 1px solid #3a3f4b; padding: 6px; }
"""

# Quoted absolute paths keep the same glyphs on every host, including
# installed runtime paths containing spaces. Qt QSS requires file paths.
from pathlib import Path
_icon_root=Path(__file__).with_name('data')
def _glyph(name):
    return (_icon_root/name).as_posix().replace(chr(34),chr(92)+chr(34))
STYLE += (
    f'QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{ image: url("{_glyph("chevron-up.svg")}"); width: 10px; height: 7px; }}'
    f'QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{ image: url("{_glyph("chevron-down.svg")}"); width: 10px; height: 7px; }}'
    f'QCheckBox::indicator:checked {{ image: url("{_glyph("check.svg")}"); }}'
)

# Light mode retains the same sizing and orange accent.
_LIGHT_COLORS = {
    "#f5f6f8": "#20242b",
    "#111318": "#f5f6f8",
    "#1b1e25": "#ffffff",
    "#2d313b": "#d8dce3",
    "#a9adb7": "#626975",
    "#ff9f43": "#bd5f08",
    "#14171d": "#ffffff",
    "#3a3f4b": "#c7ccd5",
    "#b96416": "#f3b77d",
    "#272b34": "#ffffff",
    "#323743": "#eef0f4",
    "#f28c28": "#e97f16",
    "#70747d": "#9298a2",
    "#20232a": "#eceef2",
    "#343945": "#d8dce3",
    "#292d35": "#dfe2e7",
    "#ffffff": "#20242b",
}
LIGHT_STYLE = re.sub(
    r"#[0-9a-f]{6}",
    lambda match: _LIGHT_COLORS.get(match.group(), match.group()),
    STYLE,
)
