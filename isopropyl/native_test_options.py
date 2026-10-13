"""Shared native surface-test configuration."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from PyQt6.QtWidgets import QDialog,QFormLayout,QComboBox,QSpinBox,QDialogButtonBox
class TestOptionsDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent);self.setWindowTitle('Surface test');self.resize(410,180)
        form=QFormLayout(self);self.mode=QComboBox();self.mode.addItems(['Full surface','Capacity probe + full surface']);form.addRow('Test mode',self.mode)
        self.passes=QSpinBox();self.passes.setRange(1,4);self.passes.setValue(4);form.addRow('Pattern passes',self.passes)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel);buttons.accepted.connect(self.accept);buttons.rejected.connect(self.reject);form.addRow(buttons)
    @property
    def options(self):return dict(passes=self.passes.value(),capacity_first=bool(self.mode.currentIndex()))
