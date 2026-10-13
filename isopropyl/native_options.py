"""Compact media controls shared by the native desktop interfaces."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import replace
from pathlib import Path
from PyQt6.QtWidgets import (QDialog,QFormLayout,QComboBox,QLineEdit,QSpinBox,
    QDialogButtonBox,QCheckBox,QLabel,QPushButton,QFileDialog,QHBoxLayout,QWidget,QMessageBox,QVBoxLayout,QScrollArea)
from .native_style import STYLE

class MediaOptionsDialog(QDialog):
    def __init__(self,options,parent=None):
        super().__init__(parent);self.options=options
        self.setWindowTitle('Media options');self.resize(500,440);self.setStyleSheet(parent.styleSheet() if parent else STYLE)
        outer=QVBoxLayout(self);scroll=QScrollArea();scroll.setWidgetResizable(True);body=QWidget();scroll.setWidget(body);outer.addWidget(scroll)
        form=QFormLayout(body);form.setSpacing(10)
        def choice(label,values,current):
            control=QComboBox()
            for text,value in values:control.addItem(text,value)
            control.setCurrentIndex(max(0,control.findData(current)));form.addRow(label,control);return control
        self.mode=choice('Write mode',[('Automatic','auto'),('Raw image (DD)','dd'),('Extract ISO files','iso')],options.mode)
        self.table=choice('Partition scheme',[('MBR','mbr'),('GPT','gpt')],options.partition_table)
        self.fs=choice('Filesystem',[('FAT32','fat32'),('NTFS','ntfs')],options.filesystem)
        self.firmware=choice('Target firmware',[('UEFI','uefi'),('Legacy BIOS (experimental)','bios'),('UEFI + BIOS (experimental)','both')],options.firmware)
        self.label=QLineEdit(options.label);form.addRow('Volume label',self.label)
        self.cluster=choice('Allocation unit',[('Automatic',None)]+[(f'{n:,} bytes',n) for n in (512,1024,2048,4096,8192,16384,32768,65536)],options.cluster_size)
        self.persistence=QSpinBox();self.persistence.setRange(0,1048576);self.persistence.setSuffix(' MiB');self.persistence.setValue(options.persistence_size//1048576);form.addRow('Persistence',self.persistence)
        self.release=choice('Ubuntu Casper profile',[('Choose release',''),('20.04 amd64','20.04'),('22.04 amd64','22.04'),('24.04 amd64','24.04')],options.persistence_release)
        row=QWidget();layout=QHBoxLayout(row);layout.setContentsMargins(0,0,0,0)
        self.overlay=QLineEdit(str(options.zip_overlay or ''));self.overlay.setPlaceholderText('Optional ZIP overlay')
        browse=QPushButton('Browse…');browse.clicked.connect(self.browse);layout.addWidget(self.overlay);layout.addWidget(browse);form.addRow('Add files',row)
        self.final_verify=QCheckBox('Final full read-back after activation');self.final_verify.setChecked(getattr(options,'final_verification',True));form.addRow(self.final_verify)
        self.unsigned=QCheckBox('Allow unsigned UEFI:NTFS loaders (requires compatible firmware)');self.unsigned.setChecked(options.allow_unsigned_uefi_ntfs);form.addRow(self.unsigned)
        note=QLabel('ISO mode builds a new filesystem. Persistence requires a supported Ubuntu amd64 Casper image. BIOS support uses the same experimental profiles as Linux.');note.setWordWrap(True);note.setObjectName('muted');form.addRow(note)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save|QDialogButtonBox.StandardButton.Cancel);buttons.accepted.connect(self.save);buttons.rejected.connect(self.reject);outer.addWidget(buttons)
        self.mode.currentIndexChanged.connect(self.update_controls);self.update_controls()
    def browse(self):
        path,_=QFileDialog.getOpenFileName(self,'Choose ZIP overlay','','ZIP archive (*.zip)')
        if path:self.overlay.setText(path)
    def update_controls(self):
        enabled=self.mode.currentData()!='dd'
        for control in (self.table,self.fs,self.firmware,self.label,self.cluster,self.persistence,self.release,self.overlay):control.setEnabled(enabled)
    def save(self):
        if self.mode.currentData()!='dd' and self.persistence.value() and (self.persistence.value()<256 or not self.release.currentData()):
            QMessageBox.warning(self,'Persistence profile','Choose an Ubuntu release and at least 256 MiB of persistence.');return
        self.options=replace(self.options,mode=self.mode.currentData(),partition_table=self.table.currentData(),filesystem=self.fs.currentData(),firmware=self.firmware.currentData(),label=self.label.text().strip(),cluster_size=self.cluster.currentData(),persistence_size=0 if self.mode.currentData()=='dd' else self.persistence.value()*1048576,persistence_release=self.release.currentData(),final_verification=self.final_verify.isChecked(),allow_unsigned_uefi_ntfs=self.unsigned.isChecked(),zip_overlay=None if self.mode.currentData()=='dd' or not self.overlay.text().strip() else Path(self.overlay.text().strip()))
        self.accept()
