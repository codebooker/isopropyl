"""Restore options without expanding the main window."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from PyQt6.QtWidgets import QDialog,QFormLayout,QComboBox,QLineEdit,QCheckBox,QDialogButtonBox
from .native_style import STYLE
class RestoreOptionsDialog(QDialog):
    def __init__(self,parent=None,device_size=32*1024**3,sector_size=512):
        super().__init__(parent);self.setWindowTitle('Restore / format');self.resize(430,280);self.setStyleSheet(parent.styleSheet() if parent else STYLE)
        form=QFormLayout(self)
        self.size=device_size;self.sector_size=sector_size
        from .formatting import restore_filesystem_size_supported
        self.fs=QComboBox();self.fs.addItems([fs for fs in ['FAT12','FAT16','FAT32','exFAT','NTFS','UDF','ext2','ext3','ext4'] if restore_filesystem_size_supported(fs.lower(),device_size)]);self.fs.setCurrentText('FAT32');form.addRow('Filesystem',self.fs)
        self.table=QComboBox();self.table.addItems(['MBR','GPT']);self.table.setCurrentIndex(int(device_size//sector_size>0xFFFFFFFF));form.addRow('Partition scheme',self.table)
        self.label=QLineEdit('ISOPROPYL');form.addRow('Volume label',self.label)
        self.cluster=QComboBox();self.cluster.addItem('Automatic',None)

        form.addRow('Allocation unit',self.cluster)
        self.quick=QCheckBox('Quick format (preserves unused data bytes)');self.quick.setChecked(True);form.addRow(self.quick)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel);buttons.accepted.connect(self.save);buttons.rejected.connect(self.reject);form.addRow(buttons)
        self.fs.currentTextChanged.connect(self.update_clusters);self.table.currentTextChanged.connect(self.update_filesystems);self.update_filesystems()
    def update_filesystems(self):
        from .formatting import restore_filesystem_geometry_supported
        selected=self.fs.currentText();self.fs.blockSignals(True);self.fs.clear()
        self.fs.addItems([fs for fs in ['FAT12','FAT16','FAT32','exFAT','NTFS','UDF','ext2','ext3','ext4']
            if restore_filesystem_geometry_supported(fs.lower(),self.size,self.sector_size,self.table.currentText().lower())])
        index=self.fs.findText(selected);self.fs.setCurrentIndex(max(0,index));self.fs.blockSignals(False);self.update_clusters()
    def update_clusters(self):
        from .formatting import restore_allocation_unit_sizes
        selected=self.cluster.currentData();self.cluster.clear();self.cluster.addItem("Automatic",None)
        choices=restore_allocation_unit_sizes(self.fs.currentText().lower(),self.size,self.sector_size,self.table.currentText().lower())
        if self.fs.currentText()=="UDF":choices=(self.sector_size,)
        for n in choices:self.cluster.addItem(f"{n:,} bytes",n)
        self.cluster.setCurrentIndex(max(0,self.cluster.findData(selected)))
    def save(self):
        self.options=dict(filesystem=self.fs.currentText().lower(),partition_table=self.table.currentText().lower(),label=self.label.text().strip(),cluster_size=self.cluster.currentData(),quick=self.quick.isChecked());self.accept()
