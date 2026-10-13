"""Native settings, diagnostics and verified artifact cache controls."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from PyQt6.QtWidgets import (QDialog,QVBoxLayout,QFormLayout,QComboBox,QLineEdit,
    QLabel,QCheckBox,QPushButton,QPlainTextEdit,QDialogButtonBox,QMessageBox,QListWidget,QAbstractItemView)
from .native_style import STYLE
class PreferencesDialog(QDialog):
    def __init__(self,settings,parent=None):
        super().__init__(parent);self.settings=settings;self.setWindowTitle('Settings & diagnostics');self.resize(560,440);self.setStyleSheet(parent.styleSheet() if parent else STYLE)
        layout=QVBoxLayout(self);form=QFormLayout();layout.addLayout(form)
        self.theme=QComboBox();self.theme.addItems(['Dark','Light']);self.theme.setCurrentIndex(int(settings.value('theme','dark')=='light'));form.addRow('Appearance',self.theme)
        self.units=QComboBox();self.units.addItems(['Decimal (GB)','Binary (GiB)']);self.units.setCurrentIndex(int(settings.value('binary_units',False,type=bool)));form.addRow('Size units',self.units)
        self.sparse=QCheckBox('Store zero ranges as sparse holes in raw backups');self.sparse.setChecked(settings.value('sparse_backup',True,type=bool));form.addRow(self.sparse)
        self.ignored=QLineEdit(', '.join(settings.value('ignored',[],type=list)));form.addRow('Ignored drive IDs / paths',self.ignored)
        label=QLabel(f'Settings: {settings.fileName()}');label.setWordWrap(True);label.setObjectName('muted');layout.addWidget(label)
        from .logging_setup import read_log
        self.log=QPlainTextEdit(read_log());self.log.setReadOnly(True);layout.addWidget(self.log)
        copy=QPushButton('Copy diagnostics');copy.clicked.connect(self.copy);layout.addWidget(copy)
        self.cache=QLabel();self.cache.setWordWrap(True);layout.addWidget(self.cache)
        clear=QPushButton('Manage downloaded boot helpers…');clear.clicked.connect(self.manage_cache);layout.addWidget(clear);self.refresh_cache()
        reset=QPushButton('Reset saved settings');reset.clicked.connect(self.reset);layout.addWidget(reset)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save|QDialogButtonBox.StandardButton.Cancel);buttons.accepted.connect(self.save);buttons.rejected.connect(self.reject);layout.addWidget(buttons)
    def copy(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.log.toPlainText())
    def refresh_cache(self):
        from .bootloaders import inventory_cache
        try:
            self.inventory=inventory_cache();self.cache.setText(f'Boot helper cache: {self.inventory.total_size:,} bytes')
        except Exception as error:self.inventory=None;self.cache.setText(str(error))
    def reset(self):
        self.settings.clear();self.settings.sync();self.accept()
    def manage_cache(self):
        self.refresh_cache()
        if self.inventory is None:return
        dialog=QDialog(self);dialog.setWindowTitle('Downloaded boot helpers');dialog.resize(500,350);layout=QVBoxLayout(dialog)
        listing=QListWidget();listing.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        artifacts=list(self.inventory.artifacts)
        for artifact in artifacts:listing.addItem(f'{artifact.family} {artifact.version} · {artifact.name} · {artifact.size:,} bytes'+(' (protected)' if not artifact.deletion_safe else ''))
        layout.addWidget(listing);remove=QPushButton('Remove selected');layout.addWidget(remove)
        def selected():
            from .bootloaders import delete_cached_artifacts
            keys=[artifacts[listing.row(item)].key for item in listing.selectedItems() if artifacts[listing.row(item)].deletion_safe]
            try:
                result=delete_cached_artifacts(keys)
                if result.issues:QMessageBox.information(dialog,'Cache',"\n".join(result.issues))
                dialog.accept();self.refresh_cache()
            except Exception as error:QMessageBox.critical(dialog,'Cannot update cache',str(error))
        remove.clicked.connect(selected);close=QPushButton('Close');close.clicked.connect(dialog.reject);layout.addWidget(close);dialog.exec()

    def clear_cache(self):
        from .bootloaders import delete_cached_artifacts
        if not self.inventory:return
        keys=[item.key for item in self.inventory.artifacts if item.deletion_safe]
        if QMessageBox.question(self,'Clear boot helper cache','Remove verified downloaded boot helpers? They will be downloaded again when needed.',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,QMessageBox.StandardButton.Cancel)!=QMessageBox.StandardButton.Yes:return
        try:delete_cached_artifacts(keys);self.refresh_cache()
        except Exception as error:QMessageBox.critical(self,'Cannot clear cache',str(error))
    def save(self):
        self.settings.setValue('theme','light' if self.theme.currentIndex() else 'dark')
        self.settings.setValue('sparse_backup',self.sparse.isChecked())
        self.settings.setValue('binary_units',bool(self.units.currentIndex()));self.settings.setValue('ignored',[p.strip() for p in self.ignored.text().split(',') if p.strip()]);self.settings.sync()
        from PyQt6.QtCore import QSettings
        if self.settings.status()!=QSettings.Status.NoError:
            QMessageBox.critical(self,'Cannot save settings','The settings file could not be saved.');return
        self.accept()
