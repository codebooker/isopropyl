PREFIX ?= /usr/local
DESTDIR ?=
PYTHON ?= python3
PYTHON_VERSION := $(shell $(PYTHON) -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_SITE ?= $(PREFIX)/lib/python$(PYTHON_VERSION)/site-packages

.PHONY: test install uninstall
test:
	python3 -m unittest discover -s tests -v

install:
	install -Dm755 isopropyl-gui $(DESTDIR)$(PREFIX)/bin/isopropyl
	install -d $(DESTDIR)$(PYTHON_SITE)
	cp -r isopropyl $(DESTDIR)$(PYTHON_SITE)/isopropyl
	install -Dm644 data/io.github.codebooker.isopropyl.desktop $(DESTDIR)$(PREFIX)/share/applications/io.github.codebooker.isopropyl.desktop
	install -Dm644 data/io.github.codebooker.isopropyl.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/io.github.codebooker.isopropyl.svg
	install -Dm644 data/icons/48x48/apps/io.github.codebooker.isopropyl.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/48x48/apps/io.github.codebooker.isopropyl.png
	install -Dm644 data/icons/64x64/apps/io.github.codebooker.isopropyl.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/64x64/apps/io.github.codebooker.isopropyl.png
	install -Dm644 data/icons/128x128/apps/io.github.codebooker.isopropyl.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/128x128/apps/io.github.codebooker.isopropyl.png
	install -Dm644 data/icons/256x256/apps/io.github.codebooker.isopropyl.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/256x256/apps/io.github.codebooker.isopropyl.png
	install -Dm644 data/io.github.codebooker.isopropyl.metainfo.xml $(DESTDIR)$(PREFIX)/share/metainfo/io.github.codebooker.isopropyl.metainfo.xml

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/isopropyl
	rm -rf $(DESTDIR)$(PYTHON_SITE)/isopropyl
	rm -f $(DESTDIR)$(PREFIX)/share/applications/io.github.codebooker.isopropyl.desktop
	rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/io.github.codebooker.isopropyl.svg
	rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/48x48/apps/io.github.codebooker.isopropyl.png
	rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/64x64/apps/io.github.codebooker.isopropyl.png
	rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/128x128/apps/io.github.codebooker.isopropyl.png
	rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/256x256/apps/io.github.codebooker.isopropyl.png
	rm -f $(DESTDIR)$(PREFIX)/share/metainfo/io.github.codebooker.isopropyl.metainfo.xml
