# Install NEuca script

INSTALL=/usr/bin/install
NEUCA=$(NEUCA_PREFIX)/usr/local/bin/neuca
NEUCA_INIT=$(NEUCA_PREFIX)/etc/init.d/neuca

.PHONY: default install uninstall install-neuca uninstall-neuca install-debian-init-script install-redhat-init-script uninstall-debian install-Ubuntu-init-script uninstall-Ubuntu-init-script install-fedora-init-script uninstall-fedora-init-script

default: install

install: install-neuca install-init-script

uninstall: uninstall-init-script uninstall-neuca

install-neuca: neuca.py
	$(INSTALL) -d $(NEUCA_PREFIX)/etc/neuca $(NEUCA_PREFIX)/usr/local/bin
	$(INSTALL) neuca.py $(NEUCA_PREFIX)/usr/local/bin
	ln -s neuca.py $(NEUCA)
	ln -s neuca.py $(NEUCA)-netconf
	ln -s neuca.py $(NEUCA)-user-script
	ln -s neuca.py $(NEUCA)-distro
	ln -s neuca.py $(NEUCA)-user-data

install-init-script:
	$(MAKE) install-$(shell $(NEUCA)-distro)-init-script

install-Ubuntu-init-script: install-debian-init-script

install-debian-init-script: $(NEUCA)
	$(INSTALL) init-scripts/neuca.debian $(NEUCA_INIT)
	update-rc.d neuca start 99 2 3 4 5 .

install-fedora-init-script: install-redhat-init-script

install-redhat-init-script:
	$(INSTALL) init-scripts/neuca.redhat $(NEUCA_INIT)
	chkconfig --add neuca 

uninstall-neuca: $(NEUCA)
	rm /usr/local/bin/neuca*

uninstall-init-script:
	$(MAKE) uninstall-$(shell $(NEUCA)-distro)-init-script

uninstall-Ubuntu-init-script: uninstall-debian-init-script

uninstall-debian-init-script:
	rm -f $(NEUCA_INIT)
	update-rc.d neuca remove

uninstall-fedora-init-script: uninstall-redhat-init-script

uninstall-redhat-init-script:
	chkconfig --del neuca 
	rm -f $(NEUCA_INIT)
