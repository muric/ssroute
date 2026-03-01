APP_NAME := ssroute
INSTALL_DIR := /usr/bin
CONFIG_DIR := /etc/ssroute
SYSTEMD_DIR := /lib/systemd/system

.PHONY: all build clean install install-service uninstall deb

all: build

build:
	cargo build --release

clean:
	cargo clean

deb: build
	cargo deb --no-build

install: build
	install -m 0755 ./target/release/$(APP_NAME) $(INSTALL_DIR)/$(APP_NAME)
	@echo "Installed $(APP_NAME) to $(INSTALL_DIR)/$(APP_NAME)"

install-service: install
	@mkdir -p $(CONFIG_DIR)
	@test -f $(CONFIG_DIR)/ssroute.conf || install -m 0600 ssroute.conf.example $(CONFIG_DIR)/ssroute.conf
	cp ssroute.service $(SYSTEMD_DIR)/$(APP_NAME).service
	systemctl daemon-reload
	@echo ""
	@echo "Installed. Files:"
	@echo "  Binary:  $(INSTALL_DIR)/$(APP_NAME)"
	@echo "  Config:  $(CONFIG_DIR)/ssroute.conf"
	@echo "  Service: $(SYSTEMD_DIR)/$(APP_NAME).service"
	@echo ""
	@echo "Install route data: sudo dpkg -i ssroute-data_all.deb"
	@echo "Then: sudo systemctl enable --now $(APP_NAME)"

uninstall:
	-systemctl stop $(APP_NAME) 2>/dev/null
	-systemctl disable $(APP_NAME) 2>/dev/null
	rm -f $(SYSTEMD_DIR)/$(APP_NAME).service
	rm -f $(INSTALL_DIR)/$(APP_NAME)
	systemctl daemon-reload
	@echo "Uninstalled $(APP_NAME). Config left in $(CONFIG_DIR)/"
