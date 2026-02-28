APP_NAME := ssroute
INSTALL_DIR := /usr/bin
CONFIG_DIR := /etc/ssroute
SYSTEMD_DIR := /etc/systemd/system

.PHONY: all build clean install install-service uninstall

all: build

build:
	cargo build --release

clean:
	cargo clean

install: build
	install -m 0755 ./target/release/$(APP_NAME) $(INSTALL_DIR)/$(APP_NAME)
	@echo "Installed $(APP_NAME) to $(INSTALL_DIR)/$(APP_NAME)"

install-service: install
	@mkdir -p $(CONFIG_DIR)
	@test -f $(CONFIG_DIR)/ssroute.conf || cp ssroute.conf.example $(CONFIG_DIR)/ssroute.conf
	cp -r data $(CONFIG_DIR)/
	cp -r default_route $(CONFIG_DIR)/
	cp ssroute.service $(SYSTEMD_DIR)/$(APP_NAME).service
	systemctl daemon-reload
	@echo ""
	@echo "Installed. Files:"
	@echo "  Binary:  $(INSTALL_DIR)/$(APP_NAME)"
	@echo "  Config:  $(CONFIG_DIR)/ssroute.conf"
	@echo "  Routes:  $(CONFIG_DIR)/data/, $(CONFIG_DIR)/default_route/"
	@echo "  Service: $(SYSTEMD_DIR)/$(APP_NAME).service"
	@echo ""
	@echo "Edit $(CONFIG_DIR)/ssroute.conf then run:"
	@echo "  sudo systemctl enable --now $(APP_NAME)"

uninstall:
	-systemctl stop $(APP_NAME) 2>/dev/null
	-systemctl disable $(APP_NAME) 2>/dev/null
	rm -f $(SYSTEMD_DIR)/$(APP_NAME).service
	rm -f $(INSTALL_DIR)/$(APP_NAME)
	systemctl daemon-reload
	@echo "Uninstalled $(APP_NAME). Config left in $(CONFIG_DIR)/"
