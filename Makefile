APP_NAME := ssroute
INSTALL_DIR := /usr/bin
SYSTEMD_DIR := /etc/systemd/system
WORK_DIR := /opt/ssroute

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
	@mkdir -p $(WORK_DIR)
	@test -f $(WORK_DIR)/ssroute.conf || cp ssroute.conf.example $(WORK_DIR)/ssroute.conf
	@test -d $(WORK_DIR)/data || mkdir -p $(WORK_DIR)/data
	@test -d $(WORK_DIR)/default_route || mkdir -p $(WORK_DIR)/default_route
	@echo "[Unit]" > $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "Description=$(APP_NAME) - Shadowsocks routing daemon" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "After=network-online.target" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "Wants=network-online.target" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "[Service]" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "Type=simple" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "WorkingDirectory=$(WORK_DIR)" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "ExecStart=$(INSTALL_DIR)/$(APP_NAME)" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "Restart=on-failure" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "RestartSec=5" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "[Install]" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	@echo "WantedBy=multi-user.target" >> $(SYSTEMD_DIR)/$(APP_NAME).service
	systemctl daemon-reload
	@echo "Service installed. Edit $(WORK_DIR)/ssroute.conf then run:"
	@echo "  sudo systemctl enable $(APP_NAME)"
	@echo "  sudo systemctl start $(APP_NAME)"

uninstall:
	-systemctl stop $(APP_NAME) 2>/dev/null
	-systemctl disable $(APP_NAME) 2>/dev/null
	rm -f $(SYSTEMD_DIR)/$(APP_NAME).service
	rm -f $(INSTALL_DIR)/$(APP_NAME)
	systemctl daemon-reload
	@echo "Uninstalled $(APP_NAME)"
