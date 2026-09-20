BINARY_NAME=memchk
GLOBAL_BIN_DIR=/usr/local/bin
LOCAL_BIN_DIR=$(HOME)/.local/bin

.PHONY: all build clean install install-local
all: build

build:
	@echo "[*] Compiling $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) main.go
	@echo "[+] Build complete: ./$(BINARY_NAME)"

clean:
	@echo "[*] Cleaning up..."
	rm -f $(BINARY_NAME)
	@echo "[+] Cleaned"

install: build
	@echo "[*] Installing globally to ${GLOBAL_BIN_DIR}..."
	sudo mdkir -p $(GLOBAL_BIN_DIR)
	sudo cp $(BINARY_NAME) $(GLOBAL_BIN_DIR)/
	sudo chmod +x $(GLOBAL_BIN_DIR)/$(BINARY_NAME)
	@echo "[+] Installation succesful! You can now run: sudo ${BINARY_NAME}"

install-local: build
	@echo "[*] Installing locally to $(LOCAL_BIN_DIR)"
	mkdir -p $(LOCAL_BIN_DIR)
	cp $(BINARY_NAME) $(LOCAL_BIN_DIR)
	chmod +x $(LOCAL_BIN_DIR)/{BINARY_NAME}
	@echo "[+] Installed to $(LOCAL_BIN_DIR)"
	@echo "[!] Make sure ${LOCAL_BIN_DIR} is in your $$PATH"