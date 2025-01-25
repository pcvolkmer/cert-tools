ifndef VERBOSE
.SILENT:
endif

GITTAG = $(shell git describe --tag --abbrev=0 2>/dev/null | sed -En 's/v(.*)$$/\1/p')
ifeq ($(findstring -, $(GITTAG)), -)
    GITDEV = $(shell git describe --tag 2>/dev/null | sed -En 's/v(.*)-([0-9]+)-g([0-9a-f]+)$$/.dev.\2+\3/p')
else
    GITDEV = $(shell git describe --tag 2>/dev/null | sed -En 's/v(.*)-([0-9]+)-g([0-9a-f]+)$$/-dev.\2+\3/p')
endif
VERSION := "$(GITTAG)$(GITDEV)"

NAME := cert-tools

package-all: win-installer win-package linux-package

.PHONY: version
version:
	echo $(VERSION)

.PHONY: win-installer
win-installer: win-binary-x86_64
	makensis installer.nsi
	mv target/$(NAME)-installer.exe target/$(NAME)-installer-$(VERSION).exe || ren target/$(NAME)-installer.exe target/$(NAME)-installer-$(VERSION).exe

.PHONY: win-package
win-package: win-binary-x86_64
	mkdir $(NAME) || true
	cp target/x86_64-pc-windows-gnu/release/cert-tools.exe $(NAME)/
	cp target/x86_64-pc-windows-gnu/release/cert-tools-ui.exe $(NAME)/
	cp LICENSE $(NAME)/
	# first try (linux) zip command, then powershell sub command to create ZIP file
	zip target/$(NAME)-$(VERSION)_win64.zip $(NAME)/* || powershell Compress-ARCHIVE $(NAME) target\$(NAME)-$(VERSION)_win64.zip
	rm -rf $(NAME) || true

.PHONY: linux-package
linux-package: linux-binary-x86_64
	mkdir $(NAME) || true
	cp target/x86_64-unknown-linux-gnu/release/cert-tools $(NAME)/
	cp target/x86_64-unknown-linux-gnu/release/cert-tools-ui $(NAME)/
	cp LICENSE $(NAME)/
	tar -czvf target/$(NAME)-$(VERSION)_linux.tar.gz $(NAME)/
	rm -rf $(NAME) || true

binary-all: win-binary-x86_64 linux-binary-x86_64

.PHONY: win-binary-x86_64
win-binary-x86_64:
	# Temp cargo file
	cp Cargo.toml  Cargo.toml.0
	cp ui/Cargo.toml  ui/Cargo.toml.0
	sed -i 's/^version.*/version = $(VERSION)/' Cargo.toml
	sed -i 's/^version = .*/version = $(VERSION)/' ui/Cargo.toml
	cargo build --release --target=x86_64-pc-windows-gnu
	cargo build --release --package cert-tools-ui --target=x86_64-pc-windows-gnu
	# Restore temp
	mv Cargo.toml.0 Cargo.toml
	mv ui/Cargo.toml.0 ui/Cargo.toml

.PHONY: linux-binary-x86_64
linux-binary-x86_64:
	# Temp cargo file
	cp Cargo.toml  Cargo.toml.0
	cp ui/Cargo.toml  ui/Cargo.toml.0
	sed -i 's/^version.*/version = $(VERSION)/' Cargo.toml
	sed -i 's/^version = .*/version = $(VERSION)/' ui/Cargo.toml
	cargo build --release --target=x86_64-unknown-linux-gnu
	cargo build --release --package cert-tools-ui --target=x86_64-unknown-linux-gnu
	# Restore temp
	mv Cargo.toml.0 Cargo.toml
	mv ui/Cargo.toml.0 ui/Cargo.toml

.PHONY: install
install:
	cargo install --path .

.PHONY: clean
clean:
	cargo clean
	rm -rf osc-variant 2>/dev/null || true
	rm *_win64.zip 2>/dev/null || true
	rm *_linux.tar.gz 2>/dev/null || true