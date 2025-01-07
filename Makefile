ifndef VERBOSE
.SILENT:
endif

TAG = `git describe --tag 2>/dev/null`

REV = git`git rev-parse HEAD | cut -c1-7`

NAME = cert-tools

package-all: win-installer win-package linux-package

.PHONY: win-installer
win-installer: win-binary-x86_64
	makensis installer.nsi
	mv target/$(NAME)-installer.exe target/$(NAME)-installer-$(TAG).exe || ren target/$(NAME)-installer.exe target/$(NAME)-installer-$(TAG).exe

.PHONY: win-package
win-package: win-binary-x86_64
	mkdir $(NAME) || true
	cp target/x86_64-pc-windows-gnu/release/cert-tools.exe $(NAME)/
	cp target/x86_64-pc-windows-gnu/release/cert-tools-ui.exe $(NAME)/
	cp LICENSE $(NAME)/
	# first try (linux) zip command, then powershell sub command to create ZIP file
	zip target/$(NAME)-$(TAG)_win64.zip $(NAME)/* || powershell Compress-ARCHIVE $(NAME) target\$(NAME)-$(TAG)_win64.zip
	rm -rf $(NAME) || true

.PHONY: linux-package
linux-package: linux-binary-x86_64
	mkdir $(NAME) || true
	cp target/x86_64-unknown-linux-gnu/release/cert-tools $(NAME)/
	cp target/x86_64-unknown-linux-gnu/release/cert-tools-ui $(NAME)/
	cp LICENSE $(NAME)/
	tar -czvf target/$(NAME)-$(TAG)_linux.tar.gz $(NAME)/
	rm -rf $(NAME) || true

binary-all: win-binary-x86_64 linux-binary-x86_64

.PHONY: win-binary-x86_64
win-binary-x86_64:
	cargo build --release --target=x86_64-pc-windows-gnu
	cargo build --release --package cert-tools-ui --target=x86_64-pc-windows-gnu

.PHONY: linux-binary-x86_64
linux-binary-x86_64:
	cargo build --release --target=x86_64-unknown-linux-gnu
	cargo build --release --package cert-tools-ui --target=x86_64-unknown-linux-gnu

.PHONY: install
install:
	cargo install --path .

.PHONY: clean
clean:
	cargo clean
	rm -rf osc-variant 2>/dev/null || true
	rm *_win64.zip 2>/dev/null || true
	rm *_linux.tar.gz 2>/dev/null || true