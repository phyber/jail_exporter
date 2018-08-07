CARGO=			cargo
CARGO_BUILD=		$(CARGO) build
CARGO_BUILD_RELEASE=	$(CARGO_BUILD) --release
CARGO_OUTDATED=		$(CARGO) outdated
CARGO_TEST=		$(CARGO) test
CARGO_UPDATE=		$(CARGO) update

build:
	$(CARGO_BUILD)

release:
	$(CARGO_BUILD_RELEASE)

test:
	$(CARGO_TEST)

outdated:
	$(CARGO_OUTDATED)

update:
	$(CARGO_UPDATE)
