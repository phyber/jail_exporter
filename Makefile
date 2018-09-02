CARGO=	cargo

.PHONY: build release test outdated update doc

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

outdated:
	$(CARGO) outdated

update:
	$(CARGO) update

doc:
	$(CARGO) doc --no-deps
