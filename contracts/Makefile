build:
	cargo build --target wasm32-unknown-unknown --release --manifest-path ./Cargo.toml
	@echo "Build complete. Optimizing WASM if soroban CLI is installed..."
	@which soroban > /dev/null 2>&1 && $(foreach wasm, $(wildcard target/wasm32-unknown-unknown/release/*.wasm), \
		soroban contract optimize --wasm $(wasm);) || echo "soroban CLI not found, skipping optimization step."

test:
	cargo test

check:
	cargo check --target wasm32-unknown-unknown --release

clean:
	cargo clean

.PHONY: build test check clean
