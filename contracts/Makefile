build:
	cargo build --target wasm32-unknown-unknown --release --manifest-path ./Cargo.toml
	@echo "Build complete. Optimizing WASM..."
	$(foreach wasm, $(wildcard ../target/wasm32-unknown-unknown/release/*.wasm), \
		soroban contract optimize --wasm $(wasm);)

test:
	cargo test

clean:
	cargo clean

.PHONY: build test clean
