MSRV := `cargo metadata --no-deps --format-version 1 | jq -r '.packages | map(select(.name == "wol")) | first | .rust_version'`

default:
    just --list

vet:
    cargo vet --locked

test-msrv:
    cargo +{{MSRV}} build --locked --all-features
    cargo +{{MSRV}} test --locked --all-features

lint-stable:
    cargo +stable deny --all-features --locked check
    cargo +stable fmt -- --check
    cargo +stable doc

test-stable:
    # Just the library crate
    cargo +stable build --locked
    # Regular CLI build, for use e.g. in distribution packages
    cargo +stable build --locked --features cli
    # Test all features build for manpage, etc.
    cargo +stable build --locked --all-features
    cargo +stable clippy --locked --all-targets --all-features
    cargo +stable test --locked --all-features

test-all: vet test-msrv lint-stable test-stable test-windows
