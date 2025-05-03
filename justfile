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

test-all: vet test-msrv lint-stable test-stable

_dist:
    rm -rf dist
    mkdir -p dist
    curl https://codeberg.org/swsnr.keys > dist/.key

# Build and sign a reproducible archive of cargo vendor sources
_vendor: _dist
    rm -rf vendor/
    cargo vendor --locked
    echo SOURCE_DATE_EPOCH="$(env LC_ALL=C TZ=UTC0 git show --quiet --date='format-local:%Y-%m-%dT%H:%M:%SZ' --format="%cd" HEAD)"
    # See https://reproducible-builds.org/docs/archives/
    env LC_ALL=C TZ=UTC0 tar --numeric-owner --owner 0 --group 0 \
        --sort name --mode='go+u,go-w' --format=posix \
        --pax-option=exthdr.name=%d/PaxHeaders/%f \
        --pax-option=delete=atime,delete=ctime \
        --mtime="$(env LC_ALL=C TZ=UTC0 git show --quiet --date='format-local:%Y-%m-%dT%H:%M:%SZ' --format="%cd" HEAD)" \
        -c -f "dist/wol-$(git describe)-vendor.tar.zst" \
        --zstd vendor
    ssh-keygen -Y sign -f dist/.key -n file "dist/wol-$(git describe)-vendor.tar.zst"

# Build and sign a reproducible git archive bundle
_git-archive: _dist
    env LC_ALL=C TZ=UTC0 git archive --format tar \
        --prefix "wol-$(git describe)/" \
        --output "dist/wol-$(git describe).tar" HEAD
    zstd --rm "dist/wol-$(git describe).tar"
    ssh-keygen -Y sign -f dist/.key -n file "dist/wol-$(git describe).tar.zst"

[linux]
package-linux: _dist
    cargo build --all-features --locked --release
    mkdir "dist/wol-$(git describe)-linux-x86_64"
    mv -t "dist/wol-$(git describe)-linux-x86_64" target/release/wol
    env LC_ALL=C tar --numeric-owner --owner 0 --group 0 --sort name \
        --mode='go+u,go-w' --format=posix \
        --pax-option=exthdr.name=%d/PaxHeaders/%f \
        --pax-option=delete=atime,delete=ctime \
        -C dist/ \
        -c -f "dist/wol-$(git describe)-linux-x86_64.tar.zst" --zstd \
        "wol-$(git describe)-linux-x86_64"
    rm -rf dist/wol-$(git describe)-linux-x86_64
    ssh-keygen -Y sign -f dist/.key -n file "dist/wol-$(git describe)-linux-x86_64.tar.zst"

[windows]
package-windows: _dist
    cargo build --all-features --locked --release
    7z a "dist/wol-$(git describe)-windows-x86_64.zip" target/release/wol.exe
    ssh-keygen -Y sign -f dist/.key -n file "dist/wol-$(git describe)-windows-x86_64.zip"

[linux]
_package-os: package-linux

[windows]
_package-os: package-windows

package: _git-archive _vendor _package-os

_post-release:
    @echo "Create a release for the new version at https://codeberg.org/swsnr/wol.rs/tags"
    @echo "Upload dist/ to the release"

release *ARGS: test-all && package _post-release
    cargo release {{ARGS}}
