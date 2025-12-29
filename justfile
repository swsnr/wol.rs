MSRV := `cargo +stable metadata --no-deps --format-version 1 | jq -r '.packages | map(select(.name == "wol")) | first | .rust_version'`

default:
    just --list

clean:
    rm -rf dist

_dist:
    rm -rf dist
    mkdir -p dist
    curl https://codeberg.org/swsnr.keys > dist/.key

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

package: _package-os

_post-release:
    @echo "Create a release for the new version at https://codeberg.org/swsnr/wol.rs/tags"
    @echo "Upload dist/ to the release"

release *ARGS: && package _post-release
    cargo release {{ARGS}}
