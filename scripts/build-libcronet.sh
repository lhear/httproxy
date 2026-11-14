#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
lock="$root/naiveproxy.lock"
work=${CRONET_BUILD_DIR:-$root/.cronet-build}

triple=${1:?usage: build-libcronet.sh <target-triple> [destination]}
destination=${2:-$root/cronet}

if [ ! -f "$lock" ]; then
    echo "naiveproxy.lock is missing" >&2
    exit 1
fi

repository=$(awk '$1 == "repository" { print $2; exit }' "$lock")
commit=$(awk '$1 == "commit" { print $2; exit }' "$lock")
if [ -z "$repository" ] || [ -z "$commit" ]; then
    echo "naiveproxy.lock needs a repository and a commit" >&2
    exit 1
fi

openwrt=
mac=
elf=0
shared=0
windows_static=0
output=static

case "$triple" in
x86_64-unknown-linux-gnu)
    target='target_os="linux" target_cpu="x64"'
    elf=1
    shared=1
    ;;
aarch64-unknown-linux-gnu)
    target='target_os="linux" target_cpu="arm64"'
    elf=1
    shared=1
    ;;
x86_64-unknown-linux-musl)
    target='target_os="openwrt" target_cpu="x64" build_static=true use_allocator_shim=false use_partition_alloc=false'
    openwrt='arch=x86_64 release=24.10.0 gcc_ver=13.3.0 target=x86 subtarget=64'
    elf=1
    ;;
aarch64-unknown-linux-musl)
    target='target_os="openwrt" target_cpu="arm64" build_static=true use_allocator_shim=false use_partition_alloc=false'
    openwrt='arch=aarch64_generic release=24.10.0 gcc_ver=13.3.0 target=layerscape subtarget=armv8_64b'
    elf=1
    ;;
x86_64-linux-android)
    target='target_os="android" target_cpu="x64" is_desktop_android=true default_min_sdk_version=24 is_high_end_android=true'
    elf=1
    ;;
aarch64-linux-android)
    target='target_os="android" target_cpu="arm64" is_desktop_android=true default_min_sdk_version=24 is_high_end_android=true'
    elf=1
    ;;
x86_64-apple-darwin)
    target='target_os="mac" target_cpu="x64"'
    mac=1
    ;;
aarch64-apple-darwin)
    target='target_os="mac" target_cpu="arm64"'
    mac=1
    ;;
x86_64-pc-windows-msvc)
    target='target_os="win" target_cpu="x64"'
    output=dll
    windows_static=${CRONET_WINDOWS_STATIC:-1}
    ;;
aarch64-pc-windows-msvc)
    target='target_os="win" target_cpu="arm64"'
    output=dll
    windows_static=${CRONET_WINDOWS_STATIC:-1}
    ;;
*)
    echo "no Cronet build for $triple" >&2
    exit 1
    ;;
esac

args='is_official_build=true
is_chrome_branded=true
exclude_unwind_tables=true
enable_resource_allowlist_generation=false
symbol_level=0
is_clang=true
use_sysroot=false
fatal_linker_warnings=false
treat_warnings_as_errors=false
use_clang_modules=false
is_cronet_build=true
use_udev=false
use_aura=false
use_ozone=false
use_gio=false
use_glib=false
use_platform_icu_alternatives=true
is_perfetto_embedder=true
disable_file_support=true
enable_websockets=false
use_kerberos=false
disable_zstd_filter=false
enable_mdns=false
enable_reporting=false
include_transport_security_state_preload_list=false
enable_device_bound_sessions=false
enable_bracketed_proxy_uris=true
enable_quic_proxy_support=true
enable_disk_cache_sql_backend=false
use_nss_certs=false
enable_backup_ref_ptr_support=false
enable_dangling_raw_ptr_checks=false
use_thin_lto=false
is_cfi=false
use_cfi_icall=false
chrome_pgo_phase=2'

if [ -n "$mac" ]; then
    args="$args
mac_allow_system_xcode_for_official_builds_for_testing=true
enable_dsyms=false"
fi

ninja_targets=cronet_static
if [ "$shared" = 1 ]; then
    ninja_targets="cronet_static cronet"
fi
if [ "$output" = dll ]; then
    ninja_targets=cronet
    if [ "$windows_static" = 1 ]; then
        ninja_targets="cronet cronet_static"
    fi
fi

if [ "${CRONET_DRY_RUN:-0}" = 1 ]; then
    printf 'triple %s\nargs %s %s\nninja %s\n' "$triple" "$args" "$target" "$ninja_targets"
    exit 0
fi

src=$work/naiveproxy/src

fetch() {
    if [ -d "$work/naiveproxy/.git" ] && [ "$(git -C "$work/naiveproxy" rev-parse HEAD 2>/dev/null || true)" = "$commit" ]; then
        return
    fi
    rm -rf "$work/naiveproxy"
    mkdir -p "$work/naiveproxy"
    git -C "$work/naiveproxy" init --quiet
    git -C "$work/naiveproxy" fetch --quiet --depth 1 "$repository" "$commit"
    git -C "$work/naiveproxy" checkout --quiet --detach "$commit"
}

value() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | head -n 1
}

manifest() {
    ninja_file=$1
    to=$2
    : > "$to"
    for lib in $(value libs "$ninja_file"); do
        case "$lib" in
        *.lds) ;;
        -l:*) printf 'arg=%s\n' "$lib" >> "$to" ;;
        -l*) printf 'lib=%s\n' "${lib#-l}" >> "$to" ;;
        *) printf 'arg=%s\n' "$lib" >> "$to" ;;
        esac
    done
    set -- $(value frameworks "$ninja_file")
    while [ $# -gt 0 ]; do
        if [ "$1" = "-framework" ] && [ $# -ge 2 ]; then
            printf 'framework=%s\n' "$2" >> "$to"
            shift 2
        else
            shift
        fi
    done
    for flag in $(value ldflags "$ninja_file"); do
        case "$flag" in
        -Wl,-wrap,*) printf 'arg=%s\n' "$flag" >> "$to" ;;
        esac
    done
}

prelink() {
    archive=$1
    to=$2
    bin=$src/third_party/llvm-build/Release+Asserts/bin
    scratch=$work/prelink/$triple
    mkdir -p "$scratch"
    "$bin/llvm-nm" --defined-only --extern-only --format=just-symbols --quiet "$archive" |
        grep -E '^(Cronet_|bidirectional_stream_|__wrap_)[A-Za-z0-9_.]*$|^(aligned_alloc|calloc|cfree|free|malloc|malloc_size|malloc_usable_size|memalign|posix_memalign|pvalloc|realloc|valloc|__libc_calloc|__libc_cfree|__libc_free|__libc_malloc|__libc_memalign|__libc_pvalloc|__libc_realloc|__libc_valloc|__posix_memalign)$' |
        sort -u > "$scratch/globals.txt" || true
    if ! grep -q '^Cronet_' "$scratch/globals.txt"; then
        echo "$archive defines none of Cronet's C API" >&2
        exit 1
    fi
    set -- "$bin/ld.lld" -r --force-group-allocation
    while read -r symbol; do
        set -- "$@" -u "$symbol"
    done < "$scratch/globals.txt"
    "$@" "$archive" -o "$scratch/libcronet.o"
    "$bin/llvm-objcopy" --keep-global-symbols="$scratch/globals.txt" "$scratch/libcronet.o"
    rm -f "$to"
    "$bin/llvm-ar" rcsD "$to" "$scratch/libcronet.o"
    rm -f "$scratch/libcronet.o" "$scratch/globals.txt"
}

fetch

sysroot=$(cd "$src" && EXTRA_FLAGS="$target" OPENWRT_FLAGS="$openwrt" sh -c '. ./get-sysroot.sh >/dev/null && printf %s "${WITH_SYSROOT:-}"')

keyring=$src/build/linux/sysroot_scripts/keyring.gpg
if [ -n "$sysroot" ] && [ ! -d "$src/$sysroot/lib" ] && [ -f "$keyring" ] && command -v gpg >/dev/null 2>&1; then
    rm -f "$keyring"
    (cd "$src" && bash ./build/linux/sysroot_scripts/generate_keyring.sh)
fi

(
    cd "$src"
    EXTRA_FLAGS="$target" OPENWRT_FLAGS="$openwrt" sh ./get-clang.sh
)

if [ -n "$sysroot" ]; then
    args="$args
target_sysroot=\"//$sysroot\""
fi
if command -v ccache >/dev/null 2>&1; then
    args="$args
cc_wrapper=\"ccache\""
fi

gn=$src/gn/out/gn
if [ -f "$src/gn/out/gn.exe" ]; then
    gn=$src/gn/out/gn.exe
fi

(
    cd "$src"
    DEPOT_TOOLS_WIN_TOOLCHAIN=0 "$gn" gen out/cronet --args="$args $target"
    ninja -C out/cronet $ninja_targets
)

out=$src/out/cronet
package=$destination/$triple
rm -rf "$package"
mkdir -p "$package"

case "$output" in
dll)
    cp "$out/cronet.dll" "$package/cronet.dll"
    cp "$out/cronet.dll.lib" "$package/cronet.dll.lib"
    if [ "$windows_static" = 1 ]; then
        cp "$out/obj/components/cronet/cronet_static.lib" "$package/cronet.lib"
        manifest "$out/obj/components/cronet/cronet_sample.ninja" "$package/cronet.link"
    fi
    ;;
*)
    archive=$out/obj/components/cronet/libcronet_static.a
    if [ "$elf" = 1 ] && [ "${CRONET_PRELINK:-1}" = 1 ]; then
        prelink "$archive" "$package/libcronet.a"
    else
        cp "$archive" "$package/libcronet.a"
    fi
    if [ "$shared" = 1 ]; then
        cp "$out/libcronet.so" "$package/libcronet.so"
    fi
    manifest "$out/obj/components/cronet/cronet_sample.ninja" "$package/cronet.link"
    ;;
esac

cp "$work/naiveproxy/CHROMIUM_VERSION" "$package/VERSION"
cp "$work/naiveproxy/LICENSE" "$package/LICENSE"

echo "$(cd "$package" && pwd)"
