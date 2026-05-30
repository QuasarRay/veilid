import sys
from typing import Annotated
from pathlib import Path
import os

import dagger
from dagger import Ignore, dag, function, object_type
import platform

VEILID_REPO = "registry.gitlab.com/veilid/veilid"
ZIG_VERSION = "0.13.0"
CMAKE_VERSION_MINOR = "4.0"
CMAKE_VERSION_PATCH = "4.0.2"
BINARYEN_VERSION = "125"
RUST_VERSION = "1.92.0"
RUST_UNIT_TESTS_NIGHTLY_VERSION="nightly-2026-01-01"
RUST_PACKAGE_TESTS_NIGHTLY_VERSION="nightly"
RETRY_COUNT = "12"
RUSTUP_HOME = "/usr/local/rustup"
RUSTUP_DIST_SERVER = "https://static.rust-lang.org"
CARGO_HOME = "/usr/local/cargo"
# Disable incremental compilation in CI - useless in ephemeral containers and wastes disk
CARGO_INCREMENTAL = "0" 
# Reduce debug info to line-tables-only (still gives backtraces, much smaller binaries)
CARGO_PROFILE_TEST_DEBUGINFO = "1"
# Limit parallel jobs to match medium runner resources (2 vCPU, 8GB RAM)
CARGO_BUILD_JOBS = "1"


# Contains ignore patterns that are not included in the .gitignore file
DIRECTORY_IGNORE_PATTERNS = [
    ".dagger/",
    "dagger.gen.go",
    "dagger.json",
]

# Validate host architecture
ARCH = platform.machine()
if ARCH == "x86_64":
    DEFAULT_CARGO_TARGET = "x86_64-unknown-linux-gnu"
    DEFAULT_CARGO_MUSL_TARGET = "x86_64-unknown-linux-musl"
elif ARCH == "aarch64":
    DEFAULT_CARGO_TARGET = "aarch64-unknown-linux-gnu"
    DEFAULT_CARGO_MUSL_TARGET = "aarch64-unknown-linux-musl"
else:
    raise ValueError(f"Unsupported host platform: {ARCH}")

@object_type
class Veilid:

    def _base_container(self) -> dagger.Container:
        """Creates the base container with all environment variables and initial setup"""

        return (
            dag.container()
            .from_("ubuntu:18.04")
            .with_env_variable("RUSTUP_HOME", RUSTUP_HOME)
            .with_env_variable("RUSTUP_DIST_SERVER", RUSTUP_DIST_SERVER)
            .with_env_variable("CARGO_HOME", CARGO_HOME)
            .with_env_variable("CARGO_INCREMENTAL", CARGO_INCREMENTAL)
            .with_env_variable("CARGO_PROFILE_TEST_DEBUGINFO", CARGO_PROFILE_TEST_DEBUGINFO)
            .with_env_variable("CARGO_BUILD_JOBS", CARGO_BUILD_JOBS)
            .with_env_variable("PATH", f"$PATH:{CARGO_HOME}/bin:/usr/local/zig", expand=True)
            .with_env_variable("LD_LIBRARY_PATH", "/usr/local/lib")
            .with_env_variable("RUST_BACKTRACE", "1")
            .with_env_variable("BINSTALL_DISABLE_TELEMETRY", "true")
            .with_env_variable("BINSTALL_NO_CONFIRM", "true")
            .with_env_variable("DEFAULT_CARGO_TARGET", DEFAULT_CARGO_TARGET)
            .with_workdir("/veilid")
        )

    @function
    def deps_base(self) -> dagger.Container:
        """Install build prerequisites & setup required directories"""
        container = self._base_container()

        # Configure apt
        apt_config = f"""Acquire::Retries "{RETRY_COUNT}";
        Acquire::https::Timeout "240";
        Acquire::http::Timeout "240";
        APT::Get::Assume-Yes "true";
        APT::Install-Recommends "false";
        APT::Install-Suggests "false";
        Debug::Acquire::https "true";"""

        container = container.with_new_file("/etc/apt/apt.conf.d/99custom", apt_config)

        # Update package lists
        container = container.with_exec(["apt-get", "-y", "update"])

        # Install base packages including Windows cross-compilation tools
        base_packages = [
            "apt-get", "install", "-y",
            "ca-certificates", "iproute2", "curl", "build-essential",
            "libssl-dev", "openssl", "file", "git", "pkg-config",
            "libdbus-1-dev", "libdbus-glib-1-dev", "libgirepository1.0-dev",
            "libcairo2-dev", "checkinstall", "unzip", "zip", "libncursesw5-dev",
            "libncurses5-dev", "gcc-mingw-w64-x86-64", "mingw-w64", "jq"
        ]
        container = container.with_exec(base_packages)

        # Install cross-compilation toolchains and development libraries based on architecture
        arch = platform.machine()
        if arch == "x86_64":
            container = container.with_exec([
                "apt-get", "install", "-y",
                "gcc-aarch64-linux-gnu", "libc6-dev-arm64-cross"
            ])
        elif arch == "aarch64":
            container = container.with_exec([
                "apt-get", "install", "-y",
                "gcc-x86-64-linux-gnu", "libc6-dev-amd64-cross", "gcc-multilib-x86-64-linux-gnu"
            ])
        else:
            container = container.with_exec([
                "apt-get", "install", "-y",
                "gcc-aarch64-linux-gnu", "gcc-x86-64-linux-gnu",
                "libc6-dev-arm64-cross", "libc6-dev-amd64-cross", "gcc-multilib-x86-64-linux-gnu"
            ])

        # Install CMake
        arch = platform.machine()
        cmake_url = f"https://cmake.org/files/v{CMAKE_VERSION_MINOR}/cmake-{CMAKE_VERSION_PATCH}-linux-{arch}.sh"
        container = (
            container
            .with_exec(["curl", "--retry", RETRY_COUNT, "--retry-connrefused", "-O", cmake_url])
            .with_exec(["mkdir", "/opt/cmake"])
            .with_exec(["sh", f"cmake-{CMAKE_VERSION_PATCH}-linux-{arch}.sh", "--skip-license", "--prefix=/opt/cmake"])
            .with_exec(["ln", "-s", "/opt/cmake/bin/cmake", "/usr/local/bin/cmake"])
        )

        return container

    @function
    def deps_rust(self) -> dagger.Container:
        """Install Rust toolchain, targets, and cargo tools"""
        container = self.deps_base()

        # Install rustup and Rust toolchain
        container = container.with_exec([
            "sh", "-c",
            f"curl --retry {RETRY_COUNT} --retry-connrefused --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain={RUST_VERSION} -y -c clippy --no-modify-path --profile minimal"
        ])

        # Set permissions and verify installation
        container = container.with_exec([
            "chmod", "-R", "a+w", RUSTUP_HOME, CARGO_HOME
        ]).with_exec([
            "rustup", "--version"
        ]).with_exec([
            "cargo", "--version"
        ]).with_exec([
            "rustc", "--version"
        ])

        # Install Rust targets with retry logic
        rust_targets = [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-gnu",
            # "aarch64-pc-windows-gnullvm",
            "aarch64-apple-darwin",
            "aarch64-linux-android",
            "armv7-linux-androideabi",
            "i686-linux-android",
            "x86_64-linux-android",
            "wasm32-unknown-unknown"
        ]

        # Add targets (simplified without complex retry logic for now)
        for target in rust_targets:
            container = container.with_exec(["rustup", "target", "add", target])

        # Add a single default-target nightly toolchain for some tests
        container = container.with_exec(["rustup", "toolchain", "install", f"{RUST_UNIT_TESTS_NIGHTLY_VERSION}", "-c", "miri,rust-src"])

        # Install cargo tools (try binstall of musl targets first, then fallback to regular install)
        # (Doing it this way so we don't have to install the musl rust targets, which binstall will default to building with)
        container = container.with_exec([
            "sh", "-c",
            "curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash",
        ]).with_exec([
            "sh", "-c",
            f"curl --retry {RETRY_COUNT} --retry-connrefused -L --proto '=https' --tlsv1.2 -sSf https://gitlab.com/api/v4/projects/79785586/packages/generic/cargo-chef/0.1.73/cargo-chef-x86_64-unknown-linux-musl.tar.gz | tar -xz -C {CARGO_HOME}/bin"
        ]).with_exec([
            "sh", "-c",
            f"cargo binstall cargo-msrv --disable-strategies=compile --targets {DEFAULT_CARGO_MUSL_TARGET} || cargo install cargo-msrv --locked"
        ]).with_exec([
            "sh", "-c",
            f"cargo binstall cargo-nextest --disable-strategies=compile --targets {DEFAULT_CARGO_MUSL_TARGET} || cargo install cargo-nextest --locked"
        ]).with_exec([
            "sh", "-c",
            f"cargo binstall cargo-docs-rs --disable-strategies=compile --targets {DEFAULT_CARGO_MUSL_TARGET} || cargo install cargo-docs-rs --locked"
        ])

        # Install Zig for cross-compilation (no binstall available for zigbuild yet)
        arch = platform.machine()
        zig_url = f"https://ziglang.org/download/{ZIG_VERSION}/zig-linux-{arch}-{ZIG_VERSION}.tar.xz"
        container = (
            container
            .with_exec(["curl", "--retry", RETRY_COUNT, "--retry-connrefused", "-L", "-O", zig_url])
            .with_exec(["tar", "-C", "/usr/local", "-xJf", f"zig-linux-{arch}-{ZIG_VERSION}.tar.xz"])
            .with_exec(["mv", f"/usr/local/zig-linux-{arch}-{ZIG_VERSION}", "/usr/local/zig"])
            .with_exec(["cargo", "install", "cargo-zigbuild", "--locked"])
        )

        # Install binaryen wasm-opt
        binaryen_url = f"https://github.com/WebAssembly/binaryen/releases/download/version_{BINARYEN_VERSION}/binaryen-version_{BINARYEN_VERSION}-{arch}-linux.tar.gz"
        container = (
            container
            .with_exec(["curl", "--retry", RETRY_COUNT, "--retry-connrefused", "-L", "-o", "binaryen.tar.gz", "-O", binaryen_url])
            .with_exec(["mkdir", "/tmp/binaryen"])
            .with_exec(["tar", "-C", "/tmp/binaryen", "-xvf", "binaryen.tar.gz", f"--strip-components=1"])
            .with_exec(["cp", f"/tmp/binaryen/bin/wasm-opt", f"{CARGO_HOME}/bin"])
        )

        return container

    @function
    def deps_linux(self) -> dagger.Container:
        """Linux build dependencies (base + rust without Android tools)"""
        # In Dagger, we can simply call deps_rust which already includes everything needed
        # The Earthfile version copies artifacts, but in Dagger the container already has everything
        return self.deps_rust()

    @function
    def deps_cache(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)]) -> dagger.Container:
        """Pre-compile Rust dependencies for faster builds using cargo-chef"""
        container = self.deps_linux()

        # Create project directory structure
        container = container.with_exec([
            "mkdir", "-p",
            "veilid-cli", "veilid-core", "veilid-core/examples/basic",
            "veilid-core/examples/private_route", "veilid-server", "veilid-tools",
            "veilid-wasm", "veilid-flutter", "veilid-flutter/rust", "veilid-remote-api"
        ])

        # Copy only Cargo.toml files and build configuration for dependency resolution
        container = (
            container
            .with_file(".cargo/config.toml", source.file(".cargo/config.toml"))
            .with_file("Cargo.lock", source.file("Cargo.lock"))
            .with_file("Cargo.toml", source.file("Cargo.toml"))
            .with_file("veilid-cli/Cargo.toml", source.file("veilid-cli/Cargo.toml"))
            .with_file("veilid-core/Cargo.toml", source.file("veilid-core/Cargo.toml"))
            .with_file("veilid-core/examples/basic/Cargo.toml", source.file("veilid-core/examples/basic/Cargo.toml"))
            .with_file("veilid-core/examples/private_route/Cargo.toml", source.file("veilid-core/examples/private_route/Cargo.toml"))
            .with_file("veilid-server/Cargo.toml", source.file("veilid-server/Cargo.toml"))
            .with_file("veilid-tools/Cargo.toml", source.file("veilid-tools/Cargo.toml"))
            .with_file("veilid-remote-api/Cargo.toml", source.file("veilid-remote-api/Cargo.toml"))
            .with_file("veilid-flutter/rust/Cargo.toml", source.file("veilid-flutter/rust/Cargo.toml"))
            .with_file("veilid-wasm/Cargo.toml", source.file("veilid-wasm/Cargo.toml"))
        )

        # Prepare cargo chef recipe based on dependencies
        # Careful not to include veilid-flutter or veilid-wasm in the package lists here as they add the 'json-camel-case' feature
        # which will screw up the build of veilid-server because it will automatically add that feature inappropriately

        container = container.with_exec([
            "cargo", "chef", "prepare", "--recipe-path", "recipe.json"
        ])

        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--profile=test", "--tests",
            "--target", DEFAULT_CARGO_TARGET, "--all-targets", "--locked", 
            "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools",
            "-p", "veilid-core", "-p", "veilid-remote-api"
        ])

        # Cook dependencies for clippy x86_64-unknown-linux-gnu
        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--zigbuild=clippy",
            "--target", "x86_64-unknown-linux-gnu", "--all-targets", "--locked", 
            "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools",
            "-p", "veilid-core", "-p", "veilid-remote-api"
        ])

        # Cook dependencies for clippy aarch64-unknown-linux-gnu
        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--zigbuild=clippy",
            "--target", "aarch64-unknown-linux-gnu", "--all-targets", "--locked", 
            "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools",
            "-p", "veilid-core", "-p", "veilid-remote-api"
        ])

        # Cook dependencies for clippy x86_64-pc-windows-gnu
        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--zigbuild=clippy",
            "--target", "x86_64-pc-windows-gnu", "--all-targets", "--locked", 
            "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools",
            "-p", "veilid-core", "-p", "veilid-remote-api"
        ])

        # Cook dependencies for clippy aarch64-apple-darwin
        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--zigbuild=clippy",
            "--target", "aarch64-apple-darwin", "--all-targets", "--locked", 
            "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools",
            "-p", "veilid-core", "-p", "veilid-remote-api"
        ])

        # Cook WASM dependencies
        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--zigbuild=clippy",
            "--target", "wasm32-unknown-unknown", "--all-targets", "--locked",
            "-p", "veilid-wasm"
        ])
        container = container.with_exec([
            "cargo", "chef", "cook", "--recipe-path", "recipe.json", "--zigbuild=clippy",
            "--target", "wasm32-unknown-unknown", "--all-targets", "--locked",
            "--no-default-features", "--features=default-wasm",
            "-p", "veilid-flutter"
        ])

        return container

    @function
    def code_linux(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Container:
        """Import the whole veilid code repository with build dependencies"""
        # Choose base container based on BASE parameter
        if base == "local":
            # Use local deps_cache (equivalent to +build-linux-cache)
            container = self.deps_cache(source)
        elif base == "uncached":
            # Use just deps-linux without cache
            container = self.deps_linux()
        else:
            # Use remote cache image from registry (equivalent to container mode)
            container = dag.container().from_(f"{ci_registry_image}/build-cache:latest")

        # Copy the full source code
        container = (
            container
            .with_directory("/veilid", source)
            .with_workdir("/veilid")
        )

        # Check to make sure Cargo.lock is up to date
        container = container.with_exec(["cargo", "update", "-w", "--locked"])

        # Restore original Cargo.lock (copy it again to ensure it's preserved)
        container = container.with_file("Cargo.lock", source.file("Cargo.lock"))

        # Install the wasm-bindgen CLI tool that we need, which depends on the Cargo.lock version of wasm-bindgen being used
        container = container.with_exec([
            "sh", "-c", 
            f"WASM_BINDGEN_VERSION=$(cargo tree --locked -p veilid-wasm -i wasm-bindgen | head -n 1 | cut -c 15-); "
            f"cargo binstall wasm-bindgen-cli --disable-strategies=compile --targets {DEFAULT_CARGO_MUSL_TARGET} --version $WASM_BINDGEN_VERSION || "
            f"cargo install wasm-bindgen-cli --locked --version $WASM_BINDGEN_VERSION"
        ])

        return container

    @function
    async def clippy(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run clippy linting for multiple targets"""
        container = self.code_linux(source, base, ci_registry_image)

        # Run clippy for different targets
        result = await container.with_exec(["./scripts/_clippy_all.sh", "--cleanup"]).combined_output()

        return f"Clippy completed:\n{result}"

    @function
    async def msrv(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run MSRV checks for all crates"""
        container = self.code_linux(source, base, ci_registry_image)

        result = await container.with_exec(["./scripts/_msrv_all.sh"]).combined_output()

        return f"MSRV check completed:\n{result}"

    @function
    def build_windows_amd64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Build Windows AMD64 binaries and return the target directory"""
        container = self.code_linux(source, base, ci_registry_image)
        target="x86_64-pc-windows-gnu"

        # Build release binaries for x86_64-pc-windows-gnu
        # Careful not to include veilid-flutter or veilid-wasm here as they add the 'json-camel-case' feature
        # which will screw up the build of veilid-server because it will automatically add that feature inappropriately
        out = (
            container.with_exec([
                "cargo", "zigbuild", "--locked", "--target", target, "--release", "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools", "-p", "veilid-core", "-p", "veilid-remote-api"
            ])
            .with_exec(["rm", "-rf", f"./target/{target}/release/.fingerprint"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/build"]) 
            .with_exec(["rm", "-rf", f"./target/{target}/release/deps"]) 
            .with_exec(["rm", "-rf", f"./target/{target}/release/examples"]) 
            .with_exec(["rm", "-rf", f"./target/{target}/release/incremental"]) 
            .directory(f"./target/{target}/release")
        )

        # Return the built artifacts directory
        return out


    @function
    def build_linux_amd64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Build Linux AMD64 binaries and return the target directory"""
        container = self.code_linux(source, base, ci_registry_image)
        target="x86_64-unknown-linux-gnu"

        # Build release binaries for x86_64-unknown-linux-gnu
        # Careful not to include veilid-flutter or veilid-wasm here as they add the 'json-camel-case' feature
        # which will screw up the build of veilid-server because it will automatically add that feature inappropriately
        out = (
            container.with_exec([
                "cargo", "zigbuild", "--locked", "--target", target, "--release", "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools", "-p", "veilid-core", "-p", "veilid-remote-api"
            ])
            .with_exec(["rm", "-rf", f"./target/{target}/release/.fingerprint"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/build"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/deps"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/examples"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/incremental"])
            .directory(f"./target/{target}/release")
        )

        # Return the built artifacts directory
        return out

    @function
    def build_linux_arm64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Build Linux ARM64 binaries and return the target directory"""
        container = self.code_linux(source, base, ci_registry_image)
        target="aarch64-unknown-linux-gnu"

        # Build release binaries for aarch64-unknown-linux-gnu
        # Careful not to include veilid-flutter or veilid-wasm here as they add the 'json-camel-case' feature
        # which will screw up the build of veilid-server because it will automatically add that feature inappropriately
        out = (
            container.with_exec([
                "cargo", "zigbuild", "--locked", "--target", target, "--release", "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools", "-p", "veilid-core", "-p", "veilid-remote-api"
            ])
            .with_exec(["rm", "-rf", f"./target/{target}/release/.fingerprint"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/build"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/deps"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/examples"])
            .with_exec(["rm", "-rf", f"./target/{target}/release/incremental"])
            .directory(f"./target/{target}/release")
        )

        # Return the built artifacts directory
        return out

    # No support yet. One could do this with a host-mount of the Apple Developer SDKs and running on a MacOS machine.
    # @function
    # def build_macos_arm64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
    #     """Build MacOS ARM64 binaries and return the target directory"""
    #     container = self.code_linux(source, base, ci_registry_image)
    #     target="aarch64-apple-darwin"
    #     # Build release binaries for aarch64-apple-darwin
    #     # Careful not to include veilid-flutter or veilid-wasm here as they add the 'json-camel-case' feature
    #     # which will screw up the build of veilid-server because it will automatically add that feature inappropriately
    #     out = (
    #         container.with_exec([
    #             "cargo", "zigbuild", "--locked", "--target", target, "--release", "-p", "veilid-server", "-p", "veilid-cli", "-p", "veilid-tools", "-p", "veilid-core", "-p", "veilid-remote-api"
    #         ])
    #         .with_exec(["rm", "-rf", f"./target/{target}/release/.fingerprint"])
    #         .with_exec(["rm", "-rf", f"./target/{target}/release/build"])
    #         .with_exec(["rm", "-rf", f"./target/{target}/release/deps"])
    #         .with_exec(["rm", "-rf", f"./target/{target}/release/examples"])
    #         .with_exec(["rm", "-rf", f"./target/{target}/release/incremental"])
    #         .directory(f"./target/{target}/release")
    #     )

    #     # Return the built artifacts directory
    #     return out

    @function
    async def test_msrv_all(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run MSRV checks for all crates"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_msrv_all.sh"]).combined_output()
        return f"MSRV check completed:\n{result}"

    @function
    async def test_check_wasm_builds_dart(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Check WASM builds for Dart"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_check_wasm_builds.sh", "dart"]).combined_output()
        return f"WASM Dart build check completed:\n{result}"

    @function
    async def test_check_wasm_builds_js(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Check WASM builds for JS"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_check_wasm_builds.sh", "js"]).combined_output()
        return f"WASM JS build check completed:\n{result}"

    @function
    async def test_clippy_wasm32_unknown_unknown(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run clippy for wasm32-unknown-unknown"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_clippy_wasm32_unknown_unknown.sh"]).combined_output()
        return f"Clippy wasm32-unknown-unknown completed:\n{result}"

    @function
    async def test_clippy_x86_64_pc_windows_gnu(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run clippy for x86_64-pc-windows-gnu"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_clippy_x86_64_pc_windows_gnu.sh"]).combined_output()
        return f"Clippy x86_64-pc-windows-gnu completed:\n{result}"

    @function
    async def test_clippy_aarch64_apple_darwin(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run clippy for aarch64-apple-darwin"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_clippy_aarch64_apple_darwin.sh"]).combined_output()
        return f"Clippy aarch64-apple-darwin completed:\n{result}"

    @function
    async def test_clippy_x86_64_unknown_linux_gnu(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run clippy for x86_64-unknown-linux-gnu"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_clippy_x86_64_unknown_linux_gnu.sh"]).combined_output()
        return f"Clippy x86_64-unknown-linux-gnu completed:\n{result}"

    @function
    async def test_clippy_x86_64_unknown_linux_gnu_async_std(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run clippy for x86_64-unknown-linux-gnu with async-std"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_clippy_x86_64_unknown_linux_gnu_async_std.sh"]).combined_output()
        return f"Clippy x86_64-unknown-linux-gnu async-std completed:\n{result}"

    @function
    async def test_build_docs(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Build documentation"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_build_docs.sh"]).combined_output()
        return f"Documentation build completed:\n{result}"

    @function
    async def test_unit_tests_all(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run all unit tests"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_unit_tests_all.sh"]).combined_output()
        return f"Unit tests completed:\n{result}"

    @function
    async def test_all(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Run all tests (serially! for desktop, not CI use!)"""
        results = []
        results.append(await self.test_msrv_all(source, base, ci_registry_image))
        results.append(await self.test_check_wasm_builds_dart(source, base, ci_registry_image))
        results.append(await self.test_check_wasm_builds_js(source, base, ci_registry_image))
        results.append(await self.test_clippy_wasm32_unknown_unknown(source, base, ci_registry_image))
        results.append(await self.test_clippy_x86_64_pc_windows_gnu(source, base, ci_registry_image))
        results.append(await self.test_clippy_aarch64_apple_darwin(source, base, ci_registry_image))
        results.append(await self.test_clippy_x86_64_unknown_linux_gnu(source, base, ci_registry_image))
        results.append(await self.test_clippy_x86_64_unknown_linux_gnu_async_std(source, base, ci_registry_image))
        results.append(await self.test_build_docs(source, base, ci_registry_image))
        results.append(await self.test_unit_tests_all(source, base, ci_registry_image))
        return "\n\n=== TEST SUMMARY ===\n" + "\n\n".join(results)

    @function
    async def test_docs(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], rust_nightly_version: str , base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Build and test documentation with a specific nightly version (for package testing)"""
        container = self.code_linux(source, base, ci_registry_image)
        result = await container.with_exec(["./scripts/_build_docs.sh", rust_nightly_version]).combined_output()
        return f"Documentation build completed:\n{result}"

    @function
    async def package_test_all(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> str:
        """Tests to run before packaging releases"""
        results = []

        # Test DOCS.RS build with most recent nightly (this will probably install a newer version than what is in the cache, but for this test it is important to use the latest nightly)
        docs_result = await self.test_docs(source, RUST_PACKAGE_TESTS_NIGHTLY_VERSION, base, ci_registry_image)
        results.append(docs_result)

        return "\n\n=== TEST SUMMARY ===\n" + "\n\n".join(results)

    @function
    def package_deb(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], target_arch: str, is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package DEB files for specified architecture"""
        # Get built binaries
        if target_arch == "amd64":
            build_dir = self.build_linux_amd64(source)
            rust_target = "x86_64-unknown-linux-gnu"
        elif target_arch == "arm64":
            build_dir = self.build_linux_arm64(source)
            rust_target = "aarch64-unknown-linux-gnu"
        else:
            raise ValueError(f"Unsupported architecture: {target_arch}")

        # Start with code-linux for the packaging scripts
        container = self.code_linux(source, base, ci_registry_image)

        # Copy build artifacts into container
        container = (
            container
            .with_directory("/veilid/package", source.directory("package"))
            .with_file(f"/veilid/target/{rust_target}/release/veilid-server", build_dir.file("veilid-server"))
            .with_file(f"/veilid/target/{rust_target}/release/veilid-cli", build_dir.file("veilid-cli"))
        )

        # Set nightly flag
        nightly_flag = "true" if is_nightly else "false"

        # Create DEB packages
        container = (
            container
            .with_exec([
                "/veilid/package/debian/earthly_make_veilid_server_deb.sh",
                target_arch, rust_target, nightly_flag
            ])
            .with_exec([
                "/veilid/package/debian/earthly_make_veilid_cli_deb.sh",
                target_arch, rust_target, nightly_flag
            ])
        )

        # Return the package output directory
        return container.directory("/dpkg/out")

    @function
    def package_rpm(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], target_arch: str, is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package RPM files for specified architecture"""
        # Get built binaries
        if target_arch == "x86_64":
            build_dir = self.build_linux_amd64(source,base,ci_registry_image)
            rust_target = "x86_64-unknown-linux-gnu"
            platform = "linux/amd64"
        elif target_arch == "aarch64":
            build_dir = self.build_linux_arm64(source,base,ci_registry_image)
            rust_target = "aarch64-unknown-linux-gnu"
            platform = "linux/arm64"
        else:
            raise ValueError(f"Unsupported architecture: {target_arch}")

        # Use Rocky Linux for RPM packaging
        container = (
            dag.container(platform=dagger.Platform(platform))
            .from_("rockylinux:9")
            .with_exec(["yum", "install", "-y", "createrepo", "rpm-build", "rpm-sign", "yum-utils", "rpmdevtools"])
            .with_exec(["rpmdev-setuptree"])
        )

        # Set up directory structure
        container = (
            container
            .with_exec(["mkdir", "-p", "/veilid/target"])
            .with_exec(["mkdir", "-p", "/veilid/veilid-cli", "/veilid/veilid-server"])
            .with_exec(["mkdir", "-p", "/rpm-work-dir/veilid-server"])
        )

        # Copy necessary files
        container = (
            container
            .with_file("/veilid/veilid-cli/Cargo.toml", source.file("veilid-cli/Cargo.toml"))
            .with_file("/veilid/veilid-server/Cargo.toml", source.file("veilid-server/Cargo.toml"))
            .with_directory("/veilid/package", source.directory("package"))
            .with_file(f"/veilid/target/{rust_target}/release/veilid-server", build_dir.file("veilid-server"))
            .with_file(f"/veilid/target/{rust_target}/release/veilid-cli", build_dir.file("veilid-cli"))
        )

        # Set nightly flag
        nightly_flag = "true" if is_nightly else "false"

        # Create RPM packages
        container = (
            container
            .with_exec([
                "veilid/package/rpm/veilid-server/earthly_make_veilid_server_rpm.sh",
                target_arch, rust_target, nightly_flag
            ])
            .with_exec([
                "veilid/package/rpm/veilid-cli/earthly_make_veilid_cli_rpm.sh",
                target_arch, rust_target, nightly_flag
            ])
        )

        # Return the RPM output directory
        return container.directory(f"/root/rpmbuild/RPMS/{target_arch}")

    @function
    async def package_zip(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], target_arch: str, is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package ZIP files for specified architecture"""
        # Get built binaries
        if target_arch == "amd64":
            build_dir = self.build_windows_amd64(source, base, ci_registry_image)
            rust_target = "x86_64-pc-windows-gnu"
        # elif target_arch == "arm64":
        #     build_dir = self.build_windows_arm64(source, base, ci_registry_image)
        #     rust_target = "aarch64-pc-windows-gnullvm"
        else:
            raise ValueError(f"Unsupported architecture: {target_arch}")

        # Start with code-linux for the packaging scripts
        container = self.code_linux(source, base, ci_registry_image)

        # Copy build artifacts into container
        container = container.with_directory(f"/veilid/target/{rust_target}/release", build_dir)

        # Copy package directory
        container = container.with_directory("/veilid/package", source.directory("package"))

        # Create ZIP packages
        container = (
            container
            .with_workdir(f"/veilid/target/{rust_target}/release")
            .with_exec(["mkdir","-p","/out"])
            .with_exec(["/veilid/package/cargo_version.sh", "/veilid/veilid-server/Cargo.toml"],redirect_stdout="/tmp/version")
            .with_exec(["sh","-c",r"date '+%Y%m%d'"],redirect_stdout="/tmp/datestamp")
        )
        version = (await container.file("/tmp/version").contents()).strip()
        datestamp = (await container.file("/tmp/datestamp").contents()).strip()

        if is_nightly:
            container = container.with_exec([
                "zip",
                f"/out/veilid-{datestamp}_{target_arch}.zip",
                "veilid-server.exe",
                "veilid-cli.exe"
            ])
        else:
            container = container.with_exec([
                "zip",
                f"/out/veilid-{version}_{target_arch}.zip",
                "veilid-server.exe",
                "veilid-cli.exe"
            ])

        # Return the package output directory
        return container.directory("/out")

    @function
    def package_linux_amd64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package both DEB and RPM for Linux AMD64"""
        # Create a container to collect all packages
        container = dag.container().from_("alpine:latest").with_exec(["mkdir", "-p", "/packages"])

        # Get DEB packages
        deb_dir = self.package_deb(source, "amd64", is_nightly,base,ci_registry_image)
        container = container.with_directory("/packages/deb", deb_dir)

        # Get RPM packages
        rpm_dir = self.package_rpm(source, "x86_64", is_nightly,base,ci_registry_image)
        container = container.with_directory("/packages/rpm", rpm_dir)

        return container.directory("/packages")

    @function
    def package_linux_arm64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package both DEB and RPM for Linux ARM64"""
        # Create a container to collect all packages
        container = dag.container().from_("alpine:latest").with_exec(["mkdir", "-p", "/packages"])

        # Get DEB packages
        deb_dir = self.package_deb(source, "arm64", is_nightly, base, ci_registry_image)
        container = container.with_directory("/packages/deb", deb_dir)

        # Get RPM packages
        rpm_dir = self.package_rpm(source, "aarch64", is_nightly, base, ci_registry_image)
        container = container.with_directory("/packages/rpm", rpm_dir)

        return container.directory("/packages")


    @function
    async def package_linux(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package for all Linux architectures (AMD64 and ARM64)"""

        # Create a container to collect all packages
        container = dag.container().from_("alpine:latest").with_exec(["mkdir", "-p", "/packages"])

        # Get AMD64 packages
        amd64_dir = self.package_linux_amd64(source, is_nightly, base, ci_registry_image)
        container = container.with_directory("/packages/amd64", amd64_dir)

        # Get ARM64 packages
        arm64_dir = self.package_linux_arm64(source, is_nightly, base, ci_registry_image)
        container = container.with_directory("/packages/arm64", arm64_dir)

        return container.directory("/packages")

    @function
    async def package_windows_amd64(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package ZIP for Windows AMD64"""
        # Create a container to collect all packages
        container = dag.container().from_("alpine:latest").with_exec(["mkdir", "-p", "/packages"])

        # Get Zip packages
        zip_dir = await self.package_zip(source, "amd64", is_nightly, base, ci_registry_image)
        container = container.with_directory("/packages/zip", zip_dir)

        return container.directory("/packages")

    @function
    async def package_windows(self, source: Annotated[dagger.Directory, Ignore(DIRECTORY_IGNORE_PATTERNS)], is_nightly: bool = False, base: str = "local", ci_registry_image: str = VEILID_REPO) -> dagger.Directory:
        """Package for all Windows architectures (AMD64)"""
        # Create a container to collect all packages
        container = dag.container().from_("alpine:latest").with_exec(["mkdir", "-p", "/packages"])

        # Get AMD64 packages
        amd64_dir = await self.package_windows_amd64(source, is_nightly, base, ci_registry_image)
        container = container.with_directory("/packages/amd64", amd64_dir)

        return container.directory("/packages")