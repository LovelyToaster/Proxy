# Repository Guidelines

## Project Structure & Module Organization

- `cmd/proxy` contains the unified binary for management CLI, foreground execution, and service hosting. `cmd/m0` and `cmd/proxy-probe` provide network test utilities.
- `internal/` contains configuration, routing, DNS, outbound connections, sessions, service management, and platform capture packages. Tests live beside implementation files.
- `configs/` holds example YAML configurations. `platform/` contains Linux systemd templates.
- `scripts/` provides platform smoke tests, diagnostics, and packaging. `dist/` contains packaged runtime files; `artifacts/` records acceptance results.

## Build, Test, and Development Commands

Use Go 1.26.4 or newer from the repository root.

```sh
go build ./cmd/...
go test ./...
go vet ./...
go run ./cmd/proxy --config configs/m1.yaml config check
go run ./cmd/proxy --config configs/m1.yaml run
```

These commands compile all entry points, run package tests, check common code issues, validate configuration, and start the foreground daemon. The M1 example disables capture by default.

On Windows, `./scripts/windows/m1-windows.ps1` builds and verifies dual-stack loopback forwarding and daemon management. Linux capture acceptance uses the scripts in `scripts/linux/` (`m1-linux.sh`, `m2-linux.sh`, `m3-linux.sh`, and `global-linux.sh` with `linux-lab.sh`); consult `README.md` for required binaries and privileges.

## Coding Style & Naming Conventions

Format Go changes with `gofmt` and use standard Go naming: short lowercase package names, exported `MixedCaps` identifiers, and descriptive unexported names. Preserve platform suffixes such as `_linux.go` and `_windows.go` and associated build constraints. Keep operating-system integration in the relevant platform packages. Follow existing YAML structure and `snake_case` configuration keys.

## Windows & Linux Feature Parity

Windows and Linux must provide identical user-facing functionality and behavior. Implement every feature and fix on both platforms, including configuration semantics, CLI commands, routing, TCP/UDP, IPv4/IPv6, DNS, service lifecycle, reload, status reporting, and failure recovery. OS-specific mechanisms may differ, but must preserve equivalent outcomes; do not silently omit features or weaken guarantees on either platform.

For every change, review both platform implementations and add equivalent regression coverage. Verify affected behavior on both operating systems, including capture cleanup and loop prevention where relevant. Record Windows and Linux results separately in pull requests. Missing runtime verification or a platform parity gap is unfinished work and must be stated explicitly; cross-compilation alone does not establish parity.

## Testing Guidelines

Use Go's `testing` package with adjacent `*_test.go` files and `TestXxx` functions. Cover configuration rejection, forwarding behavior, cleanup, and platform-specific failure paths when changing those areas. No numeric coverage threshold is documented. Set `PROXY_TEST_IPV6=1` for optional IPv6 DNS downstream tests. Run privileged capture tests separately on the target OS; a successful cross-build does not establish runtime correctness.

## Commit & Pull Request Guidelines

This checkout has no Git metadata, so existing commit conventions cannot be verified. Use concise imperative subjects, optionally prefixed with `feat:`, `fix:`, or `docs:`. Pull requests should explain the behavior change, link relevant issues, list tested operating systems and commands, and distinguish build checks from live capture acceptance.

## Documentation & README Maintenance

After completing any task, evaluate whether `README.md` needs to be updated. Whenever user-facing behavior, configuration keys or defaults, CLI commands/flags, Web UI features, or build/test workflows change, update `README.md` before finishing so documentation stays aligned with the codebase.

## Security & Configuration

Never commit proxy credentials or private endpoints. Test capture changes in isolated namespaces or scoped application scenarios first. Preserve precise rule cleanup, upstream bypass, and loop-prevention behavior; global capture affects host networking.
