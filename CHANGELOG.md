# Change Log

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.1.2] - 2020-03-10

### Added
- Add goreleaser support
- Add version flag for transocks cmd

## [1.1.1] - 2019-03-16

### Changed
- Replace `syscall` with `golang.org/x/sys/unix`, contriubted by @otariidae (#14).

## [1.1.0] - 2018-11-13

### Changed
- Update `github.com/cybozu-go/cmd` to `github.com/cybozu-go/well` (#7, #9).
- Replace TravisCI with CircleCI.

## [1.0.0] - 2016-09-01

### Added
- transocks now adopts [github.com/cybozu-go/well][well] framework.  
  As a result, it implements [the common spec][spec] including graceful restart.

### Changed
- The default configuration file path is now `/etc/transocks.toml`.
- "listen" config option becomes optional.  Default is "localhost:1081".
- Configuration items for logging is changed.

[well]: https://github.com/cybozu-go/well
[spec]: https://github.com/cybozu-go/well/blob/master/README.md#specifications
[Unreleased]: https://github.com/cybozu-go/transocks/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/cybozu-go/transocks/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cybozu-go/transocks/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cybozu-go/transocks/compare/v0.1...v1.0.0
