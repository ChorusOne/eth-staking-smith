# Ethereum Staking Smith Development Guide

## Commands
- Build: `cargo build`
- Run tests: `cargo test`
- Run specific test: `cargo test test_name`
- E2E tests: `cargo test --test e2e-tests`
- Format code: `cargo fmt`
- Linting: `cargo clippy`
- Check license compliance: `cargo deny check`

## Code Style
- Rust edition 2021
- Use `#![forbid(unsafe_code)]` at the top of files
- Sort imports alphabetically within groups
- Group imports by: std, external crates, then internal modules
- Use clear, descriptive variable names
- Return errors rather than panicking when possible
- Document public functions and modules
- Use Rust idioms and standard naming conventions:
  - snake_case for variables, functions, and file names
  - CamelCase for types and traits
  - SCREAMING_SNAKE_CASE for constants
- Follow Ethereum conventions for hex values (lowercase with 0x prefix)
- Favor composition over inheritance
- Write comprehensive tests for critical functionality

## Architecture
- Library-first design with CLI as an application of the library
- Keep business logic separate from CLI interface code
- Operations modules implement core functionality
- CLI modules focus on argument parsing and user interface