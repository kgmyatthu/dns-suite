# DNS Suite

DNS Suite is a Rust workspace that provides a minimal DNS client implementation and a small CLI example. The `dns_core` library handles encoding and decoding DNS packets, while the `example` crate offers a `dig`-style command-line interface for sending queries over UDP with automatic TCP fallback when responses are truncated.

## Workspace layout
- `dns_core`: Library crate with packet buffer helpers, header parsing, DNS record representations, and query-type definitions.
- `example`: Command-line tool built on `dns_core` for performing DNS lookups from the terminal.

## Quickstart
1. Ensure you have a recent Rust toolchain (2024 edition).
2. Build the workspace:
   ```bash
   cargo build
   ```
3. Run a DNS query (defaults to `@8.8.8.8` when no server is provided):
   ```bash
   cargo run -p example -- @1.1.1.1 example.com A
   ```

The CLI prints a human-readable response, including header flags and individual sections similar to `dig`.

## Testing
Run the full test suite with:
```bash
cargo test
```
