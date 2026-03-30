# Installation
> This documentation applies to brutecraber v0.6.0

> This project is under active development

## Requirements
  - Git (Only required for manual instalation)
  - Rust (Only required for manual instalatión)

---

# Automatic installation (Recommended)

Download the latest precompiled binary from my repository releases

https://github.com/Erikgavs/brutecraber/releases

## Steps
  Download the binary for your OS (Temporaly only compatible wit linux and macOS)
  
  Make the binary executable 
  
  ```bash
  chmod +x brutecraber
  ```
  Run the tool
 
  ```bash
  ./brutecraber
  ```

---

# Manual instalation (From Source)

## Steps

### Clone the repository

```bash
git clone https://github.com/Erikgavs/brutecraber

cd brutecraber
```

### Build the project

```bash
cargo build --release
```

### Run the binary

```bash
./target/release/brutecraber
```

## Install the tool globaly

```bash
cargo install --path .
```

---

# Troubleshooting

cargo not found

Make sure you have installed rust

https://rust-lang.org/tools/install/
