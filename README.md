# CheckPlz

**CheckPlz** is an Rust adaptation of the popular **(ThreatCheck)[https://github.com/rasta-mouse/ThreatCheck]** tool, designed to scan files for potential threats while leveraging AMSI (Antimalware Scan Interface). By isolating malicious content with precision and providing comprehensive analysis, CheckPlz offers an enhanced and efficient file scanning experience.

## Key Features
- **Rust Implementation:** Built entirely in Rust for optimal performance and security.
- **AMSI Integration:** Perform accurate buffer scans for threat detection.
- **Binary Search Threat Isolation:** Precisely locate the section of a file causing detection.
- **Hex Dump Analysis:** Visualize malicious content with a detailed hexadecimal and ASCII dump.
- **Debugging Support:** Enable verbose output for deeper insights.
- **Customizable Output:** Choose between raw or colorful, human-friendly terminal outputs.

## System Requirements
- **Rust:** Latest stable version for compilation and usage.
- **Operating System:** Windows (AMSI compatibility required).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/CheckPlz.git
   cd CheckPlz
   ```
2. Compile the project:
   ```bash
   cargo build --release
   ```
3. The executable will be available at `target/release/checkplz.exe`.

## Usage Instructions
Run CheckPlz with the desired options:

```bash
checkplz --file <FILE_PATH> [--amsi] [--debug] [--raw]
```

### Available Options
- `--file <FILE_PATH>`: Path to the file to be scanned (required).
- `--amsi`: Use AMSI-based scanning to identify threats.
- `--debug`: Enable verbose debugging output.
- `--raw`: Produce raw, unformatted text suitable for automation.

### Example Commands
- Scan a file using AMSI:
  ```bash
  checkplz --file malicious.exe --amsi
  ```

- Scan a file with debug output enabled:
  ```bash
  checkplz --file suspicious.exe --amsi --debug
  ```

- Perform a scan with raw output formatting:
  ```bash
  checkplz --file unknown.exe --amsi --raw
  ```

## Output Overview
- **Scan Results:** Displays detection status, potential malicious offsets, and the time taken for scanning.
- **Hex Dump Analysis:** Detailed views of the suspicious sections, highlighting malicious bytes.

## License
This project is licensed under the MIT License. Refer to the `LICENSE` file for full details.

## Contribution Guidelines
We welcome contributions to CheckPlz! Feel free to submit issues or pull requests through the GitHub repository.

## Disclaimer
**CheckPlz** is a Rust-only adaptation of **ThreatCheck**, developed for educational and testing purposes. Ensure compliance with all applicable laws and regulations while using this tool.

---

Take your threat detection capabilities to the next level with **CheckPlz**!

