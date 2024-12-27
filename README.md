# CheckPlz

**CheckPlz** is a file scanning tool written in Rust that leverages AMSI (Antimalware Scan Interface) and Windows Defender to detect potential threats in files. The tool supports binary search to isolate malicious content within a file, providing detailed scan results.

## Features
- **AMSI Scanning:** Utilize the AMSI interface to scan buffers and detect threats.
- **Windows Defender Scanning:** Use Windows Defender's command-line interface to analyze files for threats.
- **Binary Search Isolation:** Automatically locate the specific part of the file causing a detection.
- **Hex Dump Analysis:** Display a hex dump of malicious content.
- **Debug Mode:** Output detailed debug information during the scan.
- **ANSI and Raw Output:** Supports colorful terminal output or raw text for easier scripting integration.

## Requirements
- Rust (latest stable version recommended)
- Windows operating system

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/CheckPlz.git
   cd CheckPlz
   ```
2. Build the project:
   ```bash
   cargo build --release
   ```
3. The compiled binary will be available in `target/release/checkplz.exe`.

## Usage
Run the tool with the required options:

```bash
checkplz --file <FILE_PATH> [--amsi] [--msdefender] [--debug] [--raw]
```

### Options
- `--file <FILE_PATH>`: Path to the file to be scanned (required).
- `--amsi`: Use AMSI for scanning.
- `--msdefender`: Use Windows Defender for scanning.
- `--debug`: Enable debug mode for detailed output.
- `--raw`: Use raw output without ANSI colors.

### Examples
- Scan a file using AMSI:
  ```bash
  checkplz --file testfile.exe --amsi
  ```

- Scan a file using Windows Defender with debug output:
  ```bash
  checkplz --file testfile.exe --msdefender --debug
  ```

- Scan a file using both AMSI and Windows Defender, outputting raw text:
  ```bash
  checkplz --file testfile.exe --amsi --msdefender --raw
  ```

## Output
- **Scan Results:** Displays detection status, offset of malicious content (if any), and time taken for the scan.
- **Hex Dump Analysis:** Provides a detailed view of malicious content for further analysis.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests to improve the tool.

## Disclaimer
**CheckPlz** is provided for educational and testing purposes only. Use it responsibly and ensure compliance with all applicable laws and regulations.

---

Happy scanning!

