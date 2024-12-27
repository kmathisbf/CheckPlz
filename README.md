# CheckPlz

**CheckPlz** is a versatile file scanning tool written in Rust, designed to detect malicious content within files using two robust methods:

- **AMSI (Antimalware Scan Interface)**: Scans file content in-memory to identify threats.
- **Windows Defender**: Utilizes the built-in antivirus solution for comprehensive file scans.

The tool also features a binary search capability to pinpoint malicious content and provides detailed scan results with both AMSI and Windows Defender outputs.

## Features

- **AMSI Scanning**: Perform in-memory scans using Microsoft's Antimalware Scan Interface.
- **Windows Defender Integration**: Leverages the Windows Defender command-line interface for threat detection.
- **Binary Search**: Isolate and identify malicious content within files.
- **Comprehensive Reporting**: Includes detailed scan results with hex dump analysis.
- **Flexible Scanning Modes**: Choose between AMSI, Windows Defender, or both.
- **Debug Mode**: Output detailed information during scans for analysis.

## Installation

1. Install [Rust](https://www.rust-lang.org/tools/install) on your system.
2. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/CheckPlz.git
   cd CheckPlz
   ```
3. Build the project:
   ```bash
   cargo build --release
   ```
4. Run the executable:
   ```bash
   ./target/release/CheckPlz
   ```

## Usage

```bash
Usage: CheckPlz [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>           Path to the file to scan
  -a, --amsi                  Use AMSI scan
  -m, --msdefender            Use Windows Defender scan
  -d, --debug                 Enable debug mode for detailed output
  -r, --raw                   Output raw data without ANSI colors
  -h, --help                  Print help information
  -V, --version               Print version information
```

### Examples

```bash
# Scan a file using AMSI:
CheckPlz --file path/to/file --amsi

# Scan a file using Windows Defender:
CheckPlz --file path/to/file --msdefender

# Scan a file using both AMSI and Windows Defender with debug output:
CheckPlz --file path/to/file --amsi --msdefender --debug

# Output results in raw format:
CheckPlz --file path/to/file --raw
```

## How It Works

1. **AMSI Scanning**:
   - Initializes an AMSI context.
   - Scans the file content and buffers for threats.
   - If a threat is detected, performs a binary search to isolate the malicious segment.

2. **Windows Defender Scanning**:
   - Invokes `MpCmdRun.exe` to scan the file.
   - Analyzes the output for threat detection.
   - Performs a binary search if a threat is found.

3. **Binary Search**:
   - Recursively scans segments of the file to locate malicious content.
   - Produces detailed logs and results.

## Requirements

- **Windows OS**: Required for AMSI and Windows Defender integration.
- **Rust**: For building and running the tool.
- **Windows Defender**: Installed and accessible via `MpCmdRun.exe`.

## Contributions

Contributions are welcome! Feel free to fork this repository, create a new branch, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

CheckPlz is built with a focus on precision and reliability, leveraging AMSI and Windows Defender to provide a powerful scanning solution for files.
