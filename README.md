# DPT-Shell Dump API

A PHP-based tool for extracting, analyzing, and restoring DEX files from DPT-shell protected Android applications. This API allows you to process protected DEX files and code.bin files to recover original method implementations.

## Features

-  Extract embedded ZIP archives from DEX files
-  Parse multi-dex code.bin structures
-  Restore method bytecode from code.bin to DEX files
-  Generate JSON dumps of recovered method signatures
-  Fix DEX headers and checksums after patching
-  Support for multi-dex applications (classes.dex, classes2.dex, etc.)

## Installation

### Requirements

- PHP 7.4 or higher
- ZipArchive extension
- JSON extension

### Setup

For Website and Php
```bash
git clone https://github.com/yourusername/dpt-shell-dump-api.git
cd dpt-shell-dump-api
cd webapi
```
For csharp and win only
```bash
git clone https://github.com/yourusername/dpt-shell-dump-api.git
cd dpt-shell-dump-api
cd cs-dptshell
dotnet run 
```

2. Ensure the required PHP extensions are enabled in your `php.ini`:
```ini
extension=zip
extension=json
```

3. Place the files on your web server or use PHP built-in server:
```bash
php -S localhost:8000
```

## API Usage

### Endpoint
```
POST /api.php
```

### Request Format

Send a multipart/form-data POST request with two files:
- `dex`: The protected DEX file (e.g., classes.dex)
- `code`: The code.bin file extracted from the APK

### Example using cURL

```bash
curl -X POST "https://your-server.com/api.php" \
  -F "dex=@classes.dex" \
  -F "code=@code.bin"
```

### Example using PowerShell

```powershell
curl.exe -X POST "https://your-server.com/api.php" `
  -F "dex=@classes.dex" `
  -F "code=@code.bin"
```

### Example using Python

```python
import requests

url = "https://your-server.com/api.php"
files = {
    'dex': open('classes.dex', 'rb'),
    'code': open('code.bin', 'rb')
}

response = requests.post(url, files=files)
result = response.json()
print(result)
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "status": "success",
  "summary": {
    "extractedFiles": ["classes.dex", "classes2.dex", ...],
    "dexFiles": ["classes.dex", "classes2.dex", ...],
    "jsonFiles": ["classes.dex.json", "classes2.dex.json", ...],
    "restored": [
      {
        "dexIndex": 0,
        "dexFile": "classes.dex",
        "restoredMethods": 42
      }
    ],
    "elapsedSeconds": 1.234,
    "multidex": {
      "version": 1,
      "dexCount": 2
    },
    "notes": []
  },
  "patchedDex": [
    {
      "fileName": "classes.dex",
      "sizeBytes": 524288,
      "base64": "UEsDBBQAAAAA..."
    }
  ],
  "jsonDump": [
    {
      "fileName": "classes.dex.json",
      "sizeBytes": 1024,
      "content": [
        {
          "Lcom/example/MainActivity;": [
            {
              "methodId": 0,
              "code": "[6e,20,01,00,0e,00]"
            }
          ]
        }
      ]
    }
  ]
}
```

### Error Response

```json
{
  "status": "error",
  "message": "Error description"
}
```

## Class Documentation

### DexManipulator

The main class that handles all DEX manipulation operations.

#### Public Methods

- **runFullPipeline($dexInput, $codeInput)**: Complete processing pipeline that extracts, patches, and generates JSON dumps
- **restoreDexFromCodeFile($dex, $codeBlob)**: Restore a single DEX file using code.bin data
- **restoreDexFromEmbeddedZip($dex)**: Restore DEX using embedded ZIP from another DEX
- **extractEmbeddedZipFromDex($dex)**: Extract embedded ZIP signature from DEX
- **readMultiDexCode($buf)**: Parse code.bin structure
- **parseDex($dex)**: Parse DEX file structure
- **patchDexInsns($dex, $insnsOff, $codeBytes)**: Patch method instructions at specific offset
- **fixDexHeaders($dex)**: Recalculate and fix DEX headers (checksum, SHA1, file size)

## Use Cases

1. **DPT-Shell Protection Analysis**: Extract protected method implementations
2. **Malware Analysis**: Recover hidden or encrypted DEX code
3. **Security Research**: Study Android protection mechanisms
4. **Forensics**: Extract embedded DEX files from protected applications

## Limitations

- Requires valid DEX and code.bin files from DPT-shell protected apps
- Maximum file size depends on PHP memory limits
- Some heavily obfuscated methods may not be recoverable

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## contributor
@aantik_mods
@AbhikrX

## Disclaimer

This tool is for educational and security research purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## Support

For issues, questions, or contributions, please open an issue on GitHub.
