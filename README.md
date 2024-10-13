# SQLi OS-Shell Uploader

![Main Interface](https://github.com/dotdesh71/SQLi-OS-Shell-Uploader/blob/main/os-shell.png)

A Python-based SQL injection (SQLi) vulnerability scanner with an OS shell uploader, designed using `Tkinter` for the GUI. The tool allows you to scan a target URL for SQLi vulnerabilities using payloads from an external file (`sqli.txt`), and if vulnerable, upload a `shell.php` file to the server. It features multithreading, real-time scan progress tracking, and advanced error handling.

# (Windows Version Available)

## Features

- **Scan for SQLi vulnerabilities** using custom payloads from `sqli.txt`.
- **OS-shell upload functionality** to upload a `shell.php` file to vulnerable URLs.
- **Real-time payload count display** showing the progress of the scan (e.g., `Payload 1/1000 Tested`).
- **Dynamic logging** of vulnerable URLs and responses.
- **GIF Animation** displayed while the scan is in progress.
- **Multithreading** for smooth scanning and database operations.
- **Pause, Resume, and Stop functionality** for better control during scanning.
- **Save scan results** to a text file.
- **Reset functionality** to clear logs and start fresh.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.x
- The following Python libraries:
  - `tkinter` (comes with most Python installations)
  - `requests`
  - `Pillow` (for handling GIF animations)
  - `sqlite3` (comes with Python)

You can install the required libraries via pip:

    pip install requests Pillow
    
### Usage
1. Clone the repository
2. git clone https://github.com/dotdesh71/SQLi-OS-Shell-Uploader.git
3. cd SQLi-OS-Shell-Uploader

Running the tool

bash

python os-shell.py

or Double Click on os-shell.exe

4. User Interface Guide

    Enter URL: Input the target URL, e.g., https://www.example.com/index.php?id=.
    Scan: Starts scanning the URL for SQLi vulnerabilities using the loaded payloads.
    Upload Shell: Attempts to upload a shell.php file after vulnerabilities are detected.
    Pause/Resume: Pauses or resumes the scan.
    Stop: Stops the scan immediately.
    Reset: Resets the interface and clears logs.
    Save Result: Saves the scan results to a .txt file.

5. Scan Log and Progress

During the scan, vulnerable URLs will be displayed in the log area along with the payload that triggered the vulnerability. A progress bar and a dynamic payload counter (e.g., Payload 3/1000 Tested) are updated in real-time.
6. Shell Upload

Once a vulnerability is detected, you can use the Upload Shell button to attempt to upload a shell (shell.php) to the target URL. The content of the shell can be modified in the upload_shell() method.
Screenshots
Main Interface

Vulnerable URL Detection

Shell Upload

Error Handling

All errors during the scan or file operations are logged in the error.log file. You can check this file for details on any exceptions or issues that occur.
Known Issues

    The scan can be interrupted manually with the Stop button, but results up to that point will still be saved.
    SQLite3 errors may occur if multiple threads access the database without proper synchronization. This is handled in the implementation, but please report any bugs if found.

License

This project is licensed under the MIT License. See the LICENSE file for more details.
Disclaimer

This tool is intended for educational and ethical testing purposes only. Use it responsibly and only on systems where you have explicit permission to test. The author is not responsible for any misuse of this tool.

