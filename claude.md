
1. Repository Structure Tree
The file structure based on the provided paths is as follows:

Plaintext

np4abdou1/fsociety/fsociety-fbffa908f46575b2d126e82024ba2e2fd283e74c/
├── .gitattributes
├── .gitignore
├── LICENSE
├── README.md
├── game.exe
├── make.bat
├── .github/
│   └── workflows/
│       ├── build-release.yml
│       └── build_and_release.yml
├── libs/
│   ├── chacha/
│   │   └── chacha20.h
│   ├── sqlite/
│   │   ├── sqlite3.c
│   │   └── sqlite3.h
│   └── zstd/
│       └── include/
│           ├── zdict.h
│           ├── zstd.h
│           └── zstd_errors.h
├── src/
│   ├── chkstk_stub.c
│   ├── chkstk_stub_x64.asm
│   ├── chrome_decrypt.cpp
│   ├── chrome_inject.cpp
│   ├── encryptor.cpp
│   ├── reflective_loader.c
│   ├── reflective_loader.h
│   ├── resource.rc
│   ├── syscall_trampoline_arm64.asm
│   ├── syscall_trampoline_x64.asm
│   ├── syscalls.cpp
│   ├── syscalls.h
│   ├── syscalls_obfuscation.cpp
│   └── syscalls_obfuscation.h
├── t.py
└── tools/
    ├── binary_morph.py
    ├── comrade_abe.py
    ├── game.exe.zst
    ├── obfuscate.py
    └── zstd.exe
Total Files: 34

2. General Use and Purpose
Purpose: This repository hosts a sophisticated post-exploitation tool designed to bypass App-Bound Encryption (ABE) in Chromium-based browsers (Chrome, Brave, Edge). Its primary goal is to decrypt and exfiltrate sensitive user data—specifically cookies, passwords, and payment information—which are typically protected by ABE, a mechanism that binds encryption keys to the specific browser identity.

How it Works (The "Kill Chain"):

Injector (chromelevator.exe / chrome_inject.cpp): The tool starts by acting as a loader. It uses direct system calls (syscalls) to evade EDR (Endpoint Detection and Response) hooks.

Process Hollowing: It creates a legitimate browser process (e.g., chrome.exe) in a suspended state.

Reflective Injection: It injects a payload DLL directly into the memory of this suspended browser process. This allows the payload to run inside the trusted process.

Privilege Inheritance: Because the payload runs inside the signed browser executable, it bypasses the App-Bound Encryption checks. The operating system believes the request is coming from the legitimate browser.

Decryption (chrome_decrypt.cpp): The injected payload uses the browser's own COM (Component Object Model) interfaces (IElevator) to request the decryption of the master key.

Exfiltration: Once the data is decrypted, it is bundled and exfiltrated, likely to a Telegram channel or C2 server defined in the code.

3. Detailed File Analysis
Here is an analysis of the files for which content was provided:

src/chrome_inject.cpp
Goal: Acts as the entry point and loader. It is responsible for preparing the target environment and injecting the malicious payload.

Key Functionality:

Anti-Analysis: Disables AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows) via memory patching to blind security tools.

Direct Syscalls: Implements a syscall engine to call kernel functions (NtAllocateVirtualMemory, NtCreateThreadEx) directly, bypassing user-mode hooks often placed by antiviruses.

Process Hollowing: Launches a target browser in CREATE_SUSPENDED mode.

Network Service Killing: Hunts for and terminates browser "Network Service" processes to release file locks on the SQLite databases (Cookies/Login Data) so they can be read.

Payload Injection: Decrypts the embedded PAYLOAD_DLL resource (ChaCha20 encrypted) and maps it into the target process.

src/chrome_decrypt.cpp
Goal: The payload DLL that runs inside the victim browser process.

Key Functionality:

COM Hijacking: Instantiates the IElevator COM interface. This is the core of the ABE bypass. It calls DecryptData on this interface to get the AES-256 master key.

Database Parsing: Uses SQLite to query Cookies, Login Data, and Web Data files.

Data Extraction: Decrypts the database entries using the master key obtained via COM.

Exfiltration: Contains logic to upload data to Telegram (TelegramUploader class) and a Cloudflare worker. It gathers system info (IP, OS, Discord tokens).

Fingerprinting: Collects browser version, extensions, and history.

src/encryptor.cpp
Goal: A build-time utility.

Key Functionality: Takes the compiled payload DLL (chrome_decrypt.dll) and encrypts it using ChaCha20. This encrypted blob is what gets embedded into the final injector executable to hide the malicious code from static analysis.

src/reflective_loader.c
Goal: A custom PE (Portable Executable) loader.

Key Functionality: This code allows the DLL to load itself from memory without using the Windows API LoadLibrary. It manually resolves imports and relocations. This is a standard technique in stealthy malware to avoid dropping files to disk.

src/syscalls.cpp & src/syscalls_obfuscation.cpp
Goal: Manages the direct system calls.

Key Functionality: Dynamically resolves syscall numbers (SSNs) from ntdll.dll at runtime. It includes obfuscation logic to hide which syscalls are being used from memory scanners.

make.bat
Goal: The build script.

Key Functionality: Automates the compilation process using MSVC (cl.exe). It compiles the libraries, the payload, runs the encryptor on the payload, compiles the resource file, and finally compiles the injector.

tools/comrade_abe.py
Goal: A research tool for analyzing COM interfaces.

Key Functionality: It scans browser executables (like elevation_service.exe) to find the specific CLSIDs and IIDs (Interface IDs) used for App-Bound Encryption. It can generate C++ stubs to interact with these interfaces, which are likely used to update chrome_decrypt.cpp when browsers update their security mechanisms.

tools/obfuscate.py
Goal: Source code obfuscator.

Key Functionality: A Python script that modifies C++ source files before compilation. It encrypts string literals (XOR encryption), adds junk code (dead code), and obfuscates control flow/integers to make reverse engineering the final binary harder.

tools/binary_morph.py
Goal: Post-compilation binary modification.

Key Functionality: Modifies the final .exe to change its signature. It adds entropy (fake data sections), randomizes timestamps, and fills "code caves" (empty spaces in the binary) with NOP instructions. This is designed to evade hash-based detection (static signatures).

t.py
Goal: A simple Telegram bot listener.

Key Functionality: Uses requests to poll the Telegram API. It prints out messages received by the bot. This is likely used by the developer to debug the exfiltration or monitor victims in real-time.

4. Deep Code Analysis (Logic Breakdown)
The user requested to "analyze every single line". Below is a breakdown of the logic flow for the most critical files provided.

A. src/chrome_inject.cpp (The Injector)
Evasion Initialization (Lines ~500-550 in wmain):

Calls DisableAMSI() and DisableETW() immediately to blind Windows Defender and event logging.

Performs environmental checks (RAM size, CPU cores, VM drivers) to detect if it is running in a sandbox or analyst VM. If detected, it exits.

Syscall Setup (InitializeSyscalls):

Scans ntdll.dll to find the "SSN" (System Service Number) for kernel functions like NtOpenProcess. It sorts them by address to deduce the numbers dynamically, ensuring compatibility across Windows versions.

Target Logic (RunInjectionWorkflow):

KillBrowserNetworkService: Iterates through running processes using syscalls. It looks for browser processes with the command line network.mojom.NetworkService. It kills them to ensure the SQLite database files (Cookies/Login Data) are not locked by the browser, allowing the reading of these files later.

CreateSuspended: Uses CreateProcessW to launch the target browser (e.g., chrome.exe) with the CREATE_SUSPENDED flag. This creates a valid process container that is paused.

Injection (InjectionManager::execute):

NtAllocateVirtualMemory: Allocates memory in the remote (suspended) process.

NtWriteVirtualMemory: Writes the encrypted payload and the pipe name into the target process.

NtProtectVirtualMemory: Sets the memory to PAGE_EXECUTE_READ (executable).

NtCreateThreadEx: Creates a remote thread pointing to the ReflectiveLoader function within the injected DLL.

B. src/chrome_decrypt.cpp (The Payload)
DLL Entry (DllMain):

Spawns a new thread DecryptionThreadWorker to avoid blocking the loader.

Communication (PipeLogger):

Connects back to the named pipe created by the injector to receive configuration (output path, flags) and send status updates.

Master Key Decryption (MasterKeyDecryptor::Decrypt):

Line ~1034: Initializes COM (CoInitializeEx).

Line ~1060: Reads the Local State file to find the app_bound_encrypted_key.

Line ~1083: Calls CoCreateInstance to load the browser's elevation service (e.g., IOriginalBaseElevator).

Line ~1110: Calls elevator->DecryptData. This is the exploit core. It asks the browser's own service to decrypt the key. Because the request comes from inside chrome.exe (where this DLL is injected), the service complies.

Data Extraction (DecryptionOrchestrator::Run):

Iterates through user profiles (Default, Profile 1, etc.).

Uses SQLite queries defined in Data::GetExtractionConfigs to select encrypted cookies and passwords.

Uses Crypto::DecryptGcm (AES-256-GCM) using the master key obtained in the previous step to decrypt the database entries.

Exfiltration (DataUploader & TelegramUploader):

UploadAllData: If this is the last browser instance being processed, it gathers all collected JSON files.

Compression: Uses ZSTD (Zstandard) to compress the stolen data into a .tar.zst archive.

Upload: Sends the archive to a Telegram bot via WinHttpSendRequest to api.telegram.org.

C. tools/comrade_abe.py (Research Tool)
Loading TypeLib: Uses comtypes to load the Type Library resource from a target executable (e.g., elevation_service.exe).

Interface Analysis: Iterates through all interfaces (TKIND_INTERFACE). It looks for methods matching the signature of ABE functions (specifically EncryptData and DecryptData).

Stub Generation: If a matching interface is found, it auto-generates valid C++ code (structs and vtables) that can be pasted into chrome_decrypt.cpp to support that specific browser version. This allows the attacker to quickly adapt to browser updates.

Summary
This is a highly advanced, custom-built "stealer" specifically targeting the mechanisms browsers use to protect data (App-Bound Encryption). It uses "Living off the Land" techniques (using the browser's own services against it) combined with sophisticated evasion (syscalls, obfuscation) to steal credentials.
