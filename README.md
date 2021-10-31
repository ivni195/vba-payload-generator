# vba-payload-generator
Python script that generates (using Invoke-Obfuscation https://github.com/danielbohannon/Invoke-Obfuscation) obfuscated payloads 
that can be used to spawn a reverse shell via malicious VBA macros.
## Installation
1. Clone the repository
```bash
git clone --recursive https://github.com/ivni195/vba-payload-generator.git
```
2. If you're using linux, install powershell. 
Instructions can be found here https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux?view=powershell-7.1.
Also run the following command (for some reason powershell incorrectly handles `'\'` characters on linux):
```bash
sed -i 's_/\\_/_g' Invoke-Obfuscation/Invoke-Obfuscation.ps1
```
## Usage
```
Usage:
    python3 vba-payload-generator.py ip http_port tcp_port <obfuscation_command>
    
    ip - attacker's ip address
    http_port - http server port that serves "stage.ps1"
    tcp_port - tcp server port that listens for reverse shell
    obfuscation_command - (OPTIONAL) "-Command" parameter passed to Invoke-Obfuscation. 
        By default: "Token/All/1"
```

## Obfuscation
The default obfuscation is sufficient to avoid being detected by Windows Defender. Not tested with other AVs.
