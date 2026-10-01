; Inno Setup script for the Windows installer (issue #34).
;
; Built by CI (.github/workflows/release.yml) with:
;   iscc /DAppVersion=<version> /DSourceDir=<folder with the exe and docs> /DOutputDir=<out> packaging\windows\installer.iss
;
; Installs:
;   {app} = C:\Program Files\Chipkin\BACnet SC Hub      the program and its documentation
;   {commonappdata}\Chipkin\BACnetSCHub\hub.conf         settings (kept on upgrade)
;   {commonappdata}\Chipkin\BACnetSCHub\certs\           certificates (a lab set is made if empty)
;   {commonappdata}\Chipkin\BACnetSCHub\logs\hub.log     the hub's rotating log
; and, if the "service" task is ticked (the default), registers and starts the
; "BACnetSCHub" Windows service (start on boot, restart on failure) with
; BACnetExampleBSCHUB --install-service. Uninstalling removes the service and
; the program, and keeps the settings, certificates and logs.
;
; {commonappdata}\Chipkin\BACnetSCHub holds private keys (the hub's and the
; lab CA's) and hub.conf's secrets, so it is NOT left with ProgramData's
; inherited ACL (which lets every local user read files and create new ones):
; the first [Run] entry makes it SYSTEM + Administrators only, and repairs the
; ACL of an existing install on upgrade. The service runs as its own virtual
; account, NT SERVICE\BACnetSCHub (not LocalSystem), which gets Modify on that
; folder and nothing else.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{6C1A2F7E-3B6D-4C57-9E0B-5A1D2C4B8F31}
AppName=BACnet SC Hub
AppVersion={#AppVersion}
AppPublisher=Chipkin Automation Systems
AppPublisherURL=https://store.chipkin.com/
AppSupportURL=https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP
DefaultDirName={autopf}\Chipkin\BACnet SC Hub
DefaultGroupName=BACnet SC Hub
DisableProgramGroupPage=yes
LicenseFile={#SourceDir}\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=BACnetSCHub-{#AppVersion}-setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\BACnetExampleBSCHUB.exe

[Tasks]
Name: "service"; Description: "Run the hub as a Windows service (starts on boot)"; Flags: checkedonce
Name: "firewall"; Description: "Allow BACnet/IP (UDP 47808) and BACnet/SC (TCP 4443) through Windows Firewall"; Flags: checkedonce

[Dirs]
Name: "{commonappdata}\Chipkin\BACnetSCHub"
Name: "{commonappdata}\Chipkin\BACnetSCHub\certs"
Name: "{commonappdata}\Chipkin\BACnetSCHub\logs"

[Files]
Source: "{#SourceDir}\BACnetExampleBSCHUB.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\*.pdf"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\THIRD-PARTY-LICENSES-windows.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\example.conf"; DestDir: "{app}"; Flags: ignoreversion

[Code]
function ConfPath(): String;
begin
  Result := ExpandConstant('{commonappdata}\Chipkin\BACnetSCHub\hub.conf');
end;

procedure WriteDefaultConfig();
var
  Lines: TArrayOfString;
begin
  if FileExists(ConfPath()) then
    exit;
  SetArrayLength(Lines, 6);
  Lines[0] := '# Settings for the BACnetSCHub service. Every key is listed in ' + ExpandConstant('{app}') + '\example.conf.';
  Lines[1] := 'sc-cert-dir = certs';
  Lines[2] := 'log-file = logs\hub.log';
  Lines[3] := 'log-max-size-mb = 10';
  Lines[4] := 'log-max-files = 5';
  Lines[5] := '# device-name = <a name unique on your BACnet network>';
  SaveStringsToFile(ConfPath(), Lines, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteDefaultConfig();
end;

[Run]
; SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) only - by SID, so it
; works on non-English Windows. First the folder itself (inheritable), then
; everything already inside it (an earlier install's files, hub.conf) is reset
; to inherit just that. Not "/T" on the first command: (OI)(CI) grants mean
; nothing on a file, so files would be left with an empty ACL.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\Chipkin\BACnetSCHub"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /Q"; Flags: runhidden waituntilterminated; StatusMsg: "Restricting access to the settings and certificates..."
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\Chipkin\BACnetSCHub\*"" /reset /T /Q"; Flags: runhidden waituntilterminated
; A lab certificate set if certs\ is empty (the hub refuses to replace an existing one).
Filename: "{app}\BACnetExampleBSCHUB.exe"; Parameters: "--sc-cert-dir ""{commonappdata}\Chipkin\BACnetSCHub\certs"" --generate-certs"; Flags: runhidden waituntilterminated; StatusMsg: "Making lab certificates..."; Check: not FileExists(ExpandConstant('{commonappdata}\Chipkin\BACnetSCHub\certs\issuer-certificate.pem'))
Filename: "{app}\BACnetExampleBSCHUB.exe"; Parameters: "--install-service --config ""{commonappdata}\Chipkin\BACnetSCHub\hub.conf"""; Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "Installing the service..."
; Run it as the virtual account NT SERVICE\BACnetSCHub instead of LocalSystem, and
; let only that account (besides SYSTEM and Administrators) into the data folder.
Filename: "{sys}\sc.exe"; Parameters: "config BACnetSCHub obj= ""NT SERVICE\BACnetSCHub"""; Flags: runhidden waituntilterminated; Tasks: service
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\Chipkin\BACnetSCHub"" /grant ""NT SERVICE\BACnetSCHub:(OI)(CI)M"" /Q"; Flags: runhidden waituntilterminated; Tasks: service
Filename: "{sys}\sc.exe"; Parameters: "start BACnetSCHub"; Flags: runhidden waituntilterminated; Tasks: service
; netsh doesn't de-duplicate by name, so remove any rule from an earlier install first.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BACnet SC Hub (BACnet/IP)"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BACnet SC Hub (BACnet/SC)"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BACnet SC Hub (BACnet/IP)"" dir=in action=allow protocol=UDP localport=47808 program=""{app}\BACnetExampleBSCHUB.exe"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BACnet SC Hub (BACnet/SC)"" dir=in action=allow protocol=TCP localport=4443 program=""{app}\BACnetExampleBSCHUB.exe"""; Flags: runhidden waituntilterminated; Tasks: firewall

[UninstallRun]
Filename: "{app}\BACnetExampleBSCHUB.exe"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BACnet SC Hub (BACnet/IP)"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallIp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BACnet SC Hub (BACnet/SC)"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallSc"
