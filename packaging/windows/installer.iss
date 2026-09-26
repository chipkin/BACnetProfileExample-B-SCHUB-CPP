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
Name: "firewall"; Description: "Allow BACnet/IP (UDP 47808) and BACnet/SC (TCP 47819) through Windows Firewall"; Flags: checkedonce

[Dirs]
Name: "{commonappdata}\Chipkin\BACnetSCHub"
Name: "{commonappdata}\Chipkin\BACnetSCHub\certs"
Name: "{commonappdata}\Chipkin\BACnetSCHub\logs"

[Files]
Source: "{#SourceDir}\BACnetExampleBSCHUB.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\*.pdf"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
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
; A lab certificate set if certs\ is empty (the hub refuses to replace an existing one).
Filename: "{app}\BACnetExampleBSCHUB.exe"; Parameters: "--sc-cert-dir ""{commonappdata}\Chipkin\BACnetSCHub\certs"" --generate-certs"; Flags: runhidden waituntilterminated; StatusMsg: "Making lab certificates..."; Check: not FileExists(ExpandConstant('{commonappdata}\Chipkin\BACnetSCHub\certs\issuer-certificate.pem'))
Filename: "{app}\BACnetExampleBSCHUB.exe"; Parameters: "--install-service --config ""{commonappdata}\Chipkin\BACnetSCHub\hub.conf"""; Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "Installing the service..."
Filename: "{sys}\sc.exe"; Parameters: "start BACnetSCHub"; Flags: runhidden waituntilterminated; Tasks: service
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BACnet SC Hub (BACnet/IP)"" dir=in action=allow protocol=UDP localport=47808 program=""{app}\BACnetExampleBSCHUB.exe"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""BACnet SC Hub (BACnet/SC)"" dir=in action=allow protocol=TCP localport=47819 program=""{app}\BACnetExampleBSCHUB.exe"""; Flags: runhidden waituntilterminated; Tasks: firewall

[UninstallRun]
Filename: "{app}\BACnetExampleBSCHUB.exe"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BACnet SC Hub (BACnet/IP)"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallIp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""BACnet SC Hub (BACnet/SC)"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallSc"
