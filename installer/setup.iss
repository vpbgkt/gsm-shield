; ============================================================
; GSM Shield AV — Inno Setup 6 Installer Script
; Requirements: 22.1, 22.2, 22.3, 22.4, 22.5
;
; Build pipeline (Stage 3):
;   iscc installer\setup.iss
;
; Source files are taken from electron-builder's unpacked output:
;   ..\dist\win-unpacked\*
;
; The installer runs Defender-disable and WSC-registration steps at the
; end of installation (Req 22.4) via the [Run] section below.
; The application also supports re-triggering from Settings via
; electron/first-run.js if the install-time registration fails.
; ============================================================

#define AppName      "GSM Shield AV"
#define AppVersion   "1.0.0"
#define AppPublisher "GSM Shield"
#define AppURL       "https://gsmshield.io"
#define AppExeName   "GSM Shield AV.exe"
#define ServiceName  "GSMShieldAVService"

; ============================================================
[Setup]
; ---- Identity ----
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}

; ---- Privileges (Req 22.1) ----
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=

; ---- Architecture (64-bit install on x64) ----
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64

; ---- Directories ----
DefaultDirName={autopf}\GSMShieldAV
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes

; ---- Output ----
OutputDir=..\dist\installer
OutputBaseFilename=GSMShieldAV-Setup
SetupIconFile=..\assets\icons\tray-green.ico

; ---- Compression ----
Compression=lzma2/max
SolidCompression=yes
LZMAUseSeparateProcess=yes

; ---- Wizard appearance (Req 22.2) ----
WizardStyle=modern
DisableWelcomePage=no

; ---- License (Req 22.2) ----
LicenseFile=license.txt

; ---- Uninstall ----
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
CreateUninstallRegKey=yes

; ---- Registry uninstaller entry (Req 22.5) ----
; Written automatically by Inno Setup for the [UninstallDelete] and
; [Registry] sections below. The canonical uninstall key path is:
;   HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}}

; ---- Misc ----
ShowLanguageDialog=no
LanguageDetectionMethod=none
MinVersion=10.0.17763

; ============================================================
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ============================================================
; Multi-step wizard pages (Req 22.2):
;   1. Welcome
;   2. License Agreement  (LicenseFile= above)
;   3. Installation folder (DefaultDirPage auto-shown)
;   4. Tasks (optional desktop shortcut — below)
;   5. Installation progress
;   6. Completion screen
; ============================================================

; ============================================================
[Tasks]
; Optional desktop shortcut — checked by default (Req 22.2)
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

; ============================================================
[Files]
; Copy all application files from electron-builder's unpacked output (Req 22.3)
; The source directory contains the Electron app, ClamAV binaries + DLLs,
; bundled virus definitions, PowerShell scripts, and all other assets.
Source: "..\dist\win-unpacked\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; ============================================================
[Icons]
; Start Menu shortcut
Name: "{group}\{#AppName}";          FileName: "{app}\{#AppExeName}"; \
    WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; FileName: "{uninstallexe}"

; Desktop shortcut — only created if the task checkbox was ticked
Name: "{autodesktop}\{#AppName}";    FileName: "{app}\{#AppExeName}"; \
    WorkingDir: "{app}"; Tasks: desktopicon

; ============================================================
[Registry]
; Add application entry to Windows uninstaller list (Req 22.5)
; (Inno Setup also writes its own key; this mirrors the explicit path
;  specified in the requirements for custom metadata.)
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV"; \
    ValueType: string; ValueName: "DisplayName";          ValueData: "{#AppName}"; \
    Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV"; \
    ValueType: string; ValueName: "DisplayVersion";       ValueData: "{#AppVersion}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV"; \
    ValueType: string; ValueName: "Publisher";            ValueData: "{#AppPublisher}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV"; \
    ValueType: string; ValueName: "URLInfoAbout";         ValueData: "{#AppURL}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV"; \
    ValueType: string; ValueName: "InstallLocation";      ValueData: "{app}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\GSMShieldAV"; \
    ValueType: string; ValueName: "UninstallString";      ValueData: "{uninstallexe}"

; ============================================================
; POST-INSTALL: DEFENDER REPLACEMENT (Req 22.4)
; ============================================================
;
; Run disable-defender.ps1 and register-wsc.ps1 at the end of
; installation so that GSM Shield AV replaces Microsoft Defender
; immediately, without requiring the user to open the app first.
; Both scripts are installed to {app}\resources\scripts\ by
; electron-builder's extraFiles configuration.
;
; disable-defender.ps1 is best-effort (Tamper Protection may block it).
; register-wsc.ps1 creates registry keys under
; HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID} which
; causes Windows to recognize GSM Shield AV as the active antivirus.
; ============================================================

[Run]
; Step 1 - Attempt to disable Defender real-time monitoring (best-effort)
; The script logs its own output to ProgramData\GSMShieldAV\defender-watchdog.log
; and the first-run module logs to AppData\GSMShieldAV\error.log.
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -NonInteractive -File ""{app}\resources\scripts\disable-defender.ps1"""; \
    Flags: runhidden waituntilterminated; StatusMsg: "Configuring Windows Defender..."

; Step 2 - Register GSM Shield AV with Windows Security Center (best-effort)
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -NonInteractive -File ""{app}\resources\scripts\register-wsc.ps1"""; \
    Flags: runhidden waituntilterminated; StatusMsg: "Registering GSM Shield AV with Windows Security Center..."

; ============================================================
; UNINSTALL SEQUENCE (Req 22.5)
; ============================================================

; Step 1 — Stop and remove the background service
[UninstallRun]
; Stop the node-windows service before files are deleted.
; Uses SC to stop then delete; errors are ignored (service may not be running).
Filename: "sc.exe"; Parameters: "stop ""{#ServiceName}"""; \
    Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "sc.exe"; Parameters: "delete ""{#ServiceName}"""; \
    Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"

; Step 2 — Re-enable Windows Defender (Req 22.5, 21.5)
; Runs restore-defender.ps1 with ExecutionPolicy Bypass and NonInteractive flags.
; The script is installed to {app}\resources\scripts\ by electron-builder's
; extraFiles configuration (defender/scripts/ → resources/scripts/).
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -NonInteractive -File ""{app}\resources\scripts\restore-defender.ps1"""; \
    Flags: runhidden waituntilterminated; RunOnceId: "RestoreDefender"

; ============================================================
[UninstallDelete]
; Remove the application installation directory entirely
Type: filesandordirs; Name: "{app}"

; ============================================================
[Code]
// ============================================================
// Pascal Script — handles the optional AppData deletion prompt
// after uninstallation completes (Req 22.5).
// ============================================================

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  AppDataDir: string;
  MsgResult: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    AppDataDir := ExpandConstant('{localappdata}\GSMShieldAV');

    // Only prompt if the AppData directory actually exists
    if DirExists(AppDataDir) then
    begin
      MsgResult := MsgBox(
        'Do you want to delete your user data (scan history, whitelist, quarantine, and settings)?' + #13#10 + #13#10 +
        'Location: ' + AppDataDir + #13#10 + #13#10 +
        'Click Yes to permanently delete user data, or No to keep it.',
        mbConfirmation,
        MB_YESNO
      );

      if MsgResult = IDYES then
      begin
        DelTree(AppDataDir, True, True, True);
      end;
    end;
  end;
end;
