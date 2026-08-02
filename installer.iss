; FocusGuard Installer Script for Inno Setup
; Requer Inno Setup 6.x - https://jrsoftware.org/isinfo.php

#define MyAppName "FocusGuard"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "FocusGuard"
#define MyAppURL "https://github.com/focusguard"
#define MyAppExeName "FocusGuard.Manager.exe"
#define MyServiceName "FocusGuard Service"
#define MyServiceExe "FocusGuard.Service.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=installer-output
OutputBaseFilename=FocusGuard-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startservice"; Description: "Iniciar servico automaticamente"; GroupDescription: "Servico:"; Flags: checkedonce

[Files]
Source: "publish\{#MyServiceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "publish\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "publish\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "publish\*.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "publish\appsettings*.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName} Manager"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName} Manager"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Instala o servico
Filename: "sc.exe"; Parameters: "create ""{#MyServiceName}"" binPath=""{app}\{#MyServiceExe}"" start=auto DisplayName=""{#MyServiceName}"""; Flags: runhidden waituntilterminated
; Define descricao do servico
Filename: "sc.exe"; Parameters: "description ""{#MyServiceName}"" ""Servico de protecao de foco e produtividade"""; Flags: runhidden waituntilterminated
; Inicia o servico se selecionado
Filename: "sc.exe"; Parameters: "start ""{#MyServiceName}"""; Tasks: startservice; Flags: runhidden waituntilterminated
; Abre o Manager apos instalacao
Filename: "{app}\{#MyAppExeName}"; Description: "Abrir {#MyAppName} Manager"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Para o servico antes de desinstalar
Filename: "sc.exe"; Parameters: "stop ""{#MyServiceName}"""; Flags: runhidden waituntilterminated
; Aguarda o servico parar
Filename: "timeout.exe"; Parameters: "/t 3 /nobreak"; Flags: runhidden waituntilterminated
; Remove o servico
Filename: "sc.exe"; Parameters: "delete ""{#MyServiceName}"""; Flags: runhidden waituntilterminated

[Code]
// Para o servico antes da desinstalacao dos arquivos
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Tenta parar o servico novamente por seguranca
    Exec('sc.exe', 'stop "{#MyServiceName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2000);
  end;
end;
