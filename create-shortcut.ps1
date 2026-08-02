$WshShell = New-Object -ComObject WScript.Shell
$Desktop = [Environment]::GetFolderPath('Desktop')
$Shortcut = $WshShell.CreateShortcut("$Desktop\FocusGuard Manager.lnk")
$Shortcut.TargetPath = "D:\Dev\Personal\FocusGuard\publish\manager\FocusGuard.Manager.exe"
$Shortcut.WorkingDirectory = "D:\Dev\Personal\FocusGuard\publish\manager"
$Shortcut.Description = "FocusGuard Manager"
$Shortcut.Save()
Write-Host "Atalho criado na area de trabalho!"
