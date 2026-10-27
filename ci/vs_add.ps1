# Adds components to the runner's Visual Studio installation.
# Usage: pwsh ci/vs_add.ps1 <component id> [<component id> ...]
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
Write-Host "Visual Studio: $vs"
$a = @('/c', 'vs_installer.exe', 'modify', '--installPath', "`"$vs`"")
foreach ($c in $args) { $a += @('--add', $c) }
$a += @('--quiet', '--norestart', '--nocache')
Write-Host "Adding $($args -join ', ')"
$p = Start-Process -FilePath cmd.exe -ArgumentList $a -WorkingDirectory "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer" -Wait -PassThru -WindowStyle Hidden
Write-Host "vs_installer exit code: $($p.ExitCode)"
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { exit 1 }
exit 0
