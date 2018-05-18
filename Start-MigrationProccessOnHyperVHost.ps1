param(
    [ValidateNotNullOrEmpty()]
    [String] $RunasAccountName = "esxadm",

    [ValidateNotNullOrEmpty()]
    [String] $ScriptSMBPath = "\\nfs\SmbShare\MigrationScript",

    [ValidateNotNullOrEmpty()]
    [String] $VMMServer = "vmm.azureline.ru",

    [int]$ReportPort = 8989
)

function listen-port {
    param([int]$port)

    $endpoint = new-object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
    $listener = new-object System.Net.Sockets.TcpListener $endpoint
    $listener.start()

    do {
        $client = $listener.AcceptTcpClient() # will block here until connection
        $stream = $client.GetStream();
        $reader = New-Object System.IO.StreamReader $stream
        do {

            $line = $reader.ReadLine()
            if ($line) { write-host $line.Replace("`r", "") }
        } while ($line -and $line -ne ([char]4))
        $reader.Dispose()
        $stream.Dispose()
        $client.Dispose()
    } while ($line -ne ([char]4))
    $listener.stop()
}

# main body
Import-Module NetSecurity

$vmmModuleInstalled = $true
if ((Get-Module VirtualMachineManager -ListAvailable) -eq $null)
{
    Write-Host "VMM module not installed!" -ForegroundColor Yellow
    $vmmModuleInstalled = $false
}

if (!$vmmModuleInstalled)
{
    $tempName = [Guid]::NewGuid()
    $portableModulesPath = "$($env:windir)\Temp\$($tempName)"
    Write-Host "`tCopying portable modules to $portableModulesPath..."
    Copy-Item -Path "$ScriptSMBPath\ps" -Destination $portableModulesPath -Recurse
}

if ($vmmModuleInstalled)
{
    Import-Module VirtualMachineManager
}
else
{
    Import-Module "$portableModulesPath\vmm\psModules\virtualmachinemanager\virtualmachinemanager.psd1"
}


Write-Host "Getting VM host for script execution..."
$vmHost = Get-SCVMHost -VMMServer $VMMServer -ErrorAction SilentlyContinue | ? VirtualizationPlatform -eq 'HyperV' | select -first 1
if ($vmHost -eq $null)
{
    Write-Host "Unable to get VM host for script execution!" -ForegroundColor Red
    return
}
Write-Host "VM host for script execution: `"$($vmHost.Name)`""

Write-Host "Getting runas account `"$RunasAccountName`""
$runasAccount = Get-SCRunAsAccount -VMMServer $VMMServer $RunasAccountName -ErrorAction SilentlyContinue
if ($runasAccount -eq $null)
{
    Write-Host "Unable to get runas account `"$RunasAccountName`"!" -ForegroundColor Red
    return
}

# set timeout to 3 days!
Write-Host "Execting script on $($vmHost) using account `"$($runasAccount.Domain)\$($runasAccount.UserName)`""
$invokeResult = Invoke-SCScriptCommand -VMMServer $VMMServer -Executable "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe " -CommandParameters "-file `"$ScriptSMBPath\Migrate-VMware2HyperV.ps1`" -ReportHost `"$($env:COMPUTERNAME)`" -ReportPort $ReportPort -VMMServer `"$VMMServer`"" -RunAsAccount $runasAccount -VMHost $vmHost -TimeoutSeconds 259200 -RunAsynchronously

if ($ReportPort -ne 0)
{
    Write-Host "Creating firewall exception for port $ReportPort"
    if ((Get-NetFirewallRule -Name "HVMigrationReport" -ErrorAction SilentlyContinue) -ne $null)
    {
        [void](Remove-NetFirewallRule -Name "HVMigrationReport" -ErrorAction SilentlyContinue)
    }
    [void](New-NetFirewallRule -Name "HVMigrationReport" -DisplayName ".Port for HV Migration reports" -Action "Allow" -Profile "Domain" -Direction "InBound" -RemotePort "Any" -LocalPort $ReportPort -Protocol "TCP")

    Write-Host "Start listening for messages from migration script..."
    . listen-port -port $ReportPort
}

if (!$vmmModuleInstalled)
{
    Write-Host "Removing portable modules folder..." -ForegroundColor Green
    Remove-Item $portableModulesPath -Recurse -Force -ErrorAction SilentlyContinue
}

if ($ReportPort -ne 0)
{
    Write-Host "Removing firewall exception for port $ReportPort"
    [void](Remove-NetFirewallRule -Name "HVMigrationReport" -ErrorAction SilentlyContinue)
}
Write-Host "Migration script ended"
