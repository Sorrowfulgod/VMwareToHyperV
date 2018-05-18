<#
#>

param(
        [ValidateNotNullOrEmpty()]
        [String] $vmListFile = "tomigrate.csv",

        [ValidateNotNullOrEmpty()]
        [String[]] $NFSDatastores = @("nfs"),

#        [ValidateNotNullOrEmpty()]
#        [String[]] $NFSDatastores = @("nfs","nfs1"),

        [ValidateNotNullOrEmpty()]
        [String] $vCenterServer = "vc.azureline.ru",

        [ValidateNotNullOrEmpty()]
        [String] $VMMServer = "vmm.azureline.ru",

        [ValidateNotNullOrEmpty()]
        [String] $SMBShareName = 'SmbShare',

        [ValidateNotNullOrEmpty()]
        [String] $HardwareProfileNameGen1 = 'Gen1',

        [ValidateNotNullOrEmpty()]
        [String] $HardwareProfileNameGen2 = 'Gen2',

        [ValidateNotNullOrEmpty()]
        [String] $LibraryVirtualHardDiskName = 'Blank Disk - Small.vhdx',

        [String]$ReportHost,

        [int]$ReportPort,

        [ValidateNotNullOrEmpty()]
        [int] $MaxmigrationsPerDatastore = 1
    )

function WriteGlobalLog
{
    param([string]$message, [string]$filename, [switch]$skipWriteToFile)

    $logString = "{0}: {1}" -f (Get-Date).ToString("dd.MM.yyyy hh:MM:ss"), $message
    Write-Host $logString -ForegroundColor Yellow

    if (!$skipWriteToFile)
    {
        $mtx = New-Object System.Threading.Mutex($false, "WriteLogMutex")
        [void]$mtx.WaitOne()
        $logString | Out-File -FilePath $("$($WorkingFolder)\\migrate_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy")) -Append
        if (!$([String]::IsNullOrEmpty($filename)))
        {
            $logString | Out-File -FilePath $("$($WorkingFolder)\\{1}_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy"), $filename) -Append
        }

        if ($ReportTCP)
        {
            $client = New-Object System.Net.Sockets.TcpClient $ReportHost, $ReportPort
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter $stream
            $writer.Write($logString)
            $writer.Dispose()
            $stream.Dispose()
            $client.Dispose()
        }

        [void]$mtx.ReleaseMutex()
    }
}

workflow MigrateVMs
{
    param($VmList, $vCenterServer, $MaxmigrationsPerDatastore, $NFSDatastoresList, 
          $UtilsPath, $ICPath, $VMMServer, $SMBLocation, $SMBShareName, $HardwareProfileNameGen1, $HardwareProfileNameGen2,
          $LibraryVirtualHardDiskName, $WorkingFolder, $powerCLIInstalled, $vmmModuleInstalled, $portableModulesPath, 
          $ReportTCP, $ReportHost, $ReportPort)

    function WriteGlobalLog
    {
        param([string]$message, [string]$filename, [switch]$skipWriteToFile)

        $logString = "{0}: {1}" -f (Get-Date).ToString("dd.MM.yyyy hh:MM:ss"), $message
        Write-Host $logString -ForegroundColor Yellow

        if (!$skipWriteToFile)
        {
            $mtx = New-Object System.Threading.Mutex($false, "WriteLogMutex")
            [void]$mtx.WaitOne()
            $logString | Out-File -FilePath $("$($using:WorkingFolder)\\migrate_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy")) -Append
            if (!$([String]::IsNullOrEmpty($filename)))
            {
                $logString | Out-File -FilePath $("$($using:WorkingFolder)\\{1}_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy"), $filename) -Append
            }

            if ($using:ReportTCP)
            {
                $client = New-Object System.Net.Sockets.TcpClient $using:ReportHost, $using:ReportPort
                $stream = $client.GetStream()
                $writer = New-Object System.IO.StreamWriter $stream
                $writer.Write($logString)
                $writer.Dispose()
                $stream.Dispose()
                $client.Dispose()
            }
            [void]$mtx.ReleaseMutex()
        }
    }

    WriteGlobalLog -message "Workflow running" -filename $vmName

    foreach -parallel ($vmDetails in $workflow:VmList)
    {
        $ReportTCP = $workflow:ReportTCP
        $ReportHost = $workflow:ReportHost
        $ReportPort = $workflow:ReportPort

        $logFolder = $workflow:WorkingFolder
        $vmName = $vmDetails.VSphereVMName
        $VMMSaveMac = $vmDetails.SaveMac

        $pcliInstalled = $workflow:powerCLIInstalled
        $vmmInstalled = $workflow:vmmModuleInstalled 
        $modulesPath = $workflow:portableModulesPath

        WriteGlobalLog -message "VM name in VCenter `"$vmName`". Target VMM VM Network `"$($vmDetails.VMMNetworkName)`". Save MAC: $VMMSaveMac" -filename $vmName

        WriteGlobalLog -message "Acquire free datastore for vm `"$vmName`"..." -filename $vmName
        $NFSDatastoreName = $null
        do
        {
            foreach($key in $workflow:NFSDatastoresList.Keys)
            {
                if ($workflow:NFSDatastoresList[$key] -lt $workflow:MaxmigrationsPerDatastore -and $NFSDatastoreName -eq $null)
                {
                    $NFSDatastoreName = $key
                    $x = $workflow:NFSDatastoresList[$key]++
                }
            }

            if ($NFSDatastoreName -eq $null)
            {
                WriteGlobalLog -message "No free datasource for vm `"$vmName`". Sleeping 10 sec" -skipWriteToFile
                Start-Sleep -Seconds 10
            }
        } while($NFSDatastoreName -eq $null)
        WriteGlobalLog -message "Acquired datastore `"$NFSDatastoreName`" for vm `"$vmName`"" -filename $vmName

        try
        {
            #VMWare block
            $VMWareVMDetails = InlineScript 
            {
                $ErrorActionPreference = "Stop"

                if ($using:pcliInstalled)
                {
                    Import-Module VMware.VimAutomation.Core
                }
                else
                {
                    Import-Module "$using:modulesPath\cli\VMware.VimAutomation.Sdk.psd1"
                    Import-Module "$using:modulesPath\cli\VMware.VimAutomation.Common.psd1"
                    Import-Module "$using:modulesPath\cli\VMware.VimAutomation.CIS.Core.psd1"
                    Import-Module "$using:modulesPath\cli\VMware.VimAutomation.Core.psd1"
                }

                function WriteGlobalLog
                {
                    param([string]$message, [string]$filename, [switch]$skipWriteToFile)

                    $logString = "{0}: {1}" -f (Get-Date).ToString("dd.MM.yyyy hh:MM:ss"), $message
                    Write-Host $logString -ForegroundColor Yellow

                    if (!$skipWriteToFile)
                    {
                        $mtx = New-Object System.Threading.Mutex($false, "WriteLogMutex")
                        [void]$mtx.WaitOne()
                        $logString | Out-File -FilePath $("$($using:logFolder)\\migrate_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy")) -Append
                        if (!$([String]::IsNullOrEmpty($filename)))
                        {
                            $logString | Out-File -FilePath $("$($using:logFolder)\\{1}_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy"), $filename) -Append
                        }

                        if ($using:ReportTCP)
                        {
                            $client = New-Object System.Net.Sockets.TcpClient $using:ReportHost, $using:ReportPort
                            $stream = $client.GetStream()
                            $writer = New-Object System.IO.StreamWriter $stream
                            $writer.Write($logString)
                            $writer.Dispose()
                            $stream.Dispose()
                            $client.Dispose()
                        }
                        [void]$mtx.ReleaseMutex()
                    }
                }
                  
                Set-PowerCLIConfiguration -WebOperationTimeoutSeconds -1 -Confirm:$false

                $VMMServer = $using:VMMServer
                $VMName = $using:vmName
                $VMMTargetNetwork = $using:vmDetails.VMMNetworkName
                $VMMTargetVMGeneration = 1 # Generation for VM in Hyper-V
                $VMMTargetVMNumCPU = 0 # Number of CPU for VM in Hyper-V
                $VMMTargetVMMemoryMB = 0 # Number of RAM for VM in Hyper-V
                $VMMTargetVMIsLinux = $false # Is VM is linux VM
                $VMMTargetVMDisks = @() # list of virtual machine disks
                $VMMTargetVMNetworkAdapters = @() # list of virtual machine network adapters
                $Success = $true
                $ExecError = ""

                try 
                {
                    WriteGlobalLog -message "Processing VCenter vm `"$VMName`"" -filename $VMName

                    # connecting to VCenter
                    WriteGlobalLog -message "Connecting to VCenter server `"$($using:vCenterServer)`"..." -filename $VMName
                    $viServer = Connect-VIServer -Server $using:vCenterServer -Force -NotDefault -WarningAction SilentlyContinue #-Username $using:vCenterUser -Password $using:vCenterPassword
                    $vCenterVm = Get-VM -Server $viServer -Name $VMName

                    # here get from AD OS name and service pack revision
                    # $vCenterVm.Guest.Hostname

                    # get base properties of VM    
                    if ($vCenterVm.ExtensionData.Config.Firmware -ne "bios")
                    {
                        $VMMTargetVMGeneration = 2
                    }

                    $VMMTargetVMNumCPU = $vCenterVm.NumCPU
                    $VMMTargetVMMemoryMB = $vCenterVm.MemoryMB
                    $VMMTargetVMIsLinux = $false
                    if ($vCenterVm.Guest.GuestFamily -notmatch "windowsGuest")
                    {
                        $VMMTargetVMIsLinux = $true
                    }

                    #get VM Network adapters
                    if ($vCenterVm.Guest.Nics -eq $null)
                    {
                        throw "Unable get network info for `"$VMName`"! Check VM status!"
                    }

                    if ($vCenterVm.Guest.Nics.Count -gt 1)
                    {
                        throw "Unsupported config of VM `"`"! {0} network adapters instead of 1. I don't want migrate this!" -f $vCenterVm.Guest.Nics.Count
                    }

                    foreach($nic in $vCenterVm.Guest.Nics)
                    {
                        $VMMTargetVMNetworkAdapters += new-object PSCustomObject -Property @{
                            MacAddress = $nic.Device.MacAddress;
                            IpAddress = $nic.IPAddress | ?{$_ -notmatch ":"};
                        }
                    }

                    # Temporary disable clone creation
                    #WriteGlobalLog -message "Create copy of `"$VMName`" to `"$VMName-clone`"..." -filename $VMName
                    #$targetCloneDS = $vCenterVm | Get-HardDisk | select -first 1 | Get-Datastore -Server $viServer
                    #$cloneVM = New-VM -Server $viServer -Name "$VMName-clone" -VM $vCenterVm -VMHost $vCenterVm.VMHost -Datastore $targetCloneDS -ErrorAction SilentlyContinue
    
                    #storage vMotion disks to NFS
                    $targetDatastore = Get-Datastore -Server $viServer -Name $using:NFSDatastoreName
                    $targetDatastoreHost = $targetDatastore.RemoteHost[0].ToString()
                    $targetDatastorePath = $targetDatastore.RemotePath.Replace("/","").ToString()
                    $hardDisks = $vCenterVm | Get-HardDisk -Server $viServer
                    $diskFormats = @()
                    foreach($disk in $hardDisks)
                    {
                        # store formats because after migration 
                        $diskFormats += new-object PSCustomObject -Property @{
                            Name = $disk.Name
                            Fixed = $($disk.StorageFormat -notmatch "thin")
                        }
                        WriteGlobalLog -message "Performing storage vMotion for `"$($disk.Filename)`" to datastore `"$($using:NFSDatastoreName)`"" -filename $VMName
                        $disk | Move-HardDisk -Server $viServer -Datastore $targetDatastore -confirm:$false
                    }

                    # get VM disks
                    $hardDisks = $vCenterVm | Get-HardDisk -Server $viServer
                    foreach($disk in $hardDisks)
                    {
                        $fileName = $disk.Filename.Substring($disk.Filename.LastIndexOf('/') + 1)
                        $dsEnd = $disk.Filename.IndexOf("]") + 2
                        $loc = $disk.Filename.Substring($dsEnd, $disk.Filename.IndexOf("/") - $dsEnd)
                        $VMMTargetVMDisks += new-object PSCustomObject -Property @{
                            Folder = $loc
                            Filename = $fileName
                            CapacityKB = $disk.CapacityKB
                            Fixed = ($diskFormats | ? Name -match $($disk.Name)).Fixed
                            IsBootable = $($disk.Name -match "hard disk 1") # Assume 'Hard disk 1' is always boot disk
                        }
                    }

                    $startTime = $using:vmDetails.StartTime
                    if (!([String]::IsNullOrEmpty($startTime)))
                    {
                        Disconnect-VIServer -Server $viServer -Confirm:$false

                        $now = Get-Date
                        $schedTime = [DateTime]::Parse($startTime)
                        $toSleep = [int]($schedTime - $now).TotalSeconds

                        WriteGlobalLog -message "VM migration scheduled at `"$startTime`". Sleeping $toSleep seconds..." -filename $VMName
                        Start-Sleep -Seconds $toSleep

                        $viServer = Connect-VIServer -Server $using:vCenterServer -Force -NotDefault -WarningAction SilentlyContinue #-Username $using:vCenterUser -Password $using:vCenterPassword
                        $vCenterVm = Get-VM -Server $viServer -Name $VMName
                    }

                    WriteGlobalLog -message "Shutting down VM `"$VMName`"..." -filename $VMName
                    Shutdown-VMGuest -VM $vCenterVm -Server $viServer -Confirm:$false

                    WriteGlobalLog -message "Waiting `"$VMName`" to shutdown..." -filename $VMName
                    while ($vCenterVm.PowerState -ne 'PoweredOff')
                    {
                        Start-Sleep -Seconds 5

                        $vCenterVm = Get-VM -Server $viServer -Name $VMName
                    }

                    WriteGlobalLog -message "Disconnecting from VCenter server `"$($using:vCenterServer)`"..." -filename $VMName
                    Disconnect-VIServer -Server $viServer -Confirm:$false
                } 
                catch 
                { 
                    $Success = $false
                    $ExecError = $_
                }

                $nfsParam = New-Object PSObject -Property @{
                    NFSRemoteHost = $targetDatastoreHost
                    NFSRemoteShare = $targetDatastorePath
                }

                $vmParams = New-Object PSObject -Property @{
                    VMName = $VMName;
                    VMMTargetNetwork = $VMMTargetNetwork
                    VMMTargetVMGeneration = $VMMTargetVMGeneration # Generation for VM in Hyper-V
                    VMMTargetVMNumCPU = $VMMTargetVMNumCPU # Number of CPU for VM in Hyper-V
                    VMMTargetVMMemoryMB = $VMMTargetVMMemoryMB # Number of RAM for VM in Hyper-V
                    VMMTargetVMIsLinux = $VMMTargetVMIsLinux # Is VM is linux VM
                    VMMTargetVMDisks = $VMMTargetVMDisks # list of virtual machine disks
                    VMMTargetVMNetworkAdapters = $VMMTargetVMNetworkAdapters # list of virtual machine network adapters
                    Success = $Success
                    Error = $ExecError
                }


                New-Object PSObject -Property @{
                    VMParams = $vmParams
                    NFSParams = $nfsParam
                }
            } -PSAuthentication Negotiate

            if (! $($VMWareVMDetails.VMParams.Success) )
            {
                throw $($VMWareVMDetails.VMParams.Error)
            }

            $VMMTargetNetwork = $VMWareVMDetails.VMParams.VMMTargetNetwork;
            $VMMTargetVMGeneration = $VMWareVMDetails.VMParams.VMMTargetVMGeneration; # Generation for VM in Hyper-V
            $VMMTargetVMNumCPU = $VMWareVMDetails.VMParams.VMMTargetVMNumCPU; # Number of CPU for VM in Hyper-V
            $VMMTargetVMMemoryMB = $VMWareVMDetails.VMParams.VMMTargetVMMemoryMB; # Number of RAM for VM in Hyper-V
            $VMMTargetVMIsLinux = $VMWareVMDetails.VMParams.VMMTargetVMIsLinux; # Is VM is linux VM
            $VMMTargetVMDisks = $VMWareVMDetails.VMParams.VMMTargetVMDisks; # list of virtual machine disks
            $VMMVHDXFiles = @()

            #
            # Here get IP pool in VMM and details (GW, DNS)
            #
            WriteGlobalLog -message $("Getting info for network adapter from VMM...") -filename $vmName
            $VCNetworkAdapters = $VMWareVMDetails.VMParams.VMMTargetVMNetworkAdapters; # list of virtual machine network adapters
            $GetDetailsResult = InlineScript 
            {
                if ($using:vmmInstalled)
                {
                    Import-Module VirtualMachineManager
                }
                else
                {
                    Import-Module "$using:modulesPath\vmm\psModules\virtualmachinemanager\virtualmachinemanager.psd1"
                }

                $Success = $true
                $ExecError = ""
                $Mask = ""
                try
                {
                    $AdaptersList = @()
                    $VCNetworkAdapters = $using:VCNetworkAdapters
                    $VMName = $using:vmName

                    $VMMTargetNetwork = $using:VMMTargetNetwork
                    $VMNetworkAdapters = $using:VCNetworkAdapters

                    $VMNetwork = Get-SCVMNetwork $VMMTargetNetwork -VMMServer $using:VMMServer
                    if ($VMNetwork -eq $null)
                    {
                        throw "Unable to get VM Network `"$VMMTargetNetwork`""
                    }

                    $LogicalNetworkDefinition = Get-SCLogicalNetworkDefinition -LogicalNetwork $VMNetwork.LogicalNetwork
                    if ($LogicalNetworkDefinition.SubnetVLans -is [System.Array])
                    {
                        throw "Unable to get VM Network `"$VMMTargetNetwork`""
                    }

                    $IPPool = Get-SCStaticIPAddressPool -LogicalNetworkDefinition $LogicalNetworkDefinition -Subnet $VMNetwork.VMSubnet.SubnetVLans.Subnet
                    if ($IPPool -eq $null)
                    {
                        throw "Unable to get IP pool!"
                    }

                    # convert CIDR to netmask
                    [int]$CIDRBits = [int]$IPPool.Subnet.SubString($IPPool.Subnet.IndexOf("/") + 1)
                    $CIDR_Bits = ('1' * $CIDRBits).PadRight(32, '0')
                    $Octets = $CIDR_Bits -split '(.{8})' -ne ''
                    $Mask = ($Octets | ForEach { [Convert]::ToInt32($_, 2) }) -join '.'
                }
                catch
                {
                    $Success = $false
                    $ExecError = $_
                }

                if ($Success)
                {
                    $AdapterConfig = new-object PSCustomObject -Property @{
                        MacAddress = $VMNetworkAdapters[0].MacAddress;
                        IpAddress = $VMNetworkAdapters[0].IpAddress;
                        SubnetMask = $Mask
                        Gateways = $IPPool.DefaultGateways
                        DNSServers = $IPPool.DNSServers
                        DNSSuffix = $IPPool.DNSSuffix
                        VLANID = $IPPool.VLanID
                    }
                    $AdaptersList += $AdapterConfig
                }

                New-Object PSObject -Property @{
                    AdaptersList = $AdaptersList
                    Success = $Success
                    Error = $ExecError
                }
            }

            if (!$GetDetailsResult.Success)
            {
                throw $GetDetailsResult.Error
            }

            $VMMTargetVMNetworkAdapters = $GetDetailsResult.AdaptersList
            WriteGlobalLog -message $("Full info for network adapter: IP {0}, Mask: {1}, Gateways {2}, DNS: {3} DNSSuffix: {4} VLANID {5}" -f $VMMTargetVMNetworkAdapters[0].IpAddress, $VMMTargetVMNetworkAdapters[0].SubnetMask, $VMMTargetVMNetworkAdapters[0].Gateways, $VMMTargetVMNetworkAdapters[0].DNSServers, $VMMTargetVMNetworkAdapters[0].DNSSuffix, $VMMTargetVMNetworkAdapters[0].VLANID) -filename $vmName
            #
            #
            #

            # converting disks and inject tools into system vhdx
            $nfsHost = $VMWareVMDetails.NFSParams.NFSRemoteHost
            $nfsShare = $VMWareVMDetails.NFSParams.NFSRemoteShare
            $SMBShare = $workflow:SMBShareName
            $SMBPath = "\\{0}\{1}" -f $nfsHost, $SMBShare
            WriteGlobalLog -message $("Using SMB share `"{0}`" for disk convertion and vm creation" -f $SMBPath) -filename $vmName

            foreach ($vmDisk in $VMMTargetVMDisks)
            {
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($vmDisk.Filename)
                $VMDKFile = "$fileName-flat.vmdk"
                $VHDXFile = "$fileName.vhdx"

                WriteGlobalLog -message $("Cloning(copying) file `"$VMDKFile`" from NFS Share to SMB share") -filename $vmName
                $moveResult = InlineScript 
                { 
                    $moveRes = ""
                    #$nfsShare = Get-NFSShare -Name $using:nfsShare 
                    $smbShare = Get-SMBShare -Name $using:SMBShare
                    $smbShareDir = "{0}\{1}" -f $($smbShare.Path), $($using:vmDisk.Folder)
                    $smbFile = $("{0}\{1}" -f $smbShareDir, $using:VHDXFile)
                    $vmdkFile = $("{0}\{1}" -f $smbShareDir, $using:VMDKFile)
                    if ($(Get-Item $smbShareDir -ErrorAction SilentlyContinue) -eq $null)
                    {
                        $outnull = New-Item -Type Directory $smbShareDir 
                    }

                    $moveRes += "Clone file using block clone..."
                    $result = Invoke-Expression ". $using:UtilsPath\RefsClone.exe `"$vmdkFile`" `"$smbFile`" 2>&1" -ErrorAction SilentlyContinue
                    if ($LASTEXITCODE -eq -1)
                    {
                        $moveRes += "Unable to clone file using Block Clone: $result"
                        $moveRes += "`r`nUsing copy instead`r`n"

                        Copy-Item "$vmdkFile" "$smbFile" -Force
                    }
                    else
                    {
                        $moveRes += $result
                    }

                    #Move-Item $("{0}\{1}\{2}" -f $($nfsShare.Path), $($using:vmDisk.Folder), $using:VMDKFile) $("{0}\{1}" -f $smbShareDir, $using:VMDKFile) -Force
                    #Rename-Item $("{0}\{1}" -f $smbShareDir, $using:VMDKFile) $smbFile -Force
                    Get-ACL $($smbShare.Path) | Set-Acl $smbFile

                    $moveRes 
                } -PSComputerName $nfsHost -PSAuthentication Negotiate

                WriteGlobalLog -message $moveResult -filename $vmName

                $VMDKFilePath = "{0}\{1}\{2}" -f $SMBPath, $vmDisk.Folder, $VMDKFile
                $VHDXSmbPath = "{0}\{1}\{2}" -f $SMBPath, $vmDisk.Folder, $VHDXFile
                WriteGlobalLog -message $("`tDisk name: {0}, SizeKb: {1}, Fixed: {2}, Bootable: {3}. Full SMB path {4}. VDMK {5}. Converting to vhdx" -f $vmDisk.Filename, $vmDisk.CapacityKB, $vmDisk.Fixed, $vmDisk.IsBootable, $VHDXSmbPath, $VMDKFilePath) -filename $VMName

                $tempFile = new-object PSCustomObject -Property @{
                    Path = $("{0}\{1}" -f $SMBPath, $vmDisk.Folder);
                    Name = $VHDXFile;
                    Bootable = $vmDisk.IsBootable;
                    SizeGB = $($vmDisk.CapacityKB / 1048576);
                }
                $VMMVHDXFiles += $tempFile
                
                # without loop strange shit may happens...
                
                $success = $false
                for ($i = 0; $i -lt 5 -and $success -ne $true; $i++)
                {
                    WriteGlobalLog -message $("`tConverting `"{0}`" to VHD... Try $i" -f $VHDXSmbPath) -filename $VMName
                    $result = Invoke-Expression ". $UtilsPath\vhdtool /convert `"$VHDXSmbPath`" 2>&1" -ErrorAction SilentlyContinue
                    #$result
                    foreach ($r in $result) { if (!$success) { $success = $r.Contains("Complete") } }

                    if (!$success)
                    {
                        Start-Sleep -Seconds 10
                    }
                }
                if (!$success)
                {
                    WriteGlobalLog -message $("`tConvert `"{0}`" to VHD failed: {1}, {2}" -f $VHDXSmbPath, $result[0], $result) -filename $VMName
                    throw ""
                }

                WriteGlobalLog -message $("`tConverting `"{0}`" to VHDX..." -f $VHDXSmbPath) -filename $VMName
                $result = Invoke-Expression ". $UtilsPath\vhdxtool upgrade -f `"$VHDXSmbPath`" 2>&1" -ErrorAction SilentlyContinue
                #$result
                $success = $false
                foreach ($r in $result) { if (!$success) { $success = $r.Contains("Success") } }
                if (!$success)
                {
                    WriteGlobalLog -message $("`tConvert `"{0}`" to VHDX failed: {1}" -f $VHDXSmbPath, $result) -filename $VMName
                    throw ""
                }

                if (!$vmDisk.Fixed)
                {
                    WriteGlobalLog -message $("`t`"{0}`" not fixed. Convert to dynamic..." -f $VHDXSmbPath) -filename $VMName
                    $result = Invoke-Expression ". $UtilsPath\vhdxtool dynamize -f $VHDXSmbPath 2>&1" -ErrorAction SilentlyContinue
                    $success = $false
                    foreach ($r in $result) { if (!$success) { $success = $r.Contains("Success") } }
                    if (!$success)
                    {
                        WriteGlobalLog -message $("`Dynamize `"{0}`" failed: {1}" -f $VHDXSmbPath, $result) -filename $VMName
                    }
                }

                # inject Hyper-V IC and remove VMWare IC. configure IP address
                if ($vmDisk.IsBootable) 
                {
                    WriteGlobalLog -message $("{0} is bootable. Injecting Hyper-V tools and VMWare tools uninstall" -f $VHDXSmbPath) -filename $VMName
                    $VMRegID = [Guid]::NewGuid()
                    
                    WriteGlobalLog -message "Mounting VHDX `"$VHDXSmbPath`"..." -filename $VMName
                    $VHDXDisk = Mount-DiskImage -ImagePath $VHDXSmbPath -StorageType VHDX –PassThru

                    if ($VHDXDisk -eq $null)
                    {
                        throw "Mount VHDX `"$VHDXSmbPath` failed!"
                    }

                    try
                    {
                        $VHDFolder = $null
                        $MountedDiskNumber = (Get-DiskImage -ImagePath $VHDXSmbPath).Number
                        $mountedDriveLetters = (Get-Disk -Number $MountedDiskNumber | Get-Partition | ?{ -not ([String]::IsNullOrEmpty($_.DriveLetter)) }).DriveLetter
                        if ( -not ($mountedDriveLetters -is [System.Array]) )
                        {
                            $mountedDriveLetters = @($mountedDriveLetters)
                        }

                        WriteGlobalLog -message "mounted drive letters for disk `"$mountedDriveLetters`". Count: $($mountedDriveLetters.Count)" -filename $VMName
                        for ($i = 0; $i -lt $mountedDriveLetters.Count -and $VHDFolder -eq $null; $i++)
                        {
                            $drive = "$($mountedDriveLetters[$i]):\"
                            WriteGlobalLog -message "Checking `"$drive`"" -filename $VMName
                            $folder = Get-Item $("{0}windows" -f $drive) -ErrorAction SilentlyContinue
                            if ($folder -ne $null)
                            {
                                $VHDFolder = $drive
                            }
                        }

                        if ($VHDFolder -eq $null)
                        {
                            throw $("Unable to find suitable system drive! HddNum: {0}, Letters: {1}, vhdfol: {2}" -f $MountedDiskNumber, $mountedDriveLetters, $VHDFolder)
                        }

                        WriteGlobalLog -message "VHDX mounted under `"$VHDFolder`"" -filename $VMName

                        $ICFolder = $VHDFolder + "TempHV"
                        $VMwareToolsUninstall = $ICFolder + "\vmguest\VMwareToolsUninstall.bat"
                        $SetGuestIP = $ICFolder + "\vmguest\SetIP.bat"
                        $VHDSystemHive = $VHDFolder + "WINDOWS\SYSTEM32\CONFIG\SYSTEM"
                        $VHDSoftwareHive = $VHDFolder + "WINDOWS\SYSTEM32\CONFIG\SOFTWARE"
                        $RegArgLoadSystemHive = "HKLM\$($VMRegID)System"
                        $RegArgLoadSoftwareHive = "HKLM\$($VMRegID)Software"
                        $RegServicesPath = "HKLM:\$($VMRegID)System\ControlSet001\Services\"
                        $RegSoftwarePath = "HKLM:\$($VMRegID)Software\Microsoft\Windows\CurrentVersion\uninstall"
                        $RegHVInstall = $RegServicesPath + "HVInstall\"
                        $RegHVInstallEnum = $RegHVInstall + "Enum\"
                        $RegHVInstallParameters = $RegHVInstall + "Parameters\"
                        $RegHVInstallSecurity = $RegHVInstall + "Security\"

                        WriteGlobalLog -message "Copy tools package..." -filename $VMName
                        $supress = New-Item -Path $VHDFolder -Name "TempHV" -Type Directory -ErrorAction SilentlyContinue
                        Copy-Item $ICPath -Destination $ICFolder -Recurse -Force


                        WriteGlobalLog -message "Loading system hive `"$RegArgLoadSystemHive`"..."  -filename $VMName
                        $supress = Invoke-Expression ". reg load `"$RegArgLoadSystemHive`" $VHDSystemHive"
                        WriteGlobalLog -message "Loading software hive `"$RegArgLoadSoftwareHive`"..." -filename $VMName
                        $supress = Invoke-Expression ".  reg load `"$RegArgLoadSoftwareHive`" $VHDSoftwareHive"

                        WriteGlobalLog -message "Creating registry items..." -filename $VMName
                        $supress = New-Item -Path $RegServicesPath -Name HVInstall
                        $supress = New-Item -Path $RegHVInstall -Name Enum
                        $supress = New-Item -Path $RegHVInstall -Name Parameters
                        $supress = New-Item -Path $RegHVInstall -Name Security

                        $supress = New-ItemProperty -Path $RegHVInstall -Name Type -PropertyType Dword -Value 16
                        $supress = New-ItemProperty -Path $RegHVInstall -Name Start -PropertyType Dword -Value 2
                        $supress = New-ItemProperty -Path $RegHVInstall -Name ErrorControl -PropertyType Dword -Value 1
                        $supress = New-ItemProperty -Path $RegHVInstall -Name WOW64 -PropertyType Dword -Value 1
                        $supress = New-ItemProperty -Path $RegHVInstall -Name DisplayName -PropertyType String -Value 'HVInstall'
                        $supress = New-ItemProperty -Path $RegHVInstall -Name ObjectName -PropertyType String -Value 'LocalSystem'
                        $supress = New-ItemProperty -Path $RegHVInstall -Name ImagePath -PropertyType ExpandString -Value 'c:\TempHV\vmguest\srvany.exe'

                        $supress = New-ItemProperty -Path $RegHVInstallEnum -Name '0' -PropertyType String -Value 'Root\LEGACY_HVINSTALL\0000'
                        $supress = New-ItemProperty -Path $RegHVInstallEnum -Name Count -PropertyType Dword -Value 1
                        $supress = New-ItemProperty -Path $RegHVInstallEnum -Name NextInstance -PropertyType Dword -Value 1

                        $supress = New-ItemProperty -Path $RegHVInstallParameters -Name Application -PropertyType String -Value 'c:\TempHV\vmguest\VMwareToolsUninstall.bat'

                        $supress = New-ItemProperty -Path $RegHVInstallSecurity -Name Security -PropertyType Binary -Value ([byte[]](0x01,0x00,0x14,0x80,0xb8,0x00,0x00,0x00,0xc4,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x02,0x00,0x1c,0x00,0x01,0x00,0x00,0x00,0x02,0x80,0x14,0x00,0xff,0x01,0x0f,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0xfd,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0xff,0x01,0x0f,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x8d,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x8d,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x01,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x0b,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0xfd,0x01,0x02,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x23,0x02,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00))

                        $supress = Set-ItemProperty -Path "$($RegServicesPath)ParPort" -Name Start -Value 4 

                        WriteGlobalLog -message "Creating uninstall for VMWare tools..." -filename $VMName
                        $regSoftwareKeys = Get-childItem $RegSoftwarePath
                        $VMwareToolsGUID = $null
                        for($i = 0; $i -lt $regSoftwareKeys.Count -and $VMwareToolsGUID -eq $null; $i++)
                        {
                            $key = $regSoftwareKeys[$i]
                            $UninstallItem = $key.pschildname
                            $UninstallItemProperty = Get-Itemproperty $RegSoftwarePath\$UninstallItem
                            if ($UninstallItemProperty.DisplayName -match "VMware Tools") 
                            {
                                $VMwareToolsGUID = $UninstallItem
                                
                                $VMwareUninstallText = "MsiExec.exe /uninstall " + $VMwareToolsGUID  + " /qn /norestart /l*v C:\TempHV\VMwareToolsUninstall.log`
reg delete HKLM\SYSTEM\CurrentControlSet\Services\HVInstall\Parameters /v Application /f`
reg add HKLM\SYSTEM\CurrentControlSet\Services\HVInstall\Parameters /v Application /t REG_SZ /d c:\TempHV\vmguest\HVInstall.bat`
c:\TempHV\vmguest\psshutdown.exe -accepteula -f -r -t 5"
                                $VMwareUninstallText | Set-Content $VMwareToolsUninstall -Encoding Ascii
                                WriteGlobalLog -message "Uninstall command for VMWare tools: $VMwareUninstallText" -filename $VMName
                            }
                        }

                        # generate inject ip cmd
                        $IPDNSServers = $VMMTargetVMNetworkAdapters[0].DNSServers
                        $dnsServersCmd = "wmic nicconfig where IPEnabled=true call SetDNSServerSearchOrder ("
                        foreach($dns in $IPDNSServers)
                        {
                            $dnsServersCmd += "`"$dns`","
                        }
                        $dnsServersCmd = $dnsServersCmd.SubString(0, $dnsServersCmd.Length - 1) + ")"

                        $Gateways = $VMMTargetVMNetworkAdapters[0].Gateways
                        $gatewaysCmd = "WMIC NICCONFIG WHERE ipenabled=true CALL SetGateways ("
                        foreach($gw in $Gateways)
                        {
                            $gatewaysCmd += "`"$gw`","
                        }
                        $gatewaysCmd = $gatewaysCmd.SubString(0, $gatewaysCmd.Length - 1) + ")"

                        $IP = $VMMTargetVMNetworkAdapters[0].IpAddress
                        $IPSubnetMask = $VMMTargetVMNetworkAdapters[0].SubnetMask

                        $dnsSuffix = $VMMTargetVMNetworkAdapters[0].DNSSuffix
                        $dnsSuffixCmd = ""
                        if (! ([String]::IsNullOrEmpty($dnsSuffix)) )
                        {
                            $dnsSuffixCmd = "WMIC NICCONFIG WHERE ipenabled=true CALL SetDNSDomain $dnsSuffix"
                        }

                        $SetGuestIP = "`r`n`r`nWMIC NICCONFIG WHERE ipenabled=true CALL EnableStatic (`"$IP`"),(`"$IPSubnetMask`")`r`n`r`n$gatewaysCmd`r`n`r`n$dnsServersCmd`r`n`r`n$dnsSuffixCmd`r`n`r`n"

                        WriteGlobalLog -message "Storing set ip command: $SetGuestIP" -filename $VMName
                        $SetGuestIP | Out-File $($ICFolder + "\vmguest\HVReboot.bat") -Encoding Ascii
                        #$SetGuestIP = "`r`nc:\TempHV\vmguest\psshutdown.exe -accepteula -f -r -t 30`r`nreg delete HKLM\SYSTEM\CurrentControlSet\Services\HVInstall /f`r`necho Y | rmdir /S /Q c:\TempHV\vmguest\support`r`necho Y | del C:\TempHV\vmguest\instsrv.exe`r`necho Y | del C:\TempHV\vmguest\HVInstall.bat`r`necho Y | del C:\TempHV\vmguest\psshutdown.exe`r`ncopy c:\Windows\vmgcoinstall.log c:\TempHV\`r`ncopy c:\Windows\vmguestsetup.log c:\TempHV\`r`ncopy c:\Windows\vmguestsetup.msi.log c:\TempHV\`r`ncopy c:\Windows\Wdf01009Inst.log c:\TempHV\`r`n"
                        $SetGuestIP = "`r`necho Y | rmdir /S /Q c:\TempHV\vmguest\support`r`necho Y | del C:\TempHV\vmguest\instsrv.exe`r`necho Y | del C:\TempHV\vmguest\HVInstall.bat`r`necho Y | del C:\TempHV\vmguest\psshutdown.exe`r`ncopy c:\Windows\vmgcoinstall.log c:\TempHV\`r`ncopy c:\Windows\vmguestsetup.log c:\TempHV\`r`ncopy c:\Windows\vmguestsetup.msi.log c:\TempHV\`r`ncopy c:\Windows\Wdf01009Inst.log c:\TempHV\`r`nsc delete HVInstall`r`ntaskkill /im srvany.exe /f`r`n"
                        
                        $SetGuestIP | Out-File $($ICFolder + "\vmguest\HVReboot.bat") -Append -Encoding Ascii
    
                        WriteGlobalLog -message "Unloading registry hives.." -filename $VMName
                        $supress = Invoke-Expression ". reg unload $RegArgLoadSystemHive"
                        $supress = Invoke-Expression ". reg unload $RegArgLoadSoftwareHive"
                    }
                    catch
                    {
                        throw $_
                    }
                    finally
                    {
                        WriteGlobalLog -message "Dismounting VHDX..." -filename $VMName
                        Dismount-DiskImage –ImagePath $VHDXSmbPath
                    }
                }
                # end of -- inject Hyper-V IC and remove VMWare IC
            }

            #SCVMM Block
            $vmmResult = InlineScript
            {
                function WriteGlobalLog
                {
                    param([string]$message, [string]$filename, [switch]$skipWriteToFile)

                    $logString = "{0}: {1}" -f (Get-Date).ToString("dd.MM.yyyy hh:MM:ss"), $message
                    Write-Host $logString -ForegroundColor Yellow

                    if (!$skipWriteToFile)
                    {
                        $mtx = New-Object System.Threading.Mutex($false, "WriteLogMutex")
                        [void]$mtx.WaitOne()
                        $logString | Out-File -FilePath $("$($using:logFolder)\\migrate_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy")) -Append
                        if (!$([String]::IsNullOrEmpty($filename)))
                        {
                            $logString | Out-File -FilePath $("$($using:logFolder)\\{1}_{0}.log" -f (Get-Date).ToString("dd.MM.yyyy"), $filename) -Append
                        }

                        if ($using:ReportTCP)
                        {
                            $client = New-Object System.Net.Sockets.TcpClient $using:ReportHost, $using:ReportPort
                            $stream = $client.GetStream()
                            $writer = New-Object System.IO.StreamWriter $stream
                            $writer.Write($logString)
                            $writer.Dispose()
                            $stream.Dispose()
                            $client.Dispose()
                        }
                        [void]$mtx.ReleaseMutex()
                    }
                }

                $ErrorActionPreference = "Stop"

                $Success = $true
                $ExecError = ""

                try
                {
                    if ($using:vmmInstalled)
                    {
                        Import-Module VirtualMachineManager
                    }
                    else
                    {
                        Import-Module "$using:modulesPath\vmm\psModules\virtualmachinemanager\virtualmachinemanager.psd1"
                    }

                    $disksCount = 1
                    $VMName = $using:vmName
                    WriteGlobalLog -message $("Creating VM in VMM...") -filename $VMName

                    $requiredGB = 0
                    foreach($vhdx in $using:VMMVHDXFiles)
                    {
                        $requiredGB += $vhdx.SizeGB
                    }
                    WriteGlobalLog -message $("Required space(GB): $requiredGB") -filename $VMName

                    $VMMTargetNetwork = $using:VMMTargetNetwork
                    $VMNetworkAdapters = $using:VMMTargetVMNetworkAdapters
                    $VMGeneration = $using:VMMTargetVMGeneration
                    $VMMSaveMac = $using:VMMSaveMac

                    $CPUCount = $using:VMMTargetVMNumCPU
                    $MemoryMB = $using:VMMTargetVMMemoryMB
                    $VHDXList = $using:VMMVHDXFiles | Sort Bootable -Desc
                
                    $TargetHardwareProfileName = $using:HardwareProfileNameGen1

                    if ($VMGeneration -eq 2)
                    {
                        $TargetHardwareProfileName = $using:HardwareProfileNameGen2
                    }

                    $VirtualDiskLocation = $VHDXList[0].Path
                    $VirtualDiskFileName = $VHDXList[0].Name

                    $vmDescription = ""
                    $TemplateGuid = [Guid]::NewGuid()
                    $JobGuid = [Guid]::NewGuid()

                    $vmTemplateName = "TempHVTemplate$TemplateGuid"
                    $vmConfigName = "TempHVVMConfig$TemplateGuid" 
                    $vmHwProfileName = "TempHVProfile$TemplateGuid"
                    $vmTemplateDescription = ""
                    $vmmServer = $using:VMMServer

                    WriteGlobalLog -message $("`tUsing VMM server `"{0}`"" -f $vmmServer) -filename $VMName

                    WriteGlobalLog -message $("`tGet hardware profile `"$TargetHardwareProfileName`"...") -filename $VMName
                    $OriginalHardwareProfile = Get-SCHardwareProfile -VMMServer $vmmServer | ? Name -eq $TargetHardwareProfileName
                    $HardwareProfileParams = @{
                        VMMServer = $vmmServer
                        Name = $vmHwProfileName
                        CPUCount = $CPUCount
                        MemoryMB = $MemoryMB
                        HardwareProfile = $OriginalHardwareProfile 
                        JobGroup = $JobGuid
                    }

                    WriteGlobalLog -message $("`tCreate new profile with vCPU: {0}, MemoryMB: {1} ..." -f $CPUCount, $MemoryMB) -filename $VMName
                    $HardwareProfile = New-SCHardwareProfile @HardwareProfileParams

                    WriteGlobalLog -message $("`tCreating template for VM...") -filename $VMName
                    $VirtualHardDisk = Get-SCVirtualHardDisk -VMMServer $vmmServer | ? { $_.HostType -eq "LibraryServer" -and $_.Name -eq $using:LibraryVirtualHardDiskName } | Select-Object -First 1
                    $vmTemplate = New-SCVMTemplate -Name $vmTemplateName -Description $vmTemplateDescription -VirtualHardDisk $VirtualHardDisk -HardwareProfile $HardwareProfile -NoCustomization 

##
#get host and placement
                    WriteGlobalLog -message $("`tGet host for VM using host rating...") -filename $VMName
                    $vmHost = $(Get-VMHostRating -Template $vmTemplate -VMName $VMName -VMHost $(Get-VMHostCluster | Get-SCVMHost) -DiskSpaceGB $requiredGB | sort rating -Descending | select -First 1 -Property VMHost).VMHost
                    WriteGlobalLog -message $("`tUsing host `"{0}`"" -f $vmHost.Name) -filename $VMName
                    $bestVolumeName = $(Get-VMHostVolume | where{$_.IsClustered -and $_.IsAvailableForPlacement -and $_.FileSystemType -like "CSVFS*" -and $_.FileSystem -ne $null} | sort FreeSpace -Descending | select Name -First 1).Name
                    $VirtualMachineLocation = ($vmHost.RegisteredStorageFileShares | ?{$_.StorageVolume.Name -ne $null -and $_.StorageVolume.Name.StartsWith($bestVolumeName)} | sort FreeSpaceMB -desc | select -first 1).SharePath
                    if ($VirtualMachineLocation -eq $null)
                    {
                        $VirtualMachineLocation = $bestVolumeName
                    }
                    WriteGlobalLog -message $("`tUsing location for VM `"$VirtualMachineLocation`"") -filename $VMName
#
                    WriteGlobalLog -message $("`tCreating configuration for VM...") -filename $VMName
                    $vmConfig = New-SCVMConfiguration -VMTemplate $vmTemplate -Name $vmConfigName
                    $outnull = Set-SCVMConfiguration -VMConfiguration $vmConfig -VMHost $vmHost -VMLocation $VirtualMachineLocation 
                    $vmConfig = Update-SCVMConfiguration -VMConfiguration $vmConfig

                    WriteGlobalLog -message $("`tUpdating boot disk location...") -filename $VMName
                    WriteGlobalLog -message $("`tUsing `"$VirtualDiskFileName`" on `"$VirtualDiskLocation`" as boot disk") -filename $VMName
                    $outnull = Set-SCVirtualHardDiskConfiguration -VHDConfiguration $vmConfig.VirtualHardDiskConfigurations[0] -DestinationLocation $VirtualDiskLocation -FileName $VirtualDiskFileName  -DeploymentOption UseExistingVirtualDisk

                    WriteGlobalLog -message $("`tCreating virtual machine...") -filename $VMName
                    $VM = New-SCVirtualMachine -Name $VMName -Description $vmDescription -VMConfiguration $vmConfig -UseDiffDiskOptimization

                    $bus = 0
                    $lun = 1
                    WriteGlobalLog -message $("`tAdditional disk count: {0}" -f $($VHDXList.Count - 1)) -filename $VMName
                    for($i = 1; $i -lt $($VHDXList.Count); $i++)
                    {
                        $NewDiskParams = @{
                            SCSI = $true
                            VM = $VM
                            Bus = 0
                            LUN = $i 
                            UseLocalVirtualHardDisk = $true
                            FileName = $($VHDXList[$i].Name)
                            Path = $($VHDXList[$i].Path)
                        }

                        WriteGlobalLog -message $("`t`tAdding disk `"{0}`" on `"{1}`"" -f $($VHDXList[$i].Name), $($VHDXList[$i].Path)) -filename $VMName
                        New-SCVirtualDiskDrive @NewDiskParams -ErrorAction Stop
                    }

                    $VMNetwork = Get-SCVMNetwork $VMMTargetNetwork
                    if ($VMNetwork -eq $null)
                    {
                        throw "Unable to get VM Network `"$VMMTargetNetwork`""
                    }

                    $LogicalNetworkDefinition = Get-SCLogicalNetworkDefinition -LogicalNetwork $VMNetwork.LogicalNetwork
                    if ($VMNetwork -eq $null)
                    {
                        throw "Unable to get Logical network definition for `"$VMMTargetNetwork`""
                    }

                    $IPPool = Get-SCStaticIPAddressPool -LogicalNetworkDefinition $LogicalNetworkDefinition
                    if ($VMNetwork -eq $null)
                    {
                        throw "Unable to get IP Pool for `"$VMMTargetNetwork`""
                    }


                    WriteGlobalLog -message $("`tGranting `"$($VMNetworkAdapters[0].IpAddress)`" to network adapter...") -filename $VMName
                    $ip = Grant-SCIPAddress -StaticIPAddressPool $IPPool -GrantToObjectType VirtualNetworkAdapter -GrantToObjectID $($VM.VirtualNetworkAdapters[0].ID) -IPAddress $($VMNetworkAdapters[0].IpAddress)
                    if ($ip -eq $null)
                    {
                        throw "Unable grant IP $($VMNetworkAdapters[0].IpAddress)!"
                    }

                    $NetAdapterParams = @{
                        IPv4AddressType = "Static"
                        VMNetwork = $VMNetwork
                        VirtualNetworkAdapter = $VM.VirtualNetworkAdapters[0]
                        MACAddressType = "Static"
                    }

                    if ($VMNetworkAdapters[0].VLANID -ne 0)
                    {
                        $NetAdapterParams.Add("VLanEnabled", $true)
                        $NetAdapterParams.Add("VLanID", $VMNetworkAdapters[0].VLANID)
                    }

                    $macAddress = "00:00:00:00:00:00"
                    WriteGlobalLog -message $("`tSave MAC: $VMMSaveMac") -filename $VMName
                    if ($VMMSaveMac -eq 1)
                    {
                        $macAddress = $VMNetworkAdapters[0].MacAddress
                        WriteGlobalLog -message $("`tMAC address saved because config") -filename $VMName
                     }
                    $NetAdapterParams.Add("MacAddress", $macAddress)

                    WriteGlobalLog -message $("`tChange network adapter properties:") -filename $VMName
                    WriteGlobalLog -message $("`t`tConnected to: `"$VMMTargetNetwork`"") -filename $VMName
                    WriteGlobalLog -message $("`t`tMAC Address: `"$macAddress`"") -filename $VMName
                    WriteGlobalLog -message $("`t`tVLANID: `"$($VMNetworkAdapters[0].VLANID)`"") -filename $VMName
                    $outnull = Set-SCVirtualNetworkAdapter @NetAdapterParams

                    WriteGlobalLog -message $("`tStarting VM...") -filename $VMName
                    Start-SCVirtualMachine -VM $VM

                    # remove junk in main script after all
                    WriteGlobalLog -message $("`tRemoving junk VM template...") -filename $VMName
                    $outnull = Remove-SCVMTemplate -VMTemplate $vmTemplate -RunAsynchronously
                    WriteGlobalLog -message $("`tRemoving junk VM Hardware profile...") -filename $VMName
                    $outnull = Remove-SCHardwareProfile -HardwareProfile $HardwareProfile -RunAsynchronously

                # live migrate storage
                #  ?????????
                # $VM.Location
                    WriteGlobalLog -message $("`tMigrating VM files to single location `"$VirtualMachineLocation`"...") -filename $VMName
                    Move-SCVirtualMachine -VM $VM -VMHost $vmHost -Path $VirtualMachineLocation -UseLAN -UseDiffDiskOptimization
                }
                catch
                {
                    #possible delete bad vm????
                    $Success = $false
                    $ExecError = $_
                }

                New-Object PSObject -Property @{
                    Success = $Success
                    Error = $ExecError
                }
            }

            if ($vmmResult.Success -eq $false)
            {
                throw $($vmmResult.Error)
            }

            WriteGlobalLog -message "Migration of `"$VMName`" done!" -filename $VMName
            WriteGlobalLog -message "----------------------------------" -filename $VMName
            WriteGlobalLog -message "" -filename $VMName

        } # end of InlineScript
        catch
        {
            WriteGlobalLog -message "Exception `"$_`" migrating `"$vmName`"!`r`nTrace: `"$($_.ScriptStackTrace)`"" -filename $vmName
            $vmName | Out-File -FilePath ("{0}\failed.log" -f $workflow:WorkingFolder) -Encoding ascii
        }
        finally
        {
            $x = $workflow:NFSDatastoresList[$NFSDatastoreName]--
        }
    }
}

#
# main body
#

$WorkingFolder = $(Split-Path $MyInvocation.MyCommand.Path);

$utilsPath = "$WorkingFolder\utils\"
$ICSourceFolder = "$WorkingFolder\vmguest\"

Remove-Item "$WorkingFolder\failed.log" -Force -ErrorAction SilentlyContinue

$ReportTCP = $false
if ( !([String]::IsNullOrEmpty($ReportHost)) -and $ReportPort -ne 0) 
{
    WriteGlobalLog -message "Testing reporting remote port.."
    if ( (Test-NetConnection -ComputerName $ReportHost -Port $ReportPort -InformationLevel Quiet) )
    {
        WriteGlobalLog -message "Host `"$ReportHost`" responding on port $ReportPort. Using for reporting"
        $ReportTCP = $true
    }
    else
    {
        WriteGlobalLog -message "Host `"$ReportHost`" not responding on port $ReportPort"
    }
}

try
{
    WriteGlobalLog -message "Testing prerequsites.."
    WriteGlobalLog -message "Running under `"$($env:USERNAME)`""

    if (! (Test-Path "$($WorkingFolder)\$($vmListFile)") )
    {
        WriteGlobalLog -message "`"$vmListFile`" not found at $WorkingFolder!"
        throw ""
    }

    WriteGlobalLog -message "Working folder: `"$WorkingFolder`""
    if ( !(Test-Path $("{0}\HVReboot.bat" -f $ICSourceFolder)) -or !(Test-Path $("{0}\HVInstall.bat" -f $ICSourceFolder)) -or !(Test-Path $("{0}\instsrv.exe" -f $ICSourceFolder)) `
            -or !(Test-Path $("{0}\psshutdown.exe" -f $ICSourceFolder)) -or !(Test-Path $("{0}\srvany.exe" -f $ICSourceFolder)) -or !(Test-Path $("{0}\support" -f $ICSourceFolder)) )
    {
        WriteGlobalLog -message "`tSome of integration components is missing!"
        throw ""
    }
     
    if ( !(Test-Path $("{0}\vhdtool.exe" -f $utilsPath)) )
    {
        WriteGlobalLog -message "`tVHDTOOL is missing!"
        throw ""
    }

    if ( !(Test-Path $("{0}\vhdxtool.exe" -f $utilsPath)) )
    {
        WriteGlobalLog -message "`tVHDTOOL is missing!"
        throw ""
    }

    if ( !(Test-Path $("{0}\RefsClone.exe" -f $utilsPath)) )
    {
        WriteGlobalLog -message "`RefsClone is missing!"
        throw ""
    }

    #
    # here check for powercli and vmm modules... copy from share if none
    #
    $powerCLIInstalled = $true
    if ((Get-Module VMware.VimAutomation.Core -ListAvailable) -eq $null)
    {
        WriteGlobalLog -message "PowerCLI module not installed!"
        $powerCLIInstalled = $false
    }

    $vmmModuleInstalled = $true
    if ((Get-Module VirtualMachineManager -ListAvailable) -eq $null)
    {
        WriteGlobalLog -message "VMM module not installed!"
        $vmmModuleInstalled = $false
    }

    if (!$powerCLIInstalled -or !$vmmModuleInstalled)
    {
        $tempName = [Guid]::NewGuid()
        $portableModulesPath = "$($env:windir)\Temp\$($tempName)"
        WriteGlobalLog -message "Copying portable modules to $portableModulesPath..."
        Copy-Item -Path "$WorkingFolder\ps" -Destination $portableModulesPath -Recurse
    }

    #
    #

    WriteGlobalLog -message "Loading list of VMs to migrate..."
    # loading list of VM from CSV file
    $VmList = Import-Csv "$($WorkingFolder)\$($vmListFile)"

    $List = @{}
    WriteGlobalLog -message "Initialize datastores list"
    # initialize datastores list
    foreach ($ds in $NFSDatastores)
    {
        $List += @{$ds = 0}
    }

    WriteGlobalLog -message "Starting migration process"

    MigrateVMs -VmList $VmList -vCenterServer $vCenterServer -MaxmigrationsPerDatastore $MaxmigrationsPerDatastore -NFSDatastoresList $List -UtilsPath $utilsPath -ICPath $ICSourceFolder -VMMServer $VMMServer -SMBLocation $SMBLocation -SMBShareName $SMBShareName -HardwareProfileNameGen1 $HardwareProfileNameGen1 -HardwareProfileNameGen2 $HardwareProfileNameGen2 -LibraryVirtualHardDiskName $LibraryVirtualHardDiskName -WorkingFolder $WorkingFolder -powerCLIInstalled $powerCLIInstalled -vmmModuleInstalled $vmmModuleInstalled -portableModulesPath $portableModulesPath -ReportTCP $ReportTCP -ReportHost $ReportHost -ReportPort $ReportPort

    if (!$powerCLIInstalled -or !$vmmModuleInstalled)
    {
        WriteGlobalLog -message "Removing portable modules folder..."
        Remove-Item $portableModulesPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    WriteGlobalLog -message "Migration process completed"
}
catch {}
finally
{
    if ($ReportTCP)
    {
        WriteGlobalLog -message "Sutting down remote reporting..."

        $client = New-Object System.Net.Sockets.TcpClient $ReportHost, $ReportPort
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter $stream
        $writer.Write($([char]4))
        $writer.Dispose()
        $stream.Dispose()
        $client.Dispose()
    }
}