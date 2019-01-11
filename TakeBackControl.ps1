param (
    [switch]$now = $false,
    [switch]$debug = $false
)

#
# The AppXPackage class has a number of wrapper
# functions for dealling with Windows Store Apps
#
class AppXPackage
{
    #
    # Returns an array of user accounts relevant for
    # altering Windows Store App state on the local
    # computer.
    #
    [object] Accounts()
    {
        return Get-WmiObject win32_useraccount -filter "LocalAccount = True `
            and Name != 'Administrator' `
            and Name != 'DefaultAccount' `
            and Name != 'defaultUser1' `
            and Name != 'Guest' `
            and Name != 'HomeGroupUser$' `
            and Name != 'WDAGUtilityAccount' "
    }

    #
    # Every Windows Store App saves files in %AppData%\Local\Packages
    # this method tries to delete those files.
    #
    DeleteData($displayName)
    {
        foreach($Account in $this.Accounts()) {
            $AccountName = $Account.Name
            $Path = "C:\Users\$AccountName\AppData\Local\Packages\$displayName*_*"
            $Dirs = Get-Item $Path -ErrorAction SilentlyContinue
            foreach($Dir in $Dirs) {
                if ($script:debug) {
                    Write-Host "    Remove-Item -Confirm:`$false -Force -Recurse -LiteralPath '$Dir'"
                }
                #takeown /A /R /F "$Dir"
                Remove-Item -Confirm:$false -Force -Recurse -LiteralPath "$Dir"
            }
        }
    }

    #
    # Return true if the specified package is installed
    # by any user.
    #
    [bool] IsInstalled($displayName)
    {
        foreach($Account in $this.Accounts()) {
            $Sid = $Account.SID
            $Apps = Get-AppXPackage -User $Sid
            foreach($App in $Apps) {
                if ($App.Name -eq $displayName) {
                    return $true
                }
            }
        }
        return $false
    }

    #
    # Return true if the specified package is provisioned on
    # the computer; otherwise false.
    #
    [bool] IsProvisioned($displayName)
    {
        $PackageName = $this.GetProvisionedPackageName($displayName)
        if ($PackageName) {
            return $true
        }
        return $false
    }

    #
    # Makes a best attempt to get the full package name
    # from the display name from all installed packages.
    #
    # Return $null if no package was found
    #
    [string] GetInstalledPackageFullName($displayName)
    {
        $Apps = Get-AppXPackage -AllUsers
        foreach($App in $Apps) {
            if ($App.Name -eq $displayName) {
                return $App.PackageFullName
            }
        }
        return $null
    }

    #
    # Makes a best attempt to get the full package name
    # from the display name from all installed and all
    # provisioned packages.
    #
    # Return $null if no package was found
    #
    [string] GetPackageName($displayName)
    {
        $PackageName = $this.GetInstalledPackageFullName($displayName)
        if ($PackageName) {
            return $PackageName
        }

        return $this.GetProvisionedPackageName($displayName)
    }

    #
    # Makes a best attempt to get the full package name
    # from provisioned packages.
    #
    # Return $null if no package was found
    #
    [string] GetProvisionedPackageName($displayName)
    {
        $Apps = Get-AppXProvisionedPackage -Online
        foreach($App in $Apps) {
            if ($App.DisplayName -eq $displayName) {
                return $App.PackageName
            }
        }
        return $null
    }

    #
    # Returns true if the specified Windows Store App
    # is still storing user data.
    #
    [bool] HasData($displayName)
    {
        foreach($Account in $this.Accounts()) {
            $AccountName = $Account.Name
            $Path = "C:\Users\$AccountName\AppData\Local\Packages\$displayName*_*"
            $Dirs = Get-Item $Path -ErrorAction SilentlyContinue
            if ($Dirs) {
                return $true
            }
        }
        return $false
    }

    #
    # Remove the specified Windows Store App from accounts
    # that have it installed.
    #
    Remove($displayName)
    {
        foreach($Account in $this.Accounts()) {
            $Sid = $Account.SID
            $Apps = Get-AppXPackage -User $Sid -Name $displayName
            foreach($App in $Apps) {
                $PackageName = $App.PackageFullName
                if ($script:debug) {
                    Write-Host "Remove-AppXPackage -User $Sid -Package $PackageName -ErrorAction Stop"
                }
                Remove-AppXPackage -User $Sid -Package $PackageName -ErrorAction Stop
                if ($Error) {
                    return
                }
            }
        }
    }
}

# Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }

#
# Helper class to access Windows capibilities
#
class Capabilities
{
    [object] Get($displayName)
    {
        $items = Get-WindowsCapability -Online
        foreach($item in $items) {
            if ($item -eq $displayName) {
                return $item
            }
        }

        return $null
    }

    Remove($displayName)
    {
        $cap = $this.Get($displayName)
        if (!$cap) {
            return
        }

        if ($cap.State -eq 'Installed') {
            $Name = $cap.Name
            if ($global:debug) {
                Write-Host "Remove-WindowsCapability -Online -Name $Name"
            }
            Remove-WindowsCapability -Online -Name $Name
        }
    }
}

#
# Helper class for Windows Registry
#
class Registry
{
    #
    # Returns an array of user accounts relevant for
    # altering Windows Store App state on the local
    # computer.
    #
    [object] Accounts()
    {
        return Get-WmiObject win32_useraccount -filter "LocalAccount = True `
            and Name != 'Administrator' `
            and Name != 'DefaultAccount' `
            and Name != 'defaultUser1' `
            and Name != 'Guest' `
            and Name != 'HomeGroupUser$' `
            and Name != 'WDAGUtilityAccount' "
    }

    #
    # Enumerate all sub keys for the specified key for all users on the
    # computer.
    #
    [object] EnumSubKeyAllUsers($key)
    {
        $Keys = $()
        foreach($Account in $this.Accounts()) {
            $Sid = $Account.SID
            $Path = "Registry::HKEY_USERS\$Sid\$key"
            $Keys += Get-Item -Path "$Path\*"
        }
        return $Keys
    }

    #
    # Set a registry value, creating the key/value if it does not
    # exist.
    #
    Set($key, $setting, $type, $value)
    {
        $Path = "Registry::$key"
        if ( -Not ( Test-Path "$Path")) {
            Write-Host "New-Item -Path $Path -ItemType RegistryKey -Force"
            New-Item -Path "$Path" -ItemType RegistryKey -Force
        }
        Set-ItemProperty -path "$Path" -Name "$setting" -Type "$type" -Value $value
    }

    #
    # Set a registry key value for every user on the
    # computer.
    #
    SetAllUsers($key, $setting, $type, $value)
    {
        foreach($Account in $this.Accounts()) {
            $Sid = $Account.SID
            $Path = "HKEY_USERS\$Sid\$key"
            $this.Set($Path, $setting, $type, $value)
        }
    }
}

#
# Helper class for file operations
#
class Files
{
    #
    # Returns an array of user accounts relevant for
    # altering Windows Store App state on the local
    # computer.
    #
    [object] Accounts()
    {
        return Get-WmiObject win32_useraccount -filter "LocalAccount = True `
            and Name != 'Administrator' `
            and Name != 'DefaultAccount' `
            and Name != 'defaultUser1' `
            and Name != 'Guest' `
            and Name != 'HomeGroupUser$' `
            and Name != 'WDAGUtilityAccount' "
    }

    #
    # Removes all files under the specified path for all users
    #
    DeleteAllUsers($path)
    {
        foreach($Account in $this.Accounts()) {
            $AccountName = $Account.Name
            $FullPath = "C:\Users\$AccountName\$path"
            Remove-Item -LiteralPath $FullPath -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}

#
# Remove a bunch of uninteresing Windows Store apps.
#
# Run `Get-AppXProvisionedPackage -Online` to list installed apps.
#
function Apps
{
    # Order specific removal due to app dependencies.
    DeleteApp '46928bounde.EclipseManager'
    DeleteApp 'ActiproSoftwareLLC.562882FEEB491'
    DeleteApp 'AdobeSystemsIncorporated.AdobePhotoshopExpress'
    DeleteApp 'D5EA27B7.Duolingo-LearnLanguagesforFree'
    DeleteApp 'Microsoft.BingNews'
    DeleteApp 'Microsoft.BingTranslator'
    DeleteApp 'Microsoft.BingWeather'
    DeleteApp 'Microsoft.GetHelp'
    DeleteApp 'Microsoft.Getstarted'
    DeleteApp 'Microsoft.Microsoft3DViewer'
    DeleteApp 'Microsoft.MicrosoftOfficeHub'
    DeleteApp 'Microsoft.MicrosoftSolitaireCollection'
    DeleteApp 'Microsoft.MicrosoftStickyNotes'
    DeleteApp 'Microsoft.MSPaint'
    DeleteApp 'Microsoft.NetworkSpeedTest'
    DeleteApp 'Microsoft.Office.OneNote'
    DeleteApp 'Microsoft.Office.Sway'
    DeleteApp 'Microsoft.People'
    DeleteApp 'Microsoft.Print3D'
    DeleteApp 'Microsoft.SkypeApp'
    DeleteApp 'Microsoft.Windows.Photos'
    DeleteApp 'Microsoft.WindowsAlarms'
    DeleteApp 'Microsoft.WindowsCamera'
    DeleteApp 'Microsoft.WindowsFeedbackHub'
    DeleteApp 'Microsoft.WindowsMaps'
    DeleteApp 'Microsoft.WindowsSoundRecorder'
    DeleteApp 'Microsoft.ZuneMusic'
    DeleteApp 'Microsoft.ZuneVideo'

    #DeleteApp 'Microsoft.Messaging'
    #DeleteApp 'Microsoft.OneConnect'
    #DeleteApp 'Microsoft.Wallet'
    #DeleteApp 'Microsoft.Xbox.TCUI'
    #DeleteApp 'Microsoft.XboxApp'
    #DeleteApp 'Microsoft.XboxGameOverlay'
    #DeleteApp 'Microsoft.XboxGamingOverlay'
    #DeleteApp 'Microsoft.XboxIdentityProvider'
    #DeleteApp 'Microsoft.XboxSpeechToTextOverlay'
    #DeleteApp 'microsoft.windowscommunicationsapps'
    #DeleteApp 'Microsoft.Advertising.Xaml'

    # I want to remove these, but haven't figured out how yet.
    # DeleteApp 'Microsoft.Windows.PeopleExperienceHost'
}

#
# Configure these items
#
function Configure
{
    ContextMenus
    Corsair
    Desktop
    DesktopFiles
    Devices
    FileExplorer
    Network
    Paging
    PowerManagement
    RecycleBin
    RootConsole
    Services
    StartMenu
    Tasks
    UserConsole

    # Run Apps last since they have the most problems and require
    # multiple runs.
    Apps
}

#
# Cleanup Corsair stuff
#
function Corsair
{
   DeleteRegistryTreeAllUsers 'Software\Corsair\Corsair SSD Toolbox'
}

#
# Remove various context menus that are always added back.
#
function ContextMenus
{
    # 7-ZIP
    DeleteRegistryTree 'HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\7-Zip'

    # NVIDIA Control Panel
    DeleteRegistryTree 'HKEY_CLASSES_ROOT\Directory\background\shellex\ContextMenuHandlers\NvCplDesktopContext'

    # Visual Studio
    DeleteRegistryTree 'HKEY_CLASSES_ROOT\Directory\background\shell\AnyCode'
    DeleteRegistryTree 'HKEY_CLASSES_ROOT\Directory\shell\AnyCode'
}

#
# Permenantly remove Windows Store apps from the computer
#
# List Apps `Get-AppXPackage -AllUsers * | foreach-object { Write-Host $_.Name }`
#
function DeleteApp($displayName)
{
    $Apps = [AppXPackage]::new()

    if ($Apps.IsInstalled($displayName)) {
        if ($debug) {
            Write-Host "$displayName is installed. Going to try removing it first."
        }
        $Apps.Remove($displayName)
    } else {
        $PackageName = $Apps.GetProvisionedPackageName($displayName)
        if ($PackageName) {
            if ($debug) {
                Write-Host "Package NOT installed: $displayName"
                Write-Host "    Going to try and unprovision"
                Write-Host "    Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers -ErrorAction Stop"
            }
            Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers -ErrorAction Stop
            if ($Error) {
                exit
            }
        }
    }

    if ($Apps.IsInstalled($displayName)) {
        if ($debug) {
            Write-Host "Still installed: $displayName. Aborting . . ."
            Write-Host "    The next run will do more."
        }
        exit
    }

    if ($Apps.IsProvisioned($displayName)) {
        if ($debug) {
            Write-Host "Still provisioned: $displayName. Aborting . . ."
            Write-Host "    The next run will do more."
        }
        exit
    }

    if ($Apps.HasData($displayName)) {
        if ($debug) {
            Write-Host "Package NOT installed or provisioned. $displayName"
            Write-Host "    Going to try and delete user files."
        }
        $Apps.DeleteData($displayName)
    }

    if ($debug) {
        Write-Host "Package completely removed: $displayName"
    }
}

#
# Deletes a file off all user desktops
#
function DeleteDesktopFile($fileName)
{
    $ComputerName = HostName
    $Accounts = Get-WmiObject win32_useraccount -Filter "domain = '$ComputerName' "

    foreach ($Account in $Accounts) {
        $Name = $Account.Name
        Remove-Item -Path "C:\Users\$Name\Desktop\$fileName" -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

#
# Delete all registry keys in the specified path.
#
function DeleteRegistryTree($path)
{
    $realPath = "Registry::$path"
    Remove-Item -LiteralPath $realPath -Force -Recurse -ErrorAction SilentlyContinue
}

function DeleteRegistryTreeAllUsers($path)
{
    $ComputerName = HostName
    $Accounts = Get-WmiObject win32_useraccount -Filter "domain = '$ComputerName' "

    foreach($Account in $Accounts) {
        $Sid = $Account.SID
        $literalPath = "Registry::HKEY_USERS\$Sid\$path"
        Remove-Item -LiteralPath "$literalPath" -Force -Recurse -ErrorAction SilentlyContinue
    }
}

#
# Configure some desktop quality of life settings
#
function Desktop
{
    $HostName = HostName
    $Accounts = Get-WmiObject Win32_useraccount -Filter "domain = '$HostName' "
    foreach($Account in $Accounts) {
        $Sid = $Account.SID
        $Path = "Registry::HKEY_USERS\$Sid\Control Panel\Desktop"

        # Show windows contents while dragging
        Set-ItemProperty -Path $Path -Name DragFullWindows -Value 0 -ErrorAction SilentlyContinue

        # Smooth edges of screen fonts
        Set-ItemProperty -Path $Path -Name FontSmoothing -Value 2 -ErrorAction SilentlyContinue

        # Reduce the time it takes for the Start Menu to appear
        Set-ItemProperty -Path $Path -Name MenuShowDelay -Value 50 -ErrorAction SilentlyContinue

        $Path = "Registry::HKEY_USERS\$Sid\Control Panel\Keyboard"
        Set-ItemProperty -Path $Path -Name KeyboardDelay -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $Path -Name KeyboardSpeed -Value 40 -ErrorAction SilentlyContinue
    }

    $Reg = [Registry]::new()
    $Reg.SetAllUsers('Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects', 'VisualFXSetting', 'DWORD', 3)

    $Data = "90,12,03,80,10,00,00,00"
    $Hex= $Data.Split(',') | % { "0x$_"}
    $Reg.SetAllUsers('Control Panel\Desktop', 'UserPreferencesMask', 'BINARY', ([byte[]]$Hex))
    $Reg.SetAllUsers('Control Panel\Desktop\WindowMetrics', 'MinAnimate', 'String', 0)
}

#
# Removes a bunch of punk-ass desktop files
function DesktopFiles
{
    # Microsoft Crap
    DeleteDesktopFile 'desktop.ini'

    # Skype
    DeleteDesktopFile 'Skype.lnk'
}

#
# Disable device drivers
#
function Devices
{
    DisableDevice 'NVIDIA High Definition Audio'
}

#
# Disable a device driver
#
function DisableDevice($deviceName)
{
    $Devices = Get-PnpDevice| where {$_.friendlyname -eq "$deviceName" }
    $Devices | Disable-PnpDevice -Confirm:$false
}

#
# Disable a Windows Service via the registry
#
function DisableService($ServiceName)
{
    $Path = "SYSTEM\CurrentControlSet\Services\$ServiceName"
    if ( -Not ( Test-Path "Registry::HKEY_LOCAL_MACHINE\$Path")) {
        Write-Host "Service not installed: $ServiceName"
        return
    }

    if ($debug) {
        Write-Host "Set-ItemProperty -Path $Path"
    }

    $HostName = HostName
    $Rule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators", 'FullControl', 'Allow')

    $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $Acl = $Key.GetAccessControl()
    $Acl.SetAccessRule($Rule)
    $Key.SetAccessControl($Acl)

    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\$Path" -Name Start -Value 4
}

#
# Disable a Schedueled Windows Task
#
function DisableTask([string]$taskName, [string]$taskPath)
{
    Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
}

#
# Clear all event logs
#
function EventLog
{
    try {
        wevtutil el | Foreach-Object -ErrorAction SilentlyContinue { wevtutil cl "$_" >$null 2>&1 }
    } finally {}
}

#
# Fix File Exlorer
#
function FileExplorer
{
    # Annoying 3D Objects in File Explorer
    DeleteRegistryTree 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}'

    $f = [Files]::new()
    $f.DeleteAllUsers('3D Objects')
    $f.DeleteAllUsers('Contacts')
    $f.DeleteAllUsers('Links')
    $f.DeleteAllUsers('MicrosoftEdgeBackups')
}

#
# Installs this script as a task set to run everyday at 21:00
#
function Install($Path)
{
    $Args = "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$Path`" -now"
    $Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $Args
    $Trigger = New-ScheduledTaskTrigger -Daily -At 9pm
    $Passwd = Read-Host -Prompt 'Password'

    try {
        Get-ScheduledTask -TaskName 'TaskBackControl' -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName 'TakeBackControl' -Confirm:$false -ErrorAction SilentlyContinue
    } finally {
        Register-ScheduledTask -Action $Action `
                               -Trigger $Trigger `
                               -TaskName 'TakeBackControl' `
                               -Description 'Take back control over Windows settings after updates.' `
                               -User "$env:USERDOMAIN\$env:USERNAME" `
                               -Password $Passwd
    }
}

#
# Remove Microsoft Mixed Realtity Portal
#
# !WARNING! Do NOT run this. It will break the Windows
#           Start menu.
#
function MixedReality
{
    $caps = [Capabilities]::new()
    $caps.Remove('Windows Mixed Reality')

    DeleteRegistryTreeAllUsers 'Software\Microsoft\Windows\CurrentVersion\Holographic'
    DeleteRegistryTree 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\PerceptionSimulationExtensions'
    Remove-Item -Force 'C:\ProgramData\WindowsHolographicDevices\SpatialStore\*'
    DeleteApp 'Microsoft.Windows.HolographicFirstRun'
}

#
# Network related changes
#
function Network
{
    # Disable DNS Registration
    $adapters = Get-NetAdapter
    foreach($adapter in $adapters) {
        $adapter | Set-DnsClient -RegisterThisConnectionsAddress $false
    }
}

#
# Disable Paging
#
function Paging
{
    $Computer = Get-WmiObject win32_computersystem
    $Computer.AutomaticManagedPagefile = $false

    $PageFiles = Get-WmiObject Win32_PageFileSetting
    if ($PageFiles) {
        foreach($PageFile in $PageFiles) {
            $PageFile.Delete()
        }
    }
}

#
# Power Management
#
function PowerManagement
{
    # Disable System Hybernation
    powercfg -h off

    # Switch to High Performance profile
    powercfg /S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    # Switch to Balanced profile
    # powercfg /S 381b4222-f694-41f0-9685-ff5bb260df2e
}

#
# Disable the recycle-bin
#
function RecycleBin
{
    $Reg = [Registry]::new()
    $Reg.Set('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket', 'NukeOnDelete', 'DWORD', 1)

    $Keys = $Reg.EnumSubKeyAllUsers('Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume')
    foreach($Key in $Keys) {
        $Reg.Set($Key, 'NukeOnDelete', 'DWORD', 1)
    }
}

#
# Set console colors for 'root'
#
function RootConsole
{
    $ComputerName = HostName
    $Account = Get-WmiObject win32_useraccount -Filter "name = 'root' AND domain = '$ComputerName' "
    $Sid = $Account.SID
    $Path = "Registry::HKEY_USERS\$Sid\Console"

    Set-ItemProperty -Path $Path -Name FaceName -Value Consolas
    Set-ItemProperty -Path $Path -Name ColorTable00 -Value 0
    Set-ItemProperty -Path $Path -Name ColorTable01 -Value 0x00ee0000
    Set-ItemProperty -Path $Path -Name ColorTable02 -Value 0x0000cd00
    Set-ItemProperty -Path $Path -Name ColorTable03 -Value 0x00cdcd00
    Set-ItemProperty -Path $Path -Name ColorTable04 -Value 0x000000cd
    Set-ItemProperty -Path $Path -Name ColorTable05 -Value 0x00ff00ff
    Set-ItemProperty -Path $Path -Name ColorTable06 -Value 0x0000cdcd
    Set-ItemProperty -Path $Path -Name ColorTable07 -Value 0x00e5e5e5
    Set-ItemProperty -Path $Path -Name ColorTable08 -Value 0x007f7f7f
    Set-ItemProperty -Path $Path -Name ColorTable09 -Value 0x00ff5c5c
    Set-ItemProperty -Path $Path -Name ColorTable10 -Value 0x0000ff00
    Set-ItemProperty -Path $Path -Name ColorTable11 -Value 0x00ffff00
    Set-ItemProperty -Path $Path -Name ColorTable12 -Value 0x000000ff
    Set-ItemProperty -Path $Path -Name ColorTable13 -Value 0x00ff00ff
    Set-ItemProperty -Path $Path -Name ColorTable14 -Value 0x0080ffff
    Set-ItemProperty -Path $Path -Name ColorTable15 -Value 0x00ffffff
    Set-ItemProperty -Path $Path -Name LineWrap -Value 0x00000000
}

#
# Disable Services
#
function Services
{
    # Geolocation Service
    #
    # This service monitors the current location of the system
    # and manages geofences (a geographical location with associated
    # events). If you turn off this service, applications will be
    # unable to use or receive notifications for geolocation or
    # geofences.
    DisableService 'lfsvc'

    # Container service for NVIDIA root features
    DisableService 'NVDisplay.ContainerLocalSystem'

    # Shell Hardware Detection
    DisableService 'ShellHWDetection'

    # Downloaded Maps Manager
    #
    # Windows service for application access to downloaded maps.
    # This service is started on-demand by application accessing
    # downloaded maps. Disabling this service will prevent apps
    # from accessing maps.
    DisableService 'MapsBroker'

    # SSDP Discovery
    #
    # Discovers networked devices and services that use the
    # SSDP discovery protocol, such as UPnP devices. Also
    # announces SSDP devices and services running on the
    # local computer. If this service is stopped, SSDP-based
    # devices will not be discovered. If this service is
    # disabled, any services that explicitly depend on it
    # will fail to start.
    DisableService 'SSDPSRV'

    # Touch Keyboard and Handwriting Panel Service
    #
    # Enables Touch Keyboard and Handwriting Panel
    # pen and ink functionality
    DisableService 'TabletInputService'

    # Distributed Link Tracking Client
    #
    # Maintains links between NTFS files within a computer or across
    # computers in a network.
    DisableService 'TrkWks'

    # UPnP Device Host
    #
    # Allows UPnP devices to be hosted on this computer. If this
    # service is stopped, any hosted UPnP devices will stop
    # functioning and no additional hosted devices can be added.
    # If this service is disabled, any services that explicitly
    # depend on it will fail to start.
    DisableService 'upnphost'

    # Windows Media Player Network Sharing Service
    #
    # Shares Windows Media Player libraries to other networked
    # players and media devices using Universal Plug and Play.
    DisableService 'WMPNetworkSvc'

    # Delivery Optimization
    #
    # Performs content delivery optimization tasks.
    DisableService 'DoSvc'
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Name 'DownloadMode' -Value 0

    # System Restore
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'RPSessionInterval' -Value 0
}

#
# Change Start Menu Preferences
#
function StartMenu
{
    $Path = 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop'

    # Reduce the time it takes for the Start Menu to appear
    Set-ItemProperty -Path $Path -Name MenuShowDelay -Value 50
}

#
# Disable a bunch of schedueled tasks
#
function Tasks
{
    $ComputerName = HostName
    $Accounts = Get-WmiObject win32_useraccount -Filter "domain = '$ComputerName' "

    # If the user has consented to participate in the Windows
    # Customer Experience Improvement Program, this job collects
    # and sends usage data to Microsoft.
    DisableTask 'Consolidator' 'Microsoft\Windows\Customer Experience Improvement Program'

    # Goto meeting update task
    foreach ($Account in $Accounts) {
        $Sid = $Account.SID
        DisableTask "G2MUpdateTask-$Sid" '\'
        DisableTask "G2MUploadTask-$Sid" '\'
    }

    # Collects program telemetry information if opted-in to the Microsoft
    # Customer Experience Improvement Program.
    DisableTask 'Microsoft Compatibility Appraiser' '\Microsoft\Windows\Application Experience'

    # This task checks for updates to maps which you have downloaded for
    # offline use. Disabling this task will prevent Windows from notifying you
    # of updated maps.
    DisableTask 'MapsUpdateTask' '\Microsoft\Windows\Maps'

    # Windows Error Reporting task to process queued reports.
    DisableTask 'QueueReporting' '\Microsoft\Windows\Windows Error Reporting'

    # Unknown
    DisableTask 'SpeechModelDownloadTask' '\Microsoft\Windows\Speech'
}

#
# Change current user console colors and fonts
#
function UserConsole
{
    $Path = 'Registry::HKEY_CURRENT_USER\Console'

    Set-ItemProperty -Path $Path -Name FaceName -Value Consolas
    Set-ItemProperty -Path $Path -Name ColorTable00 -Value 0x00000000
    Set-ItemProperty -Path $Path -Name ColorTable01 -Value 0x00ee0000
    Set-ItemProperty -Path $Path -Name ColorTable02 -Value 0x0000cd00
    Set-ItemProperty -Path $Path -Name ColorTable03 -Value 0x00cdcd00
    Set-ItemProperty -Path $Path -Name ColorTable04 -Value 0x000000cd
    Set-ItemProperty -Path $Path -Name ColorTable05 -Value 0x00ff00ff
    Set-ItemProperty -Path $Path -Name ColorTable06 -Value 0x0000cdcd
    Set-ItemProperty -Path $Path -Name ColorTable07 -Value 0x00e5e5e5
    Set-ItemProperty -Path $Path -Name ColorTable08 -Value 0x007f7f7f
    Set-ItemProperty -Path $Path -Name ColorTable09 -Value 0x00ff5c5c
    Set-ItemProperty -Path $Path -Name ColorTable10 -Value 0x0000ff00
    Set-ItemProperty -Path $Path -Name ColorTable11 -Value 0x00ffff00
    Set-ItemProperty -Path $Path -Name ColorTable12 -Value 0x000000ff
    Set-ItemProperty -Path $Path -Name ColorTable13 -Value 0x00ff00ff
    Set-ItemProperty -Path $Path -Name ColorTable14 -Value 0x0080ffff
    Set-ItemProperty -Path $Path -Name ColorTable15 -Value 0x00ffffff
    Set-ItemProperty -Path $Path -Name LineWrap -Value 0x00000000
}

clear
if ($now) {
    Configure
    EventLog
} else {
    Write-Host 'Installing . . .'
    Install $MyInvocation.MyCommand.Definition
}
