#For more info:  https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527

#For machines where printing is not needed and we can just disable printing altogether!!!
<# Get-Service -Name Spooler
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled #>

$Session = New-Object -ComObject "Microsoft.Update.Session"
$Searcher = $Session.CreateUpdateSearcher()
$historyCount = $Searcher.GetTotalHistoryCount()
$hotfix = $Searcher.QueryHistory(0, $historyCount) | Where-Object {$_.Title -like "*KB5004945*"}
if ($null -ne $hotfix)
{
    $patchApplied = $True
}
else 
{
    Write-Host "Patch KB5004945 has not been applied and you are at risk.  Please install Windows Updates and run this script again."    
}

#Check for proper registry values
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" #this path is not defined by default
$pointAndPrintRegistryPath = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
if ($null -ne $pointAndPrintRegistryPath)
{
    $registryValuesValid = $True
    $setting1 = Get-ItemProperty -Path $path -Name "NoWarningNoElevationOnInstall" -ErrorAction SilentlyContinue #should be 0 (DWORD) or not defined (default setting)
    $setting2 = Get-ItemProperty -Path $path -Name "UpdatePromptSettings" -ErrorAction SilentlyContinue #should be 0 (DWORD) or not defined (default setting)
    $setting3 = Get-ItemProperty -Path $path -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue #should be set to 1
    if (($null -ne $setting1) -and ($setting1.NoWarningNoElevationOnInstall -ne "0"))
    {
        $registryValuesValid = $False
        Write-Host "You are at risk!.  Set the 'NoWarningNoElevationOnInstall' setting at HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint in the registry to a value of 0."
    }
    if (($null -ne $setting2) -and ($setting2.UpdatePromptSettings -ne "0"))
    {
        $registryValuesValid = $False
        Write-Host "You are at risk!.  Set the 'UpdatePromptSettings' setting at HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint in the registry to a value of 0."
    }
    if (($null -ne $setting3) -and ($setting3.RestrictDriverInstallationToAdministrators -ne "1"))
    {
        $registryValuesValid = $False
        Write-Host "You are at risk!.  Set the 'RestrictDriverInstallationToAdministrators' setting at HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint in the registry to a value of 1."
    }
}
else 
{
    if ($null -eq $pointAndPrintRegistryPath)
    {
        New-Item -Path $path -Force | Out-Null
    }
    New-ItemProperty -Path $path -Name RestrictDriverInstallationToAdministrators -Value 1 -Force | Out-Null
    $registryValuesValid = $True
}

if ($patchApplied -and $registryValuesValid)
{
    Write-Host "Patch KB5004945 has been applied."
    Write-Host "Registry values are not a risk."
    Write-Host "Printer driver installation is restricted only to Administrators"
    Write-Host "Congratulations!!! You are not at risk of the 'Print Nightmare' (CVE-2021-34527) vulnerability. Have a nice day :)"
}
