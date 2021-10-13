#For more info:  https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
#Run these steps as Administrator from a Powershell window/terminal

#set proper inheritance
icacls $env:windir\system32\config\*.* /inheritance:e

#list out existing shadow copies for a given system drive
vssadmin list shadows /for=C:

#delete existing shadow copies
vssadmin delete shadows /for=C: /Quiet

#confirm shadow copies were deleted
vssadmin list shadows /for=C:

#check for patch; if present you should be good to go, if not, need to install it!
$Session = New-Object -ComObject "Microsoft.Update.Session"
$Searcher = $Session.CreateUpdateSearcher()
$historyCount = $Searcher.GetTotalHistoryCount()
$hotfix = $Searcher.QueryHistory(0, $historyCount) | Where-Object {$_.Title -like "*kb5005033*"}
$hotfix