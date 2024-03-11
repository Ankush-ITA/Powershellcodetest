Connect-ExchangeOnline
Connect-MsolService
$ExportCSV="C:\ActionReports\ALLMailboxtest_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
$Result=""
$Results=@()
$Count=0

#Get all Mailbox data

Get-Mailbox -ResultSize Unlimited | foreach {
$Count++
$Name= $_.DisplayName
$Mailboxtype=$_.RecipientTypeDetails
$UPN=$_.UserPrincipalName
$PrimarySmtpAddress=$_.PrimarySmtpAddress
$WhenCreated=$_.WhenCreated
$WhenMailboxCreated=$_.WhenMailboxCreated
$AccountDisabled=$_.AccountDisabled
$IsDirSynced=$_.IsDirSynced
$IsInactiveMailbox=$_.IsInactiveMailbox
$IsSoftDeletedByRemove=$_.IsSoftDeletedByRemove
$ProhibitSendReceiveQuota=$_.ProhibitSendReceiveQuota
$RetentionPolicy=$_.RetentionPolicy
$ArchiveState=$_.ArchiveState
$LitigationHoldEnabled=$_.LitigationHoldEnabled
if($_.InPlaceHolds -ne $Empty)
{
 $InPlaceHoldEnabled="True"
}
else
{
 $InPlaceHoldEnabled="False"
}
$MailboxItemSize=(Get-MailboxStatistics -Identity $_.UserPrincipalName).TotalItemSize.Value
$MailboxItemSize=$MailboxItemSize.ToString().split("()")
$MBSize=$MailboxItemSize | Select-Object -Index 0
$MBSizeInBytes=$MailboxItemSize | Select-Object -Index 1
$AssignedLicenses=@()
$Licenses=(Get-MsolUser -UserPrincipalName $UPN).licenses.accountSkuId
foreach($License in $Licenses)
{
 $LicenseItem= $License -Split ":" | Select-Object -Last 1
 $AssignedLicenses=$AssignedLicenses+$LicenseItem
}
$AssignedLicenses=$AssignedLicenses -join ","
#Export results to CSV
$Result = @{'Name'=$Name;'Mailboxtype'=$Mailboxtype;'UPN'=$UPN;'PrimarySmtpAddress'=$PrimarySmtpAddress;'WhenCreated'=$WhenCreated;'WhenMailboxCreated'=$WhenMailboxCreated;'AccountDisabled'=$AccountDisabled;'IsDirSynced'=$IsDirSynced;'Mailbox Usage'=$MBSize;'MB Size (Bytes)'=$MBSizeInBytes;'Mailbox Size'=$ProhibitSendReceiveQuota;'IsSoftDeletedByRemove'=$IsSoftDeletedByRemove;'Litigation Hold Enabled'=$LitigationHoldEnabled;'In-place Hold Enabled'=$InPlaceHoldEnabled ;'Assigned Licenses'=$AssignedLicenses;'RetentionPolicy'=$RetentionPolicy;'Archive Status'=$ArchiveState}
$Results = New-Object PSObject -Property $Result
$Results |select-object 'Name','MailboxType','UPN','PrimarySmtpAddress','WhenCreated','WhenMailboxCreated','AccountDisabled','IsDirSynced','Mailbox Usage','MB Size (Bytes)','Mailbox Size','IsSoftDeletedByRemove','Litigation Hold Enabled','In-place Hold Enabled','Assigned Licenses','RetentionPolicy', 'Archive Status' | Export-CSV $ExportCSV  -NoTypeInformation -Append
 }