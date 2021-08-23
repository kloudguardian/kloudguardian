#########################################
# PowerPasswordNotify.ps1               #
#                                       #
# Notifies users of password expiration #
#                                       #
#                                       #
# Author: Avijit Chakraborty            #
#########################################

#################
# CONFIGURATION #
#################

# Variables

$PPNConfig_DebugLevel = 0

$PPNConfig_NotificationTimeInDays = 7
$PPNConfig_SMTPServerAddress = "your.smtp.server.address.or.ip.com"
$PPNConfig_FromAddress       = "noreply@company.com"
$PPNConfig_BodyIsHtml        = $true

$PPNConfig_DirectoryRoot = "LDAP://OU=Employees,DC=corp,DC=company,DC=com"
$PPNConfig_MaxPageSize = 1000

# Functions

function Configure-Notification-Subject($nName, $nNumDays)
{
	return "$nName, your password will expire in $nNumDays days."
}

function Configure-Notification-Body-Plain($nName, $nNumDays)
{
	return "Please be sure to change your password within $nNumDays."
}

function Configure-Notification-Body-Html($nName, $nNumDays)
{
	$bodyHtml =  "<h2>Your password is expiring in $nNumDays days.</h2><p>Please change your password before that time.</p>"

	return $bodyHtml
}

##########################################################################
# Edit below as needed. For most environments, this should be sufficient.#
##########################################################################

#############
# FUNCTIONS #
#############

function Get-Domain-MaxPassword-Age
{
    $ThisDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DirectoryRoot = $ThisDomain.GetDirectoryEntry()

    $DirectorySearcher = [System.DirectoryServices.DirectorySearcher]$DirectoryRoot
    $DirectorySearcher.Filter = "(objectClass=domainDNS)"
    $DirectorySearchResult = $DirectorySearcher.FindOne()

    $MaxPasswordAge = New-Object System.TimeSpan([System.Math]::ABS($DirectorySearchResult.properties["maxpwdage"][0]))

	return $MaxPasswordAge
}

function Get-Users-With-Expiring-Passwords
{
	$UsersToNotify = @()

	$DirectoryRoot = New-Object System.DirectoryServices.DirectoryEntry($PPNConfig_DirectoryRoot)
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryRoot)
	$DirectorySearcher.filter = "(&(objectCategory=Person)(objectClass=User)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!(userAccountControl:1.2.840.113556.1.4.803:=65536)))"
    $DirectorySearcher.pagesize = $PPNConfig_MaxPageSize

	$MaxPasswordAge = Get-Domain-MaxPassword-Age
	$MaxPasswordAgeDays = $MaxPasswordAge.Days

	$DirectorySearchResult = $DirectorySearcher.FindAll() |
	ForEach-Object -ErrorAction "SilentlyContinue" `
	-Process `
	{
		$PwdChanged = ([adsi]$_.path).psbase.InvokeGet("PasswordLastChanged")

		$DaysTillExpiring = $MaxPasswordAgeDays - ((Get-Date) - $PwdChanged).Days 

		if ($DaysTillExpiring -le $PPNConfig_NotificationTimeInDays)
		{
			$UserToAdd = New-Object psobject

			$UserToAdd | Add-Member NoteProperty -Name "Name" -Value ([adsi]$_.path).name[0]
			$UserToAdd | Add-Member NoteProperty -Name "Email" -Value ([adsi]$_.path).mail[0]
			$UserToAdd | Add-Member NoteProperty -Name "DaysLeft" -Value $DaysTillExpiring

			$UsersToNotify += $UserToAdd
		}

	}

	return $UsersToNotify
}

function Send-Email-Notification-Of-Expiry($nName, $nEmail, $nDaysLeft)
{
	$SmtpClient = New-Object System.Net.Mail.SmtpClient($PPNConfig_SMTPServerAddress)

	$NewMail = New-Object System.Net.Mail.MailMessage
	$NewMail.From = $PPNConfig_FromAddress
	$NewMail.To.Add($nEmail)
	$NewMail.Subject = Configure-Notification-Subject $nName $nDaysLeft

	if ($PPNConfig_BodyIsHtml)
	{
		$NewMail.IsBodyHtml = $true
		$NewMail.Body = Configure-Notification-Body-Html $nName $nDaysLeft
	}
	else
	{
		$NewMail.IsBodyHtml = $false
		$NewMail.Body = Configure-Notification-Body-Plain $nName $nDaysLeft
	}

	$SmtpClient.Send($NewMail)
}

########
# MAIN #
########

$UsersToNotify = Get-Users-With-Expiring-Passwords

foreach ($User in $UsersToNotify)
{
	if ($PPNConfig_DebugLevel -gt 0)
	{
		Write-Host $User
	}
	else
	{
		Send-Email-Notification-Of-Expiry $User.Name $User.Email $User.DaysLeft
	}
}