#should be the only variable to put up.
$site = "https://foremanhost:8443" +"/ssh/pubkey"

Disable-SslVerification

$sshstatus = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.server*'

if ($sshstatus.state -eq "NotPresent")
    {
    Write-Output "not present"
    Add-WindowsCapability –Online –Name OpenSSH.Server~~~~0.0.1.0
    }

#Startup SSH 
Set-Service sshd -StartupType Automatic
Start-Service sshd

#set some firewall rules
Set-NetFirewallrule -Name "OpenSSH-Server-In-TCP" -Action Allow
$fwRule = Get-NetFirewallrule -Name "OpenSSH-Server-In-TCP"

#Allowed IP's for access... or range:
#Com seperated @("10.0.0.1","172.14.1.0-200")
$ips = @("192.168.1.1-192.168.1.254")
foreach($r in $fwRule) { Set-NetFirewallRule -Name $r.Name -RemoteAddress $ips }

## Setup ssh key-based authentication. 
# ADJUST AS NEEDED based on the account-name in question on your endpoints, "localadmin" here is a suggestion.
# You ALSO MUST of course, replace the item below 'Place the... (etc) with the content of your desired pub key portion of your ssh key.
# Ed25519 is recommended and works from macOS (Mojave, Catalina) to Windows. See https://medium.com/risan/upgrade-your-ssh-key-to-ed25519-c6e8d60d3c54

if (Test-Path C:\Users\Administrator\.ssh -eq $false)
{
mkdir 'C:\Users\Administrator\.ssh'
}

New-Item 'C:\Users\Administrator\.ssh\authorized_keys'

$keys = Invoke-WebRequest -Uri $site


# Write public key to file
$keys | Set-Content –Path "c:\users\$user\.ssh\authorized_keys"

#last bit is to set the authorized key items so password auth is restricted and authorized keys are allowed:

(Get-Content C:\ProgramData\ssh\sshd_config) -replace "Match Group administrators", "# Match Group administrators" | sc C:\ProgramData\ssh\sshd_config

(Get-Content C:\ProgramData\ssh\sshd_config) -replace "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys", "#       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys " | sc C:\ProgramData\ssh\sshd_config

(Get-Content C:\ProgramData\ssh\sshd_config) -replace "PasswordAuthentication yes", "PasswordAuthentication no" | sc C:\ProgramData\ssh\sshd_config

# Covering both possibilities for thoroughness
(Get-Content C:\ProgramData\ssh\sshd_config) -replace "#PasswordAuthentication no", "PasswordAuthentication no" | sc C:\ProgramData\ssh\sshd_config

#restart to take affect
Restart-Service sshd
Enable-SslVerification


#just in case site is self signed
#all to allow self signed certs. 
function Disable-SslVerification
{
    if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type)
    {
        Add-Type -TypeDefinition  @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustEverything
{
    private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }
    public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
    public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
}
"@
    }
    [TrustEverything]::SetCallback()
}

function Enable-SslVerification
{
    if (([System.Management.Automation.PSTypeName]"TrustEverything").Type)
    {
        [TrustEverything]::UnsetCallback()
    }
}
