Import-Module '.\AxiadCloud-ADPublishHelper.psm1'

Connect-AxiadCloud -TenantName 'amtrak' -Platform 'demo' -BearerToken (Get-Content '.\AmtrakDemotoken.txt')

$certs=Get-AxiadCertificatesToPublish -ScriptFrequency 10080 -CertificateValidity 730 -UserGroup 'Default Group_LOCAL'

if (!$certs) {Write-Output 'No certs found'} else {Write-Output 'Certs found: '}

foreach ($cert in $certs) { 
    $upn = GetUserUPNfromCertificate -Certificate $cert 
    Write-Output 'UPN : '$upn
    $certFile = ".\" + $cert.Thumbprint + ".cer"
    Export-Certificate -Cert $cert -FilePath $certFile
} 

Disconnect-AxiadCloud