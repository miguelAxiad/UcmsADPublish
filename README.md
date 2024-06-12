Certificate Publishing to AD: Automation in PowerShell using UCMS v2 API

This automation script uses the UCMS v2 REST API. It relies on the credential methods to obtain credentials that expire within a time range and to obtain the value of the associated certificates, which can then be imported into AD. The UCMS REST API methods we use are:
1.	GET /api/v2/credentials : is called with parameters starDate and endDate that define the expiration date range. Given that we know the certificate validity period, we can use this to find credentials that correspond to certificates that were created in a specific time range.
2.	GET /api/v2/credentials/{type}/{credential_uid} : this is called for type=X509 (we are interested in certificate type credentials) and for the relevant credential_uid values. This returns an object that contains the certificate value in PEM format. 
AD requires certificates to be in DER format to be imported. This automation contains a function that performs the format conversion, as well as a function to obtain the certificate holder AD UPN. With this UPN the AD import can be performed easily.  
In UCMS API a credential object can contain several certificates (type of X509) and associated with different smart card containers. The relationship of these objects is illustrated below: 

 
![CredentialDiagram](https://github.com/GHmiguel/UcmsADPublish/assets/35546222/56d06da7-c86c-4b06-948d-8a041625b126)

The CredentialCertificate object contains the Identifier that can be used to retrieve a certificate object that contains the value of the certificate in PEM format. This means that the automation has to make a first call to GET /api/v2/credentials with a start date and end date to find the relevant credentials, and then make a second call to GET /api/v2/credentials/{type}/{credential_uid} to get the details about each relevant credential, so that only the ones that correspond to PIV authentication certificates are considered for publication to AD. 

The REST method GET /api/v2/credentials is called with start and end date parameters, and it provides an array of credentials that expire within the specified time period. As mentioned in item 1 above, we can use this to find certificates that were created in a specific time range as follows. 

 ![CreationValidityScript](https://github.com/GHmiguel/UcmsADPublish/assets/35546222/a6316d8e-7f80-4dd4-8260-abf566c04194)


In the diagram above, the automation script is executed at times T1, T2, with a given frequency (Script Frequency). Certificates created between T1 and T2 will expire in a time between T1’ and T2’. The certificate validity is a fixed period (Certificate Validity, in the diagram). Therefore, dates used for the call to GET /api/v2/credentials  with start date and end date parameters, give us these values:

startDate = T1’ = T2 + (Certificate Validity) – (Script Frequency)

endDate = T2’ = T2 + (Certificate Validity)

The condition that must be satisfied for the relevant certificates is that they are created between successive executions of the automation script. This is the period between T1 and T2 in the diagram above. Hence, we can establish the following condition:

T2 – (Script Frequency) < (Creation Date) ≤ T2

This condition applies to an execution of the automation script at time T2.

The automation is written in PowerShell 7 using VSCode, and is organized as a PowerShel module called AxiadCloud-ADPublishHelper.psm1, with manifest file AxiadCloud-ADPublishHelper.psd1.

The module exports the following functions:

1.	Connect-AxiadCloud: Caches your session information (Tenant Name, Platform and Bearer Token) for use with the Axiad Cloud commands. Must be ran first before any of the other Axiad Cloud commands. It requires the following parameters: Tenant, Platform and BearerToken. Example:

Connect-AxiadCloud -TenantName ‘tenant’ -Platform 'demo' -BearerToken (Get-Content '.\Demotoken.txt')

2.	Disconnect-AxiadCloud: Disconnect from Axiad Cloud API, deletes the cached session information. No parameters are required.
3.	Get-AxiadCertificatesToPublish: Obtains certificates to be published in AD from Axiad Cloud. Retrieves an array of X509Certificate2 objects corresponding to the certificates to be published in AD. It requires the following parameters: ScriptFrequency (in minutes)  CertificateValidity (in days), and UserGroup (name of the user group in scope). Retirns an array of X509 certificate objects.  Example: 

$certs=Get-AxiadCertificatesToPublish -ScriptFrequency 120 -CertificateValidity 180 -UserGroup 'Default Group_LOCAL'

4.	GetUserUPNfromCertificate: Obtains the UPN from the SAN extension in the input certificate, useful for importing the certificate in AD. Requires an X509 certificate object as input parameter and returns the certificate holder UPN as a string. Example: 

$upn = GetUserUPNfromCertificate -Certificate $cert

Here’s an example of how the module can be used in an automation script:
Import-Module '.\AxiadCloud-ADPublishHelper.psm1'

Connect-AxiadCloud -TenantName ‘tenant’ -Platform 'demo' -BearerToken (Get-Content '.\Demotoken.txt')

$certs=Get-AxiadCertificatesToPublish -ScriptFrequency 120 -CertificateValidity 180 -UserGroup 'Default Group_LOCAL'

if ($certs) {

foreach ($cert in $certs) { 
    $upn = GetUserUPNfromCertificate -Certificate $cert 
    $certFile = ".\" + $cert.Thumbprint + ".cer"
    Export-Certificate -Cert $cert -FilePath $certFile
    $user = Get-ADUser -Filter "UserPrincipalName -eq $upn"
    Set-ADUser $user -Certificates @{Add=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFile)}
} 
}

Disconnect-AxiadCloud



