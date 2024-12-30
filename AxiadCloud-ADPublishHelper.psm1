function InvokeGetRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )
    if (!$Script:Axiad) {
        throw "Error: Not connected to Axiad Cloud. You must run 'Connect-AxiadCloud' first."
    }
    $BaseUrl = $Script:Axiad.BaseURL -replace "/$", ""
    $Uri = $BaseUrl + $Path
    
    $Response = Invoke-RestMethod -Authentication Bearer -Token ($Script:Axiad.BearerToken | ConvertTo-SecureString -AsPlainText -Force) -Uri $Uri 

    return $Response
}

function ParseAxiadCredential ($AxiadC) {
    $Result = [PSCustomObject]@{
        userName  = $AxiadC.userName
        groups    = $AxiadC.groups
        groupName = $AxiadC.groups.groupName
        certificates = $AxiadC.groups.certificates
    }
    return $Result
}

function ParseAxiadCredentialCertificate ($CreCertificate) {
    $Result = [PSCustomObject]@{
        identifier  = $CreCertificate.identifier
        status    = $CreCertificate.status
        certificateType = $CreCertificate.certificateType
        certificateContainerName = $CreCertificate.certificateContainerName
    }
    return $Result
}

function Get-AxiadCredentials {
    [CmdletBinding()]
     param (
        [Parameter(Mandatory = $true, Position=1)]
        [DateTime]
        $StartDate,

        [Parameter(Mandatory = $true, Position=2)]
        [DateTime]
        $EndDate
    )
    $url = "/api/v2/credentials?startDate=$($StartDate.ToString('MM-dd-yyyy'))`&endDate=$($EndDate.ToString('MM-dd-yyyy'))"
    $Credentials = InvokeGetRestMethod -Path $url
    return $Credentials
}

function Get-AxiadCerticate {
    [CmdletBinding()]
     param (
        [Parameter(Mandatory = $true, Position=1)]
        [String]
        $ID
    )
    $url = "/api/v2/credentials/x509/$($ID)"
    $Certificate = InvokeGetRestMethod -Path $url
    return $Certificate
}

function GetUserUPNfromCertificate {
    <#
    .SYNOPSIS
    Obtains the UPN as a string for the input certificate
    .DESCRIPTION
    Obtains the UPN from the SAN extension in the input certificate, useful for importing the certificate in AD
    .PARAMETER Certificate
    Certificate as an X509Certificate2 object
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )
    $sanExt=$Certificate.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}
    $sanObjs = new-object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $altNamesStr=[System.Convert]::ToBase64String($sanExt.RawData)
    $sanObjs.InitializeDecode(1, $altNamesStr)
    $upn = $sanObjs.AlternativeNames | Where-Object {$_.Type -eq 11}
    return $upn.strValue
}

function Get-AxiadCertificatesToPublish {
    <#
    .SYNOPSIS
    Obtains certificates to be published in AD from Axiad Cloud
    .DESCRIPTION
    Retrieves an array of X509Certificate2 objects corresponding to the certificates to be published in AD.
    .PARAMETER ScriptFrequency
    Frequency for running the script in minutes
    .PARAMETER CertificateValidity
    Validity period for the certificates in days
    .PARAMETER UserGroup
    User Group of interest, default value: Default Group_LOCAL
    #>
    [OutputType('System.Security.Cryptography.X509Certificates.X509Certificate2[]')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position=1)]
        $ScriptFrequency,

        [Parameter(Mandatory = $true, Position=2)]
        $CertificateValidity,

        [Parameter(Mandatory = $true, Position=3)]
        $UserGroup
    )
    $Results = @()
    $GroupName = 'Default Group_LOCAL'
    $CurrentDate = Get-Date
    $StartDate = ($CurrentDate.AddDays($CertificateValidity)).AddMinutes(-$ScriptFrequency)
    $EndDate = $StartDate.AddMinutes($ScriptFrequency)
    $Credentials = Get-AxiadCredentials -StartDate $StartDate -EndDate $EndDate
    if (!$Credentials) 
    {
        Write-Warning 'No credentials found in the specified expiry period'
    }
    foreach ($Credential in $Credentials)
    {
        $CredentialObject = ParseAxiadCredential -AxiadC $Credential
        #Filter by groupName
        if ($UserGroup) 
            {
                $GroupName = $CredentialObject.groupName #use this ifthe group is SCIM
                # $GroupName = ($CredentialObject.groupName -split "," | ConvertFrom-StringData).CN    #use this if group is LDAP/AD
            }

        foreach ($Certificate in $CredentialObject.certificates)
        {
            $CertificateObject = ParseAxiadCredentialCertificate -CreCertificate $Certificate
            if ($CertificateObject.status -eq 'ACTIVE' -and 
                $CertificateObject.certificateType -eq 'X509'-and 
                $CertificateObject.certificateContainerName -eq 'CERTIFICATE_PIV_AUTHENTICATION' -and 
                $GroupName -eq $UserGroup)
            {
                $Certificate = Get-AxiadCerticate -ID $CertificateObject.identifier
                $creationDate = ConvertFromUnixTimeInMilliseconds -UnixTime $Certificate.created 
                if ($creationDate -gt $CurrentDate.AddMinutes(-$ScriptFrequency) -and
                    $creationDate -le $CurrentDate)
                {
                    $DERcertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($Certificate.value)
                    $Results += $DERcertificate 
                }
            }
        }
    }
    return $Results
}



function Get-AllAxiadActiveCertificates {
    <#
    .SYNOPSIS
    Obtains all Active certificates to be published in AD from Axiad Cloud
    .DESCRIPTION
    Retrieves an array of X509Certificate2 objects corresponding to the certificates to be published in AD.

    .PARAMETER CertificateValidity
    Validity period for the certificates in days
    .PARAMETER UserGroup
    User Group of interest, default value: Default Group_LOCAL
    #>
    [OutputType('System.Security.Cryptography.X509Certificates.X509Certificate2[]')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position=1)]
        $CertificateValidity,

        [Parameter(Mandatory = $true, Position=2)]
        $UserGroup
    )
    $Results = @()
    $GroupName = 'Default Group_LOCAL'
    $CurrentDate = Get-Date
    $StartDate = $CurrentDate
    $EndDate = $StartDate.AddDays($CertificateValidity)
    $Credentials = Get-AxiadCredentials -StartDate $StartDate -EndDate $EndDate
    if (!$Credentials) 
    {
        Write-Warning 'No credentials found in the specified expiry period'
    }
    foreach ($Credential in $Credentials)
    {
        $CredentialObject = ParseAxiadCredential -AxiadC $Credential
        
        #Filter by groupName
        $GroupName = $CredentialObject.groupName #use this ifthe group is SCIM
        # $GroupName = ($CredentialObject.groupName -split "," | ConvertFrom-StringData).CN    #use this if group is LDAP/AD
        
        foreach ($Certificate in $CredentialObject.certificates)
        {
            $CertificateObject = ParseAxiadCredentialCertificate -CreCertificate $Certificate
            if ($CertificateObject.status -eq 'ACTIVE' -and 
                $CertificateObject.certificateType -eq 'X509'-and 
                $CertificateObject.certificateContainerName -eq 'CERTIFICATE_PIV_AUTHENTICATION' -and 
                $GroupName -eq $UserGroup)
            {
                $Certificate = Get-AxiadCerticate -ID $CertificateObject.identifier
                $creationDate = ConvertFromUnixTimeInMilliseconds -UnixTime $Certificate.created 
                if ($creationDate -le $CurrentDate)
                {
                    $DERcertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($Certificate.value)
                    $Results += $DERcertificate 
                }
            }
        }
    }
    return $Results
}


function ConvertFromUnixTimeInMilliseconds($UnixTime) {
    $StartDate = Get-Date 01/01/1970
    $TimeSpan = New-TimeSpan -Seconds ($UnixTime / 1000)
    return $StartDate + $TimeSpan
}

function Connect-AxiadCloud {
    <#
    .SYNOPSIS
    Connects to Axiad Cloud API
    .DESCRIPTION
    Caches your session information (Tenant Name, Platform and Bearer Token) for use with the Axiad Cloud commands.
    Must be ran first before any of the other Axiad Cloud commands.
    .PARAMETER TenantName
    Axiad Cloud tenant name to connect to
    .PARAMETER Platform
    Axiad Cloud platform to connect to (e.g., Cloud or Demo)
    .PARAMETER BearerToken
    Axiad Cloud bearer token to use to connect to the API
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [string]
        $TenantName,

        [Parameter(Mandatory = $true, Position=2)]
        [string]
        $Platform,

        [Parameter(Mandatory = $true, Position=3)]
        [string]
        $BearerToken
    )
    if (!$Script:Axiad) {
        $Script:Axiad = @{}
        $Script:Axiad.Add('TenantName', $TenantName)
        $Script:Axiad.Add('Platform', $Platform)
        $Script:Axiad.Add('BaseURL', "https://ucms-$($TenantName.ToLower()).$($Platform.ToLower()).axiadids.net/secuera")
        $Script:Axiad.Add('BearerToken', $BearerToken)
    }
    else {
        Write-Warning "Already connected to Axiad Cloud tenant '$($Script:Axiad.TenantName)' and platform '$($Script:Axiad.Platform)'. Multiple connections are not allowed. Run 'Disconnect-AxiadCloud' before connecting."
    }
}

function Disconnect-AxiadCloud {
    <#
    .SYNOPSIS
    Disconnect from Axiad Cloud API
    .DESCRIPTION
    Deletes the cached session information.
    #>
    [CmdletBinding()]
    param ()
    if ($Script:Axiad) {
        Remove-Variable -Name Axiad -Scope Script
    }
    else {
        Write-Verbose "Already disconnected from Axiad Cloud."
    }
}

Export-ModuleMember -Function 'Get-AxiadCertificatesToPublish', 'Connect-AxiadCloud', 'Disconnect-AxiadCloud', 'GetUserUPNfromCertificate', 'Get-AllAxiadActiveCertificates'
