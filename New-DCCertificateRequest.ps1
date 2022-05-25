<#
    .SYNOPSIS
    Used to generate and optionally submit a certificate request for domain controller certificates based on a specified template. 

    .DESCRIPTION
    Used to generate and optionally submit a certificate request for domain controller certificates based on a specified template. 
    Accepts arguments to target which LDAP VIP Name is used and which Certificate Template is used. 

    .PARAMETER ComputerName
    Specify the domain controller(s) for which you wish to request certificates.
    Specifying a server other than the local host in which this is run from will only generate the request file and request the cert. It cannot install it. 
    Specifying multiple DCs, the requests will be submitted and if -CompleteRequest is supplied, the requests will be submitted and the cer's downloaded. 

    .PARAMETER LdapVipName
    Specify desired LDAP VIP/Load Balancer address for use as the Subject Alternative Name.

    .PARAMETER CertificateTemplateName
    Specifies the name of the Certificate Template desired for the request. Defaults to 'DCServerAuthTemplate'.

    .PARAMETER ExportRequestInf
    Specifies to export the request inf with filled in fields rather than the certreq encoded version.

    .PARAMETER CompleteRequest
    Specifies to submit the request to the CA and issue the certificate.

    .PARAMETER LoadBalancing
    Specifies which load balancing method to use when locating CAs. Defaults to Random.
    Random chooses from Enterprise Root CAs in the forest.
    ADSite chooses from the Enterprise Root CAs in the forest based on AD site. Falls back to random.

    .PARAMETER SkipCertificateInstall
    Specifies to skip installing the certificiate on the local system after the certificate is issued.

    .INPUTS
    None. You cannot pipe objects into New-DCCertificateRequest.

    .OUTPUTS
    A .req file in the script root for each supplied ComputerName.
    If -ExportRequestInf is specified an additional .inf will be exported for each supplied ComputerName.
    If -CompleteRequest is specified an additional .cer will be exported for each supplied ComputerName.

    .EXAMPLE
    PS> .\New-DCCertificateRequest.ps1 -ServerName DC.EXAMPLE.COM -LdapVipName LDAP.EXAMPLE.COM
    Request created 'DC.EXAMPLE.COM_20211028.req'
    #### Next Steps ####
            1. Copy the request file ('DC.EXAMPLE.COM_20211028.req') onto the target DC.
            2. Run the following command to submit the request to the CA: certreq -submit <REQUEST_FILE_PATH_ON_TARGET> <CER_OUTPUT_PATH>.cer
            3. If there arent errors, run the following command to install the Cert on the DC: certreq -accept <CER_OUTPUT_PATH>.cer

    .EXAMPLE
    PS> .\New-DCCertificateRequest.ps1 -ServerName DC.EXAMPLE.COM -LdapVipName LDAP.EXAMPLE.COM -CompleteRequest
    Returns the thumbprint of the installed certificate. 

    .LINK
    https://github.com/poolmanjim/New-DCCertificateRequest.ps1

    .NOTES
    Created By: Tyler Jacobs
    Created On: 10/28/2021
    Last Updated: 05/25/2022
    Version: 1.1.0

    REQUIREMENTS
    - Requires DCAuthCertRequestTemplate.inf to be in the same directory
    - Requires the specified certifciate template to be available. (Default: Template can be found under https://github.com/ActiveDirectoryKC/TwoTierPKI)

    .CHANGELOG
    v1.1.0
        - Introduced the CompleteRequest and LoadBalancing Parameters
        - Introduced the GetTargetEnterpriseCA function. 
        - Altered the DC request section to include the -config parameter and to use the GetTargetEnterpriseCA function.
        - Introduced the CompleteRequest and LoadBalancing Parameters
        - Introduced the GetTargetEnterpriseCA function. 
        - Altered the DC request section to include the -config parameter and to use the GetTargetEnterpriseCA function.
        - Added checks to see if the Subject being requested is the local server or not. 
            - If not, we skip submitting the request and generate the files instead. 
        - Changed -ServerName switch. Because we can submit to a CA now, this was somewhat redundent. Implied now. 
        - Updated errors for failed request generation.
        - Retired the ServerName parameter in favor of the ComputerName parameter. ServerName is used as a variable further down. 
        - Introduced ComputerName parameter to replace ServerName. 
            ComputerName is an array of strings. This allows us to generate certs for a number of DCs and then kick over the certs. 
            This will likely not be fully tested or implemented. Stick to one server. 
        - Adjusted throws to only throw if we are using a single ComputerName.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,HelpMessage="Specify the domain controller(s) for which you wish to request certificates.")]
    [string[]]$ComputerName = $(hostname), # Grabs the hostname by default. MS recommends making even array params singular. 

    [Parameter(Mandatory=$true,HelpMessage="Specify desired LDAP VIP/Load Balancer address for use as the Subject Alternative Name.")]
    [string]$LdapVipName,

    [Parameter(Mandatory=$false,HelpMessage="Specifies the name of the Certificate Template desired for the request. Defaults to 'DCServerAuthTemplate'.")]
    [string]$CertificateTemplateName = "DCServerAuthentication",

    [Parameter(Mandatory=$false,HelpMessage="Specifies to export the request inf with filled in fields rather than the certreq encoded version.")]
    [switch]$ExportRequestInf,

    [Parameter(Mandatory=$false, ParameterSetName="CompleteRequest",HelpMessage="Specifies to submit the request to the CA and issue the certificate.")]
    [switch]$CompleteRequest,

    [Parameter(Mandatory=$false, ParameterSetName="CompleteRequest",HelpMessage="Specifies which load balancing method to use when locating CAs. Defaults to Random.")]
    [ValidateSet("Random","ADSite")]
    [string]$LoadBalancing = "Random",

    [Parameter(Mandatory=$false,ParameterSetName="CompleteRequest",HelpMessage="Specifies to skip installing the certificiate on the local system after the certificate is issued.")]
    [switch]$SkipCertificateInstall
)

# Variables
$DefaultFileNameTemplate = "{0}_{1}.req"
$CADataList = [System.Collections.Generic.List[object]]::new()
$TargetCA = @{}
$DCRequestsList = [System.Collections.Generic.List[string]]::new()
$DCCertificatesList = [System.Collections.Generic.List[string]]::new()

# Domain Variables
$DomainObj = Get-ADDomain
$DomainDN = $DomainObj.DistinguishedName
$DomainDNS = $DomainObj.DnsRoot
$DomainController = (Get-ADDomainController -Discover -DomainName $DomainDNS).HostName[0] # HostName is an array. Just grab the first name.

# Certificate Template Details
$TemplateName = "DCAuthCertRequestTemplate.inf"
$CertTemplateFilter = "(&(objectclass=pKICertificateTemplate)(name=$CertificateTemplateName))" 
$CertTemplateSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
$CertTemplateEKUs = "1.3.6.1.4.1.311.54.1.2","1.3.6.1.5.2.3.5","1.3.6.1.4.1.311.20.2.2","1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"

#region Functions
function GetTargetEnterpriseCA
{
    $ConfigDN = (Get-ADRootDSE).configurationNamingContext
    # This path contains the list of CAs configured in the environment. 
    $EnrollmentServers = Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDN" -Property dnsHostName,displayName 

    # Loop through the discovered CAs and populate a list of CA servers in the CADataList collection.
    foreach( $EnrollmentServer in $EnrollmentServers )
    {
        $CAData = @{}
        $CAData.Name = $EnrollmentServer.DisplayName
        $CAData.DNSName = $EnrollmentServer.dnsHostName
        $CAData.IPAddress = (Resolve-DnsName -Name $EnrollmentServer.dnsHostName -Type A).IPAddress
        $CAData.ADSite = ((nltest /dsaddresstosite:$($CAData.IPAddress))[2]).split(" ")[5] # 2 chooses the 2nd row. 5 chooses the 5th space in that row as the index.
        $CADataList.Add( $CAData )
    }

    # If we have discovered any number of CAs, choose one. 
    if( $CADataList.Count -gt 0 )
    {
        # If we are load balancing based on AD SIte, 
        if( $LoadBalancing -eq "ADSite" )
        {
            # Attempt to find the CAs in the same AD Site as the host system. 
            $LocalCAs = [string[]]($CADataList.Where({ $PSItem.ADSite -eq (nltest /dsgetsite)[0] }).DNSName)
        }

        # If we have didn't discover any LocalCAs, choose from the overall list of CAs at Random. 
        if( !$LocalCAs -or $LocalCAs.Count -lt 1 )
        {
            ($CADataList | Get-Random) # $CADataList contains our raw CA data. 
        }
        # If we have local CAs, choose one at random as our target. 
        else
        {
            $CADataList.Where({ $PSitem.Name -eq "$($LocalCAs | Get-Random)" })
        }
    }
    # If we don't find a CA, throw an error. 
    else
    {
        Write-Host -Object "Unable to locate any Certificate Servers in the environment."

        if( $script:Computers.Count -eq 1 )
        {
            throw [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]::new("Unable to locate any Certificate Authorities in the environment")
        }
        else
        {
            Write-Error -Message "Unable to locate any Certificate Authorities in the environment"
        }
    }
}
#endregion Functions

#region Parameter Checks
#region Check CertificateTemplateName Parameter
$FoundCertificateTemplates = @()

$FoundCertificateTemplates += (Get-ADObject -LDAPFilter $CertTemplateFilter -Properties Name,DistinguishedName,msPKI-Cert-Template-OID,msPKI-Certificate-Application-Policy -SearchBase $CertTemplateSearchBase -Server $DomainController)

if( $FoundCertificateTemplates.Count -eq 0 )
{
    [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("Cannot find a certificate template in the domain '$DomainDNS' that matches the name '$CertificateTemplateName' - Exiting")
}
else
{
    if( $FoundCertificateTemplates.Count -gt 1 )
    {
        Write-Warning "Found multiple certificate templates matching the name '$CertificateTemplateName' in dthe domain '$DomainDNS' - Choosing the first one."
    }

    # Verify the correct extenions are present on the certificate template. 
    $CertTemplateCompareDiffs = Compare-Object -ReferenceObject $CertTemplateEKUs -DifferenceObject $FoundCertificateTemplates[0]."msPKI-Certificate-Application-Policy"

    if( $CertTemplateCompareDiffs )
    {
        Write-Warning "Certificate tempalte '$CertificateTemplateName' does not contain the required extensions - Continuing with request creation"
    }

    $CertificateTemplateName = $FoundCertificateTemplates[0].Name
}
#endregion Check CertificateTemplateName Parameter

foreach( $ServerName in $ComputerName )
{
    # Resolve ServerNames to Domain Controllers
    $DomainController = Get-ADDomainController -Filter "(Name -eq '$ServerName') -or (HostName -eq '$ServerName')" -Server $DomainController -ErrorAction Ignore

    if( !$DomainController )
    {
        if( $ComputerName.Count -eq 1 )
        {
            throw [System.InvalidOperationException]::new("Unable to locate domain controller named '$ServerName' in the domain '$DomainDNS' - Exiting")
        }
        else
        {
            Write-Error -Message "Unable to locate domain controller named '$ServerName' in the domain '$DomainDNS' - Skipping"
            continue # Should break out of our loops. 
        }
    }
    elseif($DomainController.Count -gt 1)
    {
        if( $ComputerName.Count -eq 1 )
        {
            throw [System.InvalidOperationException]::new("Located multiple domain controllers named '$ServerName' in the domain '$DomainDNS' - Exiting")
        }
        else
        {
            Write-Error -Message "Unable to locate domain controller named '$ServerName' in the domain '$DomainDNS' - Skipping"
            continue # Should break out of our loops. 
        }
    }

    $DefaultFileName = [string]::Format($DefaultFileNameTemplate,$DomainController.HostName,(Get-Date -Format yyyyMMdd))

    Copy-Item -Path "$PSScriptRoot\$TemplateName" -Destination "$PSScriptRoot\$DefaultFileName"
    $RequestFilePath = "$PSScriptRoot\$DefaultFileName"

    #region Generate the Request File
    # Read the template, replace values, save new file. 
    Try
    {
        $CertRequestContent = Get-Content -Path $RequestFilePath -ErrorAction Stop
    }
    Catch
    {
        Write-Error "Unable to read the certificate request template '$RequestFilePath' - Exiting"
        throw $PSItem
    }

    $CertRequestNew = $CertRequestContent
    $CertRequestNew = $CertRequestNew -replace "{DCTEMPLATE}",$CertificateTemplateName
    $CertRequestNew = $CertRequestNew -replace "{DCDN}",$DomainController.ComputerObjectDN
    $CertRequestNew = $CertRequestNew -replace "{LDAPSAN}",$LdapVipName
    $CertRequestNew = $CertRequestNew -replace "{HOSTSAN}",$DomainController.HostName
    $CertRequestNew = $CertRequestNew -replace "{DOMAINSAN}",$DomainObj.DnsRoot
    $CertRequestNew = $CertRequestNew -replace "{NBNSAN}",$DomainController.Name

    if($VerbosePreference)
    {
        Write-Host "Created the following request data"
        Write-Host $CertRequestNew
    }

    Try
    {
        $CertRequestNew | Out-File -FilePath $RequestFilePath -ErrorAction Stop
    }
    Catch
    {
        Write-Error "Unable to export request data to file '$RequestFilePath'"
        Write-Host ($PSItem | Select-Object -Property *)
    }

    if( $VerbosePreference -or $PSBoundParameters.ContainsKey("ExportRequestInf") )	 
    {
        $CertRequestNew | Out-File -FilePath [System.IO.Path]::ChangeExtension($RequestFilePath.FullName,".inf") -ErrorAction Stop
        Write-Host "Request inf saved '$([System.IO.Path]::ChangeExtension($RequestFilePath.FullName,".inf"))'" -ForegroundColor Cyan
    }

    Try
    {
        $CertRequestNew | Out-File -FilePath $RequestFilePath -ErrorAction Stop
    }
    Catch
    {
        Write-Error "Unable to export request data to file '$RequestFilePath'"
        Write-Host ($Error[0] | Select-Object -Property *)
    }

    # Generate the request file
    $RequestStatus = cmd /c "certreq -f -q -new $RequestFilePath `"$PSScriptRoot\$DefaultFileName`""

    if( $RequestStatus -like "*Request Created*" )
    {
        # Submit the request to the CA and process the response.
        if( $PSBoundParameters.ContainsKey("CompleteRequest") ) # If we use CompleteRequest and if the DC name and supplied server name match.
        {
            # Get the target CA we will communicate against. 
            $TargetCA = GetTargetEnterpriseCA
            $TargetCAConfigString = "$($TargetCA.DnsName)\$($TargetCA.Name)"
            $CertificateOutPath = $RequestFilePath.replace("req","cer")

            # Submit the request to the CA based on the config. 
            $CertSubmitResult = certreq -submit -config "$TargetCAConfigString" -q -f $RequestFilePath $CertificateOutPath $RequestFilePath.replace("req","rsp")

            # If no cer file is created, error. 
            if( !(Test-Path -Path $RequestFilePath.replace("req","cer") ) -or !$? ) # $? checks if the last command ran successfully.
            {
                Write-Host -Object $CertSubmitResult
                
                if( $ComputerName.Count -eq 1 )
                {
                    throw [System.IO.FileNotFoundException]::new( "Unable to locate the certificate file - Exiting - Path: $CertificateOutPath" )
                }
                else
                {
                    Write-Error -Message "Unable to locate the certificate file - Exiting - Path: $CertificateOutPath"
                    continue # Should break out of our loops. 
                }
            }
            # Else, install the certificate to the DC. 
            else
            {
                # If the all the following conditions are true, we attempt to install the certificate
                ## ServerName equals the hostname.
                ## ComputerName has only one item.
                ## SkipCertificateInstall wasn't specified. 
                if( $ServerName -eq $(hostname) -and ($ComputerName.Count -eq 1) -and (!$PSBoundParameters.ContainsKey("SkipCertificateInstall") -or !$SkipCertificateInstall) )
                {
                    $CertAcceptResult = certreq -accept "$CertificateOutPath" "$($CertificateOutPath.replace('cer','rsp'))"

                    if( !$? ) # if previous command was NOT successful.
                    {
                        Write-Host -Object $CertAcceptResult
                        
                        if( $ComputerName.Count -eq 1 )
                        {
                            throw "Failed to install the certificate ($CertificateOutPath) - See the response output at $("$($CertificateOutPath.replace('cer','rsp'))")"
                        }
                        else
                        {
                            Write-Error -Message "Failed to install the certificate ($CertificateOutPath) - See the response output at $("$($CertificateOutPath.replace('cer','rsp'))")"
                            continue # Should break out of our loops. 
                        }
                    }
                    else
                    {
                        # [5] matches the thumbprint which is returned from certreq -accept
                        # Remove the thumbprint field name and trim whitepace. 
                        $CertificateThumbprint = $CertAcceptResult[5].replace("Thumbprint: ","").trim()
                        # Get the certificate we just installed. It *should* be a Local Machine\My which corresponds to the local machine\Personal directory.
                        $InstalledCert = (Get-ChildItem CERT:\LocalMachine\My).Where({ $_.Thumbprint -eq $CertificateThumbprint })

                        if( !$InstalledCert )
                        {
                            
                            if( $ComputerName.Count -eq 1 )
                            {
                                throw "Unable to locate installed certificate matching thumbprint '$CertifciateThumprint'"
                            }
                            else
                            {
                                Write-Error -Message "Unable to locate installed certificate matching thumbprint '$CertifciateThumprint'"
                                continue # Should break out of our loops. 
                            }
                        }
                        else # Use write-output to make it scriptable. 
                        {
                            Write-Output -InputObject $CertificateThumbprint
                        }
                    }
                }
                else
                {
                    if( $ComputerName.Count -gt 1 ) # If we have mutliple computers, we use the collection
                    {
                        $DCCertificatesList.Add( $CertificateOutPath )
                    }
                    else # Otherwise return the certificate information. 
                    {
                        Write-Host -Object "Certificate created '$CertificateOutPath'" -ForegroundColor Cyan
                        Write-Host -Object  "#### Next Steps ####"
                        Write-Host -Object  "`t1. Copy the certificate file ($CertificateOutPath) to the target DC."
                        Write-Host -Object  "`t2. Run the following command to install the certificate onto the DC."
                        Write-Host -Object "`t`tMake sure and replace `"<CERTIFICATE_PATH>`" with the certificate path."
                        Write-Host -Object "`t`tcertreq -accept <CERTIFICATE_PATH>.cer" -ForegroundColor cyan
                    }
                }
                $CertificateOutPath = $null # Blank this out just in case. 
            }
        }
        # Generate the request and provide steps to complete the request. 
        else
        {
            if( $ComputerName.Count -gt 1 )
            {
                $DCRequestsList.Add( $RequestFilePath )
            }
            else
            {
                Write-Host "Request created '$RequestFilePath'" -ForegroundColor Cyan
                Write-Host -Object "#### Next Steps ####"
                Write-Host -Object "`t1. Copy the request file ($RequestFilePath) onto the target DC."
                Write-Host -Object "`t2. Run the following command to submit the request to the CA: "
                Write-Host -Object "`t`tcertreq -submit <REQUEST_FILE_PATH_ON_TARGET> <CER_OUTPUT_PATH>.cer" -ForegroundColor cyan
                Write-Host -Object "`t3. If there arent errors, run the following command to install the Cert on the DC: "
                Write-Host -Object "`t`tcertreq -accept <CER_OUTPUT_PATH>.cer" -ForegroundColor cyan
            }
        }
    }
    else
    {
        Write-Host -Object "Failed to generate a new certificate request - $RequestStatus"
        Write-Host -Object "Request Information"
        Write-Host -Object $CertRequestNew
        
        if( $ComputerName.Count -eq 1 )
        {
            throw "Failed to generate a new certificate request - $RequestStatus"
        }
        else
        {
            Write-Error -Message "Failed to generate a new certificate request - $RequestStatus"
            continue # Should break out of our loops. 
        }
    }
    #endregion Generate the Request File
}

if( $ComputerName.Count -gt 1 )
{
    if( $CompleteRequest -and $DCCertificatesList -gt 0 )
    {
        Write-Host -Object "Certificates created in the following paths." -ForegroundColor Cyan
        # ForEach Method is faster than the foreach statement and far faster than Foreach-Object.
        # GetEnumerator is required because while Generic Lists allow for the Foreach Method, they don't use it.
        # GetEnumerator makes this work. It is more efficient than casting them as arrays ($var -as [system.array).
        $DCCertificatesList.GetEnumerator().Foreach({ Write-Host -Object "`t$PSItem"})
        Write-Host -Object  "#### Next Steps ####"
        Write-Host -Object  "`t1. Copy the certificate file from the above list to the correct DC."
        Write-Host -Object  "`t2. Run the following command on the DC to install the certificate."
        Write-Host -Object "`t`tMake sure and replace `"<CERTIFICATE_PATH>`" with the certificate path." -NoNewline
        Write-Host -Object "`t`tcertreq -accept <CERTIFICATE_PATH>.cer" -ForegroundColor cyan
    }
    elseif( !$CompleteRequest -and $DCRequestsList -gt 0 )
    {
        Write-Host "Requests created in the following paths." -ForegroundColor Cyan
        # ForEach Method is faster than the foreach statement and far faster than Foreach-Object.
        # GetEnumerator is required because while Generic Lists allow for the Foreach Method, they don't use it.
        # GetEnumerator makes this work. It is more efficient than casting them as arrays ($var -as [system.array).
        $DCRequestsList.GetEnumerator().Foreach({ Write-Host -Object "`t$PSItem"})
        Write-Host -Object  "#### Next Steps ####"
        Write-Host -Object  "`t1. Copy the request filefrom the above list to the correct DC."
        Write-Host -Object  "`t2. Run the following command on each DC to submit the request to the CA."
        Write-Host -Object "`t`tcertreq -submit <REQUEST_FILE_PATH_ON_TARGET> <CER_OUTPUT_PATH>.cer" -ForegroundColor cyan
        Write-Host -Object "`t3. If there aren't errors, run the following command to install the Cert on the DC: "
        Write-Host -Object "`t`tcertreq -accept <CER_OUTPUT_PATH>.cer" -ForegroundColor cyan
    }
}