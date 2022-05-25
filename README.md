# New-DCCertificateRequest.ps1
Used to generate and optionally submit a certificate request for domain controller certificates based on a specified template. 
Accepts arguments to target which LDAP VIP Name is used and which Certificate Template is used. 

## PARAMETERS
### PARAMETER ComputerName
Specify the domain controller(s) for which you wish to request certificates.
Specifying a server other than the local host in which this is run from will only generate the request file and request the cert. It cannot install it. 
Specifying multiple DCs, the requests will be submitted and if -CompleteRequest is supplied, the requests will be submitted and the cer's downloaded. 

### PARAMETER LdapVipName
Specify desired LDAP VIP/Load Balancer address for use as the Subject Alternative Name.

### PARAMETER CertificateTemplateName
Specifies the name of the Certificate Template desired for the request. Defaults to 'DCServerAuthTemplate'.

### PARAMETER ExportRequestInf
Specifies to export the request inf with filled in fields rather than the certreq encoded version.

### PARAMETER CompleteRequest
Specifies to submit the request to the CA and issue the certificate.

### PARAMETER LoadBalancing
Specifies which load balancing method to use when locating CAs. Defaults to Random.
Random chooses from Enterprise Root CAs in the forest.
ADSite chooses from the Enterprise Root CAs in the forest based on AD site. Falls back to random.

### PARAMETER SkipCertificateInstall
Specifies to skip installing the certificiate on the local system after the certificate is issued.

## EXAMPLES
### EXAMPLE - Generate certificate request file for a DC.
PS> .\New-DCCertificateRequest.ps1 -ServerName DC.EXAMPLE.COM -LdapVipName LDAP.EXAMPLE.COM
Request created 'DC.EXAMPLE.COM_20211028.req'
\#### Next Steps ####
        1. Copy the request file ('DC.EXAMPLE.COM_20211028.req') onto the target DC.
        2. Run the following command to submit the request to the CA: certreq -submit <REQUEST_FILE_PATH_ON_TARGET> <CER_OUTPUT_PATH>.cer
        3. If there arent errors, run the following command to install the Cert on the DC: certreq -accept <CER_OUTPUT_PATH>.cer

### EXAMPLE - Generate, issue, and install a certificate for a DC.
PS> .\New-DCCertificateRequest.ps1 -ServerName DC.EXAMPLE.COM -LdapVipName LDAP.EXAMPLE.COM -CompleteRequest
Returns the thumbprint of the installed certificate. 

## OTHER
### INPUTS
None. You cannot pipe objects into New-DCCertificateRequest.

### OUTPUTS
A .req file in the script root for each supplied ComputerName.
If -ExportRequestInf is specified an additional .inf will be exported for each supplied ComputerName.
If -CompleteRequest is specified an additional .cer will be exported for each supplied ComputerName.


