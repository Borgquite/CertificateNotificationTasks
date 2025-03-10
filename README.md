These scripts allow the use of Windows 8+ and Windows Server 2012+ Certificate Services Lifecycle Notifications to automatically deploy new certificates after they are renewed - see https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx

Supported products:
 - SQL Server Database Engine
 - SQL Server Reporting Services
 - Hyper-V Replica
 - Network Device Enrollment Service (NDES)

You can use the script to perform certificate autorenewal, and also for SQL Server, configuring components for using a certificate for the 'first time' with just the -NewCertHash parameter.

Some script functionality depends on certificates being enrolled via Active Directory Certificate Services with specific certificate template names.
 - For SQL Server, the script uses template names of 'SQL Server' and 'Internal Web Server' respectively by default. This is not required when renewing certificates, but will be if you want to configure the 'first time' using the -NewCertHash parameter as described above.
 - For Hyper-V Replica, the script uses a template name of 'Hyper-V Replica' by default. In theory, this check can be removed.
 - For Network Device Enrollment Service, the default template names for the 'CEPEncryption' and 'EnrollmentAgentOffline' V1 certificate templates are supported - but you can also set up custom names using V2 certificates if you replaced the defaults e.g. by following https://www.microsoft.com/en-us/download/details.aspx?id=46406
If you are using Active Directory Certificate Services, ensure you update the scripts with the certificate template names you are using.

If you are using a third-party Certificate Authority e.g. Let's Encrypt you can still use the Certificate Services Lifecycle Notifications feature.

To use, review and download both files .ps1 files to a folder, then run Deploy-CertificateRenewalTasks.ps1

Then either perform a certificate autorenewal using ADCS, or when using a third-party Certificate Authority, use the PowerShell command Switch-Certificate -OldCert <thumbprint> -NewCert <thumbprint> to mark the certificate as 'replaced' and trigger the task - see https://learn.microsoft.com/en-us/powershell/module/pki/switch-certificate?view=windowsserver2022-ps
