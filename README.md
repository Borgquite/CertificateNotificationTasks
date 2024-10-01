These scripts allow the use of Windows 8+ and Windows Server 2012+ Certificate Services Lifecycle Notifications to automatically deploy new certificates after they are renewed - see https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx

Supported products:
 - SQL Server Database Engine
 - SQL Server Reporting Services

You can use the script to perform certificate autorenewal, but also to configure both of these services for the 'first time' if you supply just the -NewCertHash parameter. As provided, the deployment script, and this feature, both depend on the certificate being created via Active Directory Certificate Services using specified Certificate Template names. The script uses template names of 'SQL Server' and 'Internal Web Server' respectively by default (update the script with your names!).

If you are using a third-party Certificate Authority e.g. Let's Encrypt you can still use the Certificate Services Lifecycle Notifications feature.

To use, review and download both files .ps1 files to a folder, then run Deploy-CertificateRenewalTasks.ps1

Then either perform a certificate autorenewal using ADCS, or when using a third-party Certificate Authority, use the PowerShell command Switch-Certificate -OldCert <thumbprint> -NewCert <thumbprint> to mark the certificate as 'replaced' and trigger the task - see https://learn.microsoft.com/en-us/powershell/module/pki/switch-certificate?view=windowsserver2022-ps
