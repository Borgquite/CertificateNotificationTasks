These scripts allow the use of Windows 8+ and Windows Server 2012+ Certificate Services Lifecycle Notifications to automatically deploy new certificates after they are renewed - see https://social.technet.microsoft.com/wiki/contents/articles/14250.certificate-services-lifecycle-notifications.aspx

Supported products:
 - SQL Server Database Engine
 - SQL Server Reporting Services
 - WinRM
 - WMSvc
 - Hyper-V
 - Hyper-V Replica
 - Network Device Enrollment Service (NDES)

You can use the script to perform certificate autorenewal, and also for SQL Server, configuring components for using a certificate for the 'first time' with just the -NewCertHash parameter.

Some script functionality depends on certificates being enrolled via Active Directory Certificate Services with specific certificate template names.
 - For [SQL Server Database Engine][https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/certificate-requirements) and [SQL Server Reporting Services](https://learn.microsoft.com/en-us/sql/reporting-services/security/configure-ssl-connections-on-a-native-mode-report-server) certificates, the script uses template names of 'SQL Server' and 'Internal Web Server' respectively by default. This is not required when renewing certificates, but will be if you want to configure the 'first time' using the -NewCertHash parameter as described above.
 - For [WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https) certificates, the script uses a template name of 'WinRM' by default. The template name check can also be removed, since there is currently no support for configuring the certificate for the 'first time'.
 - For [WMSvc](https://learn.microsoft.com/en-us/iis/manage/remote-administration/remote-administration-for-iis-manager) certificates, the script uses a template name of 'WMSvc' by default. The template name check can also be removed, since there is currently no support for configuring the certificate for the 'first time'.
 - For [Hyper-V Virtual Machine Connection / SCVMM](https://learn.microsoft.com/en-gb/archive/blogs/hugofe/configuring-a-certificate-for-virtual-machine-connection-in-hyper-v-or-thru-scvmm) certificates, the script uses a template name of 'Hyper-V' by default.
 - For [Hyper-V Replica](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/set-up-hyper-v-replica) certificates, the script uses a template name of 'Hyper-V Replica' by default. The template name check can also be removed, since there is currently no support for configuring the certificate for the 'first time'.
 - For [Network Device Enrollment Service](https://www.gradenegger.eu/en/use-your-own-registration-authority-ra-certificate-templates-for-network-device-enrollment-service-ndes/) certificates, the default template names for the 'CEPEncryption' and 'EnrollmentAgentOffline' V1 certificate templates are supported - but you can also set up custom names using V2 certificates if you replaced the defaults e.g. by following https://www.microsoft.com/en-us/download/details.aspx?id=46406
If you are using Active Directory Certificate Services, ensure you update the scripts with the certificate template names you are using.

Even if you are using a third-party Certificate Authority e.g. Let's Encrypt you should still be able to use the Certificate Services Lifecycle Notifications feature for some of these certificate types, by removing the template name checks.

To use, review and download both files .ps1 files to a folder, then run Deploy-CertificateRenewalTasks.ps1

Then either perform a certificate autorenewal using ADCS, or when using a third-party Certificate Authority, use the PowerShell command Switch-Certificate -OldCert <thumbprint> -NewCert <thumbprint> to mark the certificate as 'replaced' and trigger the task - see https://learn.microsoft.com/en-us/powershell/module/pki/switch-certificate?view=windowsserver2022-ps
