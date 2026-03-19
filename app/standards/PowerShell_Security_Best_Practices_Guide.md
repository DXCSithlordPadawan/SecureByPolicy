# PowerShell Security Best Practices Guide

**Version:** 1.0  
**Date:** March 2026  
**Author:** Matrix Agent  
**Classification:** Technical Security Reference

---

## Executive Summary

This comprehensive guide provides security best practices for PowerShell scripting and administration, aligned with major industry security frameworks including NIST SP 800-53, OWASP Top Ten, DISA STIGs, CIS Benchmarks, and FIPS 140-3. The document covers PowerShell 7.x security features, credential management, execution policies, constrained language mode, Just Enough Administration (JEA), logging, injection prevention, and module security.

Organizations implementing these practices will significantly reduce their attack surface while maintaining the productivity benefits of PowerShell automation.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [PowerShell 7.x Security Features](#2-powershell-7x-security-features)
3. [Execution Policies and Script Signing](#3-execution-policies-and-script-signing)
4. [Credential Handling](#4-credential-handling)
5. [Constrained Language Mode](#5-constrained-language-mode)
6. [Just Enough Administration (JEA)](#6-just-enough-administration-jea)
7. [Logging and Transcription](#7-logging-and-transcription)
8. [Injection Prevention](#8-injection-prevention)
9. [Module Security and Trusted Repositories](#9-module-security-and-trusted-repositories)
10. [Security Standards Cross-Reference](#10-security-standards-cross-reference)
11. [Compliance Checklists](#11-compliance-checklists)
12. [References](#12-references)

---

## 1. Introduction

PowerShell is a powerful automation and configuration management framework that provides both significant productivity benefits and potential security risks. As a post-exploitation tool of choice for attackers, PowerShell security must be a priority for any organization using Windows infrastructure.

This guide addresses:

- **Defensive hardening** of PowerShell environments
- **Secure coding practices** for script development
- **Compliance alignment** with major security frameworks
- **Detection and monitoring** capabilities

### Scope

This document applies to:
- PowerShell 7.x (cross-platform)
- Windows PowerShell 5.1
- Enterprise and government environments
- Development and production systems

---

## 2. PowerShell 7.x Security Features

PowerShell 7.x introduces several security enhancements over Windows PowerShell 5.1, building on the cross-platform .NET Core foundation.

### 2.1 Key Security Improvements

| Feature | PowerShell 5.1 | PowerShell 7.x | Security Benefit |
|---------|----------------|----------------|------------------|
| SSH Remoting | No | Yes | Encrypted transport without WinRM |
| SecretManagement Module | No | Yes | Centralized secrets handling |
| PSResourceGet | No | Yes | Improved package verification |
| Cross-platform logging | No | Yes | Unified audit trail |
| Constrained Language Mode | Yes | Yes | Attack surface reduction |
| Script Block Logging | Yes | Enhanced | Better forensic capability |

### 2.2 PowerShell 7.x Installation Security

```powershell
# Verify installation integrity using published hash
$installerPath = "PowerShell-7.4.1-win-x64.msi"
$expectedHash = "SHA256_HASH_FROM_GITHUB_RELEASE"
$actualHash = (Get-FileHash -Path $installerPath -Algorithm SHA256).Hash

if ($actualHash -eq $expectedHash) {
    Write-Host "Installer integrity verified" -ForegroundColor Green
    Start-Process msiexec.exe -ArgumentList "/i $installerPath /qn" -Wait
} else {
    Write-Host "Hash mismatch - do not install!" -ForegroundColor Red
}
```

### 2.3 Side-by-Side Installation Considerations

PowerShell 7.x can run alongside Windows PowerShell 5.1. Security considerations include:

- Both versions share the same execution policy settings by default
- Module paths are separate but can be configured to share
- Logging configurations should be applied to both versions
- Group Policy settings may need version-specific targeting

---

## 3. Execution Policies and Script Signing

### 3.1 Execution Policy Overview

Execution policies control script execution conditions. While they are not a security boundary (they can be bypassed), they serve as a first line of defense against accidental execution of malicious scripts.

| Policy | Description | Recommended Use |
|--------|-------------|-----------------|
| **Restricted** | No scripts can run | Workstations with no PowerShell requirements |
| **AllSigned** | All scripts must be signed | High-security production servers |
| **RemoteSigned** | Remote scripts must be signed | General enterprise use (Microsoft default) |
| **Unrestricted** | Scripts run with warning | Never recommended |
| **Bypass** | No restrictions | Never for production |

### 3.2 Setting Execution Policy via Group Policy

**Path:** `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

```
Setting: Turn on Script Execution
Value: Allow only signed scripts (AllSigned) - for high security
       Allow local scripts and remote signed scripts (RemoteSigned) - for enterprise
```

### 3.3 Code Signing Implementation

#### Creating a Code Signing Certificate

```powershell
# Generate a self-signed code signing certificate (for internal use)
$certParams = @{
    Subject           = "CN=Internal PowerShell Code Signing"
    Type              = "CodeSigningCert"
    KeyUsage          = "DigitalSignature"
    KeyAlgorithm      = "RSA"
    KeyLength         = 4096
    HashAlgorithm     = "SHA256"
    NotAfter          = (Get-Date).AddYears(3)
    CertStoreLocation = "Cert:\CurrentUser\My"
}
$cert = New-SelfSignedCertificate @certParams

# Export for distribution
$certPassword = Read-Host -AsSecureString -Prompt "Certificate password"
Export-PfxCertificate -Cert $cert -FilePath ".\CodeSigning.pfx" -Password $certPassword
```

#### Signing Scripts

```powershell
# Get the code signing certificate
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | 
    Where-Object { $_.Subject -like "*Internal PowerShell*" } |
    Select-Object -First 1

# Sign a script with timestamp (recommended)
$signParams = @{
    Certificate   = $cert
    FilePath      = ".\MyScript.ps1"
    TimestampServer = "http://timestamp.digicert.com"
    HashAlgorithm = "SHA256"
}
Set-AuthenticodeSignature @signParams

# Verify signature
Get-AuthenticodeSignature -FilePath ".\MyScript.ps1" | 
    Select-Object Status, SignerCertificate, TimeStamperCertificate
```

### 3.4 Enterprise Certificate Authority Integration

For enterprise environments, use certificates from your internal PKI:

```powershell
# Request code signing certificate from enterprise CA
$template = "CodeSigning"
$certRequest = @{
    Template          = $template
    CertStoreLocation = "Cert:\CurrentUser\My"
    SubjectName       = "CN=PowerShell Scripts,OU=IT,O=Company,C=US"
}
Get-Certificate @certRequest
```

---

## 4. Credential Handling

### 4.1 The PSCredential Object

Never store passwords in plain text. Always use `PSCredential` objects:

```powershell
# CORRECT: Using Get-Credential (interactive)
$credential = Get-Credential -Message "Enter service account credentials"

# CORRECT: Using SecureString for automation
$username = "DOMAIN\ServiceAccount"
$securePassword = ConvertTo-SecureString -String $env:SERVICE_PASSWORD -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

# INCORRECT: Never do this
$password = "PlainTextPassword123!"  # SECURITY VIOLATION
```

### 4.2 SecureString Handling

```powershell
# Creating SecureString interactively (most secure)
$secureString = Read-Host -AsSecureString -Prompt "Enter password"

# Converting from plain text (use only when necessary)
$secureString = ConvertTo-SecureString "password" -AsPlainText -Force

# Exporting SecureString to file (encrypted with DPAPI)
$secureString | ConvertFrom-SecureString | Set-Content -Path ".\encrypted.txt"

# Importing SecureString from file (same user/machine only)
$secureString = Get-Content ".\encrypted.txt" | ConvertTo-SecureString

# Using AES key for cross-machine scenarios
$key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
$key | Set-Content -Path ".\aes.key" -Encoding Byte

# Export with AES key
$secureString | ConvertFrom-SecureString -Key $key | Set-Content ".\encrypted_aes.txt"

# Import with AES key
$key = Get-Content ".\aes.key" -Encoding Byte
$secureString = Get-Content ".\encrypted_aes.txt" | ConvertTo-SecureString -Key $key
```

### 4.3 SecretManagement Module (PowerShell 7+)

The `Microsoft.PowerShell.SecretManagement` module provides a unified interface for secrets:

```powershell
# Install the modules
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser  # Local vault

# Register a secret vault
Register-SecretVault -Name "LocalSecrets" -ModuleName Microsoft.PowerShell.SecretStore

# Store a secret
$credential = Get-Credential
Set-Secret -Name "ServiceAccount" -Secret $credential -Vault "LocalSecrets"

# Retrieve a secret
$cred = Get-Secret -Name "ServiceAccount" -Vault "LocalSecrets"

# List secrets
Get-SecretInfo -Vault "LocalSecrets"
```

### 4.4 Azure Key Vault Integration

```powershell
# Install Azure Key Vault extension
Install-Module Az.KeyVault -Scope CurrentUser

# Connect to Azure
Connect-AzAccount

# Retrieve secret from Key Vault
$secret = Get-AzKeyVaultSecret -VaultName "MyKeyVault" -Name "DatabasePassword"
$securePassword = $secret.SecretValue

# Create credential from Key Vault secret
$username = (Get-AzKeyVaultSecret -VaultName "MyKeyVault" -Name "DatabaseUser").SecretValueText
$credential = New-Object PSCredential($username, $securePassword)
```

### 4.5 Credential Security Checklist

| Practice | Status | Notes |
|----------|--------|-------|
| Never store passwords in scripts | Required | Use external vaults |
| Use PSCredential objects | Required | Standard credential handling |
| Implement SecretManagement | Recommended | Centralized secrets |
| Enable credential guard | Recommended | Windows enterprise feature |
| Rotate service account passwords | Required | Minimum 90-day rotation |
| Use gMSA where possible | Recommended | Automatic password management |

---

## 5. Constrained Language Mode

### 5.1 Overview

Constrained Language Mode (CLM) limits PowerShell's capabilities to prevent malicious activities while allowing administrative functions.

### 5.2 Language Mode Comparison

| Feature | FullLanguage | ConstrainedLanguage | NoLanguage | RestrictedLanguage |
|---------|--------------|---------------------|------------|-------------------|
| All cmdlets | Yes | Allowed cmdlets only | No | No |
| .NET types | All | Core types only | None | None |
| COM objects | Yes | No | No | No |
| Type definitions | Yes | No | No | No |
| Script blocks | Yes | Limited | No | No |
| Variables | All | Restricted | None | Limited |

### 5.3 Checking Current Language Mode

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Expected output in constrained mode:
# ConstrainedLanguage
```

### 5.4 Enabling Constrained Language Mode

#### Via Environment Variable (System-wide)

```powershell
# Set environment variable (requires admin)
[Environment]::SetEnvironmentVariable(
    "__PSLockdownPolicy", 
    "4", 
    [EnvironmentVariableTarget]::Machine
)
```

#### Via Application Control Policies

Constrained Language Mode is automatically enforced when:
- Windows Defender Application Control (WDAC) is enabled
- AppLocker is configured with script rules
- Software Restriction Policies are active

```powershell
# Verify AppLocker is enforcing
Get-AppLockerPolicy -Effective | Select-String "Script"
```

### 5.5 Allowed Types in Constrained Mode

```powershell
# These core types are allowed in Constrained Language Mode:
[Array], [Bool], [byte], [char], [DateTime], [decimal], [double],
[float], [Hashtable], [int], [long], [Object], [PSCredential],
[PSObject], [PSReference], [Regex], [sbyte], [short], [single],
[string], [switch], [TimeSpan], [uint], [ulong], [ushort], [void]
```

---

## 6. Just Enough Administration (JEA)

### 6.1 JEA Overview

Just Enough Administration provides role-based access control for PowerShell remoting, implementing the principle of least privilege.

### 6.2 JEA Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        JEA Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌─────────────────────────────────────┐   │
│  │    User      │───▶│   Session Configuration (.pssc)     │   │
│  └──────────────┘    │   - Virtual account / gMSA          │   │
│                      │   - Role capability mapping         │   │
│                      │   - Transcription settings          │   │
│                      └──────────────────┬──────────────────┘   │
│                                         │                       │
│                                         ▼                       │
│                      ┌─────────────────────────────────────┐   │
│                      │   Role Capability (.psrc)           │   │
│                      │   - Visible cmdlets                 │   │
│                      │   - Visible functions               │   │
│                      │   - Visible providers               │   │
│                      │   - Script definitions              │   │
│                      └─────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 Creating Role Capability Files

```powershell
# Create Role Capability file
$roleCapabilityParams = @{
    Path = "C:\Program Files\JEA\RoleCapabilities\DNSAdmin.psrc"
    
    # Cmdlets the role can use
    VisibleCmdlets = @(
        'Get-DnsServer',
        'Get-DnsServerZone',
        'Get-DnsServerResourceRecord',
        @{
            Name       = 'Add-DnsServerResourceRecord*'
            Parameters = @{Name = 'ZoneName'; ValidateSet = 'contoso.com'}
        },
        @{
            Name       = 'Remove-DnsServerResourceRecord'
            Parameters = @{Name = 'Force'; ValidateSet = $true}
        }
    )
    
    # Functions defined in this role
    FunctionDefinitions = @{
        Name = 'Get-DNSRecordCount'
        ScriptBlock = {
            param($ZoneName)
            (Get-DnsServerResourceRecord -ZoneName $ZoneName).Count
        }
    }
    
    # External commands
    VisibleExternalCommands = @(
        'C:\Windows\System32\ipconfig.exe',
        'C:\Windows\System32\nslookup.exe'
    )
    
    # Visible providers
    VisibleProviders = @('FileSystem')
}

New-PSRoleCapabilityFile @roleCapabilityParams
```

### 6.4 Creating Session Configuration Files

```powershell
# Create Session Configuration file
$sessionConfigParams = @{
    Path = "C:\Program Files\JEA\Configurations\DNSAdmin.pssc"
    
    # Run as virtual account
    RunAsVirtualAccount = $true
    
    # Or use Group Managed Service Account
    # GroupManagedServiceAccount = 'DOMAIN\gMSA_DNS$'
    
    # Role definitions
    RoleDefinitions = @{
        'DOMAIN\DNS_Admins' = @{
            RoleCapabilities = 'DNSAdmin'
        }
        'DOMAIN\DNS_Operators' = @{
            RoleCapabilities = 'DNSOperator'
        }
    }
    
    # Session settings
    SessionType = 'RestrictedRemoteServer'
    LanguageMode = 'ConstrainedLanguage'
    
    # Transcription
    TranscriptDirectory = 'C:\ProgramData\JEA\Transcripts'
    
    # Module imports
    ModulesToImport = @('DnsServer')
}

New-PSSessionConfigurationFile @sessionConfigParams
```

### 6.5 Registering JEA Endpoints

```powershell
# Register the JEA endpoint
Register-PSSessionConfiguration -Name "DNSAdministration" `
    -Path "C:\Program Files\JEA\Configurations\DNSAdmin.pssc" `
    -Force

# Verify registration
Get-PSSessionConfiguration -Name "DNSAdministration"

# Connect to JEA endpoint
Enter-PSSession -ComputerName "dns01.contoso.com" -ConfigurationName "DNSAdministration"
```

---

## 7. Logging and Transcription

### 7.1 Script Block Logging

Script Block Logging records the content of all script blocks processed by PowerShell.

#### Enable via Group Policy

**Path:** `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

```
Setting: Turn on PowerShell Script Block Logging
Value: Enabled

Setting: Log script block invocation start/stop events
Value: Enabled (optional, increases volume)
```

#### Enable via Registry

```powershell
# Enable Script Block Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1
```

### 7.2 Module Logging

Logs pipeline execution details for specified modules.

```powershell
# Enable Module Logging via Registry
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

# Specify modules to log
$modulePath = "$regPath\ModuleNames"
if (!(Test-Path $modulePath)) {
    New-Item -Path $modulePath -Force | Out-Null
}
Set-ItemProperty -Path $modulePath -Name "*" -Value "*"  # Log all modules
```

### 7.3 Transcription

Transcription creates text records of all PowerShell sessions.

```powershell
# Enable Transcription via Registry
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1
Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value "C:\PSTranscripts"

# Manual transcription in scripts
$transcriptPath = "C:\Logs\Transcripts\$(Get-Date -Format 'yyyyMMdd_HHmmss')_$env:USERNAME.txt"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader
# ... script operations ...
Stop-Transcript
```

### 7.4 Event Log Configuration

```powershell
# PowerShell logs to these Event Log channels:
# - Microsoft-Windows-PowerShell/Operational (Event ID 4103, 4104)
# - Windows PowerShell (Event ID 400, 403, 600)

# Increase log size for forensic capability
$logNames = @(
    'Microsoft-Windows-PowerShell/Operational',
    'Windows PowerShell'
)

foreach ($logName in $logNames) {
    $log = Get-WinEvent -ListLog $logName
    $log.MaximumSizeInBytes = 1GB
    $log.SaveChanges()
}
```

### 7.5 Logging Reference Table

| Log Type | Event ID | Information Captured | Storage Location |
|----------|----------|---------------------|------------------|
| Script Block | 4104 | Decoded script content | Operational log |
| Script Block Invocation | 4105/4106 | Start/stop times | Operational log |
| Module Logging | 4103 | Pipeline execution | Operational log |
| Engine Start | 400 | PowerShell session start | PowerShell log |
| Engine Stop | 403 | PowerShell session end | PowerShell log |
| Provider Start | 600 | Provider initialization | PowerShell log |

---

## 8. Injection Prevention

### 8.1 Understanding PowerShell Injection

Injection vulnerabilities occur when user input is incorporated into commands without proper validation or sanitization.

### 8.2 Vulnerable Code Patterns

```powershell
# VULNERABLE: Direct string expansion
$userInput = Read-Host "Enter computer name"
Invoke-Expression "Get-Process -ComputerName $userInput"

# VULNERABLE: Script block from string
$command = "Get-Service -Name $serviceName"
$scriptBlock = [ScriptBlock]::Create($command)
& $scriptBlock

# VULNERABLE: Format operator with user input
$query = "SELECT * FROM Win32_Process WHERE Name = '{0}'" -f $processName
Get-WmiObject -Query $query
```

### 8.3 Secure Coding Patterns

```powershell
# SECURE: Use parameter binding
$userInput = Read-Host "Enter computer name"
Get-Process -ComputerName $userInput

# SECURE: Use splatting
$params = @{
    ComputerName = $userInput
    Name         = "explorer"
}
Get-Process @params

# SECURE: Validate input with regex
function Get-SafeProcess {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9\-\.]+$')]
        [string]$ComputerName
    )
    Get-Process -ComputerName $ComputerName
}

# SECURE: Use ValidateSet for restricted values
function Restart-ControlledService {
    param(
        [ValidateSet('Spooler', 'W32Time', 'BITS')]
        [string]$ServiceName
    )
    Restart-Service -Name $ServiceName
}
```

### 8.4 Invoke-Expression Alternatives

```powershell
# AVOID: Invoke-Expression with user input
Invoke-Expression "Get-Service $serviceName"

# PREFER: Direct cmdlet invocation
Get-Service -Name $serviceName

# PREFER: The call operator
$command = Get-Command "Get-Service"
& $command -Name $serviceName

# PREFER: Static script blocks with parameters
$scriptBlock = { param($Name) Get-Service -Name $Name }
& $scriptBlock -Name $serviceName
```

### 8.5 Parameter Validation Attributes

```powershell
function Invoke-SecureOperation {
    [CmdletBinding()]
    param(
        # Validate against a pattern
        [ValidatePattern('^[a-zA-Z0-9_\-]+$')]
        [string]$Name,
        
        # Validate against specific values
        [ValidateSet('Start', 'Stop', 'Restart')]
        [string]$Action,
        
        # Validate numeric range
        [ValidateRange(1, 100)]
        [int]$Count,
        
        # Validate string length
        [ValidateLength(1, 50)]
        [string]$Description,
        
        # Custom validation
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { $true }
            else { throw "File does not exist: $_" }
        })]
        [string]$FilePath,
        
        # Validate not null or empty
        [ValidateNotNullOrEmpty()]
        [string]$RequiredValue
    )
    
    # Function logic here
}
```

### 8.6 WMI/CIM Query Safety

```powershell
# VULNERABLE: String concatenation in WMI queries
$name = Read-Host "Process name"
Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name = '$name'"

# SECURE: Use CIM cmdlets with parameter binding
$name = Read-Host "Process name"
Get-CimInstance -ClassName Win32_Process -Filter "Name = '$($name -replace "'", "''")'"

# SECURE: Better approach with cmdlet parameters
Get-Process -Name $name
```

---

## 9. Module Security and Trusted Repositories

### 9.1 PSResourceGet (PowerShell 7.x)

PSResourceGet is the next-generation module for managing PowerShell resources.

```powershell
# Install PSResourceGet
Install-Module Microsoft.PowerShell.PSResourceGet -Scope CurrentUser

# Register trusted repository
$repoParams = @{
    Name     = "InternalRepo"
    Uri      = "https://nuget.internal.company.com/v3/index.json"
    Trusted  = $true
    Priority = 10
}
Register-PSResourceRepository @repoParams

# Set default repository trust
Set-PSResourceRepository -Name PSGallery -Trusted $false  # Require confirmation

# Install with hash verification
Install-PSResource -Name "Pester" -Repository "PSGallery" -TrustRepository
```

### 9.2 Module Integrity Verification

```powershell
# Verify module catalog
$modulePath = (Get-Module -Name Pester -ListAvailable).ModuleBase
$catalogPath = Join-Path $modulePath "Pester.cat"

if (Test-Path $catalogPath) {
    $result = Test-FileCatalog -Path $modulePath -CatalogFilePath $catalogPath -Detailed
    if ($result.Status -eq "Valid") {
        Write-Host "Module integrity verified" -ForegroundColor Green
    } else {
        Write-Warning "Module integrity check failed!"
    }
}

# Check module signature
Get-AuthenticodeSignature -FilePath "$modulePath\Pester.psd1"
```

### 9.3 Private Repository Configuration

```powershell
# Configure internal NuGet repository
$credential = Get-Credential
$repoParams = @{
    Name               = "CompanyModules"
    SourceLocation     = "https://nuget.company.com/nuget"
    PublishLocation    = "https://nuget.company.com/nuget"
    InstallationPolicy = "Trusted"
    Credential         = $credential
}
Register-PSRepository @repoParams

# Set as default installation source
Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted
```

### 9.4 Module Allowlisting

```powershell
# Create module allowlist configuration
$allowedModules = @(
    'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.Security',
    'Microsoft.PowerShell.Utility',
    'ActiveDirectory',
    'DnsServer'
)

# Verify module before import
function Import-ApprovedModule {
    param([string]$ModuleName)
    
    if ($ModuleName -in $allowedModules) {
        Import-Module $ModuleName -Force
    } else {
        throw "Module '$ModuleName' is not approved for use"
    }
}
```

---

## 10. Security Standards Cross-Reference

### 10.1 NIST SP 800-53 Rev. 5 Mapping

| Control ID | Control Name | PowerShell Implementation |
|------------|--------------|---------------------------|
| **AC-2** | Account Management | JEA virtual accounts, gMSA usage |
| **AC-3** | Access Enforcement | Constrained Language Mode, execution policies |
| **AC-6** | Least Privilege | JEA role capabilities, reduced cmdlet exposure |
| **AU-2** | Audit Events | Script Block Logging, Module Logging |
| **AU-3** | Content of Audit Records | Transcription with invocation headers |
| **AU-12** | Audit Generation | PowerShell Operational Event Log |
| **CM-7** | Least Functionality | Disable PowerShell v2, Constrained Language Mode |
| **IA-5** | Authenticator Management | SecretManagement module, secure credential handling |
| **SC-13** | Cryptographic Protection | FIPS mode, secure hash algorithms |
| **SI-3** | Malicious Code Protection | AMSI integration, script signing |
| **SI-7** | Software Integrity | Code signing, module catalog verification |

### 10.2 OWASP Top Ten (2025) Mapping

| OWASP Category | PowerShell Risk | Mitigation |
|----------------|-----------------|------------|
| **A01: Broken Access Control** | Unrestricted PowerShell execution | JEA, Constrained Language Mode |
| **A03: Injection** | Invoke-Expression abuse | Parameter validation, avoid dynamic execution |
| **A04: Insecure Design** | Hardcoded credentials | SecretManagement, PSCredential objects |
| **A05: Security Misconfiguration** | Bypass execution policy | AllSigned policy, AppLocker |
| **A06: Vulnerable Components** | Untrusted modules | Repository allowlisting, signature verification |
| **A07: Authentication Failures** | Plain text passwords | SecureString, credential vaults |
| **A09: Security Logging Failures** | Disabled logging | Enable all logging types, SIEM integration |

### 10.3 DISA STIG Requirements

| STIG ID | Requirement | Implementation |
|---------|-------------|----------------|
| **WN10-00-000155** | PowerShell 2.0 must be disabled | `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root` |
| **WN10-CC-000326** | Script Block Logging enabled | Group Policy or registry configuration |
| **WN10-CC-000327** | Module Logging enabled | Group Policy or registry configuration |
| **WN10-CC-000330** | Transcription enabled | Group Policy or registry configuration |
| **WN11-CC-000040** | PowerShell script execution restricted | AllSigned or RemoteSigned policy |

### 10.4 CIS Benchmark Level 2 Controls

| CIS Control | Description | PowerShell Setting |
|-------------|-------------|-------------------|
| **18.9.102.1** | Turn on Module Logging | Enabled for all modules |
| **18.9.102.2** | Turn on PowerShell Script Block Logging | Enabled |
| **18.9.102.3** | Turn on Script Execution | AllSigned |
| **18.9.102.4** | Turn on PowerShell Transcription | Enabled with output directory |
| **2.3.10.9** | Configure "Network access: Remotely accessible registry paths" | Restrict PowerShell remoting paths |

### 10.5 FIPS 140-3 Compliance

```powershell
# Check FIPS mode status
$fipsEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy").Enabled

if ($fipsEnabled) {
    Write-Host "FIPS mode is enabled" -ForegroundColor Green
} else {
    Write-Host "FIPS mode is not enabled" -ForegroundColor Yellow
}

# FIPS-compliant hashing
$fipsAlgorithms = @('SHA256', 'SHA384', 'SHA512')

function Get-FIPSCompliantHash {
    param(
        [string]$FilePath,
        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string]$Algorithm = 'SHA256'
    )
    Get-FileHash -Path $FilePath -Algorithm $Algorithm
}

# FIPS-compliant secure string encryption uses Windows CNG
# which is FIPS 140-3 validated when FIPS mode is enabled
```

---

## 11. Compliance Checklists

### 11.1 Pre-Deployment Checklist

| Item | Required | Verified | Notes |
|------|----------|----------|-------|
| PowerShell 2.0 disabled | Yes | [ ] | Remove legacy attack vector |
| Execution policy configured | Yes | [ ] | AllSigned or RemoteSigned |
| Script Block Logging enabled | Yes | [ ] | Required for forensics |
| Module Logging enabled | Yes | [ ] | Track module usage |
| Transcription enabled | Yes | [ ] | Session recording |
| AMSI enabled | Yes | [ ] | Malware scanning |
| Code signing infrastructure | Recommended | [ ] | Enterprise CA or commercial |
| JEA endpoints configured | Recommended | [ ] | Least privilege remoting |
| Constrained Language Mode | Recommended | [ ] | With AppLocker/WDAC |
| Event log forwarding | Recommended | [ ] | Centralized monitoring |

### 11.2 Script Security Review Checklist

| Category | Item | Pass | Comments |
|----------|------|------|----------|
| **Credentials** | No hardcoded passwords | [ ] | |
| **Credentials** | Uses PSCredential objects | [ ] | |
| **Credentials** | Secrets from vault/KeyVault | [ ] | |
| **Input Validation** | All parameters validated | [ ] | |
| **Input Validation** | No Invoke-Expression with user input | [ ] | |
| **Input Validation** | No dynamic script blocks | [ ] | |
| **Error Handling** | Try/Catch implemented | [ ] | |
| **Error Handling** | No sensitive data in errors | [ ] | |
| **Logging** | Appropriate logging included | [ ] | |
| **Logging** | No secrets logged | [ ] | |
| **Signing** | Script is digitally signed | [ ] | |
| **Dependencies** | Modules from trusted source | [ ] | |

### 11.3 Enterprise Configuration Checklist

| Configuration | NIST | DISA | CIS L2 | Status |
|--------------|------|------|--------|--------|
| Disable PowerShell v2 | CM-7 | WN10-00-000155 | N/A | [ ] |
| Script Block Logging | AU-2 | WN10-CC-000326 | 18.9.102.2 | [ ] |
| Module Logging | AU-2 | WN10-CC-000327 | 18.9.102.1 | [ ] |
| Transcription | AU-3 | WN10-CC-000330 | 18.9.102.4 | [ ] |
| Execution Policy | CM-7 | WN11-CC-000040 | 18.9.102.3 | [ ] |
| Constrained Language Mode | AC-3 | N/A | N/A | [ ] |
| JEA Implementation | AC-6 | N/A | N/A | [ ] |
| AMSI Integration | SI-3 | N/A | N/A | [ ] |
| Code Signing | SI-7 | N/A | N/A | [ ] |
| Credential Protection | IA-5 | N/A | N/A | [ ] |

---

## 12. References

### 12.1 Official Microsoft Documentation

1. [PowerShell Security Overview](https://learn.microsoft.com/en-us/powershell/scripting/security/overview?view=powershell-7.5) - Microsoft Learn
2. [About Execution Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.6) - Microsoft Learn
3. [About Signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.5) - Microsoft Learn
4. [About Language Modes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.5) - Microsoft Learn
5. [Preventing Script Injection Attacks](https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection?view=powershell-7.5) - Microsoft Learn
6. [Windows FIPS 140 Validation](https://learn.microsoft.com/en-us/windows/security/security-foundations/certification/fips-140-validation) - Microsoft Learn

### 12.2 Security Standards

7. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls
8. [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) - OWASP
9. [OWASP Top 10:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) - OWASP Foundation
10. [DISA STIGs](https://www.cyber.mil/stigs) - Defense Information Systems Agency
11. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Center for Internet Security
12. [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - NIST CSRC

### 12.3 Community Resources

13. [PowerShell Practice and Style Guide - Security](https://poshcode.gitbook.io/powershell-practice-and-style/best-practices/security) - Community Best Practices
14. [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) - PowerShell Team Blog
15. [Secure Password Management in PowerShell](https://www.secureideas.com/blog/secure-password-management-in-powershell-best-practices) - Secure Ideas
16. [Implementing PowerShell Security Best Practices for SysAdmins](https://medium.com/tomtalkspowershell/implementing-powershell-security-best-practices-for-sysadmins-d599827202ab) - Medium

### 12.4 Tools and Utilities

17. [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) - Static Code Analysis
18. [Microsoft.PowerShell.SecretManagement](https://www.powershellgallery.com/packages/Microsoft.PowerShell.SecretManagement) - PowerShell Gallery
19. [CIS-Benchmarks PowerShell Module](https://github.com/HersheyTaichou/CIS-Benchmarks) - GitHub

---

## Appendix A: Quick Reference Commands

```powershell
# Check PowerShell version
$PSVersionTable

# Check execution policy
Get-ExecutionPolicy -List

# Check language mode
$ExecutionContext.SessionState.LanguageMode

# Check AMSI status
(Get-MpPreference).DisableScriptScanning

# Check Script Block Logging
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue

# Check installed modules
Get-InstalledModule

# Verify PowerShell 2.0 is disabled
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# List JEA endpoints
Get-PSSessionConfiguration | Where-Object { $_.RunAsUser -like "*Virtual*" -or $_.GroupManagedServiceAccount }
```

---

## Appendix B: Group Policy Settings Reference

| Policy Path | Setting | Recommended Value |
|-------------|---------|-------------------|
| Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell | Turn on Script Execution | AllSigned |
| Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell | Turn on PowerShell Script Block Logging | Enabled |
| Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell | Turn on Module Logging | Enabled (all modules) |
| Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell | Turn on PowerShell Transcription | Enabled |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | March 2026 | Matrix Agent | Initial release |

---

*This document is provided for informational purposes and should be adapted to your organization's specific security requirements and risk tolerance.*
