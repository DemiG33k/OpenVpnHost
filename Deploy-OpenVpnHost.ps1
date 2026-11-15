<#
.SYNOPSIS
    Zero-dependency interactive OpenVPN Server/Client profile generator for Windows.
.DESCRIPTION
    - Requires Admin (auto-elevates safely even when launched from a UNC share).
    - Auto-detects Public IP.
    - Prompts for setup details with sensible defaults.
    - Generates RSA-2048 keys, CA, and signed Server/Client X.509 certs natively via .NET CNG/Crypto APIs (no OpenSSL required).
    - Reuses existing CA if re-run to add more client devices without invalidating the server.
    - Enables Windows IP Routing in the registry.
    - Auto-configures Internet Connection Sharing (ICS) with manual fallback instructions.
    - Outputs unified, full-tunnel server.ovpn and client .ovpn files with inline keys.
#>

$ErrorActionPreference = 'Stop'

# 1. Enforce Administrator Privileges (with -WorkingDirectory set to SystemRoot so UNC paths never fail)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges. Restarting elevated..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -WorkingDirectory $env:SystemRoot -Verb RunAs
    exit
}

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "   OpenVPN Profile & Native PKI Generator" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

# 2. Auto-Detect Public IP
Write-Host "`nDetecting Public IP address..." -ForegroundColor Gray
$autoIP = ""
try {
    $autoIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 5).Trim()
    Write-Host "Found Public IP: $autoIP" -ForegroundColor Green
} catch {
    Write-Warning "Could not auto-detect Public IP. You will need to enter it manually."
}

# 3. Interactive Prompts
$PublicIP = Read-Host "Enter Server Public IP or DDNS [$autoIP]"
if ([string]::IsNullOrWhiteSpace($PublicIP)) { $PublicIP = $autoIP }
if ([string]::IsNullOrWhiteSpace($PublicIP)) { throw "A Public IP is required to continue." }

$ClientName = Read-Host "Enter Client Name [mobile-client]"
if ([string]::IsNullOrWhiteSpace($ClientName)) { $ClientName = "mobile-client" }

$InternalNetwork = Read-Host "Enter your local home network base IP (e.g., 192.168.0.0) [192.168.0.0]"
if ([string]::IsNullOrWhiteSpace($InternalNetwork)) { $InternalNetwork = "192.168.0.0" }

$Port = 1194
$Protocol = "udp"
$KeyDirectory = "$env:USERPROFILE\OpenVPN_Keys"
$OutputDirectory = "$env:USERPROFILE\Desktop"

$Paths = @{
    CAKey      = Join-Path $KeyDirectory "ca.key"
    CACert     = Join-Path $KeyDirectory "ca.crt"
    ServerKey  = Join-Path $KeyDirectory "server.key"
    ServerCert = Join-Path $KeyDirectory "server.crt"
    ClientKey  = Join-Path $KeyDirectory "$ClientName.key"
    ClientCert = Join-Path $KeyDirectory "$ClientName.crt"
    TLSKey     = Join-Path $KeyDirectory "ta.key"
}
$ClientOutputPath = Join-Path $OutputDirectory "$ClientName.ovpn"
$ServerOutputPath = Join-Path $OutputDirectory "server.ovpn"

# --- Native .NET Cryptography Helpers ---

function New-ExportableRsaKey {
    param ([int]$KeySize = 2048)

    # Clean up any orphaned empty-named key container left by prior $null->"" coercion
    try {
        if ([System.Security.Cryptography.CngKey]::Exists("")) {
            $orphan = [System.Security.Cryptography.CngKey]::Open("")
            $orphan.Delete()
        }
    } catch {}

    $keyParams = New-Object System.Security.Cryptography.CngKeyCreationParameters
    $keyParams.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
    $lengthBytes = [System.BitConverter]::GetBytes($KeySize)
    $lengthProp = New-Object System.Security.Cryptography.CngProperty("Length", $lengthBytes, [System.Security.Cryptography.CngPropertyOptions]::None)
    $keyParams.Parameters.Add($lengthProp)

    $cngKey = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, [NullString]::Value, $keyParams)
    $rsa = New-Object System.Security.Cryptography.RSACng($cngKey)
    $pkcs8Bytes = $cngKey.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)

    $b64 = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $pem = "-----BEGIN PRIVATE KEY-----`n$($b64 -replace "`r`n", "`n")`n-----END PRIVATE KEY-----"
    return @{ Rsa = $rsa; CngKey = $cngKey; Pem = $pem }
}

function Import-RsaKeyFromPem {
    param ([string]$PemPath)
    $pemText = Get-Content -Path $PemPath -Raw
    $b64 = ($pemText -replace "-----BEGIN PRIVATE KEY-----", "" -replace "-----END PRIVATE KEY-----", "" -replace "\s+", "")
    $pkcs8Bytes = [System.Convert]::FromBase64String($b64)
    $cngKey = [System.Security.Cryptography.CngKey]::Import($pkcs8Bytes, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
    return (New-Object System.Security.Cryptography.RSACng($cngKey))
}

function ConvertTo-CertPem {
    param ([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $derBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $b64 = [System.Convert]::ToBase64String($derBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`n$($b64 -replace "`r`n", "`n")`n-----END CERTIFICATE-----"
}

function New-RandomSerialNumber {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $serial = New-Object byte[] 16
    $rng.GetBytes($serial)
    $serial[0] = ($serial[0] -band 0x7F) -bor 0x01
    return $serial
}

function New-SignedLeafCert {
    param (
        [string]$CommonName,
        [string]$EkuOid,
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]$IssuerSubjectName,
        [System.Security.Cryptography.RSA]$IssuerRsa,
        [string]$KeyOutPath,
        [string]$CertOutPath
    )
    $leafKeyObj = New-ExportableRsaKey -KeySize 2048
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        "CN=$CommonName",
        $leafKeyObj.Rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false, $false, 0, $true)))
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
        ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment),
        $true
    )))

    $ekuCollection = New-Object System.Security.Cryptography.OidCollection
    [void]$ekuCollection.Add((New-Object System.Security.Cryptography.Oid($EkuOid)))
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ekuCollection, $false)))
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($req.PublicKey, $false)))

    $notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter  = [System.DateTimeOffset]::UtcNow.AddDays(3650)
    $serial    = New-RandomSerialNumber

    # Sign directly via X509SignatureGenerator (bypasses CopyWithPrivateKey PFX export restrictions)
    $signer = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
        $IssuerRsa,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $signedCert = $req.Create($IssuerSubjectName, $signer, $notBefore, $notAfter, $serial)
    $certPem = ConvertTo-CertPem -Cert $signedCert

    [System.IO.File]::WriteAllText($KeyOutPath, $leafKeyObj.Pem, (New-Object System.Text.UTF8Encoding $False))
    [System.IO.File]::WriteAllText($CertOutPath, $certPem, (New-Object System.Text.UTF8Encoding $False))
}

function Get-PemBlock {
    param ([string]$FilePath, [string]$BlockType)
    $Content = Get-Content -Path $FilePath -Raw
    $Pattern = "(?s)-----BEGIN $BlockType-----.*?-----END $BlockType-----"
    if ($Content -match $Pattern) { return $Matches[0] }
    throw "Valid '$BlockType' block not found in $FilePath."
}

function New-TlsAuthKey {
    param ([string]$FilePath)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 256
    $rng.GetBytes($bytes)
    $hexString = ([System.BitConverter]::ToString($bytes) -replace '-','').ToLower()

    $keyContent = "-----BEGIN OpenVPN Static key V1-----`n"
    for ($i = 0; $i -lt $hexString.Length; $i += 32) {
        $keyContent += $hexString.Substring($i, [Math]::Min(32, $hexString.Length - $i)) + "`n"
    }
    $keyContent += "-----END OpenVPN Static key V1-----`n"
    [System.IO.File]::WriteAllText($FilePath, $keyContent, (New-Object System.Text.UTF8Encoding $False))
}

try {
    # 4. Enable Windows IP Routing
    Write-Host "`nVerifying Windows IP Routing..." -ForegroundColor Cyan
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name "IPEnableRouter" -ErrorAction SilentlyContinue).IPEnableRouter
    if ($CurrentValue -ne 1) {
        Set-ItemProperty -Path $RegPath -Name "IPEnableRouter" -Value 1
        Write-Warning "Windows IP Routing enabled. You MUST reboot your PC after this script finishes for routing to take effect."
    } else {
        Write-Host "IP Routing already enabled." -ForegroundColor Green
    }

    if (-not (Test-Path $KeyDirectory)) { New-Item -ItemType Directory -Path $KeyDirectory -Force | Out-Null }
    if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    # 5. Generate Keys & Certificates via Native .NET Crypto
    Write-Host "`nGenerating Cryptographic Keys (Native .NET PKI)..." -ForegroundColor Cyan

    if (-not (Test-Path $Paths.TLSKey)) {
        New-TlsAuthKey -FilePath $Paths.TLSKey
        Write-Host "  -> TLS Auth key (ta.key) generated."
    } else {
        Write-Host "  -> Using existing TLS Auth key (ta.key)."
    }

    $notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter  = [System.DateTimeOffset]::UtcNow.AddDays(3650)

    if ((Test-Path $Paths.CACert) -and (Test-Path $Paths.CAKey)) {
        $rawCaCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Paths.CACert)
        $caSubjectName = $rawCaCert.SubjectName
        $caRsa = Import-RsaKeyFromPem -PemPath $Paths.CAKey
        Write-Host "  -> Loaded existing Certificate Authority (ca.crt)."
    } else {
        $caKeyObj = New-ExportableRsaKey -KeySize 2048
        $caRsa = $caKeyObj.Rsa
        $caReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Local-OpenVPN-CA",
            $caRsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($true, $false, 0, $true)))
        $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
            ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign),
            $true
        )))
        $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($caReq.PublicKey, $false)))

        $caCert = $caReq.CreateSelfSigned($notBefore, $notAfter)
        $caSubjectName = $caCert.SubjectName
        [System.IO.File]::WriteAllText($Paths.CAKey, $caKeyObj.Pem, (New-Object System.Text.UTF8Encoding $False))
        [System.IO.File]::WriteAllText($Paths.CACert, (ConvertTo-CertPem -Cert $caCert), (New-Object System.Text.UTF8Encoding $False))
        Write-Host "  -> Certificate Authority (ca.crt) generated."
    }

    if (-not ((Test-Path $Paths.ServerCert) -and (Test-Path $Paths.ServerKey))) {
        New-SignedLeafCert -CommonName "OpenVPN-Server" -EkuOid "1.3.6.1.5.5.7.3.1" -IssuerSubjectName $caSubjectName -IssuerRsa $caRsa -KeyOutPath $Paths.ServerKey -CertOutPath $Paths.ServerCert
        Write-Host "  -> Server Certificate (server.crt) signed."
    } else {
        Write-Host "  -> Using existing Server Certificate (server.crt)."
    }

    if (-not ((Test-Path $Paths.ClientCert) -and (Test-Path $Paths.ClientKey))) {
        New-SignedLeafCert -CommonName $ClientName -EkuOid "1.3.6.1.5.5.7.3.2" -IssuerSubjectName $caSubjectName -IssuerRsa $caRsa -KeyOutPath $Paths.ClientKey -CertOutPath $Paths.ClientCert
        Write-Host "  -> Client Certificate ($ClientName.crt) signed."
    } else {
        Write-Host "  -> Using existing Client Certificate ($ClientName.crt)."
    }

    # 6. Extract PEM Blocks & Build Unified .ovpn Files
    $CaBlock       = Get-PemBlock -FilePath $Paths.CACert -BlockType "CERTIFICATE"
    $ServerCertBlk = Get-PemBlock -FilePath $Paths.ServerCert -BlockType "CERTIFICATE"
    $ServerKeyBlk  = Get-PemBlock -FilePath $Paths.ServerKey -BlockType "PRIVATE KEY"
    $ClientCertBlk = Get-PemBlock -FilePath $Paths.ClientCert -BlockType "CERTIFICATE"
    $ClientKeyBlk  = Get-PemBlock -FilePath $Paths.ClientKey -BlockType "PRIVATE KEY"
    $TlsBlock      = Get-PemBlock -FilePath $Paths.TLSKey -BlockType "OpenVPN Static key V1"

    $ClientConfig = @"
client
dev tun
proto $Protocol
remote $PublicIP $Port
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
$CaBlock
</ca>

<cert>
$ClientCertBlk
</cert>

<key>
$ClientKeyBlk
</key>

<tls-crypt>
$TlsBlock
</tls-crypt>
"@

    $ServerConfig = @"
port $Port
proto $Protocol
dev tun
dh none
server 10.8.0.0 255.255.255.0
push "route $InternalNetwork 255.255.255.0"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-GCM
auth SHA256
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1

<ca>
$CaBlock
</ca>

<cert>
$ServerCertBlk
</cert>

<key>
$ServerKeyBlk
</key>

<tls-crypt>
$TlsBlock
</tls-crypt>
"@

    [System.IO.File]::WriteAllText($ClientOutputPath, $ClientConfig, (New-Object System.Text.UTF8Encoding $False))
    [System.IO.File]::WriteAllText($ServerOutputPath, $ServerConfig, (New-Object System.Text.UTF8Encoding $False))

    Write-Host "`nSuccess! Generated unified configs at:" -ForegroundColor Green
    Write-Host "Server: $ServerOutputPath" -ForegroundColor Green
    Write-Host "Client: $ClientOutputPath" -ForegroundColor Green

    # 7. Auto-Configure Internet Connection Sharing (ICS)
    Write-Host "`nConfiguring Internet Connection Sharing (ICS)..." -ForegroundColor Cyan
    $icsSuccess = $false
    $internetAdapterName = $null
    $vpnAdapterName = $null

    try {
        # Detect active internet-facing adapter via default route (works for both Wi-Fi and Ethernet)
        $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
            Sort-Object -Property RouteMetric, InterfaceMetric |
            Select-Object -First 1
        if ($defaultRoute) {
            $internetAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction Stop
            $internetAdapterName = $internetAdapter.Name
        }

        # Detect OpenVPN virtual adapter (prefer DCO, fall back to TAP)
        $vpnAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -like "*OpenVPN Data Channel Offload*" -or $_.Name -like "*OpenVPN Data Channel Offload*" } |
            Select-Object -First 1
        if (-not $vpnAdapter) {
            $vpnAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceDescription -like "*OpenVPN*" -or $_.InterfaceDescription -like "*TAP-Windows*" -or $_.Name -like "*OpenVPN*" } |
                Select-Object -First 1
        }
        if ($vpnAdapter) {
            $vpnAdapterName = $vpnAdapter.Name
        }

        if (-not $internetAdapterName) {
            throw "Could not detect an active internet-connected network adapter."
        }
        if (-not $vpnAdapterName) {
            throw "OpenVPN virtual adapter not found. Ensure OpenVPN Community Edition is installed."
        }

        $netShare = New-Object -ComObject HNetCfg.HNetShare.1
        $pubConn = $null
        $privConn = $null
        $otherSharedConfigs = @()

        foreach ($conn in $netShare.EnumEveryConnection) {
            $props = $netShare.NetConnectionProps($conn)
            $cfg = $netShare.INetSharingConfigurationForINetConnection($conn)

            if ($props.Name -eq $internetAdapterName) {
                $pubConn = @{ Conn = $conn; Cfg = $cfg; Name = $props.Name }
            } elseif ($props.Name -eq $vpnAdapterName) {
                $privConn = @{ Conn = $conn; Cfg = $cfg; Name = $props.Name }
            } elseif ($cfg.SharingEnabled) {
                $otherSharedConfigs += @{ Cfg = $cfg; Name = $props.Name }
            }
        }

        if (-not $pubConn -or -not $privConn) {
            throw "Could not bind COM sharing interfaces for '$internetAdapterName' -> '$vpnAdapterName'."
        }

        if ($pubConn.Cfg.SharingEnabled -and ($pubConn.Cfg.SharingConnectionType -eq 0) -and
            $privConn.Cfg.SharingEnabled -and ($privConn.Cfg.SharingConnectionType -eq 1)) {
            Write-Host "  -> Internet Connection Sharing is already active ('$internetAdapterName' -> '$vpnAdapterName')." -ForegroundColor Green
            $icsSuccess = $true
        } else {
            # Clear any stale ICS bindings on other adapters first (Windows only allows one active ICS pair)
            foreach ($stale in $otherSharedConfigs) {
                Write-Host "  -> Removing previous sharing on '$($stale.Name)'..." -ForegroundColor Gray
                $stale.Cfg.DisableSharing()
            }
            if ($pubConn.Cfg.SharingEnabled) { $pubConn.Cfg.DisableSharing() }
            if ($privConn.Cfg.SharingEnabled) { $privConn.Cfg.DisableSharing() }

            # 0 = Public (Internet source), 1 = Private (OpenVPN adapter)
            $pubConn.Cfg.EnableSharing(0)
            $privConn.Cfg.EnableSharing(1)

            Write-Host "  -> Shared '$internetAdapterName' with '$vpnAdapterName' successfully." -ForegroundColor Green
            $icsSuccess = $true
        }
    } catch {
        Write-Warning "Automatic ICS setup could not be completed: $($_.Exception.Message)"
    }

    if (-not $icsSuccess) {
        $srcHint = if ($internetAdapterName) { $internetAdapterName } else { "Wi-Fi or Ethernet" }
        $dstHint = if ($vpnAdapterName) { $vpnAdapterName } else { "OpenVPN Data Channel Offload" }
        Write-Host "`n===========================================" -ForegroundColor Yellow
        Write-Host "   Manual Internet Sharing Instructions" -ForegroundColor Yellow
        Write-Host "===========================================" -ForegroundColor Yellow
        Write-Host "To give VPN clients full internet access through your PC:" -ForegroundColor White
        Write-Host "1. Press Win + R, type 'ncpa.cpl', and press Enter." -ForegroundColor Gray
        Write-Host "2. Right-click your active internet adapter ('$srcHint') -> Properties." -ForegroundColor Gray
        Write-Host "3. Open the 'Sharing' tab." -ForegroundColor Gray
        Write-Host "4. Check 'Allow other network users to connect through this computer's Internet connection'." -ForegroundColor Gray
        Write-Host "5. Under 'Home networking connection', select '$dstHint' and click OK." -ForegroundColor Gray
        Write-Host "6. Restart/reconnect your OpenVPN server profile in the system tray." -ForegroundColor Gray
    }

} catch {
    Write-Host "`nFailed to generate OpenVPN files." -ForegroundColor Red
    Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Yellow
    exit 1
}
