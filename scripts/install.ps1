# Aether Sniffer - Windows installer
# Usage: irm https://raw.githubusercontent.com/Fredrickighile/aether-sniffer/main/scripts/install.ps1 | iex

function Install-AetherSniffer {
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $Repo = "Fredrickighile/aether-sniffer"
    $Binary = "aether-sniffer"
    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\aether-sniffer"
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ("aether-sniffer-" + [guid]::NewGuid().ToString())

    Write-Host ""
    Write-Host "  AETHER-SNIFFER - Installer" -ForegroundColor Magenta
    Write-Host "  ------------------------------"
    Write-Host ""

    try {
        if (-not [Environment]::Is64BitOperatingSystem) {
            throw "Only 64-bit Windows is supported."
        }

        # 1. Find the latest release
        Write-Host "  [1/4] Fetching latest version ..."
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "aether-sniffer-installer" }
        $tag = $release.tag_name
        if (-not $tag) { throw "Could not determine the latest version." }
        $ver = $tag.TrimStart("v")

        # 2. Download the archive and the checksums file
        $zipName = "${Binary}_${ver}_windows_amd64.zip"
        $sumName = "${Binary}_${ver}_checksums.txt"
        $base = "https://github.com/$Repo/releases/download/$tag"
        New-Item -ItemType Directory -Path $Tmp | Out-Null
        $zipPath = Join-Path $Tmp $zipName
        $sumPath = Join-Path $Tmp $sumName

        Write-Host "  [2/4] Downloading $Binary $tag (windows/amd64) ..."
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$zipName" -OutFile $zipPath
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$sumName" -OutFile $sumPath

        # 3. Verify the checksum (fail closed)
        Write-Host "  [3/4] Verifying checksum ..."
        $line = Get-Content $sumPath | Where-Object { $_ -match [regex]::Escape($zipName) } | Select-Object -First 1
        if (-not $line) { throw "No checksum found for $zipName. Aborting." }
        $expected = ($line -split "\s+")[0]
        $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash
        if ($actual -ne $expected) {
            throw "Checksum mismatch. Expected $expected but got $actual. Aborting."
        }

        # 4. Install
        Write-Host "  [4/4] Installing to $InstallDir ..."
        $extractDir = Join-Path $Tmp "extract"
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        $exe = Get-ChildItem -Path $extractDir -Recurse -Filter "$Binary.exe" | Select-Object -First 1
        if (-not $exe) { throw "$Binary.exe not found in the archive." }

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item $exe.FullName (Join-Path $InstallDir "$Binary.exe") -Force

        # Add to the user PATH if it is not there yet
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $parts = @()
        if ($userPath) { $parts = $userPath -split ";" | Where-Object { $_ } }
        if ($parts -notcontains $InstallDir) {
            $newPath = (($parts + $InstallDir) -join ";")
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        }
        if (($env:Path -split ";") -notcontains $InstallDir) {
            $env:Path = "$env:Path;$InstallDir"
        }

        Write-Host ""
        Write-Host "  ------------------------------"
        Write-Host "  Aether Sniffer $tag installed." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Get started (open a NEW terminal if the command is not found):"
        Write-Host "  > aether-sniffer scan ." -ForegroundColor Magenta
        Write-Host ""
    }
    catch {
        Write-Host ""
        Write-Host "  Install failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
    finally {
        if (Test-Path $Tmp) { Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Install-AetherSniffer