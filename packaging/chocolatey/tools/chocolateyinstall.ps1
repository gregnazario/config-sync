$ErrorActionPreference = 'Stop'

$packageName = 'config-sync'
$version     = '0.1.0'
$url         = "https://github.com/gregnazario/config-sync/releases/download/v$version/config-sync-x86_64-pc-windows-msvc-v$version.zip"

$packageArgs = @{
    packageName    = $packageName
    url            = $url
    unzipLocation  = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
    checksum       = 'PLACEHOLDER_SHA256'
    checksumType   = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs
