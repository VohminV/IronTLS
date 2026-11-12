param(
    [switch]$Clean,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root 'build'

if ($Clean -and (Test-Path $build)) {
    Remove-Item -Recurse -Force $build
}
New-Item -ItemType Directory -Force -Path $build | Out-Null

$asm = @('it_mem', 'sha256', 'hmac', 'hkdf', 'aes_gcm', 'tls13')
$objs = @()

foreach ($name in $asm) {
    $src = Join-Path $root "src\$name.asm"
    $obj = Join-Path $build "$name.obj"
    Write-Host "NASM  $name.asm"
    & nasm -f win64 -I (Join-Path $root 'include') -o $obj $src
    if ($LASTEXITCODE -ne 0) { throw "nasm failed: $name" }
    $objs += $obj
}

$tests = @(
    @{ Name = 'test_crypto'; Src = 'tests\test_crypto.c' },
    @{ Name = 'test_tls';    Src = 'tests\test_tls.c' },
    @{ Name = 'loopback';    Src = 'examples\loopback.c' }
)

foreach ($t in $tests) {
    $obj = Join-Path $build "$($t.Name).o"
    $exe = Join-Path $build "$($t.Name).exe"
    Write-Host "CC    $($t.Src)"
    & gcc -O2 -Wall -Wextra -I (Join-Path $root 'include') -c (Join-Path $root $t.Src) -o $obj
    if ($LASTEXITCODE -ne 0) { throw "gcc failed: $($t.Src)" }
    & gcc -o $exe $obj @objs -lbcrypt
    if ($LASTEXITCODE -ne 0) { throw "link failed: $($t.Name)" }
}

if ($Test) {
    Write-Host ''
    Write-Host '=== test_crypto ==='
    & (Join-Path $build 'test_crypto.exe'); if ($LASTEXITCODE -ne 0) { throw 'test_crypto failed' }
    Write-Host ''
    Write-Host '=== test_tls ==='
    & (Join-Path $build 'test_tls.exe'); if ($LASTEXITCODE -ne 0) { throw 'test_tls failed' }
    Write-Host ''
    Write-Host '=== loopback ==='
    & (Join-Path $build 'loopback.exe'); if ($LASTEXITCODE -ne 0) { throw 'loopback failed' }
    Write-Host ''
    Write-Host 'ALL TESTS PASSED'
}
