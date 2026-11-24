# Creates apps/api/.env.test (gitignored) for the DB tests. The password is read masked and never echoed.
$secure = Read-Host "Local PostgreSQL password for user 'postgres'" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $target = Join-Path $PSScriptRoot "..\apps\api\.env.test"
    $line = "TEST_PG_ADMIN_URL=postgresql+asyncpg://postgres:" + [uri]::EscapeDataString($plain) + "@localhost:5432/postgres"
    Set-Content -NoNewline -Encoding ascii -Path $target -Value $line
    Write-Host "Created $((Resolve-Path $target).Path)"
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable plain, secure -ErrorAction SilentlyContinue
}
