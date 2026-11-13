# AgentGuard publish helper.
#
# Dry run by default. It prints exactly what would happen.
# Add -Execute to create the public repo and push.
#
#   .\publish.ps1            # checks + preview
#   .\publish.ps1 -Execute   # publish (requires explicit approval)
#
# The script never edits contact details, licenses, or payment settings for you.

param(
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Fail($message) {
    Write-Host "BLOCKED: $message" -ForegroundColor Red
    exit 1
}

Write-Host "AgentGuard publish check" -ForegroundColor Cyan
Write-Host "Directory: $PSScriptRoot"

# 1. Tooling
$pythonCmd = "python"
if (Get-Command "py" -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} elseif (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe") {
    $pythonCmd = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Fail "GitHub CLI (gh) is not installed" }
$auth = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) { Fail "gh is not authenticated. Run: gh auth login" }
Write-Host "OK: python and gh are available"

# 2. Tests
Write-Host "`nRunning tests..." -ForegroundColor Cyan
& $pythonCmd -m unittest discover -s tests -q
if ($LASTEXITCODE -ne 0) { Fail "tests failed" }
Write-Host "OK: tests passed"

# 3. Self-scan (demo/vulnerable is intentionally insecure)
Write-Host "`nRunning self-scan..." -ForegroundColor Cyan
$scanDir = Join-Path $PSScriptRoot ".tmp"
New-Item -ItemType Directory -Force $scanDir | Out-Null
$scanFile = Join-Path $scanDir "publish-self-scan.md"
& $pythonCmd audit.py . --exclude demo/vulnerable --exclude tests --exclude reports --exclude audit.py --fail-on high --output $scanFile
if ($LASTEXITCODE -ne 0) { Fail "self-scan found high/critical findings" }
Write-Host "OK: self-scan clean"

# 4. Contact placeholders
$placeholderFiles = @("README.md", "OFFER.md", "site/index.html")
$hits = Select-String -Path $placeholderFiles -Pattern "Replace this line", "Replace contact placeholders", "[contact]" -SimpleMatch -ErrorAction SilentlyContinue
if ($hits) {
    Write-Host "`nContact placeholders still present:" -ForegroundColor Yellow
    $hits | ForEach-Object { Write-Host "  $($_.Path):$($_.LineNumber)  $($_.Line.Trim())" }
    Fail "replace the placeholders before publishing"
}
Write-Host "OK: no contact placeholders"

# 5. License reminder
if (-not (Test-Path "LICENSE")) {
    Write-Host "WARN: no LICENSE file. GitHub defaults to all rights reserved." -ForegroundColor Yellow
}

# 6. Preview the exact publish actions
$repoName = "agentguard"
Write-Host "`nPlanned actions:" -ForegroundColor Cyan
if (-not (Test-Path ".git")) {
    Write-Host "  git init"
    Write-Host "  git add ."
    Write-Host "  git commit -m `"AgentGuard v0.1.0`""
}
Write-Host "  gh repo create $repoName --public --source=. --remote=origin --push"
Write-Host "  gh repo edit --add-topic mcp,security,ai-agents,static-analysis,appsec"
Write-Host "  gh release create v0.1.0 --title `"v0.1.0`" --notes `"AgentGuard v0.1.0`""

if (-not $Execute) {
    Write-Host "`nDRY RUN. Nothing was published." -ForegroundColor Yellow
    Write-Host "Review OFFER.md, site/index.html, and the license. Then run:" -ForegroundColor Yellow
    Write-Host "  .\publish.ps1 -Execute" -ForegroundColor Yellow
    exit 0
}

# 7. Publish only with -Execute
Write-Host "`nPublishing..." -ForegroundColor Cyan
if (-not (Test-Path ".git")) {
    git init
    git add .
    git commit -m "AgentGuard v0.1.0"
    if ($LASTEXITCODE -ne 0) { Fail "git commit failed" }
}
gh repo view $repoName 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    gh repo create $repoName --public --source=. --remote=origin --push
    if ($LASTEXITCODE -ne 0) { Fail "gh repo create failed" }
} else {
    $branch = git branch --show-current
    if (-not $branch) { $branch = "main" }
    git push -u origin $branch
    if ($LASTEXITCODE -ne 0) { Fail "git push failed" }
}
gh repo edit --add-topic mcp,security,ai-agents,static-analysis,appsec
gh release create v0.1.0 --title "v0.1.0" --notes "First public release. Static security audit for AI agents and MCP servers."
Write-Host "`nPublished. Next: replace the GitHub links in site/index.html with the real repo URL, enable Pages, then post per LAUNCH.md." -ForegroundColor Green
