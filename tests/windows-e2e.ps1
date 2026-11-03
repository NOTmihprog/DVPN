# End to end on Windows (as Administrator; the CI runner is one): what the node does to the
# system, which the Linux netns test cannot see. Two nodes on this machine:
#   b — no TUN (-d), the group's admin, a subnet behind it (198.18.50.0/24);
#   a — TUN "dvpne2e", run as the Windows service.
# Checked on a: the Wintun adapter and its address, the route to b's subnet, *.dvpn through
# NRPT, the kill switch (routes into the tunnel, the internet blocked, a hole through the
# physical gateway still open), and that stopping the service leaves nothing behind.
#
#   tests\windows-e2e.ps1 -Dvpn target\release\dvpn.exe -Wintun path\to\wintun.dll
param(
    [Parameter(Mandatory)] [string] $Dvpn,
    [Parameter(Mandatory)] [string] $Wintun,
    # stays reachable while the kill switch is on (a hole): the CI runner's own Gitea
    [string] $Keep = "git.mihprog.com"
)
$ErrorActionPreference = "Continue"
$root = Join-Path $env:TEMP "dvpn-e2e-$PID"
$a = Join-Path $root "a"; $b = Join-Path $root "b"
$script:failed = 0
$bProc = $null

function Check([string] $what, [bool] $ok) {
    if ($ok) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:failed++ }
}

# waits up to $secs for $cond to hold
function WaitFor([scriptblock] $cond, [int] $secs = 30) {
    for ($i = 0; $i -lt $secs * 2; $i++) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Dvpn([string] $dir) {
    $out = & "$dir\dvpn.exe" --dir $dir @args 2>&1 | ForEach-Object { "$_" }
    return $out
}

function OurRoutes { @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq 7347) }
function OurNrpt { @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object Comment -like "dvpn*") }

function SetKey([string] $file, [string] $key, [string] $value) {
    (Get-Content $file) -replace "^$key = .*", "$key = $value" | Set-Content $file
}

try {
    if (Get-Service dvpn -ErrorAction SilentlyContinue) { throw "a dvpn service is installed on this machine already" }
    New-Item -ItemType Directory -Force $a, $b | Out-Null
    foreach ($d in $a, $b) { Copy-Item $Dvpn "$d\dvpn.exe"; Copy-Item $Wintun "$d\wintun.dll" }

    # b: the group and its admin, a subnet behind it
    Dvpn $b group create e2e -n b | Out-Null
    SetKey "$b\config.toml" "bind_port" '"18911"'
    $bKey = (Dvpn $b show-key | Select-Object -Last 1).Trim()
    $invite = (Dvpn $b group invite -n a --static 127.0.0.1:18911 | Select-Object -Last 1).Trim()
    Dvpn $b node set b --add-route 198.18.50.0/24 | Out-Null

    # a: joins; its own TUN; the kept host is a hole ("!") in its routes
    Dvpn $a group join $invite | Out-Null
    SetKey "$a\config.toml" "bind_port" '"18912"'
    SetKey "$a\config.toml" "tun_name" '"dvpne2e"'
    $keepIp = (Resolve-DnsName $Keep -Type A | Where-Object IPAddress | Select-Object -First 1).IPAddress
    Add-Content "$a\config.toml" "`n[ckr.remote_subnets]`n`"$bKey`" = [`"!$keepIp/32`"]"

    $bProc = Start-Process "$b\dvpn.exe" -ArgumentList "--dir", $b, "-d", "-a", "127.0.0.1:9911" -PassThru -WindowStyle Hidden `
        -RedirectStandardError "$root\b.log"
    $install = Dvpn $a service install
    Check "service installed and started" ((Get-Service dvpn).Status -eq "Running")

    Check "Wintun adapter dvpne2e up" (WaitFor { (Get-NetAdapter -Name dvpne2e -ErrorAction SilentlyContinue).Status -eq "Up" })
    Check "an address of the group on it" (WaitFor { Get-NetIPAddress -InterfaceAlias dvpne2e -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -like "10.*" })
    Check "route to b's subnet on dvpne2e" (WaitFor { Get-NetRoute -DestinationPrefix 198.18.50.0/24 -InterfaceAlias dvpne2e -ErrorAction SilentlyContinue })
    Check "hole for $keepIp through the physical network" (WaitFor { Get-NetRoute -DestinationPrefix "$keepIp/32" -ErrorAction SilentlyContinue | Where-Object InterfaceAlias -ne dvpne2e })
    Check "NRPT sends .dvpn to the node" (WaitFor { OurNrpt | Where-Object { $_.Namespace -contains ".dvpn" } })
    $bAddr = $null
    Check "b.dvpn resolves" (WaitFor { $script:bAddr = (Resolve-DnsName b.dvpn -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object IPAddress).IPAddress; $script:bAddr -like "10.*" })

    # kill switch: b is no gateway, so with it as the exit the internet is blocked
    Dvpn $a exit --v4 b | Out-Null
    Check "kill switch: default route halves on dvpne2e" (WaitFor { (OurRoutes | Where-Object { $_.InterfaceAlias -eq "dvpne2e" -and $_.DestinationPrefix -in "0.0.0.0/1", "128.0.0.0/1" }).Count -eq 2 })
    Check "kill switch: the internet is blocked" (-not (Test-Connection 1.1.1.1 -Count 2 -Quiet))
    $kept = try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "https://$Keep/").StatusCode -lt 500 } catch { $false }
    Check "kill switch: the hole ($Keep) still reachable" $kept
    Dvpn $a exit --none | Out-Null
    Check "exit off: default route halves gone" (WaitFor { -not (OurRoutes | Where-Object DestinationPrefix -in "0.0.0.0/1", "128.0.0.0/1") })
    Check "exit off: the internet is back" (WaitFor { Test-Connection 1.1.1.1 -Count 1 -Quiet } 15)

    # stop: nothing left behind
    Dvpn $a service stop | Out-Null
    Check "service stopped" ((Get-Service dvpn).Status -eq "Stopped")
    Check "no routes of ours left" (WaitFor { (OurRoutes).Count -eq 0 } 10)
    Check "no NRPT rules of ours left" ((OurNrpt).Count -eq 0)
    Check "log written" ((Get-Content "$a\dvpn.log" -ErrorAction SilentlyContinue | Select-String "Service stopping").Count -ge 1)
    $acl = (Get-Acl "$a\config.toml").Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    Check "config.toml: no Users / Authenticated Users" (-not ($acl | Where-Object { $_ -in "S-1-5-32-545", "S-1-5-11", "S-1-1-0" }))
}
catch {
    Write-Host "FAIL $_"
    $script:failed++
}
finally {
    if (Get-Service dvpn -ErrorAction SilentlyContinue) { & "$a\dvpn.exe" --dir $a service uninstall 2>&1 | Out-Null }
    if ($bProc -and -not $bProc.HasExited) { Stop-Process -Id $bProc.Id -Force }
    if ($script:failed -gt 0) {
        Write-Host "--- a\dvpn.log"; Get-Content "$a\dvpn.log" -Tail 40 -ErrorAction SilentlyContinue
        Write-Host "--- b"; Get-Content "$root\b.log" -Tail 20 -ErrorAction SilentlyContinue
    }
    # leftovers of a failed run must not stay on the machine
    OurRoutes | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    OurNrpt | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    Start-Sleep 1
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}
if ($script:failed -gt 0) { Write-Host "$($script:failed) check(s) failed"; exit 1 }
Write-Host "all checks passed"
