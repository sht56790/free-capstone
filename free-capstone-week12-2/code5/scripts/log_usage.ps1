param(
    [string]$ProcessName = "ollama",
    [string]$LogPath = "D:\김나현\나현\proxy\code4\logs\usage.csv",
    [int]$IntervalSeconds = 5
)

New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
"timestamp,cpu_seconds,pm_bytes,ws_bytes" | Out-File $LogPath -Encoding UTF8

Write-Host "Logging process '$ProcessName' usage to $LogPath (interval: $IntervalSeconds sec). Press Ctrl+C to stop."
while ($true) {
    $proc = Get-Process $ProcessName -ErrorAction SilentlyContinue
    if ($proc) {
        "{0},{1},{2},{3}" -f (Get-Date -Format s), $proc.CPU, $proc.PM, $proc.WS | Add-Content $LogPath
    } else {
        "{0},NA,NA,NA" -f (Get-Date -Format s) | Add-Content $LogPath
    }
    Start-Sleep $IntervalSeconds
}

