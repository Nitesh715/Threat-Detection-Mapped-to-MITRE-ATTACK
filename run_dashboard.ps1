param(
    [int]$Port = 8765,
    [string]$Events = "",
    [string]$Rules = "",
    [string]$State = "",
    [ValidateSet("normalized", "wazuh")][string]$Format = "normalized"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$arguments = @("-m", "soc_lab.dashboard", "--port", "$Port", "--format", $Format)
if ($Events) { $arguments += @("--events", $Events) }
if ($Rules) { $arguments += @("--rules", $Rules) }
if ($State) { $arguments += @("--state", $State) }

python @arguments
exit $LASTEXITCODE
