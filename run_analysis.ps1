param(
    [string]$Events = "soc_lab/assets/sample_events.jsonl",
    [string]$Output = "reports/demo",
    [string]$Rules = "",
    [ValidateSet("normalized", "wazuh")][string]$Format = "normalized"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$arguments = @("-m", "soc_lab.cli", $Events, "--out", $Output, "--format", $Format)
if ($Rules) { $arguments += @("--rules", $Rules) }

python @arguments
exit $LASTEXITCODE
