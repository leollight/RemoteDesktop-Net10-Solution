<#
.SYNOPSIS
    Developer-only helper for building and running the local ASP.NET Core backend during development.
    End-user Windows Host and Controller machines do not need this script or the .NET SDK.
#>
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Development", "Production")]
    [string]$EnvironmentName = "Development"
)

$ErrorActionPreference = "Stop"
$env:ASPNETCORE_ENVIRONMENT = $EnvironmentName

Write-Host "Building RemoteDesktop.sln..."
dotnet build ..\..\RemoteDesktop.sln --configuration Debug

Write-Host "Starting RemoteDesktop.Backend ($EnvironmentName profile)..."
dotnet run --project ..\..\src\RemoteDesktop.Backend\RemoteDesktop.Backend.csproj
