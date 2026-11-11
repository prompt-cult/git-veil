[CmdletBinding()]
param(
    [string]$Source = "",
    [string]$AssetDirectory = "",
    [string]$InstallerIcon = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Source) { $Source = Join-Path $root "docs\src\assets\logo@2x.png" }
if (-not $AssetDirectory) { $AssetDirectory = Join-Path $root "docs\src\assets" }
if (-not $InstallerIcon) { $InstallerIcon = Join-Path $root "installer\git-veil.ico" }

New-Item -ItemType Directory -Force -Path $AssetDirectory | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $InstallerIcon) | Out-Null

function Save-ResizedPng {
    param([System.Drawing.Image]$Image, [string]$Path, [int]$Width, [int]$Height)

    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.Clear([System.Drawing.Color]::Transparent)

        $scale = [Math]::Min($Width / $Image.Width, $Height / $Image.Height)
        $drawWidth = [int][Math]::Round($Image.Width * $scale)
        $drawHeight = [int][Math]::Round($Image.Height * $scale)
        $x = [int][Math]::Floor(($Width - $drawWidth) / 2)
        $y = [int][Math]::Floor(($Height - $drawHeight) / 2)
        $graphics.DrawImage($Image, [Drawing.Rectangle]::new($x, $y, $drawWidth, $drawHeight))
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function New-IcoFromPngs {
    param([string[]]$Paths, [string]$Path)

    $pngs = @($Paths | ForEach-Object { [IO.File]::ReadAllBytes($_) })
    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)
    try {
        $writer.Write([UInt16]0)
        $writer.Write([UInt16]1)
        $writer.Write([UInt16]$pngs.Count)
        $offset = 6 + (16 * $pngs.Count)
        for ($i = 0; $i -lt $pngs.Count; $i++) {
            $size = [int]([regex]::Match($Paths[$i], 'shield-(\d+)\.png$').Groups[1].Value)
            $dimension = if ($size -ge 256) { 0 } else { $size }
            $writer.Write([byte]$dimension)
            $writer.Write([byte]$dimension)
            $writer.Write([byte]0)
            $writer.Write([byte]0)
            $writer.Write([UInt16]1)
            $writer.Write([UInt16]32)
            $writer.Write([UInt32]$pngs[$i].Length)
            $writer.Write([UInt32]$offset)
            $offset += $pngs[$i].Length
        }
        foreach ($png in $pngs) { $writer.Write($png) }
        [IO.File]::WriteAllBytes($Path, $stream.ToArray())
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

$sourceImage = [Drawing.Bitmap]::new($Source)
try {
    Save-ResizedPng $sourceImage (Join-Path $AssetDirectory "logo.png") 1086 362
    Save-ResizedPng $sourceImage (Join-Path $AssetDirectory "logo-small.png") 543 181

    $minX = $sourceImage.Width
    $minY = $sourceImage.Height
    $maxX = 0
    $maxY = 0
    for ($y = 0; $y -lt $sourceImage.Height; $y++) {
        for ($x = 0; $x -lt [Math]::Min(640, $sourceImage.Width); $x++) {
            if ($sourceImage.GetPixel($x, $y).A -gt 0) {
                $minX = [Math]::Min($minX, $x)
                $minY = [Math]::Min($minY, $y)
                $maxX = [Math]::Max($maxX, $x)
                $maxY = [Math]::Max($maxY, $y)
            }
        }
    }
    $shield = $sourceImage.Clone(
        [Drawing.Rectangle]::new($minX, $minY, $maxX - $minX + 1, $maxY - $minY + 1),
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $iconSizes = @(16, 32, 48, 64, 128, 256)
        $iconPngs = foreach ($size in $iconSizes) {
            $path = Join-Path $AssetDirectory "shield-$size.png"
            Save-ResizedPng $shield $path $size $size
            $path
        }
        Copy-Item (Join-Path $AssetDirectory "shield-512.png") (Join-Path $AssetDirectory "favicon.png") -ErrorAction SilentlyContinue
        Save-ResizedPng $shield (Join-Path $AssetDirectory "shield-512.png") 512 512
        Copy-Item (Join-Path $AssetDirectory "shield-512.png") (Join-Path $AssetDirectory "favicon.png") -Force
        New-IcoFromPngs $iconPngs $InstallerIcon
    } finally {
        $shield.Dispose()
    }
} finally {
    $sourceImage.Dispose()
}

Write-Host "Generated logo and shield assets in $AssetDirectory"
Write-Host "Generated installer icon at $InstallerIcon"
