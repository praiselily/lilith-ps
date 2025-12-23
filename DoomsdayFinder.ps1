Write-Host "`
⠀⠀⠀⠀⣶⣄⠀⠀⠀⠀⠀⠀⢀⣶⡆⠀⠀⠀
⠀⠀⠀⢸⣿⣿⡆⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀
⠀⠀⠀⠘⣿⣿⣿⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢿⣿⣿⣤⣤⣤⣤⣼⣿⡿⠃⠀⠀⠀
⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀
⠀⠀⢠⣿⡃⣦⢹⣿⣟⣙⣿⣿⠰⡀⣿⣇⠀⠀
⠠⠬⣿⣿⣷⣶⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⡭⠤      
⠀⣼⣿⣿⣿⣿⠿⠛⠛⠛⠛⠻⢿⣿⣿⣿⣿⡀
⢰⣿⣿⣿⠋⠀⠀⠀⢀⣀⠀⠀⠀⠉⢿⣿⣿⣧
⢸⣿⣿⠃⠜⠛⠂⠀⠋⠉⠃⠐⠛⠻⠄⢿⣿⣿
⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
⠘⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡏
⠀⠈⠻⠿⣤⣀⡀⠀⠀⠀⠀⠀⣀⣠⠾⠟⠋⠀            made with love by lily<3
`n" -ForegroundColor Cyan

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class PrefetchDecompressor {
    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat,
        byte[] UncompressedBuffer,
        int UncompressedBufferSize,
        byte[] CompressedBuffer,
        int CompressedBufferSize,
        out int FinalUncompressedSize,
        IntPtr WorkSpace
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormat,
        out uint CompressBufferWorkSpaceSize,
        out uint CompressFragmentWorkSpaceSize
    );
    
    public static byte[] DecompressPrefetch(byte[] compressed) {
        if (compressed.Length < 8) return null;
        if (compressed[0] != 0x4D || compressed[1] != 0x41 || compressed[2] != 0x4D) {
            return null;
        }
        
        int uncompSize = BitConverter.ToInt32(compressed, 4);
        
        uint wsComp, wsFrag;
        if (RtlGetCompressionWorkSpaceSize(4, out wsComp, out wsFrag) != 0) return null;
        
        IntPtr workspace = Marshal.AllocHGlobal((int)wsFrag);
        byte[] result = new byte[uncompSize];
        
        try {
            int finalSize;
            byte[] compData = new byte[compressed.Length - 8];
            Array.Copy(compressed, 8, compData, 0, compData.Length);
            
            uint status = RtlDecompressBufferEx(4, result, uncompSize, 
                compData, compData.Length, out finalSize, workspace);
            
            if (status != 0) return null;
            return result;
        }
        finally {
            Marshal.FreeHGlobal(workspace);
        }
    }
}
"@

function Get-PrefetchFormatVersion {
    param([byte[]]$prefetchData)
    
    if ($prefetchData.Length -lt 8) { return 0 }
    
    $signature = [System.Text.Encoding]::ASCII.GetString($prefetchData, 4, 4)
    if ($signature -ne "SCCA") { return 0 }
    
    $version = [BitConverter]::ToUInt32($prefetchData, 0)
    return $version
}

function Extract-PrefetchFilePaths {
    param([string]$PrefetchFilePath)
    
    try {
        $rawData = [System.IO.File]::ReadAllBytes($PrefetchFilePath)
        
        $isCompressed = ($rawData[0] -eq 0x4D -and $rawData[1] -eq 0x41 -and $rawData[2] -eq 0x4D)
        
        if ($isCompressed) {
            $rawData = [PrefetchDecompressor]::DecompressPrefetch($rawData)
            if ($rawData -eq $null) {
                return @()
            }
        }
        
        if ($rawData.Length -lt 108) {
            return @()
        }
        
        $version = Get-PrefetchFormatVersion -prefetchData $rawData
        
        $signature = [System.Text.Encoding]::ASCII.GetString($rawData, 4, 4)
        if ($signature -ne "SCCA") {
            return @()
        }
        
        $stringsOffset = 0
        $stringsSize = 0
        
        switch ($version) {
            17 { $stringsOffset = [BitConverter]::ToUInt32($rawData, 100); $stringsSize = [BitConverter]::ToUInt32($rawData, 104) }
            23 { $stringsOffset = [BitConverter]::ToUInt32($rawData, 100); $stringsSize = [BitConverter]::ToUInt32($rawData, 104) }
            26 { $stringsOffset = [BitConverter]::ToUInt32($rawData, 100); $stringsSize = [BitConverter]::ToUInt32($rawData, 104) }
            30 { $stringsOffset = [BitConverter]::ToUInt32($rawData, 100); $stringsSize = [BitConverter]::ToUInt32($rawData, 104) }
            31 { $stringsOffset = [BitConverter]::ToUInt32($rawData, 100); $stringsSize = [BitConverter]::ToUInt32($rawData, 104) }
            default { $stringsOffset = [BitConverter]::ToUInt32($rawData, 100); $stringsSize = [BitConverter]::ToUInt32($rawData, 104) }
        }
        
        if ($stringsOffset -eq 0 -or $stringsSize -eq 0) {
            return @()
        } 
        if ($stringsOffset -ge $rawData.Length -or ($stringsOffset + $stringsSize) -gt $rawData.Length) {
            return @()
        }
        $filePaths = @()
        $currentPosition = $stringsOffset
        $endPosition = $stringsOffset + $stringsSize
        
        while ($currentPosition -lt $endPosition -and $currentPosition -lt $rawData.Length - 2) {
            $nullTerminator = $currentPosition
            while ($nullTerminator -lt $rawData.Length - 1) {
                if ($rawData[$nullTerminator] -eq 0 -and $rawData[$nullTerminator + 1] -eq 0) {
                    break
                }
                $nullTerminator += 2
            }
            
            if ($nullTerminator -gt $currentPosition) {
                $stringLength = $nullTerminator - $currentPosition
                if ($stringLength -gt 0 -and $stringLength -lt 2048) {
                    try {
                        $filePath = [System.Text.Encoding]::Unicode.GetString($rawData, $currentPosition, $stringLength)
                        if ($filePath.Length -gt 0) {
                            $filePaths += $filePath
                        }
                    }
                    catch { }
                }
            }
            
            $currentPosition = $nullTerminator + 2
            
            if ($filePaths.Count -gt 1000) { break }
        }
        
        return $filePaths
    }
    catch {
        return @()
    }
}

$knownMaliciousBytePatterns = @(
    @{
        Name = "pattern1"
        HexBytes = "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800"
    },
    @{
        Name = "pattern2"
        HexBytes = "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16"
    },
    @{
        Name = "pattern3"
        HexBytes = "5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3"
    }
)
$suspiciousClassNames = @(
    "net/java/f",
    "net/java/g",
    "net/java/h",
    "net/java/i",
    "net/java/k",
    "net/java/l",
    "net/java/m",
    "net/java/r",
    "net/java/s",
    "net/java/t",
    "net/java/y"
)

function ConvertFrom-HexString {
    param([string]$HexString)
    
    $bytes = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Find-BytePattern {
    param(
        [byte[]]$DataToSearch,
        [byte[]]$PatternToFind
    )
    
    $patternLength = $PatternToFind.Length
    $dataLength = $DataToSearch.Length
    
    for ($i = 0; $i -le ($dataLength - $patternLength); $i++) {
        $isMatch = $true
        for ($j = 0; $j -lt $patternLength; $j++) {
            if ($DataToSearch[$i + $j] -ne $PatternToFind[$j]) {
                $isMatch = $false
                break
            }
        }
        if ($isMatch) {
            return $true
        }
    }
    return $false
}

function Find-ClassNameInBinary {
    param(
        [byte[]]$BinaryData,
        [string]$ClassName
    )
    
    $classBytes = [System.Text.Encoding]::ASCII.GetBytes($ClassName)
    return Find-BytePattern -DataToSearch $BinaryData -PatternToFind $classBytes
}

function Test-JarFileSignature {
    param([string]$FilePath)
    
    try {
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $reader = New-Object System.IO.BinaryReader($fileStream)
        
        if ($fileStream.Length -lt 2) {
            $reader.Close()
            $fileStream.Close()
            return $false
        }
        
        $firstByte = $reader.ReadByte()
        $secondByte = $reader.ReadByte()
        
        $reader.Close()
        $fileStream.Close()
        
        return ($firstByte -eq 0x50 -and $secondByte -eq 0x4B)
    } catch {
        return $false
    }
}

function Get-SingleLetterClassFiles {
    param([string]$JarFilePath)
    
    $singleLetterClasses = @()
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        
        $jarArchive = [System.IO.Compression.ZipFile]::OpenRead($JarFilePath)
        
        foreach ($fileEntry in $jarArchive.Entries) {
            if ($fileEntry.FullName -like "*.class") {
                $className = $fileEntry.FullName
                
                $pathParts = $className -split '/'
                $fileName = $pathParts[-1]
                
                $classNameOnly = $fileName -replace '\.class$', ''
                
                if ($classNameOnly -match '^[a-zA-Z]$') {
                    $fullPath = ($pathParts[0..($pathParts.Length-2)] -join '/') + '/' + $classNameOnly
                    $singleLetterClasses += $fullPath
                }
            }
        }
        
        $jarArchive.Dispose()
    } catch {
    }
    
    return $singleLetterClasses
}

function Analyze-JarFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    $analysisResult = [PSCustomObject]@{
        IsMalicious = $false
        FoundBytePatterns = @()
        FoundSuspiciousClasses = @()
        SingleLetterClassCount = 0
        HasSpoofedExtension = $false
        ErrorMessage = $null
    }
    
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        $analysisResult.ErrorMessage = "File not found"
        return $analysisResult
    }
    
    try {
        $fileExtension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        
        $hasJarSignature = Test-JarFileSignature -FilePath $FilePath
        
        if ($hasJarSignature -and $fileExtension -ne ".jar") {
            $analysisResult.HasSpoofedExtension = $true
            $analysisResult.IsMalicious = $true
        }
        
        if (-not $hasJarSignature) {
            $analysisResult.ErrorMessage = "File is not a valid JAR/ZIP archive"
            return $analysisResult
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        
        $jarFile = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        
        $classFiles = $jarFile.Entries | Where-Object { $_.FullName -like "*.class" }
        $totalClasses = $classFiles.Count
        
        if ($totalClasses -gt 30) {
            $jarFile.Dispose()
            $analysisResult.ErrorMessage = "Skipped: Too many classes"
            return $analysisResult
        }
        
        if ($totalClasses -eq 0) {
            $jarFile.Dispose()
            $analysisResult.ErrorMessage = "No Java class files found"
            return $analysisResult
        }
        
        $allClassBytes = @()
        
        foreach ($classEntry in $classFiles) {
            $classStream = $classEntry.Open()
            $byteReader = New-Object System.IO.BinaryReader($classStream)
            $classBytes = $byteReader.ReadBytes([int]$classEntry.Length)
            $allClassBytes += $classBytes
            $byteReader.Close()
            $classStream.Close()
        }
        
        $jarFile.Dispose()
        
        foreach ($pattern in $knownMaliciousBytePatterns) {
            $patternBytes = ConvertFrom-HexString -HexString $pattern.HexBytes
            
            if (Find-BytePattern -DataToSearch $allClassBytes -PatternToFind $patternBytes) {
                $analysisResult.FoundBytePatterns += $pattern.Name
                $analysisResult.IsMalicious = $true
            }
        }
        
        foreach ($className in $suspiciousClassNames) {
            if (Find-ClassNameInBinary -BinaryData $allClassBytes -ClassName $className) {
                $analysisResult.FoundSuspiciousClasses += $className
                $analysisResult.IsMalicious = $true
            }
        }
        
        $singleLetterClasses = Get-SingleLetterClassFiles -JarFilePath $FilePath
        $analysisResult.SingleLetterClassCount = $singleLetterClasses.Count
        
        if ($analysisResult.SingleLetterClassCount -ge 5) {
            $analysisResult.IsMalicious = $true
        }
    } catch {
        $analysisResult.ErrorMessage = $_.Exception.Message
    }
    
    return $analysisResult
}

try {
    $prefetchFolder = "C:\Windows\Prefetch"

    if (-not (Test-Path $prefetchFolder)) {
        Write-Host "Prefetch folder not found?" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit
    }

    $javaPrefetchFiles = Get-ChildItem -Path $prefetchFolder -Filter "JAVA*.EXE-*.pf" -ErrorAction SilentlyContinue

    if ($javaPrefetchFiles.Count -eq 0) {
        Write-Host "No JavaW prefetch files found" -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit
    }

    Write-Host "[+] Found $($javaPrefetchFiles.Count) javaw prefetch file(s)" -ForegroundColor Green
    Write-Host ""

    $allDiscoveredPaths = @()
    $pathMetadata = @{}
    $filesProcessed = 0

    foreach ($prefetchFile in $javaPrefetchFiles) {
        $filesProcessed++
        Write-Progress -Activity "Reading prefetch files" -Status "Processing" -PercentComplete (($filesProcessed / $javaPrefetchFiles.Count) * 100)
        
        $extractedPaths = Extract-PrefetchFilePaths -PrefetchFilePath $prefetchFile.FullName
        
        if ($extractedPaths.Count -eq 0) {
            continue
        }
        
        $pathNumber = 0
        foreach ($filePath in $extractedPaths) {
            $pathNumber++
            
            if ($filePath -match '\\VOLUME\{[^\}]+\}\\(.*)$') {
                $relativePath = $Matches[1]
                $assumedFullPath = "C:\$relativePath"
                $allDiscoveredPaths += $assumedFullPath
                
                if (-not $pathMetadata.ContainsKey($assumedFullPath)) {
                    $pathMetadata[$assumedFullPath] = @{
                        SourcePrefetch = $prefetchFile.Name
                        PathIndex = $pathNumber
                    }
                }
            }
            else {
                $allDiscoveredPaths += $filePath
                
                if (-not $pathMetadata.ContainsKey($filePath)) {
                    $pathMetadata[$filePath] = @{
                        SourcePrefetch = $prefetchFile.Name
                        PathIndex = $pathNumber
                    }
                }
            }
        }
    }

    Write-Progress -Activity "Reading prefetch files" -Completed

    $uniquePaths = $allDiscoveredPaths | Select-Object -Unique

    $existingFiles = @{}
    $allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | ForEach-Object { $_.Root.Substring(0, 1) }

    foreach ($path in $uniquePaths) {
        $actualLocation = $null
        
        if (Test-Path $path -PathType Leaf) {
            $actualLocation = $path
        }
        else {
            if ($path -match '^[A-Z]:\\(.*)$') {
                $relativePath = $Matches[1]
                
                foreach ($driveLetter in $allDrives) {
                    $alternativePath = "$driveLetter`:\$relativePath"
                    
                    if (Test-Path $alternativePath -PathType Leaf) {
                        $actualLocation = $alternativePath
                        break
                    }
                }
            }
        }
        
        if ($actualLocation) {
            try {
                $fileSize = (Get-Item $actualLocation -ErrorAction Stop).Length
                
                if ($fileSize -ge 200KB -and $fileSize -le 15MB) {
                    $existingFiles[$path] = $actualLocation
                }
            } catch {
            }
        }
    }

    if ($existingFiles.Count -eq 0) {
        Write-Host "[!] No files to analyze" -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit
    }

    $detectedMalware = @()
    $filesAnalyzed = 0

    foreach ($assumedPath in $existingFiles.Keys) {
        $actualFilePath = $existingFiles[$assumedPath]
        $filesAnalyzed++
        
        Write-Progress -Activity "Analyzing files" -Status "Processing" -PercentComplete (($filesAnalyzed / $existingFiles.Count) * 100)
        
        try {
            $analysis = Analyze-JarFile -FilePath $actualFilePath
            
            if ($analysis.IsMalicious) {
                $detectedMalware += [PSCustomObject]@{
                    FilePath = $actualFilePath
                    PrefetchSource = $pathMetadata[$assumedPath].SourcePrefetch
                }
            }
        }
        catch {
        }
    }

    Write-Progress -Activity "Analyzing files" -Completed
    Write-Host ""

    if ($detectedMalware.Count -gt 0) {
        Write-Host "DOOMSDAY CLIENT FOUND!" -ForegroundColor Cyan
        Write-Host "    Found $($detectedMalware.Count) Instance(s)" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($detection in $detectedMalware) {
            Write-Host "    $($detection.FilePath)" -ForegroundColor Red
        }
    } else {
        Write-Host "No Doomsday Client found" -ForegroundColor Green
    }

    Write-Host ""
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

Read-Host "Press Enter to exit"
