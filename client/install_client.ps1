# B-Server 客户端 Windows 安装脚本
# 使用方法: 
# 方法1(推荐): powershell -ExecutionPolicy Bypass -Command "iwr -Uri 'https://raw.githubusercontent.com/wanghui5801/B-server/refs/heads/main/client/install_client.ps1' -UseBasicParsing | iex; Install-BServerClient -ServerIP '192.168.1.100' -NodeName 'MyServer'"
# 方法2: .\install_client.ps1 -ServerIP "192.168.1.100" -NodeName "MyServer"

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerIP,
    
    [Parameter(Mandatory=$false)]
    [string]$NodeName = $env:COMPUTERNAME
)

# 设置控制台编码为UTF-8
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
    # 忽略编码设置错误
}

# 颜色输出函数
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    switch ($Color) {
        "Red" { Write-Host $Message -ForegroundColor Red }
        "Green" { Write-Host $Message -ForegroundColor Green }
        "Yellow" { Write-Host $Message -ForegroundColor Yellow }
        "Blue" { Write-Host $Message -ForegroundColor Blue }
        default { Write-Host $Message }
    }
}

function Install-BServerClient {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerIP,
        
        [Parameter(Mandatory=$false)]
        [string]$NodeName = $env:COMPUTERNAME
    )

    # 验证参数
    if ([string]::IsNullOrWhiteSpace($ServerIP)) {
        Write-ColorOutput "[ERROR] ServerIP parameter is null or empty" "Red"
        exit 1
    }
    
    if ([string]::IsNullOrWhiteSpace($NodeName)) {
        $NodeName = $env:COMPUTERNAME
    }

    Write-ColorOutput "[INFO] Starting B-Server client installation..." "Blue"
    Write-ColorOutput "[INFO] Server address: ${ServerIP}:3001" "Blue"
    Write-ColorOutput "[INFO] Node name: ${NodeName}" "Blue"
    Write-ColorOutput "[DEBUG] Raw ServerIP: '${ServerIP}'" "Yellow"
    Write-ColorOutput "[DEBUG] Raw NodeName: '${NodeName}'" "Yellow"

    # Configuration variables
    $ClientDir = Join-Path $env:USERPROFILE "b-server-client"
    $ClientFile = Join-Path $ClientDir "client.py"
    $ClientURL = "https://raw.githubusercontent.com/wanghui5801/B-server/refs/heads/main/client/client.py"

    Write-ColorOutput "[INFO] Installation directory: $ClientDir" "Blue"

    # Check system dependencies
    Write-ColorOutput "[INFO] Checking system dependencies..." "Blue"

    # Check Python
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python not found"
        }
        Write-ColorOutput "[SUCCESS] Python installed: $pythonVersion" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] Python not installed, please install Python 3.7+" "Red"
        Write-ColorOutput "[INFO] Download from: https://www.python.org/downloads/" "Yellow"
        exit 1
    }

    # Check pip
    try {
        $pipVersion = pip --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "pip not found"
        }
        Write-ColorOutput "[SUCCESS] pip installed: $pipVersion" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] pip not installed, please ensure Python is correctly installed" "Red"
        exit 1
    }

    # Create installation directory
    Write-ColorOutput "[INFO] Creating installation directory..." "Blue"
    if (!(Test-Path -Path $ClientDir)) {
        New-Item -ItemType Directory -Path $ClientDir -Force | Out-Null
    }
    Set-Location -Path $ClientDir

    # Download client file
    Write-ColorOutput "[INFO] Downloading client file..." "Blue"
    try {
        Invoke-WebRequest -Uri $ClientURL -OutFile "client.py" -UseBasicParsing
        if (!(Test-Path -Path "client.py")) {
            throw "Download failed"
        }
        Write-ColorOutput "[SUCCESS] Client file downloaded successfully" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] Client file download failed: $($_.Exception.Message)" "Red"
        exit 1
    }

    # Modify client configuration
    Write-ColorOutput "[INFO] Modifying client configuration..." "Blue"
    
    try {
        $content = Get-Content -Path "client.py" -Raw -Encoding UTF8
        
        # 修改SERVER_URL - 使用变量展开
        $newServerUrl = "SERVER_URL = 'http://$ServerIP:3001'"
        $content = $content -replace "SERVER_URL = 'http://localhost:3001'", $newServerUrl
        
        # 修改NODE_NAME - 使用变量展开
        $newNodeName = "NODE_NAME = '$NodeName'"
        $content = $content -replace "NODE_NAME = socket\.gethostname\(\)", $newNodeName
        
        Set-Content -Path "client.py" -Value $content -Encoding UTF8
        
        # 验证修改是否成功
        $verifyContent = Get-Content -Path "client.py" -Raw -Encoding UTF8
        
        # 检查SERVER_URL是否修改成功
        $expectedServerUrl = "SERVER_URL = 'http://${ServerIP}:3001'"
        $serverUrlFound = $verifyContent.Contains($expectedServerUrl)
        
        # 检查NODE_NAME是否修改成功
        $expectedNodeName = "NODE_NAME = '${NodeName}'"
        $nodeNameFound = $verifyContent.Contains($expectedNodeName)
        
        Write-ColorOutput "[DEBUG] Expected Server URL: $expectedServerUrl" "Yellow"
        Write-ColorOutput "[DEBUG] Server URL found: $serverUrlFound" "Yellow"
        Write-ColorOutput "[DEBUG] Expected Node Name: $expectedNodeName" "Yellow"
        Write-ColorOutput "[DEBUG] Node Name found: $nodeNameFound" "Yellow"
        
        if ($serverUrlFound -and $nodeNameFound) {
            Write-ColorOutput "[SUCCESS] Client configuration modified successfully" "Green"
            Write-ColorOutput "[INFO] Server URL: http://${ServerIP}:3001" "Blue"
            Write-ColorOutput "[INFO] Node Name: ${NodeName}" "Blue"
        } else {
            # 显示实际的配置内容用于调试
            $relevantLines = $verifyContent -split "`n" | Where-Object { $_ -match "SERVER_URL|NODE_NAME" } | Select-Object -First 10
            Write-ColorOutput "[DEBUG] Actual configuration lines:" "Yellow"
            foreach ($line in $relevantLines) {
                Write-ColorOutput "[DEBUG] $line" "Yellow"
            }
            throw "Configuration verification failed - Expected patterns not found"
        }
    }
    catch {
        Write-ColorOutput "[ERROR] Configuration file modification failed: $($_.Exception.Message)" "Red"
        Write-ColorOutput "[DEBUG] ServerIP: '${ServerIP}'" "Yellow"
        Write-ColorOutput "[DEBUG] NodeName: '${NodeName}'" "Yellow"
        
        # 显示文件的前几行用于调试
        try {
            $filePreview = Get-Content -Path "client.py" -TotalCount 20 -Encoding UTF8
            Write-ColorOutput "[DEBUG] First 20 lines of client.py:" "Yellow"
            for ($i = 0; $i -lt $filePreview.Length; $i++) {
                Write-ColorOutput "[DEBUG] $($i+1): $($filePreview[$i])" "Yellow"
            }
        } catch {
            Write-ColorOutput "[DEBUG] Could not read client.py for debugging" "Yellow"
        }
        exit 1
    }

    # Create Python virtual environment
    Write-ColorOutput "[INFO] Creating Python virtual environment..." "Blue"
    try {
        python -m venv venv
        if ($LASTEXITCODE -ne 0) {
            throw "Virtual environment creation failed"
        }
        Write-ColorOutput "[SUCCESS] Virtual environment created successfully" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] Virtual environment creation failed: $($_.Exception.Message)" "Red"
        exit 1
    }

    # Activate virtual environment and install dependencies
    Write-ColorOutput "[INFO] Installing Python dependencies..." "Blue"
    try {
        & ".\venv\Scripts\python.exe" -m pip install --upgrade pip
        & ".\venv\Scripts\python.exe" -m pip install psutil python-socketio requests tcping "python-socketio[client]"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Package installation failed"
        }
        Write-ColorOutput "[SUCCESS] Python dependencies installed successfully" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] Dependencies installation failed: $($_.Exception.Message)" "Red"
        exit 1
    }

    # Create startup scripts
    Write-ColorOutput "[INFO] Creating management scripts..." "Blue"
    
    # 启动脚本 - 带详细错误信息
    $startScript = @"
@echo off
cd /d "%~dp0"
echo Starting B-Server Client...
echo Server: ${ServerIP}:3001
echo Node: ${NodeName}
echo.
venv\Scripts\python.exe client.py
if errorlevel 1 (
    echo.
    echo [ERROR] Client failed to start. Error code: %errorlevel%
    echo Check the following:
    echo 1. Server ${ServerIP}:3001 is accessible
    echo 2. Node '${NodeName}' is added in admin panel
    echo 3. Firewall allows outbound connections to port 3001
    echo.
)
pause
"@
    Set-Content -Path "start.bat" -Value $startScript -Encoding UTF8

    # 后台启动脚本 - 修复并添加错误检查
    $startBackgroundScript = @"
@echo off
cd /d "%~dp0"
echo Starting B-Server Client in background...
echo Server: ${ServerIP}:3001
echo Node: ${NodeName}
echo.

REM 先停止现有进程
taskkill /f /im python.exe /fi "COMMANDLINE eq *client.py*" 2>nul
taskkill /f /im pythonw.exe /fi "COMMANDLINE eq *client.py*" 2>nul

REM 启动新进程
start /min cmd /c "venv\Scripts\pythonw.exe client.py"

REM 等待进程启动
timeout /t 2 /nobreak >nul

REM 检查是否启动成功
tasklist /fi "IMAGENAME eq pythonw.exe" 2>nul | find "pythonw.exe" >nul
if %errorlevel%==0 (
    echo B-Server Client started successfully in background
) else (
    echo [ERROR] Failed to start client in background
    echo Try running start.bat to see detailed error messages
)
echo.
"@
    Set-Content -Path "start_background.bat" -Value $startBackgroundScript -Encoding UTF8

    # 停止脚本
    $stopScript = @"
@echo off
echo Stopping B-Server Client...
taskkill /f /im python.exe /fi "WINDOWTITLE eq B-Server Client" 2>nul
taskkill /f /im pythonw.exe /fi "COMMANDLINE eq *client.py*" 2>nul
echo B-Server Client stopped
pause
"@
    Set-Content -Path "stop.bat" -Value $stopScript -Encoding UTF8

    # 状态检查脚本 - 增强版
    $statusScript = @"
@echo off
echo ========================================
echo B-Server Client Status Check
echo ========================================
echo Server: ${ServerIP}:3001
echo Node: ${NodeName}
echo Installation: %~dp0
echo.
echo Checking processes...
tasklist /fi "IMAGENAME eq python.exe" 2>nul | find "python.exe" >nul
if %errorlevel%==0 (
    echo [STATUS] B-Server Client is running (foreground)
    tasklist /fi "IMAGENAME eq python.exe" 2>nul
) else (
    tasklist /fi "IMAGENAME eq pythonw.exe" 2>nul | find "pythonw.exe" >nul
    if %errorlevel%==0 (
        echo [STATUS] B-Server Client is running (background)
        tasklist /fi "IMAGENAME eq pythonw.exe" 2>nul
    ) else (
        echo [STATUS] B-Server Client is not running
        echo.
        echo To start the client:
        echo   Foreground: start.bat
        echo   Background: start_background.bat
        echo.
        echo To troubleshoot:
        echo   1. Run start.bat to see error messages
        echo   2. Check if server ${ServerIP}:3001 is accessible
        echo   3. Ensure node '${NodeName}' exists in admin panel
    )
)
echo.
pause
"@
    Set-Content -Path "status.bat" -Value $statusScript -Encoding UTF8

    # 调试脚本 - 新增
    $debugScript = @"
@echo off
cd /d "%~dp0"
echo ========================================
echo B-Server Client Debug Information
echo ========================================
echo Server: ${ServerIP}:3001
echo Node: ${NodeName}
echo Installation: %~dp0
echo Time: %date% %time%
echo.

echo [1] Testing Python environment...
venv\Scripts\python.exe --version
if errorlevel 1 (
    echo [ERROR] Python environment not working
    goto :end
)

echo [2] Testing Python modules...
venv\Scripts\python.exe -c "import sys, psutil, socketio, requests; print('All modules imported successfully')"
if errorlevel 1 (
    echo [ERROR] Python modules missing or broken
    echo Try reinstalling: venv\Scripts\python.exe -m pip install psutil python-socketio requests tcping
    goto :end
)

echo [3] Testing network connectivity...
ping -n 1 ${ServerIP} >nul
if errorlevel 1 (
    echo [ERROR] Cannot reach server ${ServerIP}
    echo Check network connection and firewall
    goto :end
) else (
    echo Server ${ServerIP} is reachable
)

echo [4] Testing client configuration...
venv\Scripts\python.exe -c "exec(open('client.py').read().split('if __name__')[0]); print(f'SERVER_URL: {SERVER_URL}'); print(f'NODE_NAME: {NODE_NAME}')"
if errorlevel 1 (
    echo [ERROR] Client configuration error
    goto :end
)

echo [5] Starting client with verbose output...
echo Press Ctrl+C to stop
venv\Scripts\python.exe client.py

:end
pause
"@
    Set-Content -Path "debug.bat" -Value $debugScript -Encoding UTF8

    # 更新脚本 - 使用字符串格式化避免变量插值问题
    $updateScript = @"
@echo off
cd /d "%~dp0"
echo Stopping client...
taskkill /f /im python.exe /fi "COMMANDLINE eq *client.py*" 2>nul
taskkill /f /im pythonw.exe /fi "COMMANDLINE eq *client.py*" 2>nul

echo Downloading latest client...
powershell -Command "Invoke-WebRequest -Uri '{0}' -OutFile 'client.py.new' -UseBasicParsing"

if exist client.py.new (
    echo Updating configuration...
    powershell -Command "(Get-Content 'client.py.new') -replace \"SERVER_URL = 'http://localhost:3001'\", \"SERVER_URL = 'http://{1}:3001'\" -replace \"NODE_NAME = socket\.gethostname\(\)\", \"NODE_NAME = '{2}'\" | Set-Content 'client.py.new'"
    
    move client.py client.py.backup
    move client.py.new client.py
    echo Client updated successfully
) else (
    echo Download failed
)
pause
"@ -f $ClientURL, $ServerIP, $NodeName
    Set-Content -Path "update.bat" -Value $updateScript -Encoding UTF8

    Write-ColorOutput "[SUCCESS] Management scripts created successfully" "Green"

    # 创建Windows服务脚本（可选）
    $serviceScript = @"
# Windows Service Installation Script
# Run as Administrator

`$serviceName = "BServerClient"
`$serviceDisplayName = "B-Server Monitoring Client"
`$servicePath = Join-Path (Get-Location) "venv\Scripts\pythonw.exe"
`$serviceArgs = Join-Path (Get-Location) "client.py"

# Install service using NSSM (Non-Sucking Service Manager)
# Download NSSM from: https://nssm.cc/download

Write-Host "To install as Windows Service:"
Write-Host "1. Download NSSM from https://nssm.cc/download"
Write-Host "2. Extract nssm.exe to this directory"
Write-Host "3. Run as Administrator: .\nssm.exe install `$serviceName `$servicePath `$serviceArgs"
Write-Host "4. Run: .\nssm.exe start `$serviceName"
"@
    Set-Content -Path "install_service.ps1" -Value $serviceScript -Encoding UTF8

    Write-ColorOutput "[SUCCESS] Management scripts created successfully" "Green"

    # Test client configuration
    Write-ColorOutput "[INFO] Testing client configuration..." "Blue"
    try {
        # Create test script dynamically to avoid variable interpolation issues
        $testContent = @"
import sys, os
sys.path.insert(0, os.getcwd())
try:
    import socket, psutil, socketio, requests
    print('[SUCCESS] All dependency modules imported successfully')
except ImportError as e:
    print(f'[ERROR] Dependency module import failed: {e}')
    sys.exit(1)

# Check configuration
with open('client.py', 'r', encoding='utf-8') as f:
    content = f.read()
    if 'http://{0}:3001' in content:
        print('[SUCCESS] Server address configured correctly')
    else:
        print('[ERROR] Server address configuration error')
        sys.exit(1)
    
    if "NODE_NAME = '{1}'" in content:
        print('[SUCCESS] Node name configured correctly')
    else:
        print('[ERROR] Node name configuration error')
        sys.exit(1)

print('[SUCCESS] Client configuration test passed')
"@ -f $ServerIP, $NodeName

        $testResult = & ".\venv\Scripts\python.exe" -c $testContent

        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "[SUCCESS] Client configuration test passed" "Green"
        } else {
            throw "Configuration test failed"
        }
    }
    catch {
        Write-ColorOutput "[ERROR] Client configuration test failed" "Red"
        Write-ColorOutput "[INFO] Continuing with installation..." "Yellow"
        # Don't exit due to test failure, continue installation process
    }

    # Display installation completion information
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-ColorOutput "[SUCCESS] B-Server client installation completed!" "Green"
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-ColorOutput "Installation Information:" "Blue"
    Write-Host "  Installation Directory: $ClientDir"
    Write-Host "  Server Address: ${ServerIP}:3001"
    Write-Host "  Node Name: ${NodeName}"
    Write-Host ""
    Write-ColorOutput "Management Commands:" "Blue"
    Write-Host "  Start Client: .\start.bat"
    Write-Host "  Start in Background: .\start_background.bat"
    Write-Host "  Check Status: .\status.bat"
    Write-Host "  Stop Client: .\stop.bat"
    Write-Host "  Update Client: .\update.bat"
    Write-Host "  Debug Client: .\debug.bat"
    Write-Host ""
    Write-ColorOutput "Important Notes:" "Yellow"
    Write-Host "  1. Please ensure node '$NodeName' is added in server admin panel"
    Write-Host "  2. Please ensure server firewall allows port 3001 access"
    Write-Host "  3. First run may require firewall permission"
    Write-Host "  4. For auto-start on boot, refer to install_service.ps1"
    Write-Host ""
    Write-ColorOutput "Troubleshooting:" "Yellow"
    Write-Host "  - If client won't start, run debug.bat for detailed diagnostics"
    Write-Host "  - If connection fails, check server IP and firewall settings"
    Write-Host "  - If node not found, add '$NodeName' in server admin panel first"
    Write-Host ""
    
    # Ask whether to start immediately
    $choice = Read-Host "Start client immediately? (Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        Write-ColorOutput "[INFO] Starting B-Server client..." "Blue"
        Write-Host "Starting client in background..."
        & ".\start_background.bat"
        Start-Sleep -Seconds 3
        Write-Host ""
        Write-ColorOutput "[INFO] Checking status..." "Blue"
        & ".\status.bat"
    } else {
        Write-ColorOutput "[INFO] To start later, run: .\start_background.bat" "Blue"
        Write-ColorOutput "[INFO] For troubleshooting, run: .\debug.bat" "Blue"
    }
    
    Write-ColorOutput "[INFO] Installation completed!" "Green"
}

# 主逻辑：处理直接运行脚本的情况
# 只有在直接运行脚本文件（而不是通过iex执行）时才检查参数
if ($MyInvocation.InvocationName -match '\.ps1$') {
    # 这是直接运行脚本文件的情况
    if (-not $ServerIP -or -not $NodeName) {
        Write-ColorOutput "[ERROR] Missing required parameters" "Red"
        Write-ColorOutput "[INFO] Usage:" "Blue"
        Write-Host "  Local run: .\install_client.ps1 -ServerIP '<ServerIP>' -NodeName '<NodeName>'"
        Write-Host "  One-click: powershell -ExecutionPolicy Bypass -Command `"iwr -Uri 'https://raw.githubusercontent.com/wanghui5801/B-server/refs/heads/main/client/install_client.ps1' -UseBasicParsing | iex; Install-BServerClient -ServerIP '<ServerIP>' -NodeName '<NodeName>'`""
        Write-Host ""
        Write-ColorOutput "[INFO] Examples:" "Blue"
        Write-Host "  .\install_client.ps1 -ServerIP '192.168.1.100' -NodeName 'MyServer'"
        Write-Host "  powershell -ExecutionPolicy Bypass -Command `"iwr -Uri 'https://raw.githubusercontent.com/wanghui5801/B-server/refs/heads/main/client/install_client.ps1' -UseBasicParsing | iex; Install-BServerClient -ServerIP '192.168.1.100' -NodeName 'MyServer'`""
        exit 1
    } else {
        # 直接运行脚本且参数正确，调用安装函数
        Install-BServerClient -ServerIP $ServerIP -NodeName $NodeName
    }
}

# 注意：一键命令通过iex执行脚本内容，然后直接调用 Install-BServerClient 函数
# 这种情况下不会进入上面的条件分支 