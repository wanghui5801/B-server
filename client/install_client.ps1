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

    Write-ColorOutput "[INFO] 开始安装 B-Server 客户端..." "Blue"
    Write-ColorOutput "[INFO] 服务器地址: $ServerIP:3001" "Blue"
    Write-ColorOutput "[INFO] 节点名称: $NodeName" "Blue"

    # 配置变量
    $ClientDir = Join-Path $env:USERPROFILE "b-server-client"
    $ClientFile = Join-Path $ClientDir "client.py"
    $ClientURL = "https://raw.githubusercontent.com/wanghui5801/B-server/refs/heads/main/client/client.py"

    Write-ColorOutput "[INFO] 安装目录: $ClientDir" "Blue"

    # 检查系统依赖
    Write-ColorOutput "[INFO] 检查系统依赖..." "Blue"

    # 检查Python
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python not found"
        }
        Write-ColorOutput "[SUCCESS] Python 已安装: $pythonVersion" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] Python 未安装，请先安装 Python 3.7+" "Red"
        Write-ColorOutput "[INFO] 下载地址: https://www.python.org/downloads/" "Yellow"
        exit 1
    }

    # 检查pip
    try {
        $pipVersion = pip --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "pip not found"
        }
        Write-ColorOutput "[SUCCESS] pip 已安装: $pipVersion" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] pip 未安装，请确保 Python 正确安装" "Red"
        exit 1
    }

    # 创建安装目录
    Write-ColorOutput "[INFO] 创建安装目录..." "Blue"
    if (!(Test-Path -Path $ClientDir)) {
        New-Item -ItemType Directory -Path $ClientDir -Force | Out-Null
    }
    Set-Location -Path $ClientDir

    # 下载客户端文件
    Write-ColorOutput "[INFO] 下载客户端文件..." "Blue"
    try {
        Invoke-WebRequest -Uri $ClientURL -OutFile "client.py" -UseBasicParsing
        if (!(Test-Path -Path "client.py")) {
            throw "Download failed"
        }
        Write-ColorOutput "[SUCCESS] 客户端文件下载完成" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] 客户端文件下载失败: $($_.Exception.Message)" "Red"
        exit 1
    }

    # 修改客户端配置
    Write-ColorOutput "[INFO] 修改客户端配置..." "Blue"
    
    try {
        $content = Get-Content -Path "client.py" -Raw
        
        # 修改SERVER_URL
        $content = $content -replace "SERVER_URL = 'http://localhost:3001'", "SERVER_URL = 'http://$ServerIP:3001'"
        
        # 修改NODE_NAME
        $content = $content -replace "NODE_NAME = socket\.gethostname\(\)", "NODE_NAME = '$NodeName'"
        
        Set-Content -Path "client.py" -Value $content -Encoding UTF8
        Write-ColorOutput "[SUCCESS] 客户端配置修改完成" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] 配置文件修改失败: $($_.Exception.Message)" "Red"
        exit 1
    }

    # 创建Python虚拟环境
    Write-ColorOutput "[INFO] 创建Python虚拟环境..." "Blue"
    try {
        python -m venv venv
        if ($LASTEXITCODE -ne 0) {
            throw "Virtual environment creation failed"
        }
        Write-ColorOutput "[SUCCESS] 虚拟环境创建完成" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] 虚拟环境创建失败: $($_.Exception.Message)" "Red"
        exit 1
    }

    # 激活虚拟环境并安装依赖
    Write-ColorOutput "[INFO] 安装Python依赖..." "Blue"
    try {
        & ".\venv\Scripts\python.exe" -m pip install --upgrade pip
        & ".\venv\Scripts\python.exe" -m pip install psutil python-socketio requests tcping "python-socketio[client]"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Package installation failed"
        }
        Write-ColorOutput "[SUCCESS] Python依赖安装完成" "Green"
    }
    catch {
        Write-ColorOutput "[ERROR] 依赖安装失败: $($_.Exception.Message)" "Red"
        exit 1
    }

    # 创建启动脚本
    Write-ColorOutput "[INFO] 创建管理脚本..." "Blue"
    
    # 启动脚本
    $startScript = @"
@echo off
cd /d "%~dp0"
echo Starting B-Server Client...
venv\Scripts\python.exe client.py
pause
"@
    Set-Content -Path "start.bat" -Value $startScript -Encoding UTF8

    # 后台启动脚本
    $startBackgroundScript = @"
@echo off
cd /d "%~dp0"
echo Starting B-Server Client in background...
start /min venv\Scripts\pythonw.exe client.py
echo B-Server Client started in background
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

    # 状态检查脚本
    $statusScript = @"
@echo off
echo Checking B-Server Client status...
tasklist /fi "IMAGENAME eq python.exe" /fi "COMMANDLINE eq *client.py*" 2>nul | find "python.exe" >nul
if %errorlevel%==0 (
    echo B-Server Client is running
) else (
    tasklist /fi "IMAGENAME eq pythonw.exe" /fi "COMMANDLINE eq *client.py*" 2>nul | find "pythonw.exe" >nul
    if %errorlevel%==0 (
        echo B-Server Client is running in background
    ) else (
        echo B-Server Client is not running
    )
)
pause
"@
    Set-Content -Path "status.bat" -Value $statusScript -Encoding UTF8

    # 更新脚本
    $updateScript = @"
@echo off
cd /d "%~dp0"
echo Stopping client...
taskkill /f /im python.exe /fi "COMMANDLINE eq *client.py*" 2>nul
taskkill /f /im pythonw.exe /fi "COMMANDLINE eq *client.py*" 2>nul

echo Downloading latest client...
powershell -Command "Invoke-WebRequest -Uri '$ClientURL' -OutFile 'client.py.new' -UseBasicParsing"

if exist client.py.new (
    echo Updating configuration...
    powershell -Command "(Get-Content 'client.py.new') -replace \"SERVER_URL = 'http://localhost:3001'\", \"SERVER_URL = 'http://$ServerIP:3001'\" -replace \"NODE_NAME = socket\.gethostname\(\)\", \"NODE_NAME = '$NodeName'\" | Set-Content 'client.py.new'"
    
    move client.py client.py.backup
    move client.py.new client.py
    echo Client updated successfully
) else (
    echo Download failed
)
pause
"@
    Set-Content -Path "update.bat" -Value $updateScript -Encoding UTF8

    Write-ColorOutput "[SUCCESS] 管理脚本创建完成" "Green"

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

    # 测试客户端配置
    Write-ColorOutput "[INFO] 测试客户端配置..." "Blue"
    try {
        $testResult = & ".\venv\Scripts\python.exe" -c @"
import sys, os
sys.path.insert(0, os.getcwd())
try:
    import socket, psutil, socketio, requests
    print('✓ 所有依赖模块导入成功')
except ImportError as e:
    print(f'✗ 依赖模块导入失败: {e}')
    sys.exit(1)

# 检查配置
with open('client.py', 'r', encoding='utf-8') as f:
    content = f.read()
    if 'http://$ServerIP:3001' in content:
        print('✓ 服务器地址配置正确')
    else:
        print('✗ 服务器地址配置错误')
        sys.exit(1)
    
    if "NODE_NAME = '$NodeName'" in content:
        print('✓ 节点名称配置正确')
    else:
        print('✗ 节点名称配置错误')
        sys.exit(1)

print('✓ 客户端配置测试通过')
"@

        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "[SUCCESS] 客户端配置测试通过" "Green"
        } else {
            throw "Configuration test failed"
        }
    }
    catch {
        Write-ColorOutput "[ERROR] 客户端配置测试失败" "Red"
        exit 1
    }

    # 显示安装完成信息
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-ColorOutput "[SUCCESS] B-Server客户端安装完成！" "Green"
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-ColorOutput "安装信息:" "Blue"
    Write-Host "  安装目录: $ClientDir"
    Write-Host "  服务器地址: $ServerIP:3001"
    Write-Host "  节点名称: $NodeName"
    Write-Host ""
    Write-ColorOutput "管理命令:" "Blue"
    Write-Host "  启动客户端: .\start.bat"
    Write-Host "  后台启动: .\start_background.bat"
    Write-Host "  检查状态: .\status.bat"
    Write-Host "  停止客户端: .\stop.bat"
    Write-Host "  更新客户端: .\update.bat"
    Write-Host ""
    Write-ColorOutput "重要提示:" "Yellow"
    Write-Host "  1. 请确保在服务器管理面板中添加了节点 '$NodeName'"
    Write-Host "  2. 请确保服务器防火墙允许3001端口访问"
    Write-Host "  3. 首次运行可能需要允许防火墙访问"
    Write-Host "  4. 如需开机自启，请参考 install_service.ps1"
    Write-Host ""
    
    # 询问是否立即启动
    $choice = Read-Host "是否立即启动客户端？(Y/N)"
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        Write-ColorOutput "[INFO] 启动B-Server客户端..." "Blue"
        Start-Process -FilePath ".\start_background.bat" -WindowStyle Hidden
        Start-Sleep -Seconds 2
        & ".\status.bat"
    }
    
    Write-ColorOutput "[INFO] 安装完成！" "Green"
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