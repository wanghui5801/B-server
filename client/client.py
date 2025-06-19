import socket
import time
import json
import platform
import psutil
import os
import socketio
import requests
import subprocess
import re
import ipaddress
import shutil
from datetime import datetime

# Configuration - can be modified as needed
SERVER_URL = 'http://localhost:8008'  # Socket.IO server address (Docker Nginx proxy)
NODE_NAME = socket.gethostname()  # Use hostname as node name, can be manually modified
NODE_LOCATION = 'Local'  # Location
CLIENT_VERSION = '1.3.1'  # 🔧 统一版本号

# Network traffic statistics (for calculating rates)
previous_net_io = None
last_net_time = None

# Prevent duplicate data sending
# 这个变量将被移除，因为我们使用了更好的连接状态管理

# Create Socket.IO client
sio = socketio.Client(
    reconnection=False,             # 🔧 禁用自动重连，由我们的简单机制处理
    logger=False,                   # 禁用详细日志，避免日志过多
    engineio_logger=False,          # 禁用Engine.IO日志
    # Engine.IO特定配置
    request_timeout=10,             # 请求超时10秒
    http_session=None,              # 可以自定义HTTP会话
    ssl_verify=True,                # SSL验证
    websocket_extra_options={       # WebSocket额外选项
        'timeout': 10,              # WebSocket连接超时
        'ping_interval': 10,        # 心跳间隔
        'ping_timeout': 20,         # 心跳超时
    }
)

# Cache system type detection results
_cached_system_type = None

# Cache CPU info (solution for Windows-specific issues)
_cached_cpu_info = None

# Global variables
_system_type_cache = None
_cpu_info_cache = None
_cache_timestamp = 0
CACHE_DURATION = 60  # Cache system info for 60 seconds to reduce overhead

# 🔧 增强全局状态跟踪
_connection_stable = False
_registration_confirmed = False
_last_successful_data_send = 0

def detect_system_type():
    """智能检测系统类型"""
    global _cached_system_type
    
    # 如果已经检测过，直接返回缓存结果
    if _cached_system_type is not None:
        return _cached_system_type
    
    try:
        print("[INFO] 正在检测系统类型...")
        system_type = "DS"  # 默认类型改为DS（物理机）
        systemd_virt_result = None  # 记录systemd-detect-virt的结果
        
        # 最优先：通过systemd-detect-virt命令检测（最权威的方法）
        try:
            result = subprocess.run(['systemd-detect-virt'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                virt_type = result.stdout.strip().lower()
                systemd_virt_result = virt_type  # 记录结果
                print(f"[INFO] systemd-detect-virt 结果: '{virt_type}'")
                
                if virt_type == 'none':
                    # systemd-detect-virt 明确表示这是物理机，直接返回，不执行任何后续检测
                    _cached_system_type = "DS"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过systemd-detect-virt - 物理机，跳过所有其他检测)")
                    return _cached_system_type
                elif virt_type != '':
                    # 检测到虚拟化环境
                    virt_map = {
                        'kvm': 'KVM',
                        'qemu': 'QEMU', 
                        'vmware': 'VMware',
                        'microsoft': 'Hyper-V',
                        'xen': 'Xen',
                        'oracle': 'VirtualBox',
                        'parallels': 'Parallels',
                        'lxc': 'LXC',
                        'docker': 'Docker',
                        'openvz': 'OpenVZ',
                        'uml': 'UML',
                        'bochs': 'Bochs',
                        'chroot': 'Chroot',
                        'systemd-nspawn': 'Systemd-nspawn',
                        'rkt': 'rkt',
                        'container-other': 'Container',
                        'qnx': 'QNX',
                        'acrn': 'ACRN',
                        'powervm': 'PowerVM',
                        'bhyve': 'bhyve',
                        'amazon': 'Amazon',
                        'podman': 'Podman'
                    }
                    _cached_system_type = virt_map.get(virt_type, virt_type.upper())
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过systemd-detect-virt)")
                    return _cached_system_type
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            print(f"[INFO] systemd-detect-virt 不可用: {e}")
            systemd_virt_result = "unavailable"  # 标记为不可用
            pass
        
        # 如果systemd-detect-virt明确返回none，我们应该在上面已经返回了
        # 这里应该不会执行到，但为了安全起见再检查一次
        if systemd_virt_result == 'none':
            print(f"[INFO] systemd-detect-virt 确认为物理机，强制返回DS")
            _cached_system_type = "DS"
            return _cached_system_type
        
        # 只有在systemd-detect-virt不可用或结果不明确时，才进行后续检测
        print(f"[INFO] systemd-detect-virt 结果: {systemd_virt_result}，继续进行其他检测...")
        
        # 检测容器环境 - 使用更精确的方法
        # 1. 检查 /.dockerenv 文件（Docker特有）
        if os.path.exists('/.dockerenv'):
            print(f"[DEBUG] 发现 /.dockerenv 文件")
            _cached_system_type = "Docker"
            print(f"[INFO] 检测到系统类型: {_cached_system_type}")
            return _cached_system_type
        
        # 2. 检查 /run/.containerenv 文件（Podman特有）
        if os.path.exists('/run/.containerenv'):
            print(f"[DEBUG] 发现 /run/.containerenv 文件")
            _cached_system_type = "Podman"
            print(f"[INFO] 检测到系统类型: {_cached_system_type}")
            return _cached_system_type
        
        # 3. 精确检查 /proc/1/cgroup 来检测容器
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup_content = f.read()
                print(f"[DEBUG] /proc/1/cgroup 内容样本: {cgroup_content[:200]}...")
                
                # 检查是否在容器的cgroup中（更精确的判断）
                lines = cgroup_content.strip().split('\n')
                for line in lines:
                    if ':/docker/' in line or line.endswith('/docker'):
                        print(f"[DEBUG] 发现Docker cgroup路径: {line}")
                        _cached_system_type = "Docker"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                        return _cached_system_type
                    elif ':/lxc/' in line or line.endswith('/lxc'):
                        print(f"[DEBUG] 发现LXC cgroup路径: {line}")
                        _cached_system_type = "LXC"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                        return _cached_system_type
                    elif '/kubepods/' in line or 'k8s_' in line:
                        print(f"[DEBUG] 发现Kubernetes cgroup路径: {line}")
                        _cached_system_type = "Kubernetes"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                        return _cached_system_type
                    elif ':/machine.slice/libpod-' in line or '/libpod-' in line:
                        print(f"[DEBUG] 发现Podman cgroup路径: {line}")
                        _cached_system_type = "Podman"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                        return _cached_system_type
                    elif '/containerd/' in line or 'containerd-' in line:
                        print(f"[DEBUG] 发现Containerd cgroup路径: {line}")
                        _cached_system_type = "Containerd"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                        return _cached_system_type
                
                # 如果没有发现明确的容器路径，但包含容器关键词，需要更谨慎
                # 避免误判：只有当路径明确指向容器时才判断为容器
                print(f"[DEBUG] /proc/1/cgroup 检查完成，未发现明确的容器特征")
                
        except (FileNotFoundError, PermissionError):
            print(f"[DEBUG] 无法读取 /proc/1/cgroup")
            pass
        
        # 4. 检查容器环境变量
        try:
            container_env_vars = ['CONTAINER', 'container', 'DOCKER_CONTAINER']
            for var in container_env_vars:
                if var in os.environ:
                    print(f"[DEBUG] 发现容器环境变量: {var}={os.environ.get(var)}")
                    _cached_system_type = "Container"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
        except:
            pass
        
        # 容器检测完成，继续进行虚拟化检测
        print(f"[INFO] 容器检测完成，继续进行虚拟化检测...")
        
        # 检测虚拟化环境 - 通过DMI信息
        try:
            # 检查系统制造商
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                vendor = f.read().strip().lower()
                print(f"[DEBUG] sys_vendor: '{vendor}'")
                if 'qemu' in vendor:
                    _cached_system_type = "QEMU"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'vmware' in vendor:
                    _cached_system_type = "VMware"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'microsoft corporation' in vendor:
                    _cached_system_type = "Hyper-V"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'xen' in vendor:
                    _cached_system_type = "Xen"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'parallels' in vendor:
                    _cached_system_type = "Parallels"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'bochs' in vendor:
                    _cached_system_type = "Bochs"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'nutanix' in vendor:
                    _cached_system_type = "Nutanix AHV"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'red hat' in vendor:
                    _cached_system_type = "RHEV"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
                elif 'citrix' in vendor:
                    _cached_system_type = "Citrix Xen"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过sys_vendor)")
                    return _cached_system_type
        except (FileNotFoundError, PermissionError):
            pass
        
        # 检查产品名称
        try:
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                product = f.read().strip().lower()
                print(f"[DEBUG] product_name: '{product}'")
                if 'virtualbox' in product:
                    _cached_system_type = "VirtualBox"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'vmware' in product:
                    _cached_system_type = "VMware"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'kvm' in product:
                    _cached_system_type = "KVM"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'qemu' in product:
                    _cached_system_type = "QEMU"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'hyper-v' in product or 'virtual machine' in product:
                    _cached_system_type = "Hyper-V"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'bochs' in product:
                    _cached_system_type = "Bochs"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'proxmox' in product:
                    _cached_system_type = "Proxmox VE"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'openstack' in product:
                    _cached_system_type = "OpenStack"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'ovirt' in product:
                    _cached_system_type = "oVirt"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'cloudstack' in product:
                    _cached_system_type = "CloudStack"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'eucalyptus' in product:
                    _cached_system_type = "Eucalyptus"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'bhyve' in product:
                    _cached_system_type = "bhyve"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
                elif 'acrn' in product:
                    _cached_system_type = "ACRN"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过product_name)")
                    return _cached_system_type
        except (FileNotFoundError, PermissionError):
            pass
        
        # 检查BIOS信息
        try:
            with open('/sys/class/dmi/id/bios_vendor', 'r') as f:
                bios_vendor = f.read().strip().lower()
                print(f"[DEBUG] bios_vendor: '{bios_vendor}'")
                if 'seabios' in bios_vendor:
                    _cached_system_type = "KVM"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过bios_vendor)")
                    return _cached_system_type
                elif 'vmware' in bios_vendor:
                    _cached_system_type = "VMware"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过bios_vendor)")
                    return _cached_system_type
                elif 'virtualbox' in bios_vendor:
                    _cached_system_type = "VirtualBox"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过bios_vendor)")
                    return _cached_system_type
                elif 'bochs' in bios_vendor:
                    _cached_system_type = "Bochs"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过bios_vendor)")
                    return _cached_system_type
                elif 'tianocore' in bios_vendor:
                    _cached_system_type = "UEFI VM"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过bios_vendor)")
                    return _cached_system_type
        except (FileNotFoundError, PermissionError):
            pass
        
        # 检测云服务商（使用更短的超时时间）
        try:
            # AWS检测
            response = requests.get('http://169.254.169.254/latest/meta-data/instance-id', 
                                  timeout=1)
            if response.status_code == 200:
                _cached_system_type = "AWS EC2"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # Azure检测
            headers = {'Metadata': 'true'}
            response = requests.get('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 
                                  headers=headers, timeout=1)
            if response.status_code == 200:
                _cached_system_type = "Azure VM"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # GCP检测
            headers = {'Metadata-Flavor': 'Google'}
            response = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/id', 
                                  headers=headers, timeout=1)
            if response.status_code == 200:
                _cached_system_type = "GCP VM"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # 阿里云检测
            response = requests.get('http://100.100.100.200/latest/meta-data/instance-id', 
                                  timeout=1)
            if response.status_code == 200:
                _cached_system_type = "阿里云ECS"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # 腾讯云检测
            response = requests.get('http://metadata.tencentcloudapi.com/latest/meta-data/instance-id', 
                                  timeout=1)
            if response.status_code == 200:
                _cached_system_type = "腾讯云CVM"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # 华为云检测
            response = requests.get('http://169.254.169.254/openstack/latest/meta_data.json', 
                                  timeout=1)
            if response.status_code == 200:
                data = response.json()
                if 'availability_zone' in data and 'huawei' in str(data).lower():
                    _cached_system_type = "华为云ECS"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
        except:
            pass
        
        try:
            # Oracle Cloud检测
            headers = {'Authorization': 'Bearer Oracle'}
            response = requests.get('http://169.254.169.254/opc/v1/instance/', 
                                  headers=headers, timeout=1)
            if response.status_code == 200:
                _cached_system_type = "Oracle Cloud"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # DigitalOcean检测
            response = requests.get('http://169.254.169.254/metadata/v1/id', 
                                  timeout=1)
            if response.status_code == 200:
                _cached_system_type = "DigitalOcean"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # Linode检测
            response = requests.get('http://169.254.169.254/linode/v1/instance', 
                                  timeout=1)
            if response.status_code == 200:
                _cached_system_type = "Linode"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        try:
            # Vultr检测
            response = requests.get('http://169.254.169.254/v1/instanceid', 
                                  timeout=1)
            if response.status_code == 200:
                _cached_system_type = "Vultr"
                print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                return _cached_system_type
        except:
            pass
        
        # 检查CPU型号来推断虚拟化 - 只在DMI检测无结果时使用
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read().lower()
                print(f"[DEBUG] 检查 cpuinfo 中的虚拟化标识...")
                if 'qemu' in cpuinfo:
                    _cached_system_type = "QEMU"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
                elif 'kvm' in cpuinfo:
                    _cached_system_type = "KVM"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
                elif 'vmware' in cpuinfo:
                    _cached_system_type = "VMware"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
                elif 'virtualbox' in cpuinfo:
                    _cached_system_type = "VirtualBox"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
                elif 'xen' in cpuinfo:
                    _cached_system_type = "Xen"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
                elif 'bochs' in cpuinfo:
                    _cached_system_type = "Bochs"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
                elif 'bhyve' in cpuinfo:
                    _cached_system_type = "bhyve"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过cpuinfo)")
                    return _cached_system_type
        except (FileNotFoundError, PermissionError):
            pass
        
        # 检查网络接口名称 - 移除容器相关检测，避免误判
        # 注意：这里只检测虚拟化平台的接口，不检测容器接口
        try:
            interfaces = os.listdir('/sys/class/net/')
            print(f"[DEBUG] 网络接口: {interfaces}")
            for iface in interfaces:
                # 只检测明确的虚拟化平台接口，避免误判
                if iface.startswith('vmbr'):
                    _cached_system_type = "Proxmox VE"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过网络接口)")
                    return _cached_system_type
                # 移除veth和docker接口检查，因为物理机安装Docker后也会有这些接口
        except:
            pass
        
        # 注意：此处不再检查特殊路径，因为在物理机上也可能存在Xen相关的文件
        # 比如安装了Xen hypervisor但当前不在虚拟机中运行的情况
        
        # 检查串口号来判断云服务商
        try:
            with open('/sys/class/dmi/id/product_serial', 'r') as f:
                serial = f.read().strip().lower()
                print(f"[DEBUG] product_serial: '{serial}'")
                if serial.startswith('ec2'):
                    _cached_system_type = "AWS EC2"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过序列号)")
                    return _cached_system_type
                elif 'google' in serial:
                    _cached_system_type = "GCP VM"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过序列号)")
                    return _cached_system_type
                elif 'vmware' in serial:
                    _cached_system_type = "VMware"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过序列号)")
                    return _cached_system_type
        except (FileNotFoundError, PermissionError):
            pass
        
        # Windows检测（如果运行在Windows上）
        if platform.system() == 'Windows':
            try:
                import wmi
                c = wmi.WMI()
                for computer in c.Win32_ComputerSystem():
                    model = computer.Model.lower()
                    manufacturer = computer.Manufacturer.lower()
                    
                    if 'virtualbox' in model or 'virtualbox' in manufacturer:
                        _cached_system_type = "VirtualBox"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (Windows WMI)")
                        return _cached_system_type
                    elif 'vmware' in model or 'vmware' in manufacturer:
                        _cached_system_type = "VMware"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (Windows WMI)")
                        return _cached_system_type
                    elif 'virtual machine' in model or 'microsoft corporation' in manufacturer:
                        _cached_system_type = "Hyper-V"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (Windows WMI)")
                        return _cached_system_type
                    elif 'parallels' in model or 'parallels' in manufacturer:
                        _cached_system_type = "Parallels"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (Windows WMI)")
                        return _cached_system_type
                    elif 'qemu' in model or 'qemu' in manufacturer:
                        _cached_system_type = "QEMU"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (Windows WMI)")
                        return _cached_system_type
                    elif 'bochs' in model or 'bochs' in manufacturer:
                        _cached_system_type = "Bochs"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (Windows WMI)")
                        return _cached_system_type
            except:
                pass
        
        # macOS检测（如果运行在macOS上）
        if platform.system() == 'Darwin':
            try:
                # 检查是否为虚拟机
                result = subprocess.run(['sysctl', '-n', 'machdep.cpu.features'], 
                                      capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    features = result.stdout.lower()
                    if 'hypervisor' in features:
                        _cached_system_type = "macOS VM"
                        print(f"[INFO] 检测到系统类型: {_cached_system_type} (macOS sysctl)")
                        return _cached_system_type
                
                # 检查Parallels
                if os.path.exists('/Applications/Parallels Desktop.app'):
                    _cached_system_type = "Parallels"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (macOS)")
                    return _cached_system_type
                
                # 检查VMware Fusion
                if os.path.exists('/Applications/VMware Fusion.app'):
                    _cached_system_type = "VMware Fusion"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (macOS)")
                    return _cached_system_type
                    
            except:
                pass
        
        # 如果都没有检测到，返回DS（物理机）
        _cached_system_type = system_type
        print(f"[INFO] 检测到系统类型: {_cached_system_type} (默认)")
        return _cached_system_type
        
    except Exception as e:
        print(f"[WARN] Failed to detect system type: {e}")
        _cached_system_type = "未知类型"
        return _cached_system_type

def get_all_disk_usage():
    """获取所有挂载分区的磁盘使用情况总和"""
    try:
        total_size = 0
        total_used = 0
        total_free = 0
        partitions_info = []
        
        # 获取所有挂载分区
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            try:
                # 跳过某些特殊的文件系统类型
                if partition.fstype in ['', 'squashfs', 'tmpfs', 'devtmpfs', 'proc', 'sysfs', 'devpts', 'cgroup', 'cgroup2', 'pstore', 'bpf', 'autofs']:
                    continue
                
                # 跳过某些特殊的挂载点
                if partition.mountpoint in ['/dev', '/proc', '/sys', '/run', '/boot/efi', '/run/lock', '/run/shm', '/run/user']:
                    continue
                
                # 获取分区使用情况
                disk_usage = psutil.disk_usage(partition.mountpoint)
                
                # 累加到总量
                total_size += disk_usage.total
                total_used += disk_usage.used
                total_free += disk_usage.free
                
                # 记录分区信息（用于调试）
                partitions_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'size_gb': round(disk_usage.total / (1024**3), 2),
                    'used_gb': round(disk_usage.used / (1024**3), 2),
                    'percent': round((disk_usage.used / disk_usage.total) * 100, 1) if disk_usage.total > 0 else 0
                })
                
            except (PermissionError, OSError, FileNotFoundError):
                # 某些分区可能没有权限访问或者不存在，跳过
                continue
        
        # 计算总体使用率
        total_percent = round((total_used / total_size) * 100, 1) if total_size > 0 else 0
        
        return {
            'total_size': total_size,
            'total_used': total_used,
            'total_free': total_free,
            'percent': total_percent,
            'partitions_count': len(partitions_info),
            'detail': f"{total_used/(1024**3):.2f} GiB / {total_size/(1024**3):.2f} GiB"
        }
        
    except Exception as e:
        print(f"[Disk] Error getting disk usage: {e}")
        # 如果出错，回退到根分区
        try:
            disk = psutil.disk_usage('/')
            return {
                'total_size': disk.total,
                'total_used': disk.used,
                'total_free': disk.free,
                'percent': round((disk.used / disk.total) * 100, 1),
                'partitions_count': 1,
                'detail': f"{disk.used/(1024**3):.2f} GiB / {disk.total/(1024**3):.2f} GiB"
            }
        except:
            return {
                'total_size': 0,
                'total_used': 0,
                'total_free': 0,
                'percent': 0,
                'partitions_count': 0,
                'detail': "0 GiB / 0 GiB"
            }

def get_cpu_usage():
    """获取更精确的CPU使用率 - 性能优化版本"""
    try:
        # 使用非阻塞方式获取CPU使用率
        # 第一次调用初始化，返回值可能不准确
        cpu_percent = psutil.cpu_percent(interval=None)
        
        # 如果是第一次调用或者返回0，使用短间隔采样
        if cpu_percent == 0.0:
            cpu_percent = psutil.cpu_percent(interval=0.1)
        
        return int(round(cpu_percent))
    except:
        try:
            # 备用方法：使用较短的间隔
            return int(psutil.cpu_percent(interval=0.5))
        except:
            return 0

def get_memory_info():
    """获取更详细的内存信息"""
    try:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # 计算更精确的内存使用率（排除缓存）
        # 在Linux上，available字段比free更准确
        if hasattr(memory, 'available'):
            actual_used = memory.total - memory.available
            actual_percent = round((actual_used / memory.total) * 100, 1)
        else:
            actual_used = memory.used
            actual_percent = round(memory.percent, 1)
        
        return {
            'percent': int(actual_percent),
            'total': memory.total,
            'used': actual_used,
            'available': getattr(memory, 'available', memory.free),
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_percent': round(swap.percent, 1),
            'detail': f"{actual_used/(1024**2):.2f} MiB / {memory.total/(1024**2):.2f} MiB",
            'swap_detail': f"{swap.used/(1024**2):.2f} MiB / {swap.total/(1024**2):.2f} MiB"
        }
    except Exception as e:
        print(f"[Memory] Error getting memory info: {e}")
        return {
            'percent': 0,
            'total': 0,
            'used': 0,
            'available': 0,
            'swap_total': 0,
            'swap_used': 0,
            'swap_percent': 0,
            'detail': "0 MiB / 0 MiB",
            'swap_detail': "0 MiB / 0 MiB"
        }

def get_cpu_info():
    """获取CPU详细信息：型号、频率、核心数、虚拟化状态 - 优化的Windows兼容版本"""
    global _cached_cpu_info
    
    try:
        # 对于Windows，如果已经缓存了CPU信息，直接返回
        # 这是因为Windows的WMI在多线程环境中容易出问题
        if platform.system() == 'Windows' and _cached_cpu_info is not None:
            return _cached_cpu_info
        
        # 获取逻辑CPU数量（线程数）
        logical_cpus = psutil.cpu_count(logical=True)
        # 获取物理CPU核心数
        physical_cpus = psutil.cpu_count(logical=False)
        
        # 如果无法获取物理核心数，使用逻辑CPU数
        if physical_cpus is None:
            physical_cpus = logical_cpus
        
        cpu_model = "Unknown CPU"
        cpu_frequency = ""
        is_virtual = False
        socket_count = 1
        threads_per_core = 1
        
        # 根据操作系统获取CPU详细信息
        if platform.system() == 'Linux':
            try:
                # 从 /proc/cpuinfo 获取基本信息
                with open('/proc/cpuinfo', 'r') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if line.startswith('model name'):
                            cpu_model = line.split(':', 1)[1].strip()
                        elif line.startswith('flags') and 'hypervisor' in line:
                            is_virtual = True
                
                # 尝试使用 lscpu 获取更详细信息
                try:
                    result = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lscpu_output = result.stdout
                        for line in lscpu_output.split('\n'):
                            line = line.strip()
                            if line.startswith('Model name:'):
                                cpu_model = line.split(':', 1)[1].strip()
                            elif line.startswith('Hypervisor vendor:'):
                                is_virtual = True
                            elif line.startswith('Virtualization type:'):
                                if 'full' in line.lower():
                                    is_virtual = True
                            elif line.startswith('Socket(s):'):
                                try:
                                    socket_count = int(line.split(':', 1)[1].strip())
                                except:
                                    pass
                            elif line.startswith('Thread(s) per core:'):
                                try:
                                    threads_per_core = int(line.split(':', 1)[1].strip())
                                except:
                                    pass
                except:
                    pass
                    
            except (FileNotFoundError, PermissionError):
                pass
                
        elif platform.system() == 'Windows':
            # Windows平台：使用多种方法检测，并缓存结果
            wmi_success = False
            
            try:
                # 尝试使用wmi模块，添加COM初始化
                import wmi
                
                # 初始化COM接口（修复多线程问题）
                try:
                    import pythoncom
                    pythoncom.CoInitialize()
                except:
                    pass
                
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    cpu_model = processor.Name.strip()
                    wmi_success = True
                    break
                    
                # 检查是否在虚拟机中
                if wmi_success:
                    try:
                        for computer_system in c.Win32_ComputerSystem():
                            if computer_system.Model and any(vm_indicator in computer_system.Model.lower() 
                                                           for vm_indicator in ['virtual', 'vmware', 'virtualbox', 'hyper-v']):
                                is_virtual = True
                            break
                    except:
                        pass
                
                # 清理COM接口
                try:
                    pythoncom.CoUninitialize()
                except:
                    pass
                    
            except (ImportError, Exception) as e:
                print(f"[CPU] WMI detection failed: {e}, trying registry method...")
                
            # 如果WMI失败，使用注册表方法作为备选
            if not wmi_success:
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                    cpu_model = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
                    winreg.CloseKey(key)
                    print(f"[CPU] Registry detection successful: {cpu_model}")
                except Exception as e:
                    print(f"[CPU] Registry detection failed: {e}")
                    pass
                    
        elif platform.system() == 'Darwin':  # macOS
            try:
                result = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], 
                                      capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    cpu_model = result.stdout.strip()
                    
                # 检查是否在虚拟机中
                result = subprocess.run(['sysctl', '-n', 'machdep.cpu.features'], 
                                      capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and 'VMM' in result.stdout:
                    is_virtual = True
            except:
                pass
        
        # 处理CPU型号和频率
        if cpu_model != "Unknown CPU":
            # 移除多余空格
            cpu_model = ' '.join(cpu_model.split())
            
            # 提取频率信息（保留 @ 频率部分）
            frequency_match = re.search(r'@\s*([\d.]+\s*GHz)', cpu_model)
            if frequency_match:
                cpu_frequency = f"@ {frequency_match.group(1)}"
                # 保留完整的CPU型号（包含频率）
                cpu_model_with_freq = cpu_model
            else:
                # 如果没有频率信息，尝试从其他地方获取
                cpu_model_with_freq = cpu_model
                cpu_frequency = ""
        else:
            cpu_model_with_freq = cpu_model
            cpu_frequency = ""
        
        # 确定核心类型和数量
        if is_virtual:
            # 虚拟机：显示逻辑CPU数作为虚拟核心
            if logical_cpus == 1:
                core_description = "1 Virtual Core"
            else:
                core_description = f"{logical_cpus} Virtual Core"
        else:
            # 物理机：根据是否支持超线程来决定显示方式
            if threads_per_core > 1 and physical_cpus != logical_cpus:
                # 支持超线程的物理机，显示物理核心数
                if physical_cpus == 1:
                    core_description = "1 Physical Core"
                else:
                    core_description = f"{physical_cpus} Physical Core"
            else:
                # 不支持超线程或单核心，显示逻辑CPU数
                if logical_cpus == 1:
                    core_description = "1 Physical Core"
                else:
                    core_description = f"{logical_cpus} Physical Core"
        
        # 构建最终的信息字符串
        # 格式：CPU型号 @ 频率 X Virtual/Physical Core
        if cpu_frequency:
            info_string = f"{cpu_model_with_freq} {core_description}"
        else:
            info_string = f"{cpu_model} {core_description}"
        
        cpu_info_result = {
            'model': cpu_model,
            'cores': physical_cpus,
            'threads': logical_cpus,
            'is_virtual': is_virtual,
            'socket_count': socket_count,
            'threads_per_core': threads_per_core,
            'frequency': cpu_frequency,
            'info_string': info_string
        }
        
        # 对于Windows，缓存CPU信息以避免后续的WMI问题
        if platform.system() == 'Windows':
            _cached_cpu_info = cpu_info_result
            print(f"[CPU] Windows CPU info cached: {info_string}")
        
        return cpu_info_result
        
    except Exception as e:
        print(f"[CPU] Error getting CPU info: {e}")
        
        # 如果是Windows且有缓存，返回缓存的信息
        if platform.system() == 'Windows' and _cached_cpu_info is not None:
            print(f"[CPU] Using cached CPU info due to error")
            return _cached_cpu_info
        
        # 否则返回默认信息
        fallback_result = {
            'model': "Unknown CPU",
            'cores': 1,
            'threads': 1,
            'is_virtual': False,
            'socket_count': 1,
            'threads_per_core': 1,
            'frequency': "",
            'info_string': "Unknown CPU 1 Core"
        }
        
        # 对于Windows，也缓存这个fallback结果，避免重复尝试
        if platform.system() == 'Windows':
            _cached_cpu_info = fallback_result
        
        return fallback_result

def get_uptime():
    """获取系统运行时间（天）"""
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_days = int(uptime_seconds / 86400)  # 转换为天
        return uptime_days
    except:
        return 0

def get_load_average():
    """获取系统负载 - 性能优化版本"""
    try:
        if hasattr(os, 'getloadavg'):
            # Unix系统使用load average（最高效的方法）
            load_1, load_5, load_15 = os.getloadavg()
            return round(load_1, 2)
        else:
            # Windows系统计算基于CPU核心数的负载
            cpu_count = psutil.cpu_count()
            # 使用非阻塞方式获取CPU使用率
            cpu_percent = psutil.cpu_percent(interval=None)
            if cpu_percent == 0.0:
                cpu_percent = psutil.cpu_percent(interval=0.1)
            # 将CPU使用率转换为类似load average的值
            load_equivalent = round((cpu_percent / 100) * cpu_count, 2)
            return load_equivalent
    except:
        return 0.0

def get_network_speed():
    """获取网络速度（B/s）- 优化版本"""
    global previous_net_io, last_net_time
    try:
        current_net_io = psutil.net_io_counters()
        current_time = time.time()
        
        if previous_net_io is None or last_net_time is None:
            previous_net_io = current_net_io
            last_net_time = current_time
            return "0B", "0B"
        
        time_delta = current_time - last_net_time
        if time_delta <= 0:
            return "0B", "0B"
            
        # 计算速度 (bytes per second)
        bytes_sent_speed = (current_net_io.bytes_sent - previous_net_io.bytes_sent) / time_delta
        bytes_recv_speed = (current_net_io.bytes_recv - previous_net_io.bytes_recv) / time_delta
        
        # 更新记录
        previous_net_io = current_net_io
        last_net_time = current_time
        
        def format_bytes(bytes_val):
            if bytes_val < 0:
                return "0B"
            elif bytes_val < 1024:
                return f"{int(bytes_val)}B"
            elif bytes_val < 1024 * 1024:
                return f"{bytes_val/1024:.1f}K"
            elif bytes_val < 1024 * 1024 * 1024:
                return f"{bytes_val/(1024*1024):.1f}M"
            else:
                return f"{bytes_val/(1024*1024*1024):.1f}G"
        
        return format_bytes(bytes_recv_speed), format_bytes(bytes_sent_speed)
    except Exception as e:
        print(f"[Network] Error calculating network speed: {e}")
        return "0B", "0B"

def format_bytes_total(bytes_val):
    """格式化总流量"""
    try:
        if bytes_val < 0:
            return "0B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.1f}K"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val/(1024*1024):.1f}M"
        elif bytes_val < 1024 * 1024 * 1024 * 1024:
            return f"{bytes_val/(1024*1024*1024):.1f}G"
        else:
            return f"{bytes_val/(1024*1024*1024*1024):.1f}T"
    except:
        return "0B"

def get_public_ipv6():
    """获取公网IPv6地址"""
    try:
        # 尝试多个IPv6服务来获取公网IPv6
        ipv6_services = [
            'https://ipv6.icanhazip.com',
            'https://v6.ident.me',
            'https://ipv6.whatismyipaddress.com/api',
            'https://6.ipw.cn'
        ]
        
        for service in ipv6_services:
            try:
                response = requests.get(service, timeout=3)
                if response.status_code == 200:
                    ipv6 = response.text.strip()
                    # 验证IPv6格式
                    try:
                        ipaddress.IPv6Address(ipv6)
                        return ipv6
                    except ipaddress.AddressValueError:
                        continue
            except:
                continue
                
        # 如果所有服务都失败，尝试从本地网络接口获取IPv6
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET6:
                        ipv6_addr = addr.address.split('%')[0]  # 移除zone id
                        try:
                            ip = ipaddress.IPv6Address(ipv6_addr)
                            # 只返回全局单播地址（公网地址）
                            if ip.is_global:
                                return ipv6_addr
                        except ipaddress.AddressValueError:
                            continue
        except:
            pass
            
        return None
    except Exception as e:
        print(f"[IPv6] Error getting IPv6 address: {e}")
        return None

def get_public_ip():
    """获取公网IP地址"""
    try:
        # 尝试多个服务来获取公网IP
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com', 
            'https://ipinfo.io/ip',
            'https://checkip.amazonaws.com'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=3)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # 简单验证IP格式
                    parts = ip.split('.')
                    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                        return ip
            except:
                continue
                
        # 如果所有服务都失败，返回内网IP作为备选
        return socket.gethostbyname(socket.gethostname())
    except:
        return '127.0.0.1'

def get_ip_addresses():
    """获取IPv4和IPv6地址并格式化"""
    ipv4 = get_public_ip()
    ipv6 = get_public_ipv6()
    
    # 格式化IP地址显示
    ip_parts = []
    
    if ipv4 and ipv4 != '127.0.0.1':
        ip_parts.append(f"ipv4:{ipv4}")
    
    if ipv6:
        ip_parts.append(f"ipv6:{ipv6}")
    
    # 如果没有有效的公网IP，显示IPv4
    if not ip_parts:
        ip_parts.append(f"ipv4:{ipv4}")
    
    return {
        'ip_display': ' | '.join(ip_parts),  # 用于显示的格式化字符串
        'ipv4': ipv4,                        # 原始IPv4地址
        'ipv6': ipv6                         # 原始IPv6地址（可能为None）
    }

def python_tcping(host, port, timeout=8):
    """Pure Python implementation of TCP ping to avoid CMD windows on Windows - 增强稳定性"""
    import socket
    import time
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Record start time
        start_time = time.time()
        
        # Attempt connection
        result = sock.connect_ex((host, int(port)))
        
        # Calculate latency
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # Convert to milliseconds
        
        sock.close()
        
        if result == 0:
            # 延迟高于500ms视为失败
            if latency > 500:
                print(f"[TCPing] ✗ High latency (>500ms): {host}:{port} - {latency:.2f}ms")
                return {
                    'host': host,
                    'port': port,
                    'latency': None,
                    'success': False,
                    'error': 'High latency'
                }
            print(f"[TCPing] ✓ Success: {host}:{port} - {latency:.2f}ms")
            return {
                'host': host,
                'port': port,
                'latency': round(latency, 2),
                'success': True
            }
        else:
            print(f"[TCPing] ✗ Connection failed: {host}:{port} - error {result}")
            return {
                'host': host,
                'port': port,
                'latency': None,
                'success': False,
                'error': f'Connection error {result}'
            }
            
    except socket.timeout:
        print(f"[TCPing] ✗ Timeout: {host}:{port}")
        return {
            'host': host,
            'port': port,
            'latency': None,
            'success': False,
            'error': 'Socket timeout'
        }
    except socket.gaierror as e:
        print(f"[TCPing] ✗ DNS resolution failed: {host}:{port} - {e}")
        return {
            'host': host,
            'port': port,
            'latency': None,
            'success': False,
            'error': f'DNS error: {e}'
        }
    except Exception as e:
        print(f"[TCPing] ✗ Exception in python_tcping: {e}")
        return {
            'host': host,
            'port': port,
            'latency': None,
            'success': False,
            'error': str(e)
        }

def find_tcping_executable():
    """查找tcping可执行文件的位置 - Windows优先使用Python包"""
    
    # Windows系统优先使用Python tcping模块，避免弹窗
    if platform.system() == 'Windows':
        print(f"[TCPing] Windows detected - checking for Python tcping module first")
        try:
            # 尝试导入tcping Python包
            import tcping
            print(f"[TCPing] Python tcping module found - using pure Python implementation")
            return 'python_module'
        except ImportError:
            print(f"[TCPing] Python tcping module not found, falling back to built-in socket method")
            return 'python_socket'
    
    # 对于Linux/Unix系统，仍然可以尝试系统的tcping
    # 首先尝试使用 shutil.which() 在PATH中查找
    tcping_path = shutil.which('tcping')
    if tcping_path:
        print(f"[TCPing] Found tcping in PATH: {tcping_path}")
        return tcping_path
    
    # 如果在PATH中找不到，尝试常见位置
    possible_paths = []
    
    if platform.system() != 'Windows':
        # Unix/Linux可能的路径
        possible_paths = [
            os.path.join(os.path.expanduser('~'), '.local', 'bin', 'tcping'),
            '/usr/local/bin/tcping',
            '/usr/bin/tcping',
            '/opt/homebrew/bin/tcping',  # macOS Homebrew
        ]
        
        # 测试每个可能的路径
        for path in possible_paths:
            if path and os.path.isfile(path) and os.access(path, os.X_OK):
                print(f"[TCPing] Found tcping at: {path}")
                return path
    
    # 如果都找不到，使用内置的Python socket方法
    print(f"[TCPing] No external tcping found, using built-in Python socket method")
    return 'python_socket'

def perform_tcping(host, port):
    """执行tcping命令并返回结果 - 增强稳定性和错误处理"""
    try:
        # 验证输入参数
        if not host or not port:
            print(f"[TCPing] ✗ 无效参数: host={host}, port={port}")
            return {
                'host': host or 'unknown',
                'port': port or 0,
                'latency': None,
                'success': False,
                'error': 'Invalid parameters'
            }
        
        # 规范化port为整数
        try:
            port = int(port)
            if port <= 0 or port > 65535:
                raise ValueError(f"Port {port} out of range")
        except (ValueError, TypeError) as e:
            print(f"[TCPing] ✗ 无效端口: {port}")
            return {
                'host': host,
                'port': port,
                'latency': None,
                'success': False,
                'error': f'Invalid port: {port}'
            }
        
        # 查找tcping方法
        tcping_method = find_tcping_executable()
        
        # 使用Python socket方法 (避免弹窗，提高稳定性)
        if tcping_method == 'python_socket':
            print(f"[TCPing] Using built-in Python socket method for {host}:{port}")
            return python_tcping(host, port, timeout=8)  # 增加超时到8秒
        
        # 使用Python tcping模块
        elif tcping_method == 'python_module':
            print(f"[TCPing] Using Python tcping module for {host}:{port}")
            try:
                import tcping
                result = tcping.Ping(host, int(port), timeout=8)  # 增加超时到8秒
                result.ping(1)  # Ping once
                
                if result.result and len(result.result) > 0:
                    avg_time = result.result[0].time if result.result[0].time else None
                    if avg_time is not None:
                        # 延迟高于500ms视为失败
                        if avg_time > 500:
                            print(f"[TCPing] ✗ 高延迟(>500ms): {host}:{port} - {avg_time}ms")
                            return {
                                'host': host,
                                'port': port,
                                'latency': None,
                                'success': False,
                                'error': 'High latency'
                            }
                        print(f"[TCPing] ✓ Success: {host}:{port} - {avg_time}ms")
                        return {
                            'host': host,
                            'port': port,
                            'latency': round(avg_time, 2),
                            'success': True
                        }
                    else:
                        print(f"[TCPing] ✗ No latency data: {host}:{port}")
                        return {
                            'host': host,
                            'port': port,
                            'latency': None,
                            'success': False,
                            'error': 'No latency data'
                        }
                else:
                    print(f"[TCPing] ✗ No result: {host}:{port}")
                    return {
                        'host': host,
                        'port': port,
                        'latency': None,
                        'success': False,
                        'error': 'No result'
                    }
            except Exception as e:
                print(f"[TCPing] Python tcping module failed: {e}, falling back to socket method")
                return python_tcping(host, port, timeout=8)
        
        # 使用外部tcping可执行文件 (仅限Linux/Unix)
        else:
            # 构建命令
            cmd = [tcping_method, str(host), '-p', str(port), '-c', '1', '--report']
            
            print(f"[TCPing] Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)  # 增加超时到15秒
            
            # 处理外部tcping命令的结果
            if result.returncode == 0:
                output = result.stdout.strip()
                print(f"[TCPing] Output: {output}")
                
                output_lower = output.lower()
                
                # 解析输出获取延迟时间
                import re
                
                # 首先检查是否连接成功（优先检查成功指示符）
                if 'connected' in output_lower:
                    # 尝试解析延迟时间
                    latency_patterns = [
                        r'time=(\d+(?:\.\d+)?)ms',
                        r'(\d+(?:\.\d+)?)ms',
                        r'time:\s*(\d+(?:\.\d+)?)ms',
                        r'latency:\s*(\d+(?:\.\d+)?)ms',
                        r'rtt:\s*(\d+(?:\.\d+)?)ms'
                    ]
                    
                    latency = None
                    for pattern in latency_patterns:
                        match = re.search(pattern, output_lower)
                        if match:
                            try:
                                latency = float(match.group(1))
                                break
                            except (ValueError, IndexError):
                                continue
                    
                    if latency is not None and latency > 0:
                        # 延迟高于500ms视为失败
                        if latency > 500:
                            print(f"[TCPing] ✗ High latency (>500ms): {host}:{port} - {latency}ms")
                            return {
                                'host': host,
                                'port': port,
                                'latency': None,
                                'success': False,
                                'error': 'High latency'
                            }
                        print(f"[TCPing] ✓ Success: {host}:{port} - {latency}ms")
                        return {
                            'host': host,
                            'port': port,
                            'latency': round(latency, 2),
                            'success': True
                        }
                    else:
                        # 连接成功但无法解析延迟或延迟为0，检查是否真的失败了
                        if '0.00ms' in output and ('0     |   1' in output or 'failed' in output.lower()):
                            print(f"[TCPing] ✗ Connected but actually failed (0ms latency): {host}:{port}")
                            return {
                                'host': host,
                                'port': port,
                                'latency': None,
                                'success': False,
                                'error': 'Zero latency failure'
                            }
                        else:
                            # 连接成功但无法解析延迟，给一个默认值
                            print(f"[TCPing] ✓ Connected but couldn't parse latency: {host}:{port}")
                            return {
                                'host': host,
                                'port': port,
                                'latency': 1.0,
                                'success': True
                            }
                else:
                    # 没有找到"connected"，检查其他成功指示符
                    success_indicators = ['open', 'reachable', 'success']
                    if any(indicator in output_lower for indicator in success_indicators):
                        print(f"[TCPing] ✓ Success detected but couldn't parse latency: {host}:{port}")
                        return {
                            'host': host,
                            'port': port,
                            'latency': 1.0,
                            'success': True
                        }
                    else:
                        # 既没有成功指示符也没有失败指示符，视为失败
                        print(f"[TCPing] ✗ No success indicators found, treating as failure: {host}:{port}")
                        print(f"[TCPing Debug] Output lower: '{output_lower}'")
                        return {
                            'host': host,
                            'port': port,
                            'latency': None,
                            'success': False,
                            'error': 'No success indicators'
                        }
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print(f"[TCPing] ✗ Failed: {host}:{port} - {error_msg}")
                return {
                    'host': host,
                    'port': port,
                    'latency': None,
                    'success': False,
                    'error': error_msg
                }
    
    except subprocess.TimeoutExpired:
        print(f"[TCPing] ✗ Timeout: {host}:{port}")
        return {
            'host': host,
            'port': port,
            'latency': None,
            'success': False,
            'error': 'Timeout'
        }
    except Exception as e:
        print(f"[TCPing] ✗ Exception: {host}:{port} - {str(e)}")
        return {
            'host': host,
            'port': port,
            'latency': None,
            'success': False,
            'error': str(e)
        }

def collect_info():
    """采集真实系统信息 - 优化版本"""
    try:
        print("[Data] Starting data collection...")
        
        # 基本信息
        ip_info = get_ip_addresses()
        status = '运行中'
        
        print(f"[Data] IP addresses: {ip_info['ip_display']}")
        if ip_info['ipv6']:
            print(f"[Data] IPv6 support detected: {ip_info['ipv6']}")
        else:
            print(f"[Data] IPv6 not available")
        
        # 系统运行时间
        uptime = get_uptime()
        print(f"[Data] Uptime: {uptime} days")
        
        # 系统负载
        load = get_load_average()
        print(f"[Data] Load average: {load}")
        
        # 网络速度
        net_in, net_out = get_network_speed()
        print(f"[Data] Network speed: ↓{net_in}/s ↑{net_out}/s")
        
        # 网络总流量
        try:
            net_io = psutil.net_io_counters()
            traffic_in = format_bytes_total(net_io.bytes_recv)
            traffic_out = format_bytes_total(net_io.bytes_sent)
            print(f"[Data] Total traffic: ↓{traffic_in} ↑{traffic_out}")
        except Exception as e:
            print(f"[Data] Error getting network stats: {e}")
            traffic_in = "0M"
            traffic_out = "0M"
        
        # CPU使用率（优化版本）
        cpu = get_cpu_usage()
        print(f"[Data] CPU usage: {cpu}%")
        
        # 内存使用率（优化版本）
        memory_info = get_memory_info()
        ram = memory_info['percent']
        print(f"[Data] Memory usage: {ram}% ({memory_info['detail']})")
        
        # 磁盘使用率（所有分区总和）
        disk_info = get_all_disk_usage()
        rom = int(disk_info['percent'])
        print(f"[Data] Disk usage: {rom}% ({disk_info['detail']}) - {disk_info['partitions_count']} partitions")
        
        # CPU信息
        cpu_info = get_cpu_info()
        print(f"[Data] CPU info: {cpu_info['info_string']}")
        
        # 详细信息
        detail = {
            'memory': memory_info['detail'],
            'swap': memory_info['swap_detail'],
            'disk': disk_info['detail'],
            'partitions_count': disk_info['partitions_count'],
            'cpu_info': cpu_info['info_string']
        }
        
        data = {
            'ip': ip_info['ip_display'],  # 显示格式化的IP地址
            'ipv4': ip_info['ipv4'],      # 原始IPv4地址
            'ipv6': ip_info['ipv6'],      # 原始IPv6地址
            'status': status,
            'type': detect_system_type(),
            'location': NODE_LOCATION,
            'uptime': uptime,
            'load': load,
            'net_in': net_in,
            'net_out': net_out,
            'traffic_in': traffic_in,
            'traffic_out': traffic_out,
            'cpu': cpu,
            'ram': ram,
            'rom': rom,
            'detail': detail
        }
        
        print(f"[Data] Collection completed successfully")
        return data
        
    except Exception as e:
        print(f"[ERR] Failed to collect system info: {e}")
        import traceback
        traceback.print_exc()
        
        # 返回默认值，确保程序不会崩溃
        return {
            'ip': 'ipv4:127.0.0.1',
            'ipv4': '127.0.0.1',
            'ipv6': None,
            'status': '异常',
            'type': detect_system_type(),
            'location': NODE_LOCATION,
            'uptime': 0,
            'load': 0.0,
            'net_in': '0B',
            'net_out': '0B',
            'traffic_in': '0M',
            'traffic_out': '0M',
            'cpu': 0,
            'ram': 0,
            'rom': 0,
            'detail': {
                'memory': '0 MiB / 0 MiB',
                'swap': '0 MiB / 0 MiB',
                'disk': '0 GiB / 0 GiB',
                'partitions_count': 0,
                'cpu_info': 'Unknown CPU(1核/1线程)'
            }
        }

# Socket.IO 事件处理器
@sio.event
def connect():
    global _connection_stable, _registration_confirmed
    print(f"[Socket] ✅ Connected to server: {SERVER_URL}")
    _connection_stable = True
    _registration_confirmed = False  # 重置注册状态，等待注册确认
    # 🔧 连接成功后立即注册，避免延迟
    print(f"[Socket] 📝 Sending registration request for node: {NODE_NAME}")
    try:
        sio.emit('register', {'node_name': NODE_NAME})
        print(f"[Socket] 📤 Registration request sent")
    except Exception as reg_error:
        print(f"[Socket] ❌ Failed to send registration: {reg_error}")

@sio.event
def disconnect():
    global _connection_stable, _registration_confirmed
    print(f"[Socket] ❌ Disconnected from server - will attempt reconnection")
    _connection_stable = False
    _registration_confirmed = False

@sio.event
def connect_error(data):
    global _connection_stable, _registration_confirmed
    print(f"[Socket] ❌ Connection error: {data}")
    _connection_stable = False
    _registration_confirmed = False

@sio.event
def reconnect():
    global _connection_stable, _registration_confirmed
    print(f"[Socket] 🔄 Reconnected to server successfully")
    _connection_stable = True
    _registration_confirmed = False  # 重置注册状态
    # 重连后重新注册
    print(f"[Socket] 📝 Sending re-registration request for node: {NODE_NAME}")
    try:
        sio.emit('register', {'node_name': NODE_NAME})
        print(f"[Socket] 📤 Re-registration request sent")
    except Exception as reg_error:
        print(f"[Socket] ❌ Failed to send re-registration: {reg_error}")

@sio.event  
def reconnect_error(data):
    global _connection_stable, _registration_confirmed
    print(f"[Socket] ❌ Reconnection error: {data}")
    _connection_stable = False
    _registration_confirmed = False

@sio.event
def connection_replaced(data):
    print(f"[Socket] ⚠️  Connection replaced by new instance: {data.get('message', 'Unknown reason')}")
    print(f"[Socket] New socket ID: {data.get('new_socket_id', 'Unknown')}") 
    print(f"[Socket] This connection will be closed, allowing new connection to take over")
    # 不需要做任何特殊处理，让Socket.IO自然断开并重连

@sio.event
def registration_success(data):
    global _registration_confirmed
    socket_id = data.get('socket_id', 'Unknown')
    print(f"[Socket] ✅ Node '{NODE_NAME}' registered successfully (socket: {socket_id})")
    _registration_confirmed = True  # 🔧 确认注册成功
    print(f"[Socket] 🎉 Registration confirmed, client is now fully operational")

@sio.event
def registration_failed(data):
    global _registration_confirmed
    error_msg = data.get('error', 'Unknown error')
    print(f"[Socket] ❌ Registration failed: {error_msg}")
    _registration_confirmed = False
    print(f"[Socket] 🔄 Will retry registration...")

@sio.event
def error(data):
    print(f"[Socket] ❌ Socket error: {data}")

# 🔧 增强TCPing请求处理，添加连接状态检查
@sio.event
def request_tcping(data):
    """响应服务器的tcping请求 - 增强错误处理和数据完整性"""
    if not sio.connected:
        print(f"[TCPing] ❌ Socket not connected, ignoring request")
        return
        
    host = data.get('host')
    port = data.get('port')
    request_id = data.get('request_id', 'unknown')
    
    if not host or not port:
        print(f"[TCPing] ❌ 收到无效请求: host={host}, port={port}")
        return
    
    print(f"[TCPing] Server requested ping to {host}:{port} (request_id: {request_id})")
    
    start_time = time.time()
    
    try:
        # 执行tcping并返回结果
        result = perform_tcping(host, port)
        
        processing_time = (time.time() - start_time) * 1000  # 转换为毫秒
        
        # 增强结果数据
        enhanced_result = {
            **result,
            'request_id': request_id,
            'node_name': NODE_NAME,
            'processing_time_ms': round(processing_time, 1),
            'timestamp': int(time.time() * 1000)
        }
        
        print(f"[TCPing] 发送结果: {host}:{port} -> {result['success']} {result.get('latency', 'N/A')}ms (处理耗时: {processing_time:.1f}ms)")
        
        # 🔧 增强发送错误处理，包含连接状态检查
        max_retries = 3
        for retry_count in range(1, max_retries + 1):
            try:
                if not sio.connected:
                    print(f"[TCPing] ❌ Socket disconnected during send, aborting")
                    break
                    
                sio.emit('tcping_result', enhanced_result)
                break  # 发送成功
            except Exception as emit_error:
                print(f"[TCPing] 发送结果失败 (尝试 {retry_count}/{max_retries}): {emit_error}")
                if retry_count < max_retries:
                    time.sleep(0.1)  # 短暂等待后重试
                else:
                    print(f"[TCPing] 发送结果最终失败: {host}:{port}")
        
    except Exception as e:
        print(f"[TCPing] 处理请求异常: {e}")
        # 发送错误结果
        error_result = {
            'host': host,
            'port': port,
            'success': False,
            'error': str(e),
            'request_id': request_id,
            'node_name': NODE_NAME,
            'timestamp': int(time.time() * 1000)
        }
        try:
            if sio.connected:
                sio.emit('tcping_result', error_result)
        except:
            print(f"[TCPing] 无法发送错误结果")

def try_connect():
    """尝试连接到服务器 - 简化版本"""
    try:
        # 🔧 简化：直接检查连接状态
        if sio.connected:
            print(f"[Socket] Already connected, skipping connection attempt")
            return True
            
        print(f"[Socket] 🔄 Attempting to connect to {SERVER_URL}...")
        
        # 🔧 简化：直接连接，不做复杂的清理
        sio.connect(SERVER_URL, wait_timeout=10)  # 10秒超时
        
        # 连接成功
        if sio.connected:
            print(f"[Socket] ✅ Connection established successfully")
            return True
        else:
            print(f"[Socket] ❌ Connection failed - socket not connected after connect()")
            return False
            
    except Exception as e:
        print(f"[Socket] ❌ Connection failed: {e}")
        return False

def send_heartbeat():
    """发送心跳包 - 增强连接检测"""
    if sio.connected:
        try:
            sio.emit('heartbeat', {
                'node_name': NODE_NAME,
                'timestamp': int(time.time() * 1000),
                'version': CLIENT_VERSION
            })
            # 只在调试模式下显示心跳日志
            # print(f"[Socket] ❤️ Heartbeat sent")
        except Exception as e:
            print(f"[Socket] ❌ Heartbeat failed: {e}")
            return False
    return True

def send_data():
    """发送监控数据 - 增强错误处理和连接检查"""
    global _last_successful_data_send, _connection_stable
    
    if not sio.connected:
        print(f"[Client] ⚠️  Socket not connected, skipping data send")
        _connection_stable = False
        return False
        
    if not _registration_confirmed:
        print(f"[Client] ⚠️  Node not registered yet, skipping data send")
        return False
        
    try:
        # 收集系统信息
        data = collect_info()
        
        # 发送数据，包含重试机制
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                if not sio.connected:
                    print(f"[Client] ❌ Socket disconnected during send attempt {attempt}")
                    _connection_stable = False
                    return False
                    
                sio.emit('report_data', data)
                # 只在第一次尝试或重试成功时显示详细日志
                if attempt == 1:
                    print(f"[Client] ✅ Data sent: CPU={data['cpu']}% RAM={data['ram']}% ROM={data['rom']}%")
                elif attempt > 1:
                    print(f"[Client] ✅ Data sent successfully (attempt {attempt})")
                
                # 🔧 记录成功发送时间
                _last_successful_data_send = time.time()
                _connection_stable = True
                return True
                
            except Exception as send_error:
                print(f"[Client] ❌ Failed to send data (attempt {attempt}/{max_retries}): {send_error}")
                _connection_stable = False
                if attempt < max_retries:
                    time.sleep(0.5)  # 等待0.5秒后重试
                else:
                    return False
                    
    except Exception as e:
        print(f"[Client] ❌ Failed to collect or send data: {e}")
        _connection_stable = False
        return False

def test_connection_stability():
    """测试连接稳定性 - 可选的诊断功能"""
    print(f"[Test] 🔧 Testing connection stability...")
    
    # 测试基本连接
    if try_connect():
        print(f"[Test] ✅ Basic connection test passed")
        
        # 测试数据发送
        if send_data():
            print(f"[Test] ✅ Data transmission test passed")
        else:
            print(f"[Test] ❌ Data transmission test failed")
        
        # 测试心跳
        if send_heartbeat():
            print(f"[Test] ✅ Heartbeat test passed")
        else:
            print(f"[Test] ❌ Heartbeat test failed")
        
        # 断开连接进行重连测试
        print(f"[Test] 🔄 Testing reconnection mechanism...")
        try:
            sio.disconnect()
            time.sleep(2)  # 等待2秒
            
            if try_connect():
                print(f"[Test] ✅ Reconnection test passed")
            else:
                print(f"[Test] ❌ Reconnection test failed")
        except Exception as e:
            print(f"[Test] ❌ Reconnection test error: {e}")
    else:
        print(f"[Test] ❌ Basic connection test failed")
    
    print(f"[Test] 🏁 Connection stability test completed")

def main():
    """主函数 - 简化重连机制，确保Socket隧道稳定性"""
    print(f"[Client] 🚀 B-Server Monitor Client v{CLIENT_VERSION} starting...")
    print(f"[Client] Node Name: {NODE_NAME}")
    print(f"[Client] Server URL: {SERVER_URL}")
    print(f"[Client] Location: {NODE_LOCATION}")
    
    # 🔧 简化参数配置 - 用户建议的简单方案
    data_send_interval = 5          # 5秒发送数据间隔
    heartbeat_interval = 30         # 30秒心跳间隔
    reconnect_interval = 2          # 🔧 简化：2秒重连间隔
    max_reconnect_attempts = 1000   # 🔧 简化：最多1000次重连尝试
    registration_timeout = 10       # 🔧 修复：注册超时时间
    
    # 简化状态跟踪变量
    last_data_send = 0
    last_heartbeat = 0
    last_registration_attempt = 0
    reconnect_count = 0             # 🔧 简化：重连计数器
    
    # 🔧 第一次连接尝试
    print(f"[Client] 🔄 Initial connection attempt...")
    if try_connect():
        reconnect_count = 0
        last_registration_attempt = time.time()  # 记录注册时间
        print(f"[Client] ✅ Initial connection successful")
    else:
        reconnect_count = 1
        print(f"[Client] ❌ Initial connection failed, will start reconnection attempts")
    
    print(f"[Client] 🔁 Entering main monitoring loop...")
    print(f"[Client] 📋 Reconnect policy: {reconnect_interval}s interval, max {max_reconnect_attempts} attempts")
    
    try:
        while True:
            current_time = time.time()
            
            # 🔧 简化连接检查 - 直接检查Socket状态
            if not sio.connected:
                # Socket断开，立即尝试重连
                if reconnect_count < max_reconnect_attempts:
                    reconnect_count += 1
                    print(f"[Client] 🔄 Reconnection attempt #{reconnect_count}/{max_reconnect_attempts}...")
                    
                    if try_connect():
                        reconnect_count = 0  # 重连成功，重置计数器
                        last_registration_attempt = current_time  # 记录注册时间
                        print(f"[Client] ✅ Reconnection successful, waiting for registration...")
                        # 重连成功后稍微延迟再发送数据
                        last_data_send = current_time + 2  # 2秒后可以发送数据
                        last_heartbeat = current_time + 3  # 3秒后发送心跳
                    else:
                        print(f"[Client] ❌ Reconnection failed, waiting {reconnect_interval}s...")
                        time.sleep(reconnect_interval)
                        continue
                else:
                    # 达到最大重连次数，停止尝试
                    print(f"[Client] 😴 Maximum reconnection attempts ({max_reconnect_attempts}) reached")
                    print(f"[Client] 🛑 Stopping client - please check server connectivity")
                    break
            
            # 🔧 修复：检查注册状态，如果连接但未注册且超时，重新尝试注册
            elif not _registration_confirmed:
                if current_time - last_registration_attempt > registration_timeout:
                    print(f"[Client] ⚠️  Registration timeout, retrying...")
                    try:
                        sio.emit('register', {'node_name': NODE_NAME})
                        last_registration_attempt = current_time
                    except Exception as reg_error:
                        print(f"[Client] ❌ Registration retry failed: {reg_error}")
                        # 注册失败可能是连接问题，下次循环会检测到并重连
            
            # 🔧 发送监控数据 (仅在连接且已注册时)
            if sio.connected and _registration_confirmed and current_time - last_data_send >= data_send_interval:
                last_data_send = current_time
                
                if send_data():
                    # 数据发送成功，连接稳定
                    pass  # _connection_stable在send_data中已设置
                else:
                    # 数据发送失败，可能是连接问题
                    print(f"[Client] ⚠️  Data send failed, connection may be unstable")
            
            # 🔧 发送心跳包 (仅在连接时)
            if sio.connected and current_time - last_heartbeat >= heartbeat_interval:
                last_heartbeat = current_time
                
                if not send_heartbeat():
                    # 心跳失败，可能是连接问题
                    print(f"[Client] ⚠️  Heartbeat failed, connection may be unstable")
            
            # 🔧 简化休眠逻辑
            if sio.connected and _registration_confirmed:
                sleep_time = 1.0  # 连接正常时短休眠
            elif sio.connected:
                sleep_time = 0.5  # 连接但未注册时短休眠，快速检测注册状态
            else:
                sleep_time = 0.5  # 断开连接时短休眠，快速重连
                
            time.sleep(sleep_time)
    except KeyboardInterrupt:
        print(f"\n[Client] 🛑 Keyboard interrupt received")
    except Exception as e:
        print(f"[Client] ❌ Unexpected error in main loop: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理工作
        print(f"[Client] 🧹 Cleaning up...")
        try:
            if sio.connected:
                print(f"[Client] 📡 Disconnecting from server...")
                sio.disconnect()
                time.sleep(1)  # 给断开连接一些时间
        except Exception as cleanup_error:
            print(f"[Client] ⚠️  Cleanup error: {cleanup_error}")
        
        print(f"[Client] 👋 Client stopped")

if __name__ == "__main__":
    main() 