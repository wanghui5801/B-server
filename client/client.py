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

# 可根据实际情况修改
SERVER_URL = 'http://localhost:3001'  # Socket.IO服务器地址
NODE_NAME = socket.gethostname()  # 使用主机名作为节点名，可以手动修改
NODE_LOCATION = '本地'  # 位置

# 网络流量统计（用于计算速率）
last_net_io = None
last_time = None

# 防止重复发送数据
last_send_time = 0
SEND_COOLDOWN = 2  # 2秒冷却时间

# 创建Socket.IO客户端
sio = socketio.Client()

# 缓存系统类型检测结果
_cached_system_type = None

# 缓存CPU信息（Windows特有问题的解决方案）
_cached_cpu_info = None

def detect_system_type():
    """智能检测系统类型"""
    global _cached_system_type
    
    # 如果已经检测过，直接返回缓存结果
    if _cached_system_type is not None:
        return _cached_system_type
    
    try:
        print("[INFO] 正在检测系统类型...")
        system_type = "DS"  # 默认类型改为DS（物理机）
        
        # 检测容器环境
        if os.path.exists('/.dockerenv'):
            _cached_system_type = "Docker"
            print(f"[INFO] 检测到系统类型: {_cached_system_type}")
            return _cached_system_type
        
        # 检查 cgroup 来检测容器
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup_content = f.read()
                if 'docker' in cgroup_content.lower():
                    _cached_system_type = "Docker"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
                elif 'lxc' in cgroup_content.lower():
                    _cached_system_type = "LXC"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
                elif 'k8s' in cgroup_content.lower() or 'kubernetes' in cgroup_content.lower():
                    _cached_system_type = "Kubernetes"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
                elif 'podman' in cgroup_content.lower():
                    _cached_system_type = "Podman"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
                elif 'containerd' in cgroup_content.lower():
                    _cached_system_type = "Containerd"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type}")
                    return _cached_system_type
        except (FileNotFoundError, PermissionError):
            pass
        
        # 检测更多容器特征
        if os.path.exists('/run/.containerenv'):
            _cached_system_type = "Podman"
            print(f"[INFO] 检测到系统类型: {_cached_system_type}")
            return _cached_system_type
        
        # 通过systemd-detect-virt命令检测（最准确的方法）
        try:
            result = subprocess.run(['systemd-detect-virt'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                virt_type = result.stdout.strip().lower()
                if virt_type != 'none':
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
                        'qnx': 'QNX',
                        'amazon': 'Amazon',
                        'podman': 'Podman'
                    }
                    _cached_system_type = virt_map.get(virt_type, virt_type.upper())
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过systemd-detect-virt)")
                    return _cached_system_type
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        # 检测虚拟化环境 - 通过DMI信息
        try:
            # 检查系统制造商
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                vendor = f.read().strip().lower()
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
        
        # 检查CPU型号来推断虚拟化
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read().lower()
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
        
        # 检查网络接口名称（一些虚拟化平台会有特殊前缀）
        try:
            interfaces = os.listdir('/sys/class/net/')
            for iface in interfaces:
                if iface.startswith('veth'):
                    _cached_system_type = "容器环境"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过网络接口)")
                    return _cached_system_type
                elif iface.startswith('docker'):
                    _cached_system_type = "Docker"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过网络接口)")
                    return _cached_system_type
                elif iface.startswith('lxc'):
                    _cached_system_type = "LXC"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过网络接口)")
                    return _cached_system_type
                elif iface.startswith('vmbr'):
                    _cached_system_type = "Proxmox VE"
                    print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过网络接口)")
                    return _cached_system_type
        except:
            pass
        
        # 检查特殊文件和目录
        special_paths = {
            '/proc/xen': 'Xen',
            '/sys/bus/xen': 'Xen',
            '/proc/vz': 'OpenVZ',
            '/proc/bc': 'OpenVZ',
            '/sys/hypervisor': 'Hypervisor',
            '/dev/vmware': 'VMware',
            '/proc/vmware': 'VMware',
            '/sys/class/dmi/id/product_serial': None  # 用于进一步检查
        }
        
        for path, virt_type in special_paths.items():
            if os.path.exists(path) and virt_type:
                _cached_system_type = virt_type
                print(f"[INFO] 检测到系统类型: {_cached_system_type} (通过特殊路径: {path})")
                return _cached_system_type
        
        # 检查串口号来判断云服务商
        try:
            with open('/sys/class/dmi/id/product_serial', 'r') as f:
                serial = f.read().strip().lower()
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
    global last_net_io, last_time
    try:
        current_net_io = psutil.net_io_counters()
        current_time = time.time()
        
        if last_net_io is None or last_time is None:
            last_net_io = current_net_io
            last_time = current_time
            return "0B", "0B"
        
        time_delta = current_time - last_time
        if time_delta <= 0:
            return "0B", "0B"
            
        # 计算每秒字节数
        bytes_sent_per_sec = max(0, (current_net_io.bytes_sent - last_net_io.bytes_sent) / time_delta)
        bytes_recv_per_sec = max(0, (current_net_io.bytes_recv - last_net_io.bytes_recv) / time_delta)
        
        # 更新全局变量
        last_net_io = current_net_io
        last_time = current_time
        
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
        
        return format_bytes(bytes_recv_per_sec), format_bytes(bytes_sent_per_sec)
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

def find_tcping_executable():
    """查找tcping可执行文件的位置 - 改进的跨平台版本"""
    
    # 首先尝试使用 shutil.which() 在PATH中查找
    tcping_path = shutil.which('tcping')
    if tcping_path:
        print(f"[TCPing] Found tcping in PATH: {tcping_path}")
        return tcping_path
    
    # 如果在PATH中找不到，尝试常见位置
    possible_paths = []
    
    if platform.system() == 'Windows':
        # Windows可能的路径
        possible_paths = [
            # 用户本地安装位置
            os.path.join(os.path.expanduser('~'), '.local', 'bin', 'tcping.exe'),
            os.path.join(os.path.expanduser('~'), '.local', 'bin', 'tcping'),
        ]
        
        # 尝试找到Python安装目录的Scripts文件夹
        python_paths = []
        for python_cmd in ['python', 'python3', 'py']:
            python_exe = shutil.which(python_cmd)
            if python_exe:
                python_dir = os.path.dirname(python_exe)
                scripts_dir = os.path.join(python_dir, 'Scripts')
                if os.path.isdir(scripts_dir):
                    python_paths.extend([
                        os.path.join(scripts_dir, 'tcping.exe'),
                        os.path.join(scripts_dir, 'tcping'),
                    ])
        
        possible_paths.extend(python_paths)
        
        # 添加更多Windows常见位置
        possible_paths.extend([
            # AppData位置
            os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Programs', 'Python', 'Scripts', 'tcping.exe'),
            os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Python', 'Scripts', 'tcping.exe'),
            # 当前Python环境的Scripts目录
            os.path.join(os.path.dirname(shutil.which('python') or ''), 'Scripts', 'tcping.exe'),
            os.path.join(os.path.dirname(shutil.which('python') or ''), 'Scripts', 'tcping'),
        ])
    else:
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
    
    # 最后尝试直接使用 'tcping' 命令（也许在PATH中但shutil.which没找到）
    try:
        result = subprocess.run(['tcping', '--help'], capture_output=True, timeout=3)
        if result.returncode in [0, 1] or b'usage' in result.stdout.lower() or b'usage' in result.stderr.lower():
            print(f"[TCPing] Using direct 'tcping' command")
            return 'tcping'
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        pass
    
    print(f"[TCPing] tcping executable not found in any common locations")
    return None

def perform_tcping(host, port):
    """执行tcping命令并返回结果 - 增强的跨平台版本"""
    try:
        # 验证输入参数
        if not host or not port:
            print(f"[TCPing] ✗ 无效参数: host={host}, port={port}")
            return {
                'host': host or 'unknown',
                'port': port or 0,
                'latency': None,  # 无效参数时应该返回None而不是0
                'success': False
            }
        
        # 查找tcping可执行文件
        tcping_cmd = find_tcping_executable()
        if not tcping_cmd:
            print(f"[TCPing] ✗ tcping executable not found")
            print(f"[TCPing] ✗ Please install tcping: pip install tcping")
            print(f"[TCPing] ✗ Or ensure tcping is in your PATH")
            return {
                'host': host,
                'port': port,
                'latency': None,
                'success': False
            }
        
        # 构建命令
        cmd = [tcping_cmd, str(host), '-p', str(port), '-c', '1', '--report']
        
        print(f"[TCPing] Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            output = result.stdout.strip()
            print(f"[TCPing] Output: {output}")
            
            output_lower = output.lower()
            
            # 解析输出获取延迟时间
            import re
            
            # 首先检查是否连接成功（优先检查成功指示符）
            if 'connected' in output_lower:
                # 检查具体的失败指示符（更精确的检查）
                specific_failure_indicators = ['time out!', 'timeout!', 'connection refused', 'unreachable', 'no route']
                
                # 如果输出包含具体的失败指示符，视为失败
                if any(indicator in output_lower for indicator in specific_failure_indicators):
                    print(f"[TCPing] ✗ Failed (detected specific failure in output): {host}:{port}")
                    return {
                        'host': host,
                        'port': port,
                        'latency': None,
                        'success': False
                    }
                
                # 尝试多种正则表达式模式来提取延迟时间
                patterns = [
                    r'time=(\d+\.?\d*)\s*ms',  # time=1.78 ms
                    r'time:\s*(\d+\.?\d*)\s*ms',  # time: 1.78 ms
                    r'(\d+\.?\d*)\s*ms'  # 任何数字+ms的组合
                ]
                
                latency = None
                
                for pattern in patterns:
                    matches = re.findall(pattern, output)
                    if matches:
                        # 如果找到多个匹配，取第一个（通常是实际的延迟时间）
                        latency = float(matches[0])
                        break
                
                print(f"[TCPing Debug] Found 'connected' in output")
                print(f"[TCPing Debug] Extracted latency: {latency}")
                
                if latency is not None and latency > 0:
                    print(f"[TCPing] ✓ Success: {host}:{port} - {latency}ms")
                    return {
                        'host': host,
                        'port': port,
                        'latency': latency,
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
                            'success': False
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
                        'success': False
                    }
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            print(f"[TCPing] ✗ Failed: {host}:{port} - {error_msg}")
            return {
                'host': host,
                'port': port,
                'latency': None,  # 失败时应该返回None而不是0
                'success': False
            }
    
    except subprocess.TimeoutExpired:
        print(f"[TCPing] ✗ Timeout: {host}:{port}")
        return {
            'host': host,
            'port': port,
            'latency': None,  # 超时时应该返回None而不是0
            'success': False
        }
    except Exception as e:
        print(f"[TCPing] ✗ Exception: {host}:{port} - {str(e)}")
        return {
            'host': host,
            'port': port,
            'latency': None,  # 异常时应该返回None而不是0
            'success': False
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
    print(f"[Socket] Connected to server: {SERVER_URL}")
    print(f"[Socket] Attempting to register node: {NODE_NAME}")
    # 尝试注册节点
    sio.emit('register', {'node_name': NODE_NAME})

@sio.event
def disconnect():
    print(f"[Socket] Disconnected from server")

@sio.event
def registration_success(data):
    print(f"[Socket] ✓ Registration successful: {data['message']}")
    print(f"[Socket] Node '{NODE_NAME}' is now authorized and connected")
    # 注册成功后不立即发送数据，等待服务器请求

@sio.event
def registration_failed(data):
    print(f"[Socket] ✗ Registration failed: {data['error']}")
    print(f"[Socket] Please ensure node '{NODE_NAME}' is added in the admin panel")
    print(f"[Socket] Retrying in 10 seconds...")

@sio.event
def error(data):
    print(f"[Socket] Error: {data['error']}")

@sio.event
def request_update(data):
    """响应服务器的更新请求"""
    print(f"[Socket] Server requested data update")
    send_data()

@sio.event
def request_tcping(data):
    """响应服务器的tcping请求"""
    host = data.get('host')
    port = data.get('port')
    print(f"[TCPing] Server requested ping to {host}:{port}")
    
    # 执行tcping并返回结果
    result = perform_tcping(host, port)
    sio.emit('tcping_result', result)

def try_connect():
    """尝试连接到服务器"""
    try:
        sio.connect(SERVER_URL)
        return True
    except Exception as e:
        print(f"[Socket] Connection failed: {e}")
        return False

def send_data():
    """发送系统数据"""
    global last_send_time
    
    current_time = time.time()
    time_since_last = current_time - last_send_time
    
    print(f"[Data] Send request - Time since last send: {time_since_last:.1f}s")
    
    if time_since_last < SEND_COOLDOWN:
        print(f"[Data] ⏸ Skipped - cooling down ({SEND_COOLDOWN - time_since_last:.1f}s remaining)")
        return False
    
    if sio.connected:
        data = collect_info()
        sio.emit('report_data', data)
        last_send_time = current_time
        print(f"[Data] ✓ Sent: CPU={data['cpu']}% RAM={data['ram']}% ROM={data['rom']}% ({data['detail']['partitions_count']} disks)")
        return True
    else:
        print(f"[Data] ✗ Skipped - not connected")
        return False

def main():
    print(f"Starting monitoring client for node: {NODE_NAME}")
    print(f"Server: {SERVER_URL}")
    print("=" * 50)
    print(f"IMPORTANT: Make sure node '{NODE_NAME}' is added in admin panel first!")
    print("=" * 50)
    
    retry_count = 0
    max_retries = 5
    base_retry_delay = 10
    
    while True:
        try:
            # 如果未连接，尝试连接
            if not sio.connected:
                print(f"[Socket] Attempting to connect (attempt {retry_count + 1})...")
                if try_connect():
                    # 连接成功，重置重试计数
                    retry_count = 0
                    print(f"[Socket] Connection established, waiting for registration...")
                    time.sleep(3)  # 给注册过程更多时间
                else:
                    retry_count += 1
                    if retry_count >= max_retries:
                        # 使用指数退避算法
                        delay = min(base_retry_delay * (2 ** (retry_count - max_retries)), 300)  # 最大5分钟
                        print(f"[Socket] Max retries exceeded, backing off for {delay}s...")
                        time.sleep(delay)
                        retry_count = 0  # 重置计数，重新开始
                    else:
                        delay = base_retry_delay
                        print(f"[Socket] Connection failed, retrying in {delay} seconds...")
                        time.sleep(delay)
                    continue
            
            # 如果已连接，保持连接状态，等待服务器请求更新
            if sio.connected:
                # 每10秒检查一次连接状态
                time.sleep(10)
            else:
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n[Main] Received interrupt signal, shutting down...")
            break
        except Exception as e:
            print(f"[Main] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(5)
    
    # 清理连接
    try:
        if sio.connected:
            print("[Main] Disconnecting from server...")
            sio.disconnect()
            time.sleep(1)  # 给断开连接一些时间
    except Exception as e:
        print(f"[Main] Error during cleanup: {e}")
    
    print(f"[Main] Client stopped")

if __name__ == '__main__':
    main() 