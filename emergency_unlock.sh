#!/bin/bash

# 紧急解锁脚本 - 当root被锁定时使用
# 使用方法: sudo bash emergency_unlock.sh

echo "=== Linux Security Check 紧急解锁脚本 ==="
echo "此脚本将清除所有用户的登录失败计数器"
echo ""

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "错误: 请以root权限运行此脚本"
    echo "使用: sudo bash emergency_unlock.sh"
    exit 1
fi

echo "正在执行紧急解锁..."

# 方法1: 使用faillock清除计数器
echo "1. 尝试使用faillock清除计数器..."
if command -v faillock >/dev/null 2>&1; then
    faillock --reset
    echo "   faillock计数器已清除"
else
    echo "   faillock命令不存在，跳过"
fi

# 方法2: 使用pam_tally2清除计数器
echo "2. 尝试使用pam_tally2清除计数器..."
if command -v pam_tally2 >/dev/null 2>&1; then
    pam_tally2 --reset
    echo "   pam_tally2计数器已清除"
else
    echo "   pam_tally2命令不存在，跳过"
fi

# 方法3: 使用pam_tally清除计数器
echo "3. 尝试使用pam_tally清除计数器..."
if command -v pam_tally >/dev/null 2>&1; then
    pam_tally --reset
    echo "   pam_tally计数器已清除"
else
    echo "   pam_tally命令不存在，跳过"
fi

# 方法4: 清除特定用户的锁定
echo "4. 清除特定用户锁定..."
USERS=("root" "admin" "administrator")

for user in "${USERS[@]}"; do
    if id "$user" >/dev/null 2>&1; then
        echo "   清除用户 $user 的锁定..."
        
        # faillock
        if command -v faillock >/dev/null 2>&1; then
            faillock --user "$user" --reset 2>/dev/null
        fi
        
        # pam_tally2
        if command -v pam_tally2 >/dev/null 2>&1; then
            pam_tally2 --user "$user" --reset 2>/dev/null
        fi
        
        # pam_tally
        if command -v pam_tally >/dev/null 2>&1; then
            pam_tally --user "$user" --reset 2>/dev/null
        fi
    fi
done

# 方法5: 删除锁定文件（如果存在）
echo "5. 清除锁定文件..."
LOCK_DIRS=("/var/run/faillock" "/var/lib/faillock" "/tmp")

for dir in "${LOCK_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "   清除 $dir 中的锁定文件..."
        rm -f "$dir"/root 2>/dev/null
        rm -f "$dir"/* 2>/dev/null
    fi
done

# 方法6: 重启相关服务
echo "6. 重启相关服务..."
systemctl restart systemd-logind 2>/dev/null && echo "   systemd-logind已重启" || echo "   systemd-logind重启失败或不存在"

echo ""
echo "=== 紧急解锁完成 ==="
echo "建议操作:"
echo "1. 立即测试root登录是否正常"
echo "2. 检查PAM配置是否正确"
echo "3. 考虑配置root白名单以避免再次被锁"
echo ""
echo "如果问题仍然存在，请检查以下文件:"
echo "- /etc/pam.d/system-auth"
echo "- /etc/pam.d/password-auth"
echo "- /etc/pam.d/common-auth"
echo ""
echo "可以使用备份文件恢复:"
echo "- cp /etc/pam.d/system-auth.backup /etc/pam.d/system-auth"
echo "- cp /etc/pam.d/password-auth.backup /etc/pam.d/password-auth"