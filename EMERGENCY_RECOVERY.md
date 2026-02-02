# 紧急恢复指南

## ⚠️ 如果root用户被锁定

### 立即恢复步骤

#### 方法1: 使用紧急解锁脚本
```bash
# 如果还能以root身份执行命令
sudo bash emergency_unlock.sh
```

#### 方法2: 手动清除锁定
```bash
# 清除所有用户的失败计数
faillock --reset

# 或者使用pam_tally2
pam_tally2 --reset

# 清除特定用户锁定
faillock --user root --reset
pam_tally2 --user root --reset
```

#### 方法3: 恢复PAM配置
```bash
# 恢复备份文件
cp /etc/pam.d/system-auth.backup /etc/pam.d/system-auth
cp /etc/pam.d/password-auth.backup /etc/pam.d/password-auth

# Ubuntu/Debian系统
cp /etc/pam.d/common-auth.backup /etc/pam.d/common-auth
```

#### 方法4: 单用户模式恢复
1. 重启系统
2. 在GRUB菜单中选择内核
3. 按'e'编辑启动参数
4. 在linux行末尾添加 `single` 或 `init=/bin/bash`
5. 按Ctrl+X启动
6. 执行恢复命令

### 预防措施

#### 1. 使用root白名单配置
在程序中选择"安全配置 - root用户白名单"选项

#### 2. 测试配置
```bash
# 在应用配置前，先在测试环境验证
# 或者保持一个SSH连接不断开
```

#### 3. 定期备份
```bash
# 手动备份PAM文件
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.manual.backup
cp /etc/pam.d/password-auth /etc/pam.d/password-auth.manual.backup
```

## 🔧 程序新功能

### 1. 紧急解锁功能
- 主菜单选择"4. 紧急解锁用户账户"
- 自动清除所有用户的失败计数器
- 重置PAM锁定状态

### 2. Root白名单选项
- 配置锁定策略时选择"安全配置"
- root用户不会被锁定
- 推荐用于生产环境

### 3. 智能配置检测
- 自动检测系统类型
- 选择合适的PAM模块
- 生成兼容的配置

## 🚨 故障排除

### 问题1: 无法SSH连接
**原因**: SSH登录被锁定
**解决**: 
1. 使用控制台登录
2. 执行 `faillock --reset`
3. 或恢复PAM配置

### 问题2: 本地登录也被锁定
**原因**: 本地认证被锁定
**解决**:
1. 单用户模式启动
2. 恢复PAM配置文件
3. 重启系统

### 问题3: 服务无法启动
**原因**: PAM配置语法错误
**解决**:
1. 检查PAM文件语法
2. 恢复备份文件
3. 重启相关服务

## 📋 检查清单

### 配置前检查
- [ ] 确保有控制台访问权限
- [ ] 保持至少一个SSH连接
- [ ] 备份当前PAM配置
- [ ] 在测试环境先验证

### 配置后检查
- [ ] 测试新SSH连接
- [ ] 测试本地登录
- [ ] 验证root用户状态
- [ ] 检查系统日志

### 紧急情况检查
- [ ] 尝试控制台登录
- [ ] 检查PAM配置文件
- [ ] 查看系统日志
- [ ] 准备单用户模式恢复

## 📞 联系支持

如果遇到无法解决的问题:
1. 保存错误日志
2. 记录系统信息
3. 准备PAM配置文件
4. 联系系统管理员

## 🔄 配置建议

### 生产环境
- 始终使用root白名单
- 设置合理的失败次数(3-5次)
- 设置适中的锁定时间(5-15分钟)
- 定期备份配置

### 测试环境
- 可以测试标准配置
- 设置较短的锁定时间
- 保持控制台访问
- 及时清除测试数据

### 开发环境
- 使用宽松的配置
- 或者不启用锁定策略
- 专注于功能开发
- 避免影响开发效率