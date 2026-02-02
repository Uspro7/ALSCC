package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// 系统类型
type SystemType int

const (
	SystemUnknown SystemType = iota
	SystemCentOS
	SystemUbuntu
	SystemDebian
	SystemKylin
	SystemEuler
	SystemRHEL
	SystemFedora
	SystemSUSE
	SystemArch
	SystemAlpine
)

// 系统信息
type SystemInfo struct {
	Type        SystemType
	Name        string
	Version     string
	PamAuthFile string
	PamPassFile string
	UseFaillock bool
	UseTally2   bool
}

// 检测系统类型
func detectSystemType() (*SystemInfo, error) {
	info := &SystemInfo{
		Type:        SystemUnknown,
		PamAuthFile: "/etc/pam.d/system-auth",
		PamPassFile: "/etc/pam.d/password-auth",
		UseFaillock: true,
		UseTally2:   false,
	}
	
	// 检查 /etc/os-release
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		osRelease := string(content)
		
		if strings.Contains(strings.ToLower(osRelease), "centos") {
			info.Type = SystemCentOS
			info.Name = "CentOS"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "ubuntu") {
			info.Type = SystemUbuntu
			info.Name = "Ubuntu"
			info.PamAuthFile = "/etc/pam.d/common-auth"
			info.PamPassFile = "/etc/pam.d/common-auth"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "debian") {
			info.Type = SystemDebian
			info.Name = "Debian"
			info.PamAuthFile = "/etc/pam.d/common-auth"
			info.PamPassFile = "/etc/pam.d/common-auth"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "kylin") {
			info.Type = SystemKylin
			info.Name = "Kylin"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "euler") || strings.Contains(strings.ToLower(osRelease), "openeuler") {
			info.Type = SystemEuler
			info.Name = "openEuler"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "red hat") || strings.Contains(strings.ToLower(osRelease), "rhel") {
			info.Type = SystemRHEL
			info.Name = "RHEL"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "fedora") {
			info.Type = SystemFedora
			info.Name = "Fedora"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "suse") || strings.Contains(strings.ToLower(osRelease), "opensuse") {
			info.Type = SystemSUSE
			info.Name = "SUSE"
			info.PamAuthFile = "/etc/pam.d/common-auth"
			info.PamPassFile = "/etc/pam.d/common-auth"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "arch") {
			info.Type = SystemArch
			info.Name = "Arch Linux"
			info.PamAuthFile = "/etc/pam.d/system-login"
			info.PamPassFile = "/etc/pam.d/system-login"
			info.UseFaillock = true
		} else if strings.Contains(strings.ToLower(osRelease), "alpine") {
			info.Type = SystemAlpine
			info.Name = "Alpine Linux"
			info.PamAuthFile = "/etc/pam.d/base-auth"
			info.PamPassFile = "/etc/pam.d/base-auth"
			info.UseFaillock = false
			info.UseTally2 = true
		}
		
		// 提取版本信息
		versionRegex := regexp.MustCompile(`VERSION_ID="([^"]+)"`)
		if matches := versionRegex.FindStringSubmatch(osRelease); len(matches) > 1 {
			info.Version = matches[1]
		}
	}
	
	// 如果无法从os-release检测，尝试其他方法
	if info.Type == SystemUnknown {
		// 检查 /etc/redhat-release
		if content, err := os.ReadFile("/etc/redhat-release"); err == nil {
			release := strings.ToLower(string(content))
			if strings.Contains(release, "centos") {
				info.Type = SystemCentOS
				info.Name = "CentOS"
			} else if strings.Contains(release, "red hat") {
				info.Type = SystemRHEL
				info.Name = "RHEL"
			} else if strings.Contains(release, "fedora") {
				info.Type = SystemFedora
				info.Name = "Fedora"
			}
		}
		
		// 检查 /etc/debian_version
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			if info.Type == SystemUnknown {
				info.Type = SystemDebian
				info.Name = "Debian"
				info.PamAuthFile = "/etc/pam.d/common-auth"
				info.PamPassFile = "/etc/pam.d/common-auth"
			}
		}
	}
	
	// 检查PAM文件是否存在，如果不存在则尝试其他路径
	if _, err := os.Stat(info.PamAuthFile); err != nil {
		alternativePaths := []string{
			"/etc/pam.d/system-auth",
			"/etc/pam.d/common-auth",
			"/etc/pam.d/system-login",
			"/etc/pam.d/login",
		}
		
		for _, path := range alternativePaths {
			if _, err := os.Stat(path); err == nil {
				info.PamAuthFile = path
				break
			}
		}
	}
	
	if _, err := os.Stat(info.PamPassFile); err != nil {
		alternativePaths := []string{
			"/etc/pam.d/password-auth",
			"/etc/pam.d/common-auth",
			"/etc/pam.d/system-login",
			"/etc/pam.d/sshd",
		}
		
		for _, path := range alternativePaths {
			if _, err := os.Stat(path); err == nil {
				info.PamPassFile = path
				break
			}
		}
	}
	
	return info, nil
}

// 检查当前锁定策略配置
func checkLockPolicy(m *model) error {
	// 检测系统类型
	sysInfo, err := detectSystemType()
	if err != nil {
		return fmt.Errorf("检测系统类型失败: %v", err)
	}
	
	// 保存系统信息到model中
	m.lockPolicyFiles = []string{sysInfo.PamAuthFile, sysInfo.PamPassFile}
	
	// 检查本地认证文件
	authAttempts, authTime, err := parsePamConfig(sysInfo.PamAuthFile, sysInfo)
	if err != nil {
		return fmt.Errorf("检查%s失败: %v", sysInfo.PamAuthFile, err)
	}
	
	// 检查密码认证文件
	passAttempts, passTime, err := parsePamConfig(sysInfo.PamPassFile, sysInfo)
	if err != nil {
		// 如果是同一个文件，不重复报错
		if sysInfo.PamAuthFile != sysInfo.PamPassFile {
			return fmt.Errorf("检查%s失败: %v", sysInfo.PamPassFile, err)
		}
	}
	
	// 使用较严格的配置作为当前配置
	if authAttempts > 0 && passAttempts > 0 {
		if authAttempts <= passAttempts {
			m.currentLockAttempts = authAttempts
			m.currentLockTime = authTime
		} else {
			m.currentLockAttempts = passAttempts
			m.currentLockTime = passTime
		}
	} else if authAttempts > 0 {
		m.currentLockAttempts = authAttempts
		m.currentLockTime = authTime
	} else if passAttempts > 0 {
		m.currentLockAttempts = passAttempts
		m.currentLockTime = passTime
	} else {
		m.currentLockAttempts = 0
		m.currentLockTime = 0
	}
	
	// 添加系统信息到消息中
	if m.currentLockAttempts == 0 {
		m.message = fmt.Sprintf("检测到系统: %s %s", sysInfo.Name, sysInfo.Version)
	} else {
		m.message = fmt.Sprintf("检测到系统: %s %s - 当前已配置锁定策略", sysInfo.Name, sysInfo.Version)
	}
	
	return nil
}

// 解析PAM配置文件
func parsePamConfig(filename string, sysInfo *SystemInfo) (int, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	
	// 查找pam_faillock或pam_tally2配置
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// 跳过注释行
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		
		// 根据系统类型检查不同的PAM模块
		if sysInfo.UseFaillock && strings.Contains(line, "pam_faillock") {
			attempts, lockTime := parseFaillockLine(line)
			if attempts > 0 {
				return attempts, lockTime, nil
			}
		}
		
		if sysInfo.UseTally2 && strings.Contains(line, "pam_tally2") {
			attempts, lockTime := parseTally2Line(line)
			if attempts > 0 {
				return attempts, lockTime, nil
			}
		}
		
		// 检查其他可能的锁定模块
		if strings.Contains(line, "pam_tally") && !strings.Contains(line, "pam_tally2") {
			attempts, lockTime := parseTallyLine(line)
			if attempts > 0 {
				return attempts, lockTime, nil
			}
		}
		
		// 检查pam_cracklib或pam_pwquality中的锁定配置
		if strings.Contains(line, "pam_cracklib") || strings.Contains(line, "pam_pwquality") {
			attempts, lockTime := parseQualityLine(line)
			if attempts > 0 {
				return attempts, lockTime, nil
			}
		}
	}
	
	return 0, 0, scanner.Err()
}

// 解析pam_faillock配置行
func parseFaillockLine(line string) (int, int) {
	attempts := 0
	lockTime := 0
	
	// 查找deny参数
	denyRegex := regexp.MustCompile(`deny=(\d+)`)
	if matches := denyRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			attempts = val
		}
	}
	
	// 查找unlock_time参数
	unlockRegex := regexp.MustCompile(`unlock_time=(\d+)`)
	if matches := unlockRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			lockTime = val / 60 // 转换为分钟
		}
	}
	
	return attempts, lockTime
}

// 解析pam_tally2配置行
func parseTally2Line(line string) (int, int) {
	attempts := 0
	lockTime := 0
	
	// 查找deny参数
	denyRegex := regexp.MustCompile(`deny=(\d+)`)
	if matches := denyRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			attempts = val
		}
	}
	
	// 查找unlock_time参数
	unlockRegex := regexp.MustCompile(`unlock_time=(\d+)`)
	if matches := unlockRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			lockTime = val / 60 // 转换为分钟
		}
	}
	
	return attempts, lockTime
}

// 应用锁定策略配置
func applyLockPolicy(m *model) error {
	// 检测系统类型
	sysInfo, err := detectSystemType()
	if err != nil {
		return fmt.Errorf("检测系统类型失败: %v", err)
	}
	
	// 备份原文件
	err = backupPamFiles(sysInfo)
	if err != nil {
		return fmt.Errorf("备份PAM文件失败: %v", err)
	}
	
	// 根据系统类型配置不同的文件
	files := []string{sysInfo.PamAuthFile}
	if sysInfo.PamPassFile != sysInfo.PamAuthFile {
		files = append(files, sysInfo.PamPassFile)
	}
	
	for _, file := range files {
		err = configurePamFile(file, m.newLockAttempts, m.newLockTime, sysInfo, m)
		if err != nil {
			return fmt.Errorf("配置%s失败: %v", file, err)
		}
	}
	
	// 更新当前配置
	m.currentLockAttempts = m.newLockAttempts
	m.currentLockTime = m.newLockTime
	
	return nil
}

// 备份PAM文件
func backupPamFiles(sysInfo *SystemInfo) error {
	files := []string{sysInfo.PamAuthFile}
	if sysInfo.PamPassFile != sysInfo.PamAuthFile {
		files = append(files, sysInfo.PamPassFile)
	}
	
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			backupFile := file + ".backup"
			cmd := exec.Command("cp", file, backupFile)
			if err := cmd.Run(); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// 配置PAM文件
func configurePamFile(filename string, attempts, lockTimeMinutes int, sysInfo *SystemInfo, m *model) error {
	// 读取原文件
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	
	lines := strings.Split(string(content), "\n")
	var newLines []string
	lockConfigAdded := false
	
	lockTimeSeconds := lockTimeMinutes * 60
	
	// 根据系统类型生成不同的配置
	var lockConfig []string
	if sysInfo.UseFaillock {
		if m.rootWhitelist {
			lockConfig = generateFaillockConfigWithRootWhitelist(attempts, lockTimeSeconds)
		} else {
			lockConfig = generateFaillockConfig(attempts, lockTimeSeconds)
		}
	} else if sysInfo.UseTally2 {
		if m.rootWhitelist {
			lockConfig = generateTally2ConfigWithRootWhitelist(attempts, lockTimeSeconds)
		} else {
			lockConfig = generateTally2Config(attempts, lockTimeSeconds)
		}
	} else {
		// 默认使用faillock
		if m.rootWhitelist {
			lockConfig = generateFaillockConfigWithRootWhitelist(attempts, lockTimeSeconds)
		} else {
			lockConfig = generateFaillockConfig(attempts, lockTimeSeconds)
		}
	}
	
	for _, line := range lines {
		// 跳过已存在的锁定配置
		if strings.Contains(line, "pam_faillock") || 
		   strings.Contains(line, "pam_tally2") || 
		   strings.Contains(line, "pam_tally") {
			continue
		}
		
		// 根据不同系统在合适位置插入配置
		insertPoint := false
		switch sysInfo.Type {
		case SystemUbuntu, SystemDebian, SystemSUSE:
			// 在pam_unix.so之前插入
			if strings.Contains(line, "auth") && strings.Contains(line, "pam_unix.so") && !lockConfigAdded {
				insertPoint = true
			}
		case SystemArch:
			// 在pam_unix.so之前插入
			if strings.Contains(line, "auth") && strings.Contains(line, "pam_unix.so") && !lockConfigAdded {
				insertPoint = true
			}
		case SystemAlpine:
			// 在pam_unix.so之前插入
			if strings.Contains(line, "auth") && strings.Contains(line, "pam_unix.so") && !lockConfigAdded {
				insertPoint = true
			}
		default:
			// CentOS, RHEL, Fedora, Kylin, Euler等
			if strings.Contains(line, "auth") && strings.Contains(line, "required") && 
			   strings.Contains(line, "pam_env.so") && !lockConfigAdded {
				insertPoint = true
			}
		}
		
		if insertPoint {
			// 先添加原行
			newLines = append(newLines, line)
			// 再添加锁定配置
			newLines = append(newLines, lockConfig...)
			lockConfigAdded = true
			continue
		}
		
		newLines = append(newLines, line)
	}
	
	// 如果没有找到合适的位置，在文件开头添加
	if !lockConfigAdded {
		var finalLines []string
		finalLines = append(finalLines, lockConfig...)
		finalLines = append(finalLines, newLines...)
		newLines = finalLines
	}
	
	// 写入文件
	newContent := strings.Join(newLines, "\n")
	return os.WriteFile(filename, []byte(newContent), 0644)
}

// 生成faillock配置
func generateFaillockConfig(attempts, lockTimeSeconds int) []string {
	return []string{
		fmt.Sprintf("auth        required      pam_faillock.so preauth deny=%d unlock_time=%d even_deny_root", attempts, lockTimeSeconds),
		fmt.Sprintf("auth        [default=die] pam_faillock.so authfail deny=%d unlock_time=%d even_deny_root", attempts, lockTimeSeconds),
		fmt.Sprintf("auth        sufficient    pam_faillock.so authsucc deny=%d unlock_time=%d", attempts, lockTimeSeconds),
		"# Account unlock for root user",
		"account     required      pam_faillock.so",
	}
}

// 生成faillock配置（root白名单版本）
func generateFaillockConfigWithRootWhitelist(attempts, lockTimeSeconds int) []string {
	return []string{
		fmt.Sprintf("auth        required      pam_faillock.so preauth deny=%d unlock_time=%d", attempts, lockTimeSeconds),
		fmt.Sprintf("auth        [default=die] pam_faillock.so authfail deny=%d unlock_time=%d", attempts, lockTimeSeconds),
		fmt.Sprintf("auth        sufficient    pam_faillock.so authsucc deny=%d unlock_time=%d", attempts, lockTimeSeconds),
		"# Account unlock (root is not affected)",
		"account     required      pam_faillock.so",
	}
}

// 生成tally2配置
func generateTally2Config(attempts, lockTimeSeconds int) []string {
	return []string{
		fmt.Sprintf("auth        required      pam_tally2.so deny=%d unlock_time=%d", attempts, lockTimeSeconds),
		"account     required      pam_tally2.so",
	}
}

// 生成tally2配置（root白名单版本）
func generateTally2ConfigWithRootWhitelist(attempts, lockTimeSeconds int) []string {
	return []string{
		fmt.Sprintf("auth        required      pam_tally2.so deny=%d unlock_time=%d no_lock_time", attempts, lockTimeSeconds),
		"account     required      pam_tally2.so",
	}
}

// 辅助函数：检查字符串是否为数字
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// 辅助函数：解析整数
func parseInt(s string) int {
	val, _ := strconv.Atoi(s)
	return val
}
// 解析pam_tally配置行
func parseTallyLine(line string) (int, int) {
	attempts := 0
	lockTime := 0
	
	// 查找deny参数
	denyRegex := regexp.MustCompile(`deny=(\d+)`)
	if matches := denyRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			attempts = val
		}
	}
	
	// 查找lock_time参数
	lockRegex := regexp.MustCompile(`lock_time=(\d+)`)
	if matches := lockRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			lockTime = val / 60 // 转换为分钟
		}
	}
	
	return attempts, lockTime
}

// 解析pam_cracklib或pam_pwquality配置行
func parseQualityLine(line string) (int, int) {
	attempts := 0
	lockTime := 0
	
	// 查找retry参数
	retryRegex := regexp.MustCompile(`retry=(\d+)`)
	if matches := retryRegex.FindStringSubmatch(line); len(matches) > 1 {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			attempts = val
		}
	}
	
	// 这些模块通常不直接处理锁定时间，返回默认值
	if attempts > 0 {
		lockTime = 5 // 默认5分钟
	}
	
	return attempts, lockTime
}
// 执行紧急解锁
func performEmergencyUnlock() error {
	// 清除faillock计数器
	cmd := exec.Command("faillock", "--reset")
	if err := cmd.Run(); err != nil {
		// 如果faillock命令不存在，尝试其他方法
		// 清除tally2计数器
		cmd = exec.Command("pam_tally2", "--reset")
		if err := cmd.Run(); err != nil {
			// 尝试清除tally计数器
			cmd = exec.Command("pam_tally", "--reset")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("无法清除锁定计数器，请手动执行: faillock --reset 或 pam_tally2 --reset")
			}
		}
	}
	
	// 清除特定用户的锁定（包括root）
	users := []string{"root"}
	
	// 获取所有用户并清除锁定
	if content, err := os.ReadFile("/etc/passwd"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) >= 1 {
				username := fields[0]
				users = append(users, username)
			}
		}
	}
	
	// 为每个用户清除锁定
	for _, user := range users {
		// 清除faillock
		cmd = exec.Command("faillock", "--user", user, "--reset")
		cmd.Run() // 忽略错误，继续下一个
		
		// 清除tally2
		cmd = exec.Command("pam_tally2", "--user", user, "--reset")
		cmd.Run() // 忽略错误，继续下一个
		
		// 清除tally
		cmd = exec.Command("pam_tally", "--user", user, "--reset")
		cmd.Run() // 忽略错误，继续下一个
	}
	
	return nil
}

// 检查用户是否被锁定
func checkUserLockStatus() ([]string, error) {
	var lockedUsers []string
	
	// 检查faillock状态
	cmd := exec.Command("faillock")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "locked") {
				// 解析用户名
				fields := strings.Fields(line)
				if len(fields) > 0 {
					lockedUsers = append(lockedUsers, fields[0])
				}
			}
		}
	}
	
	return lockedUsers, nil
}