package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	
	tea "github.com/charmbracelet/bubbletea"
)

// Custom base64 alphabet used by crypt
const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// b64From24Bit converts 3 bytes to base64 string using crypt alphabet
func b64From24Bit(b2, b1, b0 byte, n int) string {
	result := make([]byte, n)
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	for i := 0; i < n; i++ {
		result[i] = cryptAlphabet[w&0x3f]
		w >>= 6
	}
	return string(result)
}

// sha256Crypt implements the SHA-256-crypt algorithm (glibc crypt $5$)
func sha256Crypt(password, salt string, rounds int) string {
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)

	// Step 1-8: Compute digest B
	ctxB := sha256.New()
	ctxB.Write(passwordBytes)
	ctxB.Write(saltBytes)
	ctxB.Write(passwordBytes)
	digestB := ctxB.Sum(nil)

	// Step 9-12: Compute digest A
	ctxA := sha256.New()
	ctxA.Write(passwordBytes)
	ctxA.Write(saltBytes)

	// Step 11: Add bytes from digest B
	pl := len(passwordBytes)
	for pl > 32 {
		ctxA.Write(digestB)
		pl -= 32
	}
	ctxA.Write(digestB[:pl])

	// Step 12: Process password length bits
	pl = len(passwordBytes)
	for pl > 0 {
		if pl&1 != 0 {
			ctxA.Write(digestB)
		} else {
			ctxA.Write(passwordBytes)
		}
		pl >>= 1
	}
	digestA := ctxA.Sum(nil)

	// Step 13-15: Compute DP
	ctxDP := sha256.New()
	for i := 0; i < len(passwordBytes); i++ {
		ctxDP.Write(passwordBytes)
	}
	digestDP := ctxDP.Sum(nil)

	// Step 16: Produce P
	pBytes := make([]byte, 0, len(passwordBytes))
	pl = len(passwordBytes)
	for pl > 32 {
		pBytes = append(pBytes, digestDP...)
		pl -= 32
	}
	pBytes = append(pBytes, digestDP[:pl]...)

	// Step 17-19: Compute DS
	ctxDS := sha256.New()
	for i := 0; i < 16+int(digestA[0]); i++ {
		ctxDS.Write(saltBytes)
	}
	digestDS := ctxDS.Sum(nil)

	// Step 20: Produce S
	sBytes := make([]byte, 0, len(saltBytes))
	sl := len(saltBytes)
	for sl > 32 {
		sBytes = append(sBytes, digestDS...)
		sl -= 32
	}
	sBytes = append(sBytes, digestDS[:sl]...)

	// Step 21: Rounds
	digestC := digestA
	for i := 0; i < rounds; i++ {
		ctxC := sha256.New()
		if i&1 != 0 {
			ctxC.Write(pBytes)
		} else {
			ctxC.Write(digestC)
		}
		if i%3 != 0 {
			ctxC.Write(sBytes)
		}
		if i%7 != 0 {
			ctxC.Write(pBytes)
		}
		if i&1 != 0 {
			ctxC.Write(digestC)
		} else {
			ctxC.Write(pBytes)
		}
		digestC = ctxC.Sum(nil)
	}

	// Step 22: Encode result
	var result strings.Builder
	result.WriteString(b64From24Bit(digestC[0], digestC[10], digestC[20], 4))
	result.WriteString(b64From24Bit(digestC[21], digestC[1], digestC[11], 4))
	result.WriteString(b64From24Bit(digestC[12], digestC[22], digestC[2], 4))
	result.WriteString(b64From24Bit(digestC[3], digestC[13], digestC[23], 4))
	result.WriteString(b64From24Bit(digestC[24], digestC[4], digestC[14], 4))
	result.WriteString(b64From24Bit(digestC[15], digestC[25], digestC[5], 4))
	result.WriteString(b64From24Bit(digestC[6], digestC[16], digestC[26], 4))
	result.WriteString(b64From24Bit(digestC[27], digestC[7], digestC[17], 4))
	result.WriteString(b64From24Bit(digestC[18], digestC[28], digestC[8], 4))
	result.WriteString(b64From24Bit(digestC[9], digestC[19], digestC[29], 4))
	result.WriteString(b64From24Bit(0, digestC[31], digestC[30], 3))

	return result.String()
}

// parseSHA256Hash parses a SHA-256-crypt hash string
func parseSHA256Hash(hashString string) (salt string, rounds int, hash string, ok bool) {
	if !strings.HasPrefix(hashString, "$5$") {
		return "", 0, "", false
	}

	parts := strings.Split(hashString[3:], "$")

	if len(parts) == 2 {
		// Format: $5$salt$hash (default rounds)
		return parts[0], 5000, parts[1], true
	} else if len(parts) == 3 && strings.HasPrefix(parts[0], "rounds=") {
		// Format: $5$rounds=N$salt$hash
		roundsStr := strings.TrimPrefix(parts[0], "rounds=")
		r, err := strconv.Atoi(roundsStr)
		if err != nil {
			return "", 0, "", false
		}
		return parts[1], r, parts[2], true
	}

	return "", 0, "", false
}

// 弱口令检测结果
type WeakPasswordResult struct {
	Username     string
	UID          string
	HashType     string
	IsWeak       bool
	WeakPassword string
	HashValue    string
	CheckTime    time.Duration
	Status       string // "检测中", "弱口令", "安全", "跳过", "错误"
}

// Hash类型识别
type HashInfo struct {
	Type        string
	Prefix      string
	Description string
	Length      int
}

var SupportedHashes = []HashInfo{
	{"MD5", "$1$", "MD5 crypt", 34},
	{"SHA256", "$5$", "SHA-256 crypt", 63},
	{"SHA512", "$6$", "SHA-512 crypt", 106},
	{"DES", "", "DES crypt (传统)", 13},
	{"Blowfish", "$2a$", "Blowfish crypt", 60},
	{"Blowfish", "$2b$", "Blowfish crypt", 60},
	{"Blowfish", "$2y$", "Blowfish crypt", 60},
}

// 系统性能配置
type PerformanceConfig struct {
	MaxConcurrent int           // 最大并发数
	BatchSize     int           // 批处理大小
	CheckInterval time.Duration // 检查间隔
	CPULimit      float64       // CPU使用限制 (0.0-1.0)
	Priority      string        // 优先级: "low", "normal", "high"
}

// 获取系统性能配置
func getPerformanceConfig() PerformanceConfig {
	cpuCount := runtime.NumCPU()

	// 根据CPU核心数和系统负载自动调整
	config := PerformanceConfig{
		MaxConcurrent: 2,                      // 默认2个并发
		BatchSize:     50,                     // 每批50个密码
		CheckInterval: 100 * time.Millisecond, // 100ms间隔
		CPULimit:      0.3,                    // 限制30% CPU使用
		Priority:      "low",                  // 低优先级
	}

	// 根据CPU核心数调整
	if cpuCount >= 8 {
		config.MaxConcurrent = 4
		config.CPULimit = 0.5
	} else if cpuCount >= 4 {
		config.MaxConcurrent = 3
		config.CPULimit = 0.4
	}

	// 检查系统负载
	if load := getSystemLoad(); load > 2.0 {
		config.MaxConcurrent = 1
		config.CPULimit = 0.2
		config.CheckInterval = 200 * time.Millisecond
	}

	return config
}

// 获取系统负载
func getSystemLoad() float64 {
	cmd := exec.Command("uptime")
	output, err := cmd.Output()
	if err != nil {
		return 0.0
	}

	// 解析uptime输出获取负载
	loadStr := string(output)
	if idx := strings.LastIndex(loadStr, "load average:"); idx != -1 {
		loadPart := strings.TrimSpace(loadStr[idx+13:])
		loads := strings.Split(loadPart, ",")
		if len(loads) > 0 {
			if load, err := strconv.ParseFloat(strings.TrimSpace(loads[0]), 64); err == nil {
				return load
			}
		}
	}
	return 0.0
}

// 识别密码Hash类型
func identifyHashType(hash string) HashInfo {
	if hash == "" || hash == "*" || hash == "!" || hash == "!!" {
		return HashInfo{"DISABLED", "", "账户已禁用", 0}
	}

	for _, hashInfo := range SupportedHashes {
		if hashInfo.Prefix != "" && strings.HasPrefix(hash, hashInfo.Prefix) {
			return hashInfo
		}
	}

	// 根据长度判断DES
	if len(hash) == 13 && !strings.Contains(hash, "$") {
		return HashInfo{"DES", "", "DES crypt (传统)", 13}
	}

	return HashInfo{"UNKNOWN", "", "未知Hash类型", len(hash)}
}

// 读取shadow文件获取用户密码Hash
func getShadowHashes() (map[string]string, error) {
	file, err := os.Open("/etc/shadow")
	if err != nil {
		return nil, fmt.Errorf("无法读取/etc/shadow文件: %v (需要root权限)", err)
	}
	defer file.Close()

	hashes := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) >= 2 {
			username := fields[0]
			hash := fields[1]

			// 跳过大部分系统账户和禁用账户，但保留root用户进行弱口令检测
			// root用户的弱口令是最严重的安全风险
			if !isSystemAccount(username) && hash != "*" && hash != "!" && hash != "!!" && hash != "" {
				hashes[username] = hash
			}
		}
	}

	return hashes, scanner.Err()
}

// 判断是否为系统账户
func isSystemAccount(username string) bool {
	// root用户虽然是系统账户，但需要进行弱口令检测，所以不跳过
	if username == "root" {
		return false
	}
	
	systemAccounts := []string{
		"daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
		"news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
		"nobody", "systemd-network", "systemd-resolve", "syslog", "messagebus",
		"_apt", "lxd", "uuidd", "dnsmasq", "landscape", "pollinate", "sshd",
		"mysql", "apache", "nginx", "redis", "mongodb", "postgres", "ftp",
	}

	for _, sysUser := range systemAccounts {
		if username == sysUser {
			return true
		}
	}

	// 检查UID是否小于1000 (通常是系统账户)
	// 但是root(UID=0)已经在上面特殊处理了
	cmd := exec.Command("id", "-u", username)
	if output, err := cmd.Output(); err == nil {
		if uid, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			return uid < 1000 && uid != 0 // 排除root(UID=0)
		}
	}

	return false
}

// 读取弱口令字典
func loadWeakPasswords() ([]string, error) {
	file, err := os.Open("Top1000pass.txt")
	if err != nil {
		return nil, fmt.Errorf("无法读取弱口令字典文件: %v", err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords = append(passwords, password)
		}
	}

	return passwords, scanner.Err()
}

// 生成密码Hash (纯Go实现)
func generateHash(password, salt, hashType string) (string, error) {
	switch hashType {
	case "SHA256":
		// 使用纯Go实现的SHA256-crypt算法
		return generateSHA256Hash(password, salt)
	case "MD5":
		// MD5仍然使用OpenSSL（因为它工作正常）
		return generateHashWithOpenSSL(password, salt, hashType)
	case "DES":
		// DES使用OpenSSL
		return generateHashWithOpenSSL(password, salt, hashType)
	default:
		return "", fmt.Errorf("不支持的Hash类型: %s", hashType)
	}
}

// 生成SHA256 Hash (纯Go实现)
func generateSHA256Hash(password, salt string) (string, error) {
	// 默认rounds为5000
	rounds := 5000
	
	// 生成Hash部分
	hashPart := sha256Crypt(password, salt, rounds)
	
	// 构造完整的Hash字符串: $5$salt$hash
	fullHash := fmt.Sprintf("$5$%s$%s", salt, hashPart)
	
	return fullHash, nil
}

// 使用OpenSSL生成Hash（用于MD5、SHA512、DES）
func generateHashWithOpenSSL(password, salt, hashType string) (string, error) {
	var cmd *exec.Cmd

	switch hashType {
	case "MD5":
		cmd = exec.Command("openssl", "passwd", "-1", "-salt", salt, password)
	case "SHA256":
		// SHA256 crypt格式: $5$salt$hash
		cmd = exec.Command("openssl", "passwd", "-5", "-salt", salt, password)
	case "SHA512":
		// SHA512 crypt格式: $6$salt$hash
		cmd = exec.Command("openssl", "passwd", "-6", "-salt", salt, password)
	case "DES":
		// DES只使用前2个字符作为salt
		if len(salt) >= 2 {
			cmd = exec.Command("openssl", "passwd", "-crypt", "-salt", salt[:2], password)
		} else {
			return "", fmt.Errorf("DES salt长度不足")
		}
	default:
		return "", fmt.Errorf("不支持的Hash类型: %s", hashType)
	}

	output, err := cmd.Output()
	if err != nil {
		// 详细的错误信息用于调试
		if exitError, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("openssl执行失败 - 类型:%s, salt:%s, 错误:%v, stderr:%s", 
				hashType, salt, err, string(exitError.Stderr))
		}
		return "", fmt.Errorf("openssl执行失败 - 类型:%s, salt:%s, 错误:%v", hashType, salt, err)
	}

	result := strings.TrimSpace(string(output))
	
	// 验证生成的Hash格式是否正确
	if !strings.HasPrefix(result, "$") {
		return "", fmt.Errorf("生成的Hash格式不正确: %s", result)
	}
	
	return result, nil
}

// 提取Hash中的salt
func extractSalt(hash, hashType string) string {
	switch hashType {
	case "MD5":
		// $1$salt$hash
		parts := strings.Split(hash, "$")
		if len(parts) >= 3 {
			return parts[2]
		}
	case "SHA256":
		// $5$salt$hash
		parts := strings.Split(hash, "$")
		if len(parts) >= 3 {
			// SHA256的salt可能包含特殊字符，需要完整提取
			return parts[2]
		}
	case "SHA512":
		// $6$salt$hash
		parts := strings.Split(hash, "$")
		if len(parts) >= 3 {
			// SHA512的salt可能包含特殊字符，需要完整提取
			return parts[2]
		}
	case "DES":
		// salt是前两个字符
		if len(hash) >= 2 {
			return hash[:2]
		}
	}
	return ""
}

// 检测单个用户的弱口令
func checkUserWeakPassword(username, hash string, passwords []string, config PerformanceConfig) WeakPasswordResult {
	result := WeakPasswordResult{
		Username:  username,
		HashValue: hash,
		Status:    "检测中",
		CheckTime: 0,
	}

	startTime := time.Now()

	// 识别Hash类型
	hashInfo := identifyHashType(hash)
	result.HashType = hashInfo.Type

	if hashInfo.Type == "DISABLED" {
		result.Status = "跳过"
		result.CheckTime = time.Since(startTime)
		return result
	}

	if hashInfo.Type == "UNKNOWN" {
		result.Status = "错误"
		result.CheckTime = time.Since(startTime)
		return result
	}

	// 提取salt
	salt := extractSalt(hash, hashInfo.Type)
	if salt == "" {
		result.Status = "错误"
		result.CheckTime = time.Since(startTime)
		return result
	}

	// 对于SHA256，添加调试信息（仅在检测admin密码时）
	debugMode := (username == "admin" && hashInfo.Type == "SHA256")
	if debugMode {
		fmt.Printf("DEBUG - 用户: %s, Hash类型: %s, Salt: %s, Salt长度: %d\n", 
			username, hashInfo.Type, salt, len(salt))
	}

	// 分批检测密码
	for i := 0; i < len(passwords); i += config.BatchSize {
		end := i + config.BatchSize
		if end > len(passwords) {
			end = len(passwords)
		}

		batch := passwords[i:end]

		// 检测当前批次
		for _, password := range batch {
			if generatedHash, err := generateHash(password, salt, hashInfo.Type); err == nil {
				if debugMode && password == "admin" {
					fmt.Printf("DEBUG - 测试密码: %s, 生成Hash: %s, 原Hash: %s, 匹配: %t\n", 
						password, generatedHash, hash, generatedHash == hash)
				}
				
				if generatedHash == hash {
					result.IsWeak = true
					result.WeakPassword = password
					result.Status = "弱口令"
					result.CheckTime = time.Since(startTime)
					return result
				}
			} else if debugMode && password == "admin" {
				fmt.Printf("DEBUG - 密码 %s Hash生成失败: %v\n", password, err)
			}

			// 性能控制 - 添加延迟
			if config.CheckInterval > 0 {
				time.Sleep(config.CheckInterval / time.Duration(config.BatchSize))
			}
		}

		// 批次间延迟
		time.Sleep(config.CheckInterval)
	}

	result.Status = "安全"
	result.CheckTime = time.Since(startTime)
	return result
}

// 执行弱口令检测
func performWeakPasswordCheck(m *model) error {
	m.weakPasswordResults = []WeakPasswordResult{}

	// 获取性能配置
	config := getPerformanceConfig()

	// 读取shadow文件
	hashes, err := getShadowHashes()
	if err != nil {
		return err
	}

	if len(hashes) == 0 {
		return fmt.Errorf("未找到可检测的用户账户")
	}

	// 读取弱口令字典
	passwords, err := loadWeakPasswords()
	if err != nil {
		return err
	}

	if len(passwords) == 0 {
		return fmt.Errorf("弱口令字典为空")
	}

	// 开始检测
	totalUsers := len(hashes)
	currentUser := 0

	for username, hash := range hashes {
		currentUser++

		// 更新进度
		result := WeakPasswordResult{
			Username: username,
			Status:   fmt.Sprintf("检测中... (%d/%d)", currentUser, totalUsers),
		}
		m.weakPasswordResults = append(m.weakPasswordResults, result)

		// 执行检测
		finalResult := checkUserWeakPassword(username, hash, passwords, config)

		// 更新结果
		m.weakPasswordResults[len(m.weakPasswordResults)-1] = finalResult
	}

	return nil
}

// 保存弱口令检测报告
func saveWeakPasswordReport(m *model) error {
	if len(m.weakPasswordResults) == 0 {
		return fmt.Errorf("没有检测结果可保存")
	}

	filename := fmt.Sprintf("weak_password_report_%s.txt",
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建报告文件失败: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入报告头部
	fmt.Fprintf(writer, "ALSCC 弱口令检测报告\n")
	fmt.Fprintf(writer, "===================\n\n")
	fmt.Fprintf(writer, "检测时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "检测主机: %s\n", getHostname())
	fmt.Fprintf(writer, "字典文件: Top1000pass.txt\n\n")

	// 统计信息
	totalUsers := len(m.weakPasswordResults)
	weakUsers := 0
	safeUsers := 0
	errorUsers := 0
	skippedUsers := 0

	for _, result := range m.weakPasswordResults {
		switch result.Status {
		case "弱口令":
			weakUsers++
		case "安全":
			safeUsers++
		case "错误":
			errorUsers++
		case "跳过":
			skippedUsers++
		}
	}

	fmt.Fprintf(writer, "检测统计:\n")
	fmt.Fprintf(writer, "---------\n")
	fmt.Fprintf(writer, "总用户数: %d\n", totalUsers)
	fmt.Fprintf(writer, "弱口令用户: %d\n", weakUsers)
	fmt.Fprintf(writer, "安全用户: %d\n", safeUsers)
	fmt.Fprintf(writer, "检测错误: %d\n", errorUsers)
	fmt.Fprintf(writer, "跳过用户: %d\n\n", skippedUsers)

	// 弱口令详情
	if weakUsers > 0 {
		fmt.Fprintf(writer, "弱口令详情 (高危):\n")
		fmt.Fprintf(writer, "==================\n")
		for _, result := range m.weakPasswordResults {
			if result.IsWeak {
				fmt.Fprintf(writer, "用户: %s\n", result.Username)
				fmt.Fprintf(writer, "Hash类型: %s\n", result.HashType)
				fmt.Fprintf(writer, "弱口令: %s\n", result.WeakPassword)
				fmt.Fprintf(writer, "检测耗时: %s\n", result.CheckTime)
				fmt.Fprintf(writer, "建议: 立即要求用户修改密码\n")
				fmt.Fprintf(writer, "---\n")
			}
		}
		fmt.Fprintf(writer, "\n")
	}

	// 完整检测结果
	fmt.Fprintf(writer, "完整检测结果:\n")
	fmt.Fprintf(writer, "=============\n")
	for _, result := range m.weakPasswordResults {
		fmt.Fprintf(writer, "用户: %-15s | Hash类型: %-8s | 状态: %-8s | 耗时: %s\n",
			result.Username, result.HashType, result.Status, result.CheckTime)
	}

	// 安全建议
	fmt.Fprintf(writer, "\n安全建议:\n")
	fmt.Fprintf(writer, "=========\n")
	fmt.Fprintf(writer, "1. 立即要求弱口令用户修改密码\n")
	fmt.Fprintf(writer, "2. 实施强密码策略 (长度≥8位，包含大小写字母、数字、特殊字符)\n")
	fmt.Fprintf(writer, "3. 定期进行弱口令检测\n")
	fmt.Fprintf(writer, "4. 考虑实施双因素认证\n")
	fmt.Fprintf(writer, "5. 加强用户安全意识培训\n")

	return nil
}

// 获取主机名
func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}
// 简化版弱口令检测 - 使用真实shadow文件数据
func performWeakPasswordCheckSimple(m *model) error {
	m.weakPasswordResults = []WeakPasswordResult{}
	
	// 读取真实的shadow文件
	hashes, err := getShadowHashes()
	if err != nil {
		return err
	}
	
	if len(hashes) == 0 {
		return fmt.Errorf("未找到可检测的用户账户")
	}
	
	// 读取弱口令字典
	passwords, err := loadWeakPasswords()
	if err != nil {
		return err
	}
	
	if len(passwords) == 0 {
		return fmt.Errorf("弱口令字典为空")
	}
	
	// 获取性能配置
	config := getPerformanceConfig()
	
	// 检测每个用户
	for username, hash := range hashes {
		result := checkUserWeakPassword(username, hash, passwords, config)
		m.weakPasswordResults = append(m.weakPasswordResults, result)
	}
	
	return nil
}
// 带进度条的弱口令检测
func performWeakPasswordCheckWithProgress(m *model) error {
	m.weakPasswordResults = []WeakPasswordResult{}
	
	// 读取真实的shadow文件
	hashes, err := getShadowHashes()
	if err != nil {
		return err
	}
	
	if len(hashes) == 0 {
		return fmt.Errorf("未找到可检测的用户账户")
	}
	
	// 读取弱口令字典
	passwords, err := loadWeakPasswords()
	if err != nil {
		return err
	}
	
	if len(passwords) == 0 {
		return fmt.Errorf("弱口令字典为空")
	}
	
	// 获取性能配置
	config := getPerformanceConfig()
	
	// 设置进度条总数
	m.progressTotal = len(hashes)
	m.progressCurrent = 0
	
	// 检测每个用户
	userIndex := 0
	for username, hash := range hashes {
		userIndex++
		
		// 更新进度条
		m.progressCurrent = userIndex
		m.progressMessage = fmt.Sprintf("正在检测用户: %s", username)
		
		result := checkUserWeakPassword(username, hash, passwords, config)
		m.weakPasswordResults = append(m.weakPasswordResults, result)
		
		// 添加小延迟让进度条更新更平滑
		time.Sleep(200 * time.Millisecond)
	}
	
	// 检测完成
	m.progressMessage = "弱口令检测完成"
	
	return nil
}
// 异步弱口令检测命令 - 步骤式执行
func performWeakPasswordCheckAsync(config PerformanceConfig) tea.Cmd {
	return func() tea.Msg {
		// 读取真实的shadow文件
		hashes, err := getShadowHashes()
		if err != nil {
			return completeMsg{results: []WeakPasswordResult{}, err: err}
		}
		
		if len(hashes) == 0 {
			return completeMsg{results: []WeakPasswordResult{}, err: fmt.Errorf("未找到可检测的用户账户")}
		}
		
		// 读取弱口令字典
		passwords, err := loadWeakPasswords()
		if err != nil {
			return completeMsg{results: []WeakPasswordResult{}, err: err}
		}
		
		if len(passwords) == 0 {
			return completeMsg{results: []WeakPasswordResult{}, err: fmt.Errorf("弱口令字典为空")}
		}
		
		// 准备用户名列表
		usernames := make([]string, 0, len(hashes))
		for username := range hashes {
			usernames = append(usernames, username)
		}
		
		// 开始第一步
		return weakPasswordStepMsg{
			stepIndex: 0,
			totalSteps: len(usernames),
			usernames: usernames,
			hashes: hashes,
			passwords: passwords,
			config: config,
			results: []WeakPasswordResult{},
		}
	}
}

// 执行单个弱口令检测步骤
func executeWeakPasswordCheckStep(step weakPasswordStepMsg) tea.Cmd {
	return func() tea.Msg {
		if step.stepIndex >= len(step.usernames) {
			return completeMsg{results: step.results, err: nil}
		}
		
		username := step.usernames[step.stepIndex]
		hash := step.hashes[username]
		
		result := checkUserWeakPassword(username, hash, step.passwords, step.config)
		
		// 添加结果到列表
		newResults := append(step.results, result)
		
		// 添加延迟让用户看到进度
		time.Sleep(400 * time.Millisecond)
		
		// 返回下一步
		return weakPasswordStepMsg{
			stepIndex: step.stepIndex + 1,
			totalSteps: step.totalSteps,
			usernames: step.usernames,
			hashes: step.hashes,
			passwords: step.passwords,
			config: step.config,
			results: newResults,
		}
	}
}