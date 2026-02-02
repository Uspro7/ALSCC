package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// 执行安全检查
func performSecurityChecks(m *model) error {
	m.securityResults = []SecurityCheckResult{}
	
	// 计算需要执行的检查项数量
	totalChecks := 0
	for i := range SecurityChecks {
		if i < len(m.selectedChecks) && m.selectedChecks[i] {
			totalChecks++
		}
	}
	
	if totalChecks == 0 {
		return fmt.Errorf("没有选择任何检查项")
	}
	
	currentCheck := 0
	for i, check := range SecurityChecks {
		if i >= len(m.selectedChecks) || !m.selectedChecks[i] {
			continue
		}
		
		currentCheck++
		result := check
		result.Status = fmt.Sprintf("检查中... (%d/%d)", currentCheck, totalChecks)
		
		// 执行检查命令 - 添加超时控制
		cmd := exec.Command("bash", "-c", check.Command)
		
		// 设置命令超时为10秒
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, "bash", "-c", check.Command)
		
		output, err := cmd.CombinedOutput()
		
		// 保存原始输出
		result.RawOutput = strings.TrimSpace(string(output))
		
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "检查超时"
			result.Details = "命令执行超时（10秒）"
		} else if err != nil {
			result.Status = "检查失败"
			result.Details = fmt.Sprintf("命令执行失败: %v", err)
			if result.RawOutput != "" {
				result.Details += fmt.Sprintf(" (输出: %s)", result.RawOutput)
			}
		} else {
			// 根据检查项ID分析结果
			analyzeResult(&result, result.RawOutput)
		}
		
		// 添加修复建议
		if result.Status == "不合规" && !m.strictMode {
			result.FixSuggestion = getFixSuggestion(result.ID)
		}
		
		m.securityResults = append(m.securityResults, result)
	}
	
	return nil
}

// 分析检查结果
func analyzeResult(result *SecurityCheckResult, output string) {
	output = strings.TrimSpace(output)
	
	switch result.ID {
	case 1: // 网络嗅探类工具检查
		if output == "" {
			result.Status = "合规"
			result.Details = "未发现网络嗅探工具"
		} else {
			result.Status = "不合规"
			lines := strings.Split(output, "\n")
			if len(lines) > 3 {
				result.Details = fmt.Sprintf("发现 %d 个网络嗅探工具，包括: %s 等", len(lines), strings.Join(lines[:3], ", "))
			} else {
				result.Details = fmt.Sprintf("发现网络嗅探工具: %s", strings.Join(lines, ", "))
			}
		}
		
	case 2: // 开发编译类工具检查
		if output == "" {
			result.Status = "合规"
			result.Details = "未发现开发编译工具"
		} else {
			result.Status = "不合规"
			lines := strings.Split(output, "\n")
			if len(lines) > 5 {
				result.Details = fmt.Sprintf("发现 %d 个开发工具包，包括: %s 等", len(lines), strings.Join(lines[:3], ", "))
			} else {
				result.Details = fmt.Sprintf("发现以下工具: %s", strings.Join(lines, ", "))
			}
		}
		
	case 3: // 非root且UID为0的用户检查
		lines := strings.Split(output, "\n")
		rootCount := 0
		nonRootUID0 := []string{}
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				fields := strings.Split(line, ":")
				if len(fields) >= 1 {
					if fields[0] == "root" {
						rootCount++
					} else {
						nonRootUID0 = append(nonRootUID0, fields[0])
					}
				}
			}
		}
		if len(nonRootUID0) == 0 {
			result.Status = "合规"
			result.Details = "仅root用户UID为0"
		} else {
			result.Status = "不合规"
			result.Details = fmt.Sprintf("发现非root用户UID为0: %s", strings.Join(nonRootUID0, ", "))
		}
		
	case 4: // 共用账号检查
		if output == "" {
			result.Status = "合规"
			result.Details = "未发现重复用户名"
		} else {
			result.Status = "不合规"
			result.Details = fmt.Sprintf("发现可能的共用账号: %s", output)
		}
		
	case 5: // 无关账号检查
		if output == "" {
			result.Status = "合规"
			result.Details = "未发现无关账号"
		} else {
			result.Status = "不合规"
			accounts := strings.Split(output, "\n")
			if len(accounts) > 3 {
				result.Details = fmt.Sprintf("发现 %d 个无关账号，包括: %s 等", len(accounts), strings.Join(accounts[:3], ", "))
			} else {
				result.Details = fmt.Sprintf("发现无关账号: %s", strings.Join(accounts, ", "))
			}
		}
		
	case 6: // 用户组权限限制检查
		if output == "" {
			result.Status = "合规"
			result.Details = "未发现重复GID"
		} else {
			result.Status = "不合规"
			result.Details = fmt.Sprintf("发现重复GID: %s", output)
		}
		
	case 7: // 口令生存周期检查
		hasMaxDays := strings.Contains(output, "PASS_MAX_DAYS")
		hasMinDays := strings.Contains(output, "PASS_MIN_DAYS")
		hasWarnAge := strings.Contains(output, "PASS_WARN_AGE")
		
		// 提取具体数值
		maxDaysRegex := regexp.MustCompile(`PASS_MAX_DAYS\s+(\d+)`)
		minDaysRegex := regexp.MustCompile(`PASS_MIN_DAYS\s+(\d+)`)
		warnAgeRegex := regexp.MustCompile(`PASS_WARN_AGE\s+(\d+)`)
		
		var maxDays, minDays, warnAge string
		if matches := maxDaysRegex.FindStringSubmatch(output); len(matches) > 1 {
			maxDays = matches[1]
		}
		if matches := minDaysRegex.FindStringSubmatch(output); len(matches) > 1 {
			minDays = matches[1]
		}
		if matches := warnAgeRegex.FindStringSubmatch(output); len(matches) > 1 {
			warnAge = matches[1]
		}
		
		if hasMaxDays && hasMinDays && hasWarnAge && maxDays == "90" && minDays == "1" && warnAge == "7" {
			result.Status = "合规"
			result.Details = fmt.Sprintf("口令生存周期配置正确: MAX=%s, MIN=%s, WARN=%s", maxDays, minDays, warnAge)
		} else {
			result.Status = "不合规"
			missing := []string{}
			if !hasMaxDays || maxDays != "90" {
				missing = append(missing, fmt.Sprintf("PASS_MAX_DAYS应为90(当前:%s)", maxDays))
			}
			if !hasMinDays || minDays != "1" {
				missing = append(missing, fmt.Sprintf("PASS_MIN_DAYS应为1(当前:%s)", minDays))
			}
			if !hasWarnAge || warnAge != "7" {
				missing = append(missing, fmt.Sprintf("PASS_WARN_AGE应为7(当前:%s)", warnAge))
			}
			result.Details = strings.Join(missing, "; ")
		}
		
	case 8: // 口令更改最小间隔检查
		minDaysRegex := regexp.MustCompile(`PASS_MIN_DAYS\s+(\d+)`)
		if matches := minDaysRegex.FindStringSubmatch(output); len(matches) > 1 {
			minDays := matches[1]
			if minDays == "1" || minDays == "7" {
				result.Status = "合规"
				result.Details = fmt.Sprintf("口令更改最小间隔配置正确: %s天", minDays)
			} else {
				result.Status = "不合规"
				result.Details = fmt.Sprintf("口令更改最小间隔应为1或7天，当前: %s天", minDays)
			}
		} else {
			result.Status = "不合规"
			result.Details = "未找到PASS_MIN_DAYS配置"
		}
		
	case 9: // 口令过期警告天数检查
		warnAgeRegex := regexp.MustCompile(`PASS_WARN_AGE\s+(\d+)`)
		if matches := warnAgeRegex.FindStringSubmatch(output); len(matches) > 1 {
			warnAge := matches[1]
			if warnAge == "7" {
				result.Status = "合规"
				result.Details = fmt.Sprintf("口令过期警告天数配置正确: %s天", warnAge)
			} else {
				result.Status = "不合规"
				result.Details = fmt.Sprintf("口令过期警告天数应为7天，当前: %s天", warnAge)
			}
		} else {
			result.Status = "不合规"
			result.Details = "未找到PASS_WARN_AGE配置"
		}
		
	case 10: // 口令复杂度检查
		hasMinlen := strings.Contains(output, "minlen")
		hasCredit := strings.Contains(output, "credit") || strings.Contains(output, "dcredit") || strings.Contains(output, "ucredit")
		
		if hasMinlen && hasCredit {
			result.Status = "合规"
			result.Details = "口令复杂度要求已配置"
		} else {
			result.Status = "不合规"
			missing := []string{}
			if !hasMinlen {
				missing = append(missing, "最小长度(minlen)")
			}
			if !hasCredit {
				missing = append(missing, "字符类型要求(credit)")
			}
			result.Details = fmt.Sprintf("口令复杂度配置不完整，缺少: %s", strings.Join(missing, ", "))
		}
		
	case 11: // 空口令账号检查
		if output == "" {
			result.Status = "合规"
			result.Details = "未发现空口令账号"
		} else {
			result.Status = "不合规"
			accounts := strings.Split(output, "\n")
			result.Details = fmt.Sprintf("发现空口令账号: %s", strings.Join(accounts, ", "))
		}
		
	case 12: // 口令重复次数检查
		if strings.Contains(output, "remember=") {
			// 提取remember值
			rememberRegex := regexp.MustCompile(`remember=(\d+)`)
			if matches := rememberRegex.FindStringSubmatch(output); len(matches) > 1 {
				result.Status = "合规"
				result.Details = fmt.Sprintf("已配置口令重复次数限制: remember=%s", matches[1])
			} else {
				result.Status = "合规"
				result.Details = "已配置口令重复次数限制"
			}
		} else {
			result.Status = "不合规"
			result.Details = "未配置口令重复次数限制(remember参数)"
		}
		
	case 13: // su命令限制检查
		if strings.Contains(output, "pam_wheel.so use_uid") {
			result.Status = "合规"
			result.Details = "已配置su命令用户组限制"
		} else {
			result.Status = "不合规"
			if output == "" {
				result.Details = "未找到pam_wheel.so配置"
			} else {
				result.Details = "su命令配置存在但缺少wheel组限制"
			}
		}
		
	case 14: // 登录失败锁定检查
		if strings.Contains(output, "pam_faillock") || strings.Contains(output, "pam_tally") {
			result.Status = "合规"
			if strings.Contains(output, "pam_faillock") {
				result.Details = "已配置pam_faillock锁定策略"
			} else {
				result.Details = "已配置pam_tally锁定策略"
			}
		} else {
			result.Status = "不合规"
			result.Details = "未配置登录失败锁定策略(pam_faillock或pam_tally)"
		}
		
	case 15: // 登录失败记录检查
		hasLastlog := strings.Contains(output, "LASTLOG_ENAB") && strings.Contains(output, "yes")
		hasFaillog := strings.Contains(output, "FAILLOG_ENAB") && strings.Contains(output, "yes")
		
		if hasLastlog && hasFaillog {
			result.Status = "合规"
			result.Details = "登录失败记录已启用"
		} else {
			result.Status = "不合规"
			missing := []string{}
			if !hasLastlog {
				missing = append(missing, "LASTLOG_ENAB未设置为yes")
			}
			if !hasFaillog {
				missing = append(missing, "FAILLOG_ENAB未设置为yes")
			}
			result.Details = strings.Join(missing, "; ")
		}
		
	case 16: // 用户UMASK检查
		if strings.Contains(output, "umask") {
			// 提取umask值
			umaskRegex := regexp.MustCompile(`umask\s+(\d+)`)
			matches := umaskRegex.FindStringSubmatch(output)
			if len(matches) > 1 {
				umaskValue := matches[1]
				if umaskValue == "027" || umaskValue == "077" {
					result.Status = "合规"
					result.Details = fmt.Sprintf("UMASK配置正确: %s", umaskValue)
				} else {
					result.Status = "不合规"
					result.Details = fmt.Sprintf("UMASK值过低: %s (建议: 027)", umaskValue)
				}
			} else {
				result.Status = "不合规"
				result.Details = "找到umask配置但无法解析数值"
			}
		} else {
			result.Status = "不合规"
			result.Details = "未找到UMASK配置"
		}
		
	// 继续处理其他检查项...
	default:
		// 通用处理逻辑
		if output == "" {
			result.Status = "合规"
			result.Details = "检查通过"
		} else {
			result.Status = "不合规"
			result.Details = "发现配置问题: " + output
		}
	}
}

// 获取修复建议
func getFixSuggestion(checkID int) string {
	suggestions := map[int]string{
		// 工具类
		1:  "卸载网络嗅探工具: rpm -e tcpdump wireshark",
		2:  "卸载不必要的开发编译工具: rpm -e gcc gdb strace",
		
		// 账号类
		3:  "删除除root外UID为0的用户: userdel 用户名",
		4:  "建立独立运维账号，严禁共用账号",
		5:  "锁定无关账号: passwd -l 用户名 或修改/etc/shadow",
		6:  "建立独立组，严禁所有用户都在一个组",
		
		// 口令类
		7:  "配置口令生存周期: 编辑/etc/login.defs，设置PASS_MAX_DAYS 90等",
		8:  "设置口令更改最小间隔: 在/etc/login.defs中设置PASS_MIN_DAYS 1",
		9:  "设置口令过期警告: 在/etc/login.defs中设置PASS_WARN_AGE 7",
		10: "配置口令复杂度: 编辑/etc/security/pwquality.conf",
		11: "强制设置强密码，消除空口令账号",
		12: "配置口令重复限制: 在/etc/pam.d/system-auth中添加remember=5",
		
		// 认证类
		13: "配置su命令限制: 编辑/etc/pam.d/su，添加 auth required pam_wheel.so use_uid",
		14: "配置登录失败锁定: 使用本程序的锁定策略功能",
		15: "启用登录记录: 在/etc/login.defs中设置LASTLOG_ENAB yes",
		
		// 权限类
		16: "修改UMASK值: 在/etc/profile中设置 umask 027",
		17: "设置重要文件权限: chmod 644 /etc/passwd; chmod 400 /etc/shadow",
		18: "设置日志文件权限: chmod 600 /var/log/secure",
		
		// 日志类
		19: "启动日志服务: systemctl start rsyslog",
		20: "配置Cron日志: 在/etc/rsyslog.conf中添加cron.*配置",
		21: "配置远程日志: 在/etc/rsyslog.conf中添加*.* @IP",
		22: "配置su日志: 编辑/etc/rsyslog.conf，添加authpriv.*配置",
		23: "配置安全事件日志: 编辑/etc/rsyslog.conf",
		24: "配置日志轮转: 在/etc/logrotate.d/syslog中添加size 10M rotate 3",
		
		// 网络类
		25: "禁止root远程登录: 在/etc/ssh/sshd_config中设置PermitRootLogin no",
		26: "卸载telnet服务: rpm -e telnet-server",
		27: "配置SSH加密算法: 编辑/etc/ssh/sshd_config，添加安全的加密算法",
		28: "禁用ICMP重定向: sysctl -w net.ipv4.conf.all.accept_redirects=0",
		29: "启用反向路径过滤: sysctl -w net.ipv4.conf.all.rp_filter=1",
		30: "关闭IP转发: 在/etc/sysctl.conf中设置net.ipv4.ip_forward=0",
		31: "修改SNMP团体字: 编辑/etc/snmp/snmpd.conf，修改默认团体字",
		32: "禁止root登录FTP: 在/etc/vsftpd/ftpusers中添加root",
		33: "禁止匿名FTP: 在/etc/vsftpd/vsftpd.conf中设置anonymous_enable=NO",
		34: "限制远程登录IP: 配置/etc/hosts.allow和/etc/hosts.deny",
		
		// 服务类
		35: "关闭危险端口: 停止Samba等服务",
		36: "关闭不必要服务: systemctl disable 服务名",
		
		// 配置类
		37: "设置SSH Banner: 在/etc/ssh/sshd_config中配置Banner",
		38: "配置登录后Banner: 编辑/etc/motd",
		39: "删除危险文件: rm -f .rhosts .netrc hosts.equiv",
		40: "设置命令行超时: 在/etc/profile中设置TMOUT=300",
		41: "禁用Ctrl+Alt+Del: systemctl mask ctrl-alt-del.target",
		42: "清理root环境变量: 删除PATH中的当前目录引用",
		43: "限制历史命令: 在/etc/profile中设置HISTSIZE=5",
		44: "配置NTP服务: 安装并启动ntpd或chronyd服务",
		45: "配置NFS安全: 在/etc/exports中添加root_squash",
		46: "设置Coredump: 在/etc/security/limits.conf中设置core 0",
		47: "配置FTP umask: 在/etc/vsftpd/vsftpd.conf中设置local_umask=022",
		48: "配置FTP chroot: 在/etc/vsftpd/vsftpd.conf中设置chroot_local_user=YES",
		49: "隐藏FTP版本: 在/etc/vsftpd/vsftpd.conf中配置ftpd_banner",
		50: "隐藏Telnet版本: 编辑/etc/issue.net",
		
		// 网络安全
		51: "启用SYN防护: sysctl -w net.ipv4.tcp_syncookies=1",
		52: "限制SSH认证尝试: 在/etc/ssh/sshd_config中设置MaxAuthTries 3",
		53: "设置SSH超时: 在/etc/ssh/sshd_config中设置ClientAliveInterval",
		54: "设置SSH协议版本: 在/etc/ssh/sshd_config中设置Protocol 2",
		55: "设置SSH空闲超时: 在/etc/ssh/sshd_config中设置ClientAliveCountMax",
		56: "限制SSH用户: 在/etc/ssh/sshd_config中配置AllowUsers",
		
		// 权限和文件
		57: "审计SUID/SGID文件: 人工审计后按需清理特权文件",
		58: "修复世界可写文件: chmod o-w 文件名",
		59: "处理无属主文件: chown 用户:组 文件名",
		60: "设置关键目录权限: chmod 755 /etc /bin /sbin",
		61: "设置临时目录权限: chmod 1777 /tmp /var/tmp",
		62: "设置用户主目录权限: chmod 750 /home/用户名",
		
		// 系统资源
		63: "清理磁盘空间: 删除不必要文件，保证使用率<80%",
		64: "优化内存使用: 关闭不必要进程",
		65: "优化CPU负载: 检查高负载进程",
		66: "控制进程数量: 限制用户进程数",
		67: "优化网络连接: 调整网络参数",
		68: "监控系统负载: 定期检查系统负载",
		
		// 合规和安全工具
		69: "安装入侵检测工具: yum install chkrootkit rkhunter",
		70: "更新系统内核: yum update kernel",
		71: "安装防病毒软件: 根据需要安装相应软件",
		72: "修复系统完整性: rpm --rebuilddb; yum reinstall 受影响包",
	}
	
	if suggestion, exists := suggestions[checkID]; exists {
		return suggestion
	}
	return "请参考相关文档进行配置"
}

// 保存安全检查报告
func saveSecurityReport(m *model) error {
	if len(m.securityResults) == 0 {
		return fmt.Errorf("没有检查结果可保存")
	}
	
	report := strings.Builder{}
	report.WriteString("Linux Security Check 安全检查报告\n")
	report.WriteString("=" + strings.Repeat("=", 50) + "\n")
	report.WriteString(fmt.Sprintf("检查时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("检查模式: %s\n", func() string {
		if m.strictMode {
			return "严格模式（只检查）"
		}
		return "标准模式（检查+建议）"
	}()))
	report.WriteString("\n")
	
	// 统计结果
	compliant := 0
	nonCompliant := 0
	failed := 0
	
	for _, result := range m.securityResults {
		switch result.Status {
		case "合规":
			compliant++
		case "不合规":
			nonCompliant++
		case "检查失败":
			failed++
		}
	}
	
	report.WriteString("检查结果统计:\n")
	report.WriteString(fmt.Sprintf("  合规项目: %d\n", compliant))
	report.WriteString(fmt.Sprintf("  不合规项目: %d\n", nonCompliant))
	report.WriteString(fmt.Sprintf("  检查失败: %d\n", failed))
	report.WriteString(fmt.Sprintf("  总计: %d\n", len(m.securityResults)))
	report.WriteString("\n")
	
	// 详细结果
	report.WriteString("详细检查结果:\n")
	report.WriteString("-" + strings.Repeat("-", 50) + "\n")
	
	for _, result := range m.securityResults {
		report.WriteString(fmt.Sprintf("[%s] %s - %s\n", result.Level, result.Name, result.Status))
		report.WriteString(fmt.Sprintf("描述: %s\n", result.Description))
		if result.Details != "" {
			report.WriteString(fmt.Sprintf("详情: %s\n", result.Details))
		}
		if result.FixSuggestion != "" {
			report.WriteString(fmt.Sprintf("建议: %s\n", result.FixSuggestion))
		}
		report.WriteString("\n")
	}
	
	// 写入文件
	filename := fmt.Sprintf("security_report_%s.txt", time.Now().Format("20060102_150405"))
	return os.WriteFile(filename, []byte(report.String()), 0644)
}
// 保存详细安全检查报告
func saveDetailedSecurityReport(m *model) error {
	if len(m.securityResults) == 0 {
		return fmt.Errorf("没有检查结果可保存")
	}
	
	report := strings.Builder{}
	report.WriteString("Linux Security Check 详细安全检查报告\n")
	report.WriteString("=" + strings.Repeat("=", 60) + "\n")
	report.WriteString(fmt.Sprintf("检查时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("检查模式: %s\n", func() string {
		if m.strictMode {
			return "严格模式（只检查）"
		}
		return "标准模式（检查+建议）"
	}()))
	report.WriteString("\n")
	
	// 统计结果
	compliant := 0
	nonCompliant := 0
	failed := 0
	
	for _, result := range m.securityResults {
		switch result.Status {
		case "合规":
			compliant++
		case "不合规":
			nonCompliant++
		case "检查失败":
			failed++
		}
	}
	
	report.WriteString("检查结果统计:\n")
	report.WriteString(fmt.Sprintf("  合规项目: %d\n", compliant))
	report.WriteString(fmt.Sprintf("  不合规项目: %d\n", nonCompliant))
	report.WriteString(fmt.Sprintf("  检查失败: %d\n", failed))
	report.WriteString(fmt.Sprintf("  总计: %d\n", len(m.securityResults)))
	report.WriteString("\n")
	
	// 详细结果
	report.WriteString("详细检查结果:\n")
	report.WriteString("-" + strings.Repeat("-", 60) + "\n")
	
	for i, result := range m.securityResults {
		report.WriteString(fmt.Sprintf("%d. [%s] %s - %s\n", i+1, result.Level, result.Name, result.Status))
		report.WriteString(fmt.Sprintf("   描述: %s\n", result.Description))
		
		if result.Command != "" {
			report.WriteString(fmt.Sprintf("   检查命令: %s\n", result.Command))
		}
		
		if result.Details != "" {
			report.WriteString(fmt.Sprintf("   检查结果: %s\n", result.Details))
		}
		
		if result.RawOutput != "" {
			report.WriteString("   原始输出:\n")
			lines := strings.Split(result.RawOutput, "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					report.WriteString(fmt.Sprintf("     %s\n", line))
				}
			}
		}
		
		if result.FixSuggestion != "" {
			report.WriteString(fmt.Sprintf("   修复建议: %s\n", result.FixSuggestion))
		}
		
		report.WriteString("\n")
	}
	
	// 写入文件
	filename := fmt.Sprintf("security_detailed_report_%s.txt", time.Now().Format("20060102_150405"))
	return os.WriteFile(filename, []byte(report.String()), 0644)
}