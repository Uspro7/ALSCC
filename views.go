package main

import (
	"fmt"
	"strings"
	
	"github.com/charmbracelet/lipgloss"
)

func (m model) viewMainMenu() string {
	var s strings.Builder
	
	// ALSCC 字符画艺术字 - 使用彩色渐变效果
	asciiArt := `
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║     █████╗ ██╗     ███████╗ ██████╗ ██████╗                                   ║
    ║    ██╔══██╗██║     ██╔════╝██╔════╝██╔════╝                                   ║
    ║    ███████║██║     ███████╗██║     ██║                                        ║
    ║    ██╔══██║██║     ╚════██║██║     ██║                                        ║
    ║    ██║  ██║███████╗███████║╚██████╗╚██████╗                                   ║
    ║    ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝                                   ║
    ║                                                                               ║
    ║     Aznic Linux Security Compliance Check V2.0                                ║
    ║                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝`
	
	// 使用渐变色彩显示字符画
	artStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FFFF")).
		Background(lipgloss.Color("#1E293B")).
		Bold(true)
	
	s.WriteString(artStyle.Render(asciiArt))
	s.WriteString("\n\n")
	
	// 系统信息面板
	systemInfo := panelStyle.Render(
		infoStyle.Render(" 系统信息 ") + "\n" +
		normalStyle.Render("运行环境: Linux") + "  " +
		successStyle.Render("安全模式: 已启用") + "  " +
		warningStyle.Render("状态: 就绪"))
	s.WriteString(systemInfo)
	s.WriteString("\n")

	// Root检测开关面板
	rootStatus := "已禁用"
	rootStyle := dangerStyle
	if m.enableRootCheck {
		rootStatus = "已启用"
		rootStyle = warningStyle
	}
	rootPanel := panelStyle.Render(
		highlightStyle.Render(" Root用户检测 ") + "\n" +
		rootStyle.Render("状态: "+rootStatus) + "  " +
		helpStyle.Render("按R键切换") + "\n" +
		helpStyle.Render("影响：密码修改/过期检查/弱口令检测"))
	s.WriteString(rootPanel)
	s.WriteString("\n")

	// 创建彩色选项列表
	options := []struct {
		text  string
		desc  string
		color lipgloss.Style
	}{
		{"用户密码批量修改", "批量修改系统用户密码", infoStyle},
		{"检查用户密码过期时间", "检查密码使用时间和过期状态", warningStyle},
		{"检查登录失败锁定策略", "配置和检查账户锁定策略", dangerStyle},
		{"系统安全合规检查", "全面的安全配置检查 (72项检查)", successStyle},
		{"弱口令检测", "检测用户弱口令 (支持自定义字典)", highlightStyle},
		{"紧急解锁用户账户", "清除所有用户锁定状态", warningStyle},
		{"退出程序", "安全退出系统", normalStyle},
	}
	
	for i, option := range options {
		if i == m.cursor {
			// 选中项使用特殊样式
			line := selectedStyle.Render("▶ " + option.text)
			s.WriteString(line)
			s.WriteString("\n")
			// 显示描述
			desc := helpStyle.Render("    → " + option.desc)
			s.WriteString(desc)
		} else {
			// 未选中项使用对应颜色
			line := option.color.Render("  " + option.text)
			s.WriteString(line)
		}
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 选择功能  Enter 确认  q/Esc 退出程序") + "\n" +
		helpStyle.Render("版本: v2.0  |  支持系统: CentOS/Ubuntu/Debian/RHEL"))
	s.WriteString(helpPanel)
	
	// 消息显示
	if m.message != "" {
		s.WriteString("\n")
		if strings.Contains(m.message, "成功") {
			s.WriteString(successStyle.Render("✓ " + m.message))
		} else {
			s.WriteString(warningStyle.Render("[!] " + m.message))
		}
	}
	
	return s.String()
}

func (m model) viewUserList() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("用户密码批量修改")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	selectedCount := 0
	for _, user := range m.users {
		if user.Selected {
			selectedCount++
		}
	}
	
	// 统计信息面板
	statsPanel := infoStyle.Render(fmt.Sprintf("已选择用户: %d/%d", selectedCount, len(m.users)))
	s.WriteString(statsPanel)
	s.WriteString("\n\n")
	
	// 用户列表
	for i, user := range m.users {
		prefix := "  "
		if i == m.cursor {
			prefix = selectedStyle.Render("> ")
		}
		
		checkbox := "[]"
		checkboxStyle := normalStyle
		if user.Selected {
			checkbox = "[·]"
			checkboxStyle = successStyle
		}
		
		// 用户信息行
		userInfo := fmt.Sprintf("%s (UID: %d, Shell: %s)", 
			user.Username, user.UID, user.Shell)
		
		line := fmt.Sprintf("%s%s %s", 
			prefix, 
			checkboxStyle.Render(checkbox), 
			userInfo)
		
		if i == m.cursor {
			s.WriteString(selectedStyle.Render(line))
		} else if user.Selected {
			s.WriteString(successStyle.Render(line))
		} else {
			s.WriteString(normalStyle.Render(line))
		}
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 移动光标  Space/S 选择/取消  A 全选") + "\n" +
		helpStyle.Render("Enter 确认选择  Esc 返回主菜单  q 退出程序"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		s.WriteString(warningStyle.Render("[!] " + m.message))
	}
	
	return s.String()
}

func (m model) viewPasswordExpiry() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("用户密码过期检查")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	expiredUsers := []User{}
	nearExpiredUsers := []User{}
	normalUsers := []User{}
	
	for _, user := range m.users {
		if user.DaysUsed >= 90 {
			expiredUsers = append(expiredUsers, user)
		} else if user.DaysUsed >= 75 {
			nearExpiredUsers = append(nearExpiredUsers, user)
		} else {
			normalUsers = append(normalUsers, user)
		}
	}
	
	// 已过期用户 - 红色面板
	if len(expiredUsers) > 0 {
		expiredPanel := dangerStyle.Render(fmt.Sprintf(" 已过期用户 (≥90天): %d 个 ", len(expiredUsers)))
		s.WriteString(expiredPanel)
		s.WriteString("\n")
		for _, user := range expiredUsers {
			checkbox := "☐"
			checkboxStyle := normalStyle
			if user.Selected {
				checkbox = "☑"
				checkboxStyle = dangerStyle
			}
			userLine := fmt.Sprintf("  %s %s - %s", 
				checkboxStyle.Render(checkbox), 
				user.Username, 
				dangerStyle.Render(fmt.Sprintf("%d天", user.DaysUsed)))
			s.WriteString(userLine)
			s.WriteString("\n")
		}
		s.WriteString("\n")
	}
	
	// 临近过期用户 - 橙色面板
	if len(nearExpiredUsers) > 0 {
		nearExpiredPanel := warningStyle.Render(fmt.Sprintf(" 临近过期用户 (75-89天): %d 个 ", len(nearExpiredUsers)))
		s.WriteString(nearExpiredPanel)
		s.WriteString("\n")
		for _, user := range nearExpiredUsers {
			checkbox := "☐"
			checkboxStyle := normalStyle
			if user.Selected {
				checkbox = "☑"
				checkboxStyle = warningStyle
			}
			userLine := fmt.Sprintf("  %s %s - %s", 
				checkboxStyle.Render(checkbox), 
				user.Username, 
				warningStyle.Render(fmt.Sprintf("%d天", user.DaysUsed)))
			s.WriteString(userLine)
			s.WriteString("\n")
		}
		s.WriteString("\n")
	}
	
	// 正常用户 - 绿色面板
	if len(normalUsers) > 0 {
		normalPanel := successStyle.Render(fmt.Sprintf(" 正常用户 (<75天): %d 个 ", len(normalUsers)))
		s.WriteString(normalPanel)
		s.WriteString("\n")
		for _, user := range normalUsers {
			userLine := fmt.Sprintf("  %s - %s", 
				user.Username, 
				successStyle.Render(fmt.Sprintf("%d天", user.DaysUsed)))
			s.WriteString(userLine)
			s.WriteString("\n")
		}
		s.WriteString("\n")
	}
	
	selectedCount := 0
	for _, user := range m.users {
		if user.Selected {
			selectedCount++
		}
	}
	
	if selectedCount > 0 {
		selectedPanel := highlightStyle.Render(fmt.Sprintf(" 已选择 %d 个用户进行密码修改 ", selectedCount))
		s.WriteString(selectedPanel)
		s.WriteString("\n\n")
	}
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("S 单选  A 全选  D 选择过期  E 选择临近过期  X 清除选择") + "\n" +
		helpStyle.Render("Enter 修改密码  Esc 返回主菜单  q 退出程序"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		s.WriteString(warningStyle.Render("[!] " + m.message))
	}
	
	return s.String()
}

func (m model) viewPasswordTypeSelect() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("选择密码修改类型")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	selectedCount := 0
	for _, user := range m.users {
		if user.Selected {
			selectedCount++
		}
	}
	
	// 用户统计面板
	userPanel := infoStyle.Render(fmt.Sprintf(" 将为 %d 个用户修改密码 ", selectedCount))
	s.WriteString(userPanel)
	s.WriteString("\n\n")
	
	// 密码类型选项 - 使用不同颜色
	options := []struct {
		text  string
		desc  string
		style lipgloss.Style
	}{
		{"统一密码修改", "所有用户使用相同密码", successStyle},
		{"规则密码修改", "前缀+递增数字后缀", warningStyle},
		{"随机密码生成", "系统生成强随机密码", dangerStyle},
	}
	
	for i, option := range options {
		if i == m.cursor {
			line := selectedStyle.Render(fmt.Sprintf("▶ %d. %s", i+1, option.text))
			s.WriteString(line)
			s.WriteString("\n")
			// 显示描述
			desc := borderStyle.Render(helpStyle.Render("→ " + option.desc))
			s.WriteString(desc)
		} else {
			line := option.style.Render(fmt.Sprintf("  %d. %s", i+1, option.text))
			s.WriteString(line)
		}
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 选择类型  Enter 确认  Esc 返回上级  q 退出程序"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		s.WriteString(warningStyle.Render("[!] " + m.message))
	}
	
	return s.String()
}

func (m model) viewPasswordChange() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("密码修改结果")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	// 根据密码类型显示不同的标题面板
	var typePanel string
	switch m.passwordType {
	case uniformPassword:
		typePanel = successStyle.Render(" 统一密码修改完成 ")
	case ruleBasedPassword:
		typePanel = warningStyle.Render(" 规则密码修改完成 ")
	case randomPassword:
		typePanel = dangerStyle.Render(" 随机密码生成完成 ")
	}
	s.WriteString(typePanel)
	s.WriteString("\n\n")
	
	// 密码结果列表 - 使用彩色显示
	for username, password := range m.generatedPasswords {
		userLine := fmt.Sprintf("%s: %s", 
			successStyle.Render(username), 
			highlightStyle.Render(password))
		s.WriteString(userLine)
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	
	// 警告面板
	warningPanel := panelStyle.Render(
		dangerStyle.Render(" [!] 重要提醒 ") + "\n" +
		warningStyle.Render("请妥善保存这些密码信息！") + "\n" +
		helpStyle.Render("建议立即记录或截图保存"))
	s.WriteString(warningPanel)
	
	s.WriteString("\n")
	
	// 操作说明
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("按任意键返回主菜单  q 退出程序"))
	s.WriteString(helpPanel)
	
	return s.String()
}

func (m model) viewPasswordInput() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("密码输入")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	// 输入提示面板
	promptPanel := infoStyle.Render(" " + m.inputPrompt + " ")
	s.WriteString(promptPanel)
	s.WriteString("\n\n")
	
	// 输入框 - 使用彩色边框
	inputContent := normalStyle.Render("输入: ") + highlightStyle.Render(m.inputValue)
	if m.inputMode {
		inputContent += selectedStyle.Render("_") // 光标
	}
	inputBox := borderStyle.Render(inputContent)
	s.WriteString(inputBox)
	s.WriteString("\n")
	
	// 根据密码类型显示不同的提示面板
	var hintPanel string
	switch m.passwordType {
	case uniformPassword:
		hintPanel = panelStyle.Render(
			warningStyle.Render(" 密码要求 ") + "\n" +
			helpStyle.Render("• 8位以上长度") + "\n" +
			helpStyle.Render("• 包含大小写字母") + "\n" +
			helpStyle.Render("• 包含数字和特殊字符"))
	case ruleBasedPassword:
		hintPanel = panelStyle.Render(
			successStyle.Render(" 前缀规则 ") + "\n" +
			helpStyle.Render("• 输入密码前缀") + "\n" +
			helpStyle.Render("• 自动添加递增数字后缀") + "\n" +
			helpStyle.Render("• 如：前缀001, 前缀002..."))
	}
	s.WriteString(hintPanel)
	
	s.WriteString("\n")
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("Enter 确认输入  Esc 返回上级  q 退出程序"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		s.WriteString(warningStyle.Render("[!] " + m.message))
	}
	
	return s.String()
}
func (m model) viewLockPolicyCheck() string {
	var s strings.Builder
	
	s.WriteString(titleStyle.Render("登录失败锁定策略检查"))
	s.WriteString("\n\n")
	
	// 显示系统信息
	if m.message != "" && strings.Contains(m.message, "检测到系统") {
		s.WriteString(successStyle.Render("System  " + m.message))
		s.WriteString("\n\n")
	}
	
	s.WriteString("当前锁定策略配置:\n\n")
	
	// 显示配置文件路径
	if len(m.lockPolicyFiles) > 0 {
		s.WriteString(normalStyle.Render(fmt.Sprintf("本地认证文件: %s", m.lockPolicyFiles[0])))
		s.WriteString("\n")
		if m.currentLockAttempts > 0 {
			s.WriteString(fmt.Sprintf("   %s 失败 %s 次后锁定 %s 分钟\n", 
				successStyle.Render("✓"),
				dangerStyle.Render(fmt.Sprintf("%d", m.currentLockAttempts)),
				warningStyle.Render(fmt.Sprintf("%d", m.currentLockTime))))
		} else {
			s.WriteString("   " + warningStyle.Render("[!] 未配置锁定策略"))
			s.WriteString("\n")
		}
		
		if len(m.lockPolicyFiles) > 1 && m.lockPolicyFiles[1] != m.lockPolicyFiles[0] {
			s.WriteString("\n")
			s.WriteString(normalStyle.Render(fmt.Sprintf("SSH认证文件: %s", m.lockPolicyFiles[1])))
			s.WriteString("\n")
			if m.currentLockAttempts > 0 {
				s.WriteString(fmt.Sprintf("   %s 失败 %s 次后锁定 %s 分钟\n", 
					successStyle.Render("✓"),
					dangerStyle.Render(fmt.Sprintf("%d", m.currentLockAttempts)),
					warningStyle.Render(fmt.Sprintf("%d", m.currentLockTime))))
			} else {
				s.WriteString("   " + warningStyle.Render("[!] 未配置锁定策略"))
				s.WriteString("\n")
			}
		}
	}
	
	s.WriteString("\n")
	if m.currentLockAttempts == 0 {
		s.WriteString(dangerStyle.Render("[!] 建议配置登录失败锁定策略以提高安全性"))
		s.WriteString("\n\n")
		s.WriteString("是否要配置锁定策略？\n\n")
	} else {
		s.WriteString("是否要修改当前锁定策略？\n\n")
	}
	
	s.WriteString(titleStyle.Render(" 操作说明 "))
	s.WriteString("\n")
	s.WriteString(helpStyle.Render("Enter 配置/修改策略  Esc 返回主菜单  q 退出程序"))
	
	if m.message != "" && !strings.Contains(m.message, "检测到系统") {
		s.WriteString("\n\n")
		s.WriteString(warningStyle.Render("[!] " + m.message))
	}
	
	return s.String()
}

func (m model) viewLockPolicyInput() string {
	var s strings.Builder
	
	s.WriteString(titleStyle.Render("配置登录失败锁定策略"))
	s.WriteString("\n\n")
	
	s.WriteString(m.inputPrompt)
	s.WriteString("\n\n")
	
	// 显示输入框
	inputBox := normalStyle.Render("输入: ") + selectedStyle.Render(m.inputValue)
	if m.inputMode {
		inputBox += selectedStyle.Render("_") // 光标
	}
	s.WriteString(inputBox)
	s.WriteString("\n\n")
	
	// 根据输入类型显示不同的提示
	switch m.lockInputType {
	case "attempts":
		s.WriteString(helpStyle.Render("请输入失败尝试次数（建议3-5次）"))
	case "time":
		s.WriteString(helpStyle.Render("请输入锁定时间（分钟，建议5-30分钟）"))
	}
	
	s.WriteString("\n\n")
	s.WriteString(helpStyle.Render("Enter 确认, Esc 返回上级, q 退出程序"))
	
	if m.message != "" {
		s.WriteString("\n\n")
		s.WriteString(warningStyle.Render(m.message))
	}
	
	return s.String()
}
func (m model) viewEmergencyUnlock() string {
	var s strings.Builder
	
	s.WriteString(titleStyle.Render("紧急解锁用户账户"))
	s.WriteString("\n\n")
	
	s.WriteString(dangerStyle.Render("[!]️  紧急解锁功能"))
	s.WriteString("\n\n")
	
	s.WriteString("此功能将执行以下操作:\n")
	s.WriteString("1. 清除所有用户的失败登录计数\n")
	s.WriteString("2. 解锁所有被锁定的账户\n")
	s.WriteString("3. 重置PAM锁定状态\n\n")
	
	s.WriteString(warningStyle.Render("注意: 这将清除所有安全锁定状态！"))
	s.WriteString("\n\n")
	
	s.WriteString("确定要执行紧急解锁吗？\n\n")
	
	options := []string{
		"是 - 执行紧急解锁",
		"否 - 返回主菜单",
	}
	
	for i, option := range options {
		if i == m.cursor {
			if i == 0 {
				s.WriteString(dangerStyle.Render("▶ " + option))
			} else {
				s.WriteString(selectedStyle.Render("▶ " + option))
			}
		} else {
			s.WriteString(normalStyle.Render("  " + option))
		}
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	s.WriteString(helpStyle.Render("↑/↓ 选择, Enter 确认, Esc 返回上级, q 退出程序"))
	
	if m.message != "" {
		s.WriteString("\n\n")
		s.WriteString(warningStyle.Render(m.message))
	}
	
	return s.String()
}

func (m model) viewLockPolicyOptions() string {
	var s strings.Builder
	
	s.WriteString(titleStyle.Render("锁定策略配置选项"))
	s.WriteString("\n\n")
	
	s.WriteString("请选择锁定策略配置:\n\n")
	
	options := []string{
		"1. 标准配置 - 包括root用户锁定",
		"2. 安全配置 - root用户白名单（推荐）",
	}
	
	for i, option := range options {
		if i == m.cursor {
			if i == 1 {
				s.WriteString(successStyle.Render("▶ " + option))
			} else {
				s.WriteString(selectedStyle.Render("▶ " + option))
			}
		} else {
			s.WriteString(normalStyle.Render("  " + option))
		}
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	s.WriteString(warningStyle.Render("重要说明:"))
	s.WriteString("\n")
	s.WriteString("• 标准配置: root用户也会被锁定，可能导致系统无法管理\n")
	s.WriteString("• 安全配置: root用户不会被锁定，推荐用于生产环境\n")
	s.WriteString("\n")
	s.WriteString(helpStyle.Render("↑/↓ 选择, Enter 确认, Esc 返回上级, q 退出程序"))
	
	if m.message != "" {
		s.WriteString("\n\n")
		s.WriteString(warningStyle.Render(m.message))
	}
	
	return s.String()
}
func (m model) viewSecurityCheck() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("系统安全合规检查")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	// 模式选择面板
	modePanel := ""
	if m.strictMode {
		modePanel = successStyle.Render(" ✓ 严格模式 ") + normalStyle.Render(" - 只检查不修改 ") + helpStyle.Render("(按M切换)")
	} else {
		modePanel = warningStyle.Render(" ◉ 标准模式 ") + normalStyle.Render(" - 检查并提供修复建议 ") + helpStyle.Render("(按M切换)")
	}
	s.WriteString("检查模式: " + modePanel)
	s.WriteString("\n\n")
	
	// 统计信息
	selectedCount := 0
	for _, selected := range m.selectedChecks {
		if selected {
			selectedCount++
		}
	}
	
	// 显示当前位置和总数信息
	currentPos := m.cursor + 1
	totalItems := len(SecurityChecks)
	statsPanel := infoStyle.Render(fmt.Sprintf(" 已选择: %d/%d 项 ", selectedCount, totalItems)) + 
		" " + highlightStyle.Render(fmt.Sprintf(" 位置: %d/%d ", currentPos, totalItems))
	s.WriteString(statsPanel)
	s.WriteString("\n\n")
	
	// 分类统计信息
	categoryStats := make(map[string]int)
	selectedByCategory := make(map[string]int)
	
	for i, check := range SecurityChecks {
		categoryStats[check.Category]++
		if i < len(m.selectedChecks) && m.selectedChecks[i] {
			selectedByCategory[check.Category]++
		}
	}
	
	// 显示分类统计
	categoryInfo := ""
	categories := []string{"工具", "账号", "口令", "认证", "权限", "日志", "网络", "服务", "配置", "资源", "合规"}
	for _, cat := range categories {
		if total, exists := categoryStats[cat]; exists {
			selected := selectedByCategory[cat]
			if selected > 0 {
				categoryInfo += successStyle.Render(fmt.Sprintf("%s:%d/%d ", cat, selected, total))
			} else {
				categoryInfo += normalStyle.Render(fmt.Sprintf("%s:0/%d ", cat, total))
			}
		}
	}
	if categoryInfo != "" {
		s.WriteString(helpStyle.Render("分类统计: ") + categoryInfo)
		s.WriteString("\n\n")
	}
	
	// 分页显示逻辑
	const itemsPerPage = 15 // 每页显示15个项目
	totalPages := (len(SecurityChecks) + itemsPerPage - 1) / itemsPerPage
	currentPage := m.cursor / itemsPerPage
	startIdx := currentPage * itemsPerPage
	endIdx := startIdx + itemsPerPage
	if endIdx > len(SecurityChecks) {
		endIdx = len(SecurityChecks)
	}
	
	// 显示页面信息
	pageInfo := fmt.Sprintf("第 %d/%d 页 (显示 %d-%d 项)", 
		currentPage+1, totalPages, startIdx+1, endIdx)
	s.WriteString(infoStyle.Render(" " + pageInfo + " "))
	s.WriteString("\n\n")
	
	// 显示当前页的检查项目
	for i := startIdx; i < endIdx; i++ {
		check := SecurityChecks[i]
		prefix := "  "
		if i == m.cursor {
			prefix = selectedStyle.Render("▶ ")
		}
		
		checkbox := "☐"
		checkboxStyle := normalStyle
		if i < len(m.selectedChecks) && m.selectedChecks[i] {
			checkbox = "☑"
			switch check.Level {
			case "极高":
				checkboxStyle = dangerStyle
			case "高":
				checkboxStyle = dangerStyle
			case "中":
				checkboxStyle = warningStyle
			case "低":
				checkboxStyle = successStyle
			}
		}
		
		// 风险等级标签 - 使用不同颜色
		var levelStyle lipgloss.Style
		var levelLabel string
		switch check.Level {
		case "极高":
			levelStyle = dangerStyle
			levelLabel = "[极高]"
		case "高":
			levelStyle = dangerStyle
			levelLabel = "[高]"
		case "中":
			levelStyle = warningStyle
			levelLabel = "[中]"
		case "低":
			levelStyle = successStyle
			levelLabel = "[低]"
		}
		
		// 添加分类标签
		categoryLabel := helpStyle.Render(fmt.Sprintf("(%s)", check.Category))
		
		line := fmt.Sprintf("%s%s %s %s %s", 
			prefix,
			checkboxStyle.Render(checkbox),
			levelStyle.Render(levelLabel),
			check.Name,
			categoryLabel)
		
		if i == m.cursor {
			s.WriteString(selectedStyle.Render(line))
			s.WriteString("\n")
			// 显示当前项的描述 - 使用边框面板
			descPanel := borderStyle.Render(helpStyle.Render("→ " + check.Description))
			s.WriteString(descPanel)
		} else {
			s.WriteString(line)
		}
		s.WriteString("\n")
	}
	
	s.WriteString("\n")
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 移动光标  Space 选择/取消  A 全选  X 清除选择") + "\n" +
		helpStyle.Render("H 选择高风险  C 选择中风险  L 选择低风险") + "\n" +
		helpStyle.Render("M 切换模式  Enter 开始检查  Esc 返回主菜单  q 退出") + "\n" +
		warningStyle.Render("提示: 共72个检查项，建议每次选择≤15项以避免系统过载"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		s.WriteString(infoStyle.Render("💡 " + m.message))
	}
	
	return s.String()
}

func (m model) viewSecurityCheckResults() string {
	var s strings.Builder
	
	// 如果正在显示进度条，显示进度条界面
	if m.showProgress && m.isProcessing {
		return m.renderProgressBar()
	}
	
	// 彩色标题
	title := titleStyle.Render("安全检查结果")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	if len(m.securityResults) == 0 {
		loadingPanel := warningStyle.Render(" 正在执行安全检查，请稍候... ")
		s.WriteString(loadingPanel)
		s.WriteString("\n")
		return s.String()
	}
	
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
		case "检查失败", "检查超时":
			failed++
		}
	}
	
	// 彩色统计面板
	statsPanel := panelStyle.Render(
		highlightStyle.Render(" 检查结果统计 ") + "\n" +
		successStyle.Render(fmt.Sprintf("✓ 合规: %d 项", compliant)) + "  " +
		dangerStyle.Render(fmt.Sprintf("✗ 不合规: %d 项", nonCompliant)) + "  " +
		warningStyle.Render(fmt.Sprintf("[!] 失败: %d 项", failed)) + "\n" +
		infoStyle.Render(fmt.Sprintf("总计: %d 项", len(m.securityResults))))
	s.WriteString(statsPanel)
	s.WriteString("\n")
	
	// 分页显示逻辑
	const itemsPerPage = 10 // 每页显示10个结果项目
	totalPages := (len(m.securityResults) + itemsPerPage - 1) / itemsPerPage
	currentPage := m.cursor / itemsPerPage
	startIdx := currentPage * itemsPerPage
	endIdx := startIdx + itemsPerPage
	if endIdx > len(m.securityResults) {
		endIdx = len(m.securityResults)
	}
	
	// 显示页面信息和当前位置
	currentPos := m.cursor + 1
	pageInfo := fmt.Sprintf("第 %d/%d 页 (显示 %d-%d 项) | 位置: %d/%d", 
		currentPage+1, totalPages, startIdx+1, endIdx, currentPos, len(m.securityResults))
	s.WriteString(infoStyle.Render(" " + pageInfo + " "))
	s.WriteString("\n\n")
	
	// 详细结果列表标题
	detailsTitle := highlightStyle.Render(" 详细结果 ")
	s.WriteString(detailsTitle)
	s.WriteString("\n\n")
	
	// 显示当前页的检查结果
	for i := startIdx; i < endIdx; i++ {
		result := m.securityResults[i]
		prefix := "  "
		if i == m.cursor {
			prefix = selectedStyle.Render("▶ ")
		}
		
		// 状态图标和颜色
		var statusIcon string
		var statusStyle lipgloss.Style
		switch result.Status {
		case "合规":
			statusIcon = "✓"
			statusStyle = successStyle
		case "不合规":
			statusIcon = "✗"
			statusStyle = dangerStyle
		case "检查失败", "检查超时":
			statusIcon = "[!]"
			statusStyle = warningStyle
		default:
			statusIcon = "?"
			statusStyle = normalStyle
		}
		
		// 风险等级标签
		var levelStyle lipgloss.Style
		switch result.Level {
		case "极高":
			levelStyle = dangerStyle
		case "高":
			levelStyle = dangerStyle
		case "中":
			levelStyle = warningStyle
		case "低":
			levelStyle = successStyle
		}
		
		line := fmt.Sprintf("%s%s %s %s - %s",
			prefix,
			statusStyle.Render(statusIcon),
			levelStyle.Render("["+result.Level+"]"),
			result.Name,
			statusStyle.Render(result.Status))
		
		if i == m.cursor {
			s.WriteString(selectedStyle.Render(line))
		} else {
			s.WriteString(line)
		}
		s.WriteString("\n")
		
		// 显示当前选中项的详细信息
		if i == m.cursor {
			s.WriteString("\n")
			
			// 详细信息面板
			detailsContent := ""
			
			if result.Description != "" {
				detailsContent += helpStyle.Render("描述: ") + normalStyle.Render(result.Description) + "\n"
			}
			
			if result.Command != "" {
				detailsContent += helpStyle.Render("检查命令: ") + infoStyle.Render(result.Command) + "\n"
			}
			
			if result.Details != "" {
				detailsContent += helpStyle.Render("检查结果: ") + normalStyle.Render(result.Details) + "\n"
			}
			
			// 显示原始输出 - 使用不同颜色区分
			if result.RawOutput != "" {
				detailsContent += helpStyle.Render("原始输出: ") + "\n"
				lines := strings.Split(result.RawOutput, "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						detailsContent += "     " + highlightStyle.Render(line) + "\n"
					}
				}
			}
			
			if result.FixSuggestion != "" && !m.strictMode {
				detailsContent += helpStyle.Render("修复建议: ") + warningStyle.Render(result.FixSuggestion) + "\n"
			}
			
			detailsPanel := borderStyle.Render(detailsContent)
			s.WriteString(detailsPanel)
			s.WriteString("\n")
		}
	}
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 查看详情  R 重新检查  S 保存报告  D 导出详细报告") + "\n" +
		helpStyle.Render("F 显示不合规  C 显示合规  Esc 返回检查界面  q 退出程序") + "\n" +
		warningStyle.Render("提示: 分页显示检查结果，使用↑/↓键浏览所有项目"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		if strings.Contains(m.message, "成功") || strings.Contains(m.message, "已保存") {
			s.WriteString(successStyle.Render("✓ " + m.message))
		} else {
			s.WriteString(warningStyle.Render("[!] " + m.message))
		}
	}

	return s.String()
}