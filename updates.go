package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) updateMainMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c", "esc":
		return m, tea.Quit
	case "r", "R":
		// 切换Root检测开关
		m.enableRootCheck = !m.enableRootCheck
		if m.enableRootCheck {
			m.message = "⚠ 已启用Root用户检测（包含密码修改/过期检查/弱口令检测）"
		} else {
			m.message = "✓ 已禁用Root用户检测（安全模式，跳过Root用户）"
		}
		// 根据开关状态重新获取用户列表
		users, err := getSystemUsersWithRoot(m.enableRootCheck)
		if err == nil {
			m.users = users
		}
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 6 {
			m.cursor++
		}
	case "enter", " ":
		switch m.cursor {
		case 0:
			m.currentScreen = userList
			m.cursor = 0
			m.message = ""
		case 1:
			// 检查密码过期时间
			err := checkPasswordExpiry(&m)
			if err != nil {
				m.message = "检查密码过期时间失败: " + err.Error()
			} else {
				m.currentScreen = passwordExpiry
				m.cursor = 0
				m.message = ""
			}
		case 2:
			// 检查锁定策略
			err := checkLockPolicy(&m)
			if err != nil {
				m.message = "检查锁定策略失败: " + err.Error()
			} else {
				m.currentScreen = lockPolicyCheck
				m.cursor = 0
				m.message = ""
			}
		case 3:
			// 系统安全合规检查
			m.currentScreen = securityCheck
			m.cursor = 0
			m.message = ""
			// 初始化选择状态
			if len(m.selectedChecks) == 0 {
				m.selectedChecks = make([]bool, len(SecurityChecks))
				m.strictMode = true // 默认严格模式
			}
		case 4:
			// 弱口令检测
			m.currentScreen = weakPasswordCheck
			m.cursor = 0
			m.message = ""
			// 初始化弱口令检测配置
			m.weakPasswordConfig = getPerformanceConfig()
		case 5:
			// 紧急解锁
			m.currentScreen = emergencyUnlock
			m.cursor = 0
			m.message = ""
		case 6:
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) updateUserList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.users)-1 {
			m.cursor++
		}
	case " ", "s", "S":
		if m.cursor < len(m.users) {
			m.users[m.cursor].Selected = !m.users[m.cursor].Selected
		}
	case "a", "A":
		// A键只能全选，不能全不选
		allSelected := true
		for _, user := range m.users {
			if !user.Selected {
				allSelected = false
				break
			}
		}
		if !allSelected {
			for i := range m.users {
				m.users[i].Selected = true
			}
		}
	case "enter":
		selectedCount := 0
		for _, user := range m.users {
			if user.Selected {
				selectedCount++
			}
		}
		if selectedCount == 0 {
			m.message = "请至少选择一个用户"
		} else {
			m.currentScreen = passwordTypeSelect
			m.cursor = 0
			m.message = ""
		}
	}
	return m, nil
}

func (m model) updatePasswordExpiry(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "s", "S":
		// 单选功能 - 这里需要实现光标选择逻辑
		// 为简化，暂时跳过具体实现
	case "a", "A":
		// A键只能全选，不能全不选
		allSelected := true
		for _, user := range m.users {
			if !user.Selected {
				allSelected = false
				break
			}
		}
		if !allSelected {
			for i := range m.users {
				m.users[i].Selected = true
			}
		}
	case "d", "D":
		for i := range m.users {
			if m.users[i].DaysUsed >= 90 {
				m.users[i].Selected = true
			}
		}
	case "e", "E":
		for i := range m.users {
			if m.users[i].DaysUsed >= 75 && m.users[i].DaysUsed < 90 {
				m.users[i].Selected = true
			}
		}
	case "x", "X":
		for i := range m.users {
			m.users[i].Selected = false
		}
	case "enter":
		selectedCount := 0
		for _, user := range m.users {
			if user.Selected {
				selectedCount++
			}
		}
		if selectedCount == 0 {
			m.message = "请至少选择一个用户"
		} else {
			m.currentScreen = passwordTypeSelect
			m.cursor = 0
			m.message = ""
		}
	}
	return m, nil
}

func (m model) updatePasswordTypeSelect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 2 {
			m.cursor++
		}
	case "enter":
		m.passwordType = passwordType(m.cursor)
		
		switch m.passwordType {
		case uniformPassword:
			m.currentScreen = passwordInput
			m.inputValue = ""
			m.inputMode = true
			m.inputPrompt = "请输入统一密码："
			m.message = ""
		case ruleBasedPassword:
			m.currentScreen = passwordInput
			m.inputValue = ""
			m.inputMode = true
			m.inputPrompt = "请输入密码前缀："
			m.message = ""
		case randomPassword:
			// 随机密码直接生成，不需要用户输入
			err := generatePasswords(&m)
			if err != nil {
				m.message = "生成密码失败: " + err.Error()
			} else {
				m.currentScreen = passwordChange
				m.cursor = 0
				m.message = ""
			}
		}
	}
	return m, nil
}

func (m model) updatePasswordChange(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	default:
		// 清除选择状态
		for i := range m.users {
			m.users[i].Selected = false
		}
		m.generatedPasswords = make(map[string]string)
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	}
	return m, nil
}
func (m model) updatePasswordInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = passwordTypeSelect
		m.cursor = 0
		m.inputValue = ""
		m.inputMode = false
		m.message = ""
	case "enter":
		if m.inputValue == "" {
			m.message = "输入不能为空"
			return m, nil
		}
		
		// 验证输入
		switch m.passwordType {
		case uniformPassword:
			if !validatePassword(m.inputValue) {
				m.message = "密码不符合安全规则：需要8位以上，包含大小写字母、数字、特殊字符"
				return m, nil
			}
			m.uniformPass = m.inputValue
		case ruleBasedPassword:
			if len(m.inputValue) < 3 {
				m.message = "前缀长度至少3个字符"
				return m, nil
			}
			m.rulePrefix = m.inputValue
		}
		
		// 生成密码
		err := generatePasswords(&m)
		if err != nil {
			m.message = "生成密码失败: " + err.Error()
		} else {
			m.currentScreen = passwordChange
			m.cursor = 0
			m.inputValue = ""
			m.inputMode = false
			m.message = ""
		}
	case "backspace":
		if len(m.inputValue) > 0 {
			m.inputValue = m.inputValue[:len(m.inputValue)-1]
		}
	default:
		// 处理普通字符输入
		if len(msg.String()) == 1 {
			char := msg.String()
			// 限制输入长度
			if len(m.inputValue) < 50 {
				m.inputValue += char
			}
		}
	}
	return m, nil
}
func (m model) updateLockPolicyCheck(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "enter":
		// 跳转到锁定策略选项界面
		m.currentScreen = lockPolicyOptions
		m.cursor = 1 // 默认选择安全配置
		m.message = ""
	}
	return m, nil
}

func (m model) updateLockPolicyInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = lockPolicyCheck
		m.inputValue = ""
		m.inputMode = false
		m.message = ""
	case "enter":
		if m.inputValue == "" {
			m.message = "输入不能为空"
			return m, nil
		}
		
		// 验证输入是否为数字
		if !isNumeric(m.inputValue) {
			m.message = "请输入有效的数字"
			return m, nil
		}
		
		if m.lockInputType == "attempts" {
			// 保存尝试次数，继续输入锁定时间
			attempts := parseInt(m.inputValue)
			if attempts < 1 || attempts > 10 {
				m.message = "尝试次数应在1-10之间"
				return m, nil
			}
			m.newLockAttempts = attempts
			m.lockInputType = "time"
			m.inputValue = ""
			m.inputPrompt = "请输入锁定时间（分钟）："
			m.message = ""
		} else if m.lockInputType == "time" {
			// 保存锁定时间，应用配置
			lockTime := parseInt(m.inputValue)
			if lockTime < 1 || lockTime > 1440 {
				m.message = "锁定时间应在1-1440分钟之间"
				return m, nil
			}
			m.newLockTime = lockTime
			
			// 应用锁定策略配置
			err := applyLockPolicy(&m)
			if err != nil {
				m.message = "应用锁定策略失败: " + err.Error()
			} else {
				m.message = "锁定策略配置成功"
				m.currentScreen = lockPolicyCheck
				m.inputValue = ""
				m.inputMode = false
			}
		}
	case "backspace":
		if len(m.inputValue) > 0 {
			m.inputValue = m.inputValue[:len(m.inputValue)-1]
		}
	default:
		// 只允许输入数字
		if len(msg.String()) == 1 {
			char := msg.String()
			if char >= "0" && char <= "9" && len(m.inputValue) < 10 {
				m.inputValue += char
			}
		}
	}
	return m, nil
}
func (m model) updateEmergencyUnlock(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 1 {
			m.cursor++
		}
	case "enter":
		if m.cursor == 0 {
			// 执行紧急解锁
			err := performEmergencyUnlock()
			if err != nil {
				m.message = "紧急解锁失败: " + err.Error()
			} else {
				m.message = "紧急解锁成功！所有用户账户已解锁"
				m.currentScreen = mainMenu
				m.cursor = 0
			}
		} else {
			// 返回主菜单
			m.currentScreen = mainMenu
			m.cursor = 0
			m.message = ""
		}
	}
	return m, nil
}

func (m model) updateLockPolicyOptions(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = lockPolicyCheck
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 1 {
			m.cursor++
		}
	case "enter":
		// 设置root白名单选项
		m.rootWhitelist = (m.cursor == 1)
		
		// 开始配置锁定策略
		m.currentScreen = lockPolicyInput
		m.lockInputType = "attempts"
		m.inputValue = ""
		m.inputMode = true
		m.inputPrompt = "请输入失败尝试次数："
		m.message = ""
	}
	return m, nil
}
func (m model) updateSecurityCheck(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(SecurityChecks)-1 {
			m.cursor++
		}
	case " ", "s", "S":
		// 切换选择状态
		if m.cursor < len(m.selectedChecks) {
			m.selectedChecks[m.cursor] = !m.selectedChecks[m.cursor]
			// 显示选择反馈
			if m.selectedChecks[m.cursor] {
				m.message = fmt.Sprintf("已选择: %s", SecurityChecks[m.cursor].Name)
			} else {
				m.message = fmt.Sprintf("已取消: %s", SecurityChecks[m.cursor].Name)
			}
		}
	case "a", "A":
		// 全选
		for i := range m.selectedChecks {
			m.selectedChecks[i] = true
		}
		m.message = "已全选所有检查项"
	case "x", "X":
		// 清除选择
		for i := range m.selectedChecks {
			m.selectedChecks[i] = false
		}
		m.message = "已清除所有选择"
	case "h", "H":
		// 选择所有高风险项（包括极高）
		count := 0
		for i, check := range SecurityChecks {
			if check.Level == "高" || check.Level == "极高" {
				m.selectedChecks[i] = true
				count++
			}
		}
		m.message = fmt.Sprintf("已选择 %d 个高风险项", count)
	case "l", "L":
		// 选择所有低风险项
		count := 0
		for i, check := range SecurityChecks {
			if check.Level == "低" {
				m.selectedChecks[i] = true
				count++
			}
		}
		m.message = fmt.Sprintf("已选择 %d 个低风险项", count)
	case "c", "C":
		// 选择所有中风险项
		count := 0
		for i, check := range SecurityChecks {
			if check.Level == "中" {
				m.selectedChecks[i] = true
				count++
			}
		}
		m.message = fmt.Sprintf("已选择 %d 个中风险项", count)
	case "m", "M":
		// 切换模式
		m.strictMode = !m.strictMode
		if m.strictMode {
			m.message = "✓ 已切换到严格模式 - 只检查不修改"
		} else {
			m.message = "◉ 已切换到标准模式 - 检查并提供修复建议"
		}
	case "enter":
		// 开始检查
		selectedCount := 0
		for _, selected := range m.selectedChecks {
			if selected {
				selectedCount++
			}
		}
		if selectedCount == 0 {
			m.message = "[!] 请至少选择一个检查项"
		} else {
			// 限制同时执行的检查数量，避免系统过载
			if selectedCount > 15 {
				m.message = "[!] 为避免系统过载，建议一次选择不超过15个检查项。大批量检查时部分资源密集型检查将被跳过。"
				// 允许继续执行，但会跳过部分检查
			}
			
			// 初始化进度条
			m.showProgress = true
			m.isProcessing = true
			m.progressCurrent = 0
			m.progressTotal = selectedCount
			m.progressMessage = "准备开始安全检查..."
			
			// 切换到结果界面显示进度条
			m.currentScreen = securityCheckResults
			m.cursor = 0
			
			// 启动异步安全检查
			return m, tea.Batch(
				performSecurityChecksAsync(m.selectedChecks, m.strictMode),
				tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
					return t
				}),
			)
		}
	}
	return m, nil
}

func (m model) updateSecurityCheckResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = securityCheck
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.securityResults)-1 {
			m.cursor++
		}
	case "r", "R":
		// 重新检查
		selectedCount := 0
		for _, selected := range m.selectedChecks {
			if selected {
				selectedCount++
			}
		}
		if selectedCount > 15 {
			m.message = "正在重新执行安全检查（部分资源密集型检查将被跳过）..."
		} else {
			m.message = "正在重新执行安全检查..."
		}
		
		// 启动进度显示
		m.showProgress = true
		m.isProcessing = true
		m.progressCurrent = 0
		m.progressTotal = selectedCount
		m.progressMessage = "准备重新开始安全检查..."
		
		// 启动异步重新检查
		return m, tea.Batch(
			performSecurityChecksAsync(m.selectedChecks, m.strictMode),
			tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
				return t
			}),
		)
	case "s", "S":
		// 保存简要报告
		err := saveSecurityReport(&m)
		if err != nil {
			m.message = "保存报告失败: " + err.Error()
		} else {
			filename := fmt.Sprintf("security_report_%s.txt", 
				time.Now().Format("20060102_150405"))
			m.message = fmt.Sprintf("✓ 简要报告已保存到 %s", filename)
		}
	case "d", "D":
		// 导出详细报告
		err := saveDetailedSecurityReport(&m)
		if err != nil {
			m.message = "导出详细报告失败: " + err.Error()
		} else {
			filename := fmt.Sprintf("security_detailed_report_%s.txt", 
				time.Now().Format("20060102_150405"))
			m.message = fmt.Sprintf("✓ 详细报告已保存到 %s", filename)
		}
	case "f", "F":
		// 只显示不合规项
		if len(m.securityResults) > 0 {
			nonCompliantCount := 0
			for _, result := range m.securityResults {
				if result.Status == "不合规" {
					nonCompliantCount++
				}
			}
			m.message = fmt.Sprintf("发现 %d 个不合规项", nonCompliantCount)
		}
	case "c", "C":
		// 只显示合规项
		if len(m.securityResults) > 0 {
			compliantCount := 0
			for _, result := range m.securityResults {
				if result.Status == "合规" {
					compliantCount++
				}
			}
			m.message = fmt.Sprintf("发现 %d 个合规项", compliantCount)
		}
	}
	return m, nil
}

func (m model) updateWeakPasswordCheck(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = mainMenu
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 3 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0:
			// 开始弱口令检测
			// 初始化进度条
			m.showProgress = true
			m.isProcessing = true
			m.progressCurrent = 0
			m.progressTotal = 0 // 将在检测函数中设置
			m.progressMessage = "准备开始弱口令检测..."

			// 切换到结果界面显示进度条
			m.currentScreen = weakPasswordResults
			m.cursor = 0

			// 启动异步弱口令检测，传递字典路径和Root开关状态
			return m, tea.Batch(
				performWeakPasswordCheckAsync(m.dictionaryFilePath, m.enableRootCheck, m.weakPasswordConfig),
				tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
					return t
				}),
			)
		case 1:
			// 输入字典路径
			m.currentScreen = weakPasswordDictInput
			m.inputValue = m.dictionaryFilePath // 预填充当前路径
			m.inputMode = true
			m.inputPrompt = "请输入字典文件路径"
			m.message = ""
		case 2:
			// 性能配置调整
			m.currentScreen = weakPasswordConfig
			m.cursor = 0
			m.message = ""
		case 3:
			// 返回主菜单
			m.currentScreen = mainMenu
			m.cursor = 0
			m.message = ""
		}
	}
	return m, nil
}

func (m model) updateWeakPasswordResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = weakPasswordCheck
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.weakPasswordResults)-1 {
			m.cursor++
		}
	case "r", "R":
		// 重新检测
		// 启动进度显示
		m.showProgress = true
		m.isProcessing = true
		m.progressCurrent = 0
		m.progressTotal = 0 // 将在检测函数中设置
		m.progressMessage = "准备重新开始弱口令检测..."

		// 启动异步重新检测，传递字典路径和Root开关状态
		return m, tea.Batch(
			performWeakPasswordCheckAsync(m.dictionaryFilePath, m.enableRootCheck, m.weakPasswordConfig),
			tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
				return t
			}),
		)
	case "s", "S":
		// 保存报告
		err := saveWeakPasswordReport(&m)
		if err != nil {
			m.message = "保存报告失败: " + err.Error()
		} else {
			filename := fmt.Sprintf("weak_password_report_%s.txt", 
				time.Now().Format("20060102_150405"))
			m.message = fmt.Sprintf("✓ 弱口令报告已保存到 %s", filename)
		}
	case "f", "F":
		// 只显示弱口令
		if len(m.weakPasswordResults) > 0 {
			weakCount := 0
			for _, result := range m.weakPasswordResults {
				if result.IsWeak {
					weakCount++
				}
			}
			m.message = fmt.Sprintf("发现 %d 个弱口令账户", weakCount)
		}
	}
	return m, nil
}
func (m model) updateWeakPasswordConfig(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.currentScreen = weakPasswordCheck
		m.cursor = 0
		m.message = ""
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 5 {
			m.cursor++
		}
	case "left", "h":
		// 减少配置值或切换字典
		switch m.cursor {
		case 0: // 并发数
			if m.weakPasswordConfig.MaxConcurrent > 1 {
				m.weakPasswordConfig.MaxConcurrent--
			}
		case 1: // 批处理大小
			if m.weakPasswordConfig.BatchSize > 10 {
				m.weakPasswordConfig.BatchSize -= 10
			}
		case 2: // CPU限制
			if m.weakPasswordConfig.CPULimit > 0.1 {
				m.weakPasswordConfig.CPULimit -= 0.1
			}
		case 3: // 检查间隔
			if m.weakPasswordConfig.CheckInterval > 50*time.Millisecond {
				m.weakPasswordConfig.CheckInterval -= 50 * time.Millisecond
			}
		case 4: // 字典选择 - 切换到上一个字典
			if len(m.availableDictionaries) > 0 {
				// 找到当前字典的索引
				currentIndex := -1
				for i, dict := range m.availableDictionaries {
					if dict == m.dictionaryFilePath {
						currentIndex = i
						break
					}
				}
				// 切换到上一个字典（循环）
				if currentIndex > 0 {
					m.dictionaryFilePath = m.availableDictionaries[currentIndex-1]
				} else if currentIndex == 0 {
					m.dictionaryFilePath = m.availableDictionaries[len(m.availableDictionaries)-1]
				} else if len(m.availableDictionaries) > 0 {
					m.dictionaryFilePath = m.availableDictionaries[len(m.availableDictionaries)-1]
				}
				m.message = "已选择字典: " + m.dictionaryFilePath
			}
		}
	case "right", "l":
		// 增加配置值或切换字典
		switch m.cursor {
		case 0: // 并发数
			if m.weakPasswordConfig.MaxConcurrent < 8 {
				m.weakPasswordConfig.MaxConcurrent++
			}
		case 1: // 批处理大小
			if m.weakPasswordConfig.BatchSize < 200 {
				m.weakPasswordConfig.BatchSize += 10
			}
		case 2: // CPU限制
			if m.weakPasswordConfig.CPULimit < 0.8 {
				m.weakPasswordConfig.CPULimit += 0.1
			}
		case 3: // 检查间隔
			if m.weakPasswordConfig.CheckInterval < 1000*time.Millisecond {
				m.weakPasswordConfig.CheckInterval += 50 * time.Millisecond
			}
		case 4: // 字典选择 - 切换到下一个字典
			if len(m.availableDictionaries) > 0 {
				// 找到当前字典的索引
				currentIndex := -1
				for i, dict := range m.availableDictionaries {
					if dict == m.dictionaryFilePath {
						currentIndex = i
						break
					}
				}
				// 切换到下一个字典（循环）
				if currentIndex >= 0 && currentIndex < len(m.availableDictionaries)-1 {
					m.dictionaryFilePath = m.availableDictionaries[currentIndex+1]
				} else if currentIndex == len(m.availableDictionaries)-1 {
					m.dictionaryFilePath = m.availableDictionaries[0]
				} else if len(m.availableDictionaries) > 0 {
					m.dictionaryFilePath = m.availableDictionaries[0]
				}
				m.message = "已选择字典: " + m.dictionaryFilePath
			}
		}
	case "r", "R":
		// 重置为默认配置
		m.weakPasswordConfig = getPerformanceConfig()
		m.message = "已重置为默认配置"
	case "enter":
		if m.cursor == 5 {
			// 保存并返回
			m.currentScreen = weakPasswordCheck
			m.cursor = 0
			m.message = "配置已保存"
		}
	}
	return m, nil
}

// 字典路径输入界面事件处理
func (m model) updateWeakPasswordDictInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc":
			// 取消输入，返回弱口令检测界面
			m.currentScreen = weakPasswordCheck
			m.cursor = 0
			m.inputMode = false
			m.message = ""
		case "enter":
			// 验证并保存字典路径
			inputPath := strings.TrimSpace(m.inputValue)
			if inputPath == "" {
				m.message = "字典路径不能为空"
				return m, nil
			}

			// 检查文件是否存在
			if _, err := os.Stat(inputPath); os.IsNotExist(err) {
				m.message = "文件不存在: " + inputPath
				return m, nil
			}

			// 检查文件是否可读
			file, err := os.Open(inputPath)
			if err != nil {
				m.message = "无法读取文件: " + err.Error()
				return m, nil
			}
			file.Close()

			// 保存字典路径
			m.dictionaryFilePath = inputPath
			m.currentScreen = weakPasswordCheck
			m.cursor = 0
			m.inputMode = false
			m.message = "✓ 字典已设置: " + inputPath
		case "backspace":
			if len(m.inputValue) > 0 {
				// 支持UTF-8字符删除
				r := []rune(m.inputValue)
				if len(r) > 0 {
					m.inputValue = string(r[:len(r)-1])
				}
			}
		default:
			// 只接受可打印字符
			if len(msg.String()) == 1 && msg.String() >= " " && msg.String() <= "~" {
				m.inputValue += msg.String()
			}
			// 也接受一些特殊字符如路径分隔符
			if len(msg.String()) == 1 && (msg.String() == "/" || msg.String() == "\\" || msg.String() == "." || msg.String() == "-" || msg.String() == "_") {
				m.inputValue += msg.String()
			}
		}
	}
	return m, nil
}