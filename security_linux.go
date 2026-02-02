//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
	
	tea "github.com/charmbracelet/bubbletea"
)

// Linux环境下的真实安全检查实现 - 带进度显示版本
func performSecurityChecksReal(m *model) error {
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
		
		// 显示进度信息
		progressPercent := (currentCheck * 100) / totalChecks
		result.Status = fmt.Sprintf("[%d/%d] (%d%%) %s", 
			currentCheck, totalChecks, progressPercent, check.Name)
		
		// 先添加进度状态到结果中，这样用户可以看到进度
		m.securityResults = append(m.securityResults, result)
		
		// 根据命令类型设置不同的超时时间
		timeout := getCommandTimeout(check.Command)
		
		// 对于高风险的资源密集型命令，在大批量执行时跳过或使用替代命令
		if totalChecks > 15 && isResourceIntensiveCommand(check.Command) {
			result.Status = "已跳过"
			result.Details = "批量执行时跳过资源密集型检查，建议单独执行"
			result.RawOutput = "为避免系统过载，此检查项在批量执行时被跳过"
		} else {
			// 执行检查命令
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			
			// 优化命令执行，添加资源限制
			cmdStr := optimizeCommand(check.Command)
			cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
			
			output, err := cmd.CombinedOutput()
			cancel() // 立即释放资源
			
			// 保存原始输出
			result.RawOutput = strings.TrimSpace(string(output))
			if len(result.RawOutput) > 1000 {
				// 限制输出长度，避免界面卡顿
				result.RawOutput = result.RawOutput[:1000] + "\n... (输出已截断)"
			}
			
			if ctx.Err() == context.DeadlineExceeded {
				result.Status = "检查超时"
				result.Details = fmt.Sprintf("命令执行超时（%.1f秒）", timeout.Seconds())
			} else if err != nil {
				result.Status = "检查失败"
				result.Details = fmt.Sprintf("命令执行失败: %v", err)
				if result.RawOutput != "" && len(result.RawOutput) < 200 {
					result.Details += fmt.Sprintf(" (输出: %s)", result.RawOutput)
				}
			} else {
				// 根据检查项ID分析结果
				analyzeResult(&result, result.RawOutput)
			}
		}
		
		// 添加修复建议
		if result.Status == "不合规" && !m.strictMode {
			result.FixSuggestion = getFixSuggestion(result.ID)
		}
		
		// 更新结果
		m.securityResults[len(m.securityResults)-1] = result
		
		// 每个检查项之间添加小延迟，让用户看到进度
		time.Sleep(100 * time.Millisecond)
	}
	
	return nil
}

// 根据命令类型获取合适的超时时间
func getCommandTimeout(command string) time.Duration {
	// 极度危险的命令 - 很短超时
	if strings.Contains(command, "find /") && !strings.Contains(command, "head") {
		return 2 * time.Second
	}
	if strings.Contains(command, "rpm -Va") {
		return 3 * time.Second
	}
	if strings.Contains(command, "chkrootkit") || strings.Contains(command, "rkhunter") {
		return 2 * time.Second
	}
	
	// 可能耗时的命令 - 短超时
	if strings.Contains(command, "find") || 
	   strings.Contains(command, "locate") ||
	   strings.Contains(command, "which") {
		return 3 * time.Second
	}
	
	// 网络相关命令 - 中等超时
	if strings.Contains(command, "netstat") || 
	   strings.Contains(command, "ss") ||
	   strings.Contains(command, "lsof") {
		return 4 * time.Second
	}
	
	// 普通命令 - 标准超时
	return 5 * time.Second
}

// 判断是否为资源密集型命令
func isResourceIntensiveCommand(command string) bool {
	intensivePatterns := []string{
		"find /",
		"rpm -Va",
		"chkrootkit",
		"rkhunter",
		"locate",
	}
	
	for _, pattern := range intensivePatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
}

// 优化命令执行，添加限制和优化
func optimizeCommand(command string) string {
	// 对find命令添加限制，避免搜索整个文件系统
	if strings.Contains(command, "find /") && !strings.Contains(command, "head") && !strings.Contains(command, "2>/dev/null") {
		// 添加错误重定向和结果限制
		if !strings.Contains(command, "head") {
			command = command + " 2>/dev/null | head -20"
		}
	}
	
	// 对rpm -Va添加限制
	if strings.Contains(command, "rpm -Va") && !strings.Contains(command, "head") {
		command = command + " | head -20"
	}
	
	// 对netstat添加限制
	if strings.Contains(command, "netstat -an") && !strings.Contains(command, "wc -l") && !strings.Contains(command, "grep") {
		command = command + " | head -50"
	}
	
	return command
}
// 带进度条的安全检查实现
func performSecurityChecksWithProgress(m *model) error {
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
		
		// 更新进度条
		m.progressCurrent = currentCheck
		m.progressMessage = fmt.Sprintf("正在检查: %s", check.Name)
		
		result := check
		result.Status = fmt.Sprintf("检查中... (%d/%d)", currentCheck, totalChecks)
		
		// 根据命令类型设置不同的超时时间
		timeout := getCommandTimeout(check.Command)
		
		// 对于高风险的资源密集型命令，在大批量执行时跳过或使用替代命令
		if totalChecks > 15 && isResourceIntensiveCommand(check.Command) {
			result.Status = "已跳过"
			result.Details = "批量执行时跳过资源密集型检查，建议单独执行"
			result.RawOutput = "为避免系统过载，此检查项在批量执行时被跳过"
		} else {
			// 执行检查命令
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			
			// 优化命令执行，添加资源限制
			cmdStr := optimizeCommand(check.Command)
			cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
			
			output, err := cmd.CombinedOutput()
			cancel() // 立即释放资源
			
			// 保存原始输出
			result.RawOutput = strings.TrimSpace(string(output))
			if len(result.RawOutput) > 1000 {
				// 限制输出长度，避免界面卡顿
				result.RawOutput = result.RawOutput[:1000] + "\n... (输出已截断)"
			}
			
			if ctx.Err() == context.DeadlineExceeded {
				result.Status = "检查超时"
				result.Details = fmt.Sprintf("命令执行超时（%.1f秒）", timeout.Seconds())
			} else if err != nil {
				result.Status = "检查失败"
				result.Details = fmt.Sprintf("命令执行失败: %v", err)
				if result.RawOutput != "" && len(result.RawOutput) < 200 {
					result.Details += fmt.Sprintf(" (输出: %s)", result.RawOutput)
				}
			} else {
				// 根据检查项ID分析结果
				analyzeResult(&result, result.RawOutput)
			}
		}
		
		// 添加修复建议
		if result.Status == "不合规" && !m.strictMode {
			result.FixSuggestion = getFixSuggestion(result.ID)
		}
		
		m.securityResults = append(m.securityResults, result)
		
		// 每个检查项之间添加小延迟，让进度条更新更平滑
		time.Sleep(100 * time.Millisecond)
	}
	
	// 检查完成，更新进度条
	m.progressMessage = "检查完成"
	
	return nil
}
// 异步安全检查命令 - 步骤式执行
func performSecurityChecksAsync(selectedChecks []bool, strictMode bool) tea.Cmd {
	return func() tea.Msg {
		// 计算需要执行的检查项数量
		selectedItems := []int{}
		for i := range SecurityChecks {
			if i < len(selectedChecks) && selectedChecks[i] {
				selectedItems = append(selectedItems, i)
			}
		}
		
		if len(selectedItems) == 0 {
			return completeMsg{results: []SecurityCheckResult{}, err: fmt.Errorf("没有选择任何检查项")}
		}
		
		// 开始第一步
		return stepMsg{
			stepIndex: 0,
			totalSteps: len(selectedItems),
			selectedItems: selectedItems,
			strictMode: strictMode,
			results: []SecurityCheckResult{},
		}
	}
}

// 执行单个安全检查步骤
func executeSecurityCheckStep(step stepMsg) tea.Cmd {
	return func() tea.Msg {
		if step.stepIndex >= len(step.selectedItems) {
			return completeMsg{results: step.results, err: nil}
		}
		
		checkIndex := step.selectedItems[step.stepIndex]
		check := SecurityChecks[checkIndex]
		result := check
		
		// 根据命令类型设置不同的超时时间
		timeout := getCommandTimeout(check.Command)
		
		// 对于高风险的资源密集型命令，在大批量执行时跳过或使用替代命令
		if step.totalSteps > 15 && isResourceIntensiveCommand(check.Command) {
			result.Status = "已跳过"
			result.Details = "批量执行时跳过资源密集型检查，建议单独执行"
			result.RawOutput = "为避免系统过载，此检查项在批量执行时被跳过"
		} else {
			// 执行检查命令
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			
			// 优化命令执行，添加资源限制
			cmdStr := optimizeCommand(check.Command)
			cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
			
			output, err := cmd.CombinedOutput()
			cancel() // 立即释放资源
			
			// 保存原始输出
			result.RawOutput = strings.TrimSpace(string(output))
			if len(result.RawOutput) > 1000 {
				// 限制输出长度，避免界面卡顿
				result.RawOutput = result.RawOutput[:1000] + "\n... (输出已截断)"
			}
			
			if ctx.Err() == context.DeadlineExceeded {
				result.Status = "检查超时"
				result.Details = fmt.Sprintf("命令执行超时（%.1f秒）", timeout.Seconds())
			} else if err != nil {
				result.Status = "检查失败"
				result.Details = fmt.Sprintf("命令执行失败: %v", err)
				if result.RawOutput != "" && len(result.RawOutput) < 200 {
					result.Details += fmt.Sprintf(" (输出: %s)", result.RawOutput)
				}
			} else {
				// 根据检查项ID分析结果
				analyzeResult(&result, result.RawOutput)
			}
		}
		
		// 添加修复建议
		if result.Status == "不合规" && !step.strictMode {
			result.FixSuggestion = getFixSuggestion(result.ID)
		}
		
		// 添加结果到列表
		newResults := append(step.results, result)
		
		// 添加延迟让用户看到进度
		time.Sleep(300 * time.Millisecond)
		
		// 返回下一步
		return stepMsg{
			stepIndex: step.stepIndex + 1,
			totalSteps: step.totalSteps,
			selectedItems: step.selectedItems,
			strictMode: step.strictMode,
			results: newResults,
		}
	}
}