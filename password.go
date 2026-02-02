package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
)

// 生成密码
func generatePasswords(m *model) error {
	m.generatedPasswords = make(map[string]string)
	
	counter := 1
	for _, user := range m.users {
		if !user.Selected {
			continue
		}
		
		var password string
		var err error
		
		switch m.passwordType {
		case uniformPassword:
			password = generateUniformPassword(m.uniformPass)
		case ruleBasedPassword:
			password = generateRuleBasedPassword(m.rulePrefix, counter)
			counter++
		case randomPassword:
			password, err = generateRandomPassword()
			if err != nil {
				return err
			}
		}
		
		// 验证密码是否符合规则
		if !validatePassword(password) {
			return fmt.Errorf("生成的密码不符合安全规则")
		}
		
		// 实际修改用户密码
		err = changeUserPassword(user.Username, password)
		if err != nil {
			return fmt.Errorf("修改用户 %s 密码失败: %v", user.Username, err)
		}
		
		m.generatedPasswords[user.Username] = password
	}
	
	return nil
}

// 生成统一密码
func generateUniformPassword(password string) string {
	return password
}

// 生成规则密码 (前缀 + 数字后缀)
func generateRuleBasedPassword(prefix string, counter int) string {
	return fmt.Sprintf("%s%03d!", prefix, counter)
}

// 生成随机密码
func generateRandomPassword() (string, error) {
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*"
	)
	
	// 确保至少包含每种字符类型
	var password strings.Builder
	
	// 添加至少一个小写字母
	char, err := randomChar(lowercase)
	if err != nil {
		return "", err
	}
	password.WriteByte(char)
	
	// 添加至少一个大写字母
	char, err = randomChar(uppercase)
	if err != nil {
		return "", err
	}
	password.WriteByte(char)
	
	// 添加至少一个数字
	char, err = randomChar(digits)
	if err != nil {
		return "", err
	}
	password.WriteByte(char)
	
	// 添加至少一个特殊字符
	char, err = randomChar(special)
	if err != nil {
		return "", err
	}
	password.WriteByte(char)
	
	// 填充剩余字符到8位
	allChars := lowercase + uppercase + digits + special
	for password.Len() < 8 {
		char, err = randomChar(allChars)
		if err != nil {
			return "", err
		}
		password.WriteByte(char)
	}
	
	// 打乱字符顺序
	passwordBytes := []byte(password.String())
	for i := len(passwordBytes) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		passwordBytes[i], passwordBytes[j.Int64()] = passwordBytes[j.Int64()], passwordBytes[i]
	}
	
	return string(passwordBytes), nil
}

// 随机选择字符
func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

// 验证密码是否符合规则
func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	
	for _, char := range password {
		switch {
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}
	
	return hasLower && hasUpper && hasDigit && hasSpecial
}

// 修改用户密码
func changeUserPassword(username, password string) error {
	// 使用chpasswd命令修改密码
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chpasswd failed: %v, output: %s", err, string(output))
	}
	
	return nil
}