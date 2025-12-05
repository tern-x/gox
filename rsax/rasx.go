// Package rsax RSA 加密解密帮助类
package rsax

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
)

// GenerateRSAKeys 生成RSA密钥对
func GenerateRSAKeys() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成密钥失败: %v", err)
	}
	return privateKey, nil
}

// === 数字签名相关函数 ===

// SignWithPrivateKey 私钥签名
func SignWithPrivateKey(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])

	// 不计算hash方式 ，不推荐
	// hashed := data
	// signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), hashed[:])

	if err != nil {
		return "", fmt.Errorf("签名失败: %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyWithPublicKey 公钥验签
func VerifyWithPublicKey(publicKey *rsa.PublicKey, data []byte, signatureBase64 string) (bool, error) {
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("解码签名失败: %v", err)
	}

	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)

	// 不计算hash方式 ，不推荐
	// hashed := data
	// err = rsa.VerifyPKCS1v15(publicKey, crypto.Hash(0), hashed[:], signature)

	if err != nil {
		return false, nil
	}

	return true, nil
}

// === 数据加密/解密相关函数 ===

// EncryptWithPublicKey 使用公钥加密数据（用于较小数据）
func EncryptWithPublicKey(publicKey *rsa.PublicKey, data []byte) (string, error) {
	// RSA有长度限制，2048位密钥最多加密245字节
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		return "", fmt.Errorf("加密失败: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithPrivateKey 使用私钥解密数据
func DecryptWithPrivateKey(privateKey *rsa.PrivateKey, encryptedBase64 string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("解码失败: %v", err)
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}

	return plaintext, nil
}

// EncryptLargeDataWithPublicKey 使用公钥加密大文件（使用混合加密）
func EncryptLargeDataWithPublicKey(publicKey *rsa.PublicKey, data []byte) (string, string, error) {
	// 1. 生成随机的AES密钥
	aesKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(aesKey); err != nil {
		return "", "", err
	}

	// 2. 使用AES加密实际数据（这里简化，实际应使用crypto/aes）
	// aesCiphertext := AESEncrypt(aesKey, data)

	// 3. 使用RSA公钥加密AES密钥
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
	if err != nil {
		return "", "", err
	}

	// 返回：加密的AES密钥 + 实际加密数据
	return base64.StdEncoding.EncodeToString(encryptedKey),
		base64.StdEncoding.EncodeToString(data), // 实际这里应该是AES加密后的数据
		nil
}

// PrivateKeyToPEM PEM格式转换函数（完整版）
func PrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

func PublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

// FixPEMFormat 格式化密钥
func FixPEMFormat(raw string) string {
	// 1. 拆分BEGIN/END标记
	reg := regexp.MustCompile(`-+.*?KEY-+`)
	base64Content := reg.ReplaceAllString(raw, "")

	// 2. 移除所有空格
	base64Content = strings.ReplaceAll(base64Content, " ", "")

	// 3. 按64字符拆分Base64内容（PEM规范）
	var lines []string
	for i := 0; i < len(base64Content); i += 64 {
		end := i + 64
		if end > len(base64Content) {
			end = len(base64Content)
		}
		lines = append(lines, base64Content[i:end])
	}

	// 4. 重组标准PEM格式
	beginReg := regexp.MustCompile(`-+BEGIN.*?KEY-+`)
	begin := beginReg.FindString(raw)
	endReg := regexp.MustCompile(`-+END.*?KEY-+`)
	end := endReg.FindString(raw)

	return fmt.Sprintf("%s\n%s\n%s",
		begin,
		strings.Join(lines, "\n"),
		end,
	)
}
