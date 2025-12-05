package rsax_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	"github.com/tern-x/gox/rsax"
)

func TestGenerate(t *testing.T) {
	fmt.Println("=== RSA密钥对生成 ===")
	privateKey, err := rsax.GenerateRSAKeys()
	if err != nil {
		log.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	fmt.Println(publicKey.Size())
}

func TestRSA(t *testing.T) {

	content := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtwWq5Hs2F5ps6
B4056BavVtwyqJwqqXRvrV6Pf3HPgUqR0Uw2pRWBFRvGzzqy67dn4Sk+6/kI4PFk
Dd3imOb85g8eYwJQ5cecz57oSfA680qaW9is6kt+cr8f37bG1XTQDp8wrLzxWuOg
7+BZ81Ertuv1cz7I2s++T2IM3pe37J2Pym/mxG7/XpaayZ2cEeGFb9xevjkYgX+K
qOclPdLuyq7J3PcGTTPAiEaZCu0g9xKI2HaPeUN4yC5ZCEvWtlP3768e6gJFwc8L
EDisbRL0TpG6ZBIHWKtkPfXoUiu2Gm1EEW7/vQ5OeoisaAuygZo7EKNuI5hMTfAQ
0+Bei7XnAgMBAAECggEARlER+ZzHm7q5cwB/XMHZ/FdwgWfO20z8e/1zWStASbOP
E/fZmfuw+i4qsYhHvwS5kmaCpJ4miDtQNSePdhZe1FXeJHP5CfgTkhhLvMG/YHv4
4wLsav3eU2vogOOuOkVEIrboIXCmfh5EJGsvJffcD47Vat2auPokPGYvzfl++MU0
B3BBUctDUgq+/C956cGA7V320Rtbhz6HYADBpwRRpSg0MqjaxQIwhMfBFPA+1cVO
8sHDbk0IbZoS6B6pqgLuMHwJXXRQZgiOkhSEp8NhqrlHVVrmLlh/v9DhFGqT0h9a
Mx+Xfch77WuM1foHrGZWwDaRrqYgkZk2n+ViuHdxQQKBgQDeHMegV9r5lfMlxLIa
lRHmUc0uiyotBXKL9sgcxNajroID5fe/XlEw4wRVeiKDgePt7YuZTLcexa+NLLy5
Poi/1ZRtDqTIvJYhg41cpKelsPX7zszoVO82ts1tJRsuZ1QoBbDU9U69n+6EedC8
95WkPFxuVi173cjhc8rPZ/p4FwKBgQDIQ+yLjBZ8XkLLXdGlpewNW+pzxE58cQOT
NAxTdi3X2CfWH91xb8KByNZf2JFjmSCmPL0jh4RwO51JaW/7wpW015FZ8suRWYRv
ZowoQxMxFtbqS41SavpWOxxlRJkwuo+OykLsptaLT6tTgYn9m4g4ud6txmaWhHip
Sp+ZPJWCsQKBgQCPA4zuC2OtjQWQbgQX5aAu4sDwlR7E+lr1ECNtkrh5kCWbCPnq
uHoitinWN9v9PSdbzbYzMRg/sh4FEqc5x7AZhRYa2nDz56nrTl85JbPklfrs9g0u
E3IrkqzW+Ct2R4YCdxeTJ5hZtJ7Jof3rjqdFprAFQ2vp87YipIIT5el6ZQKBgFJl
P+maVZYN4kVx8FPLFHfanXfMCM7CYMor2/Zq5SmtUZaTvbRyWwCy9SCyJf9ofTpo
OxlnJGJY5LnTm7Nlt9qT5sWvU3oV7ps3Aet+zWKhFwOG2jpSsXTRFTnFI5Ic7/u7
1BUx/4uJ19+fqHqjh0RvlOLCgmrjThG5Fjkh6BHBAoGANQpuy+prF3gla0FyKWYW
o20pQ3oF0I4YkuN34iUVigKHsgtEiSVj7qtofhK4TeexPL6XyCQkhGcF8HA5PmgT
KS63vnHteGtwl6A8qCTYEsfpyXAwf1Rc7S63qbCAN/tsNID+asUeZfFF5NWTjwye
UgOgVWGTIFXfsS+NwgRRDGo=
-----END PRIVATE KEY-----`

	content = rsax.FixPEMFormat(content)
	// 步骤1：解码PEM格式数据
	block, rest := pem.Decode([]byte(content))
	if block == nil {
		log.Fatalf("解析PEM失败，剩余未解析数据长度：%d", len(rest))
	}

	// 验证PEM块类型是否为私钥
	// if block.Type != "PRIVATE KEY" {
	// 	log.Fatalf("无效的PEM块类型，期望PRIVATE KEY，实际：%s", block.Type)
	// }

	// // 尝试PKCS1
	// key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// if err != nil {
	// 	log.Fatalf("解析私钥失败：%v;%T", err,key)
	// }

	// 步骤2：解析PKCS#8格式的私钥
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("解析私钥失败：%v", err)
	}

	// logger.Info("%T", privateKey)

	// 输出私钥信息（示例：打印私钥类型）
	fmt.Printf("私钥解析成功，类型：%T\n", privateKey)
	// 如需使用私钥（如签名/加密），可将privateKey断言为具体类型（如*rsa.PrivateKey）
	rsaPriv, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		fmt.Printf("RSA私钥模数长度：%d bit\n", rsaPriv.N.BitLen())
	} else {
		log.Fatal("私钥非RSA类型")
	}

	// 测试1：数字签名和验证
	fmt.Println("\n=== 测试1：数字签名 ===")
	message := "重要交易数据"
	fmt.Printf("原始消息: %s\n", message)

	// 使用私钥签名
	signature, err := rsax.SignWithPrivateKey(rsaPriv, []byte(message))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("签名结果: %s\n", signature[:50]+"...")

	pubContent := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArcFquR7NheabOgeNOegW
r1bcMqicKql0b61ej39xz4FKkdFMNqUVgRUbxs86suu3Z+EpPuv5CODxZA3d4pjm
/OYPHmMCUOXHnM+e6EnwOvNKmlvYrOpLfnK/H9+2xtV00A6fMKy88VrjoO/gWfNR
K7br9XM+yNrPvk9iDN6Xt+ydj8pv5sRu/16WmsmdnBHhhW/cXr45GIF/iqjnJT3S
7squydz3Bk0zwIhGmQrtIPcSiNh2j3lDeMguWQhL1rZT9++vHuoCRcHPCxA4rG0S
9E6RumQSB1irZD316FIrthptRBFu/70OTnqIrGgLsoGaOxCjbiOYTE3wENPgXou1
5wIDAQAB
-----END PUBLIC KEY-----`

	pubContent = rsax.FixPEMFormat(pubContent)
	// 步骤1：解码PEM格式数据
	pubBlock, rest := pem.Decode([]byte(pubContent))
	if block == nil {
		log.Fatalf("解析PEM失败，剩余未解析数据长度：%d", len(rest))
	}

	// 验证PEM块类型是否为私钥
	// if block.Type != "PRIVATE KEY" {
	// 	log.Fatalf("无效的PEM块类型，期望PRIVATE KEY，实际：%s", block.Type)
	// }

	// // 尝试PKCS1
	// key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// if err != nil {
	// 	log.Fatalf("解析私钥失败：%v;%T", err,key)
	// }

	publicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		log.Fatalf("解析公钥失败：%v", err)
	}
	fmt.Printf("公钥解析成功，类型：%T\n", publicKey)

	// 如需使用私钥（如签名/加密），可将privateKey断言为具体类型（如*rsa.PrivateKey）
	rsaPub, ok := publicKey.(*rsa.PublicKey)
	if ok {
		fmt.Printf("RSA模数长度：%d bit\n", rsaPriv.N.BitLen())
	} else {
		log.Fatal("非RSA类型")
	}

	// 使用公钥验签
	valid, err := rsax.VerifyWithPublicKey(rsaPub, []byte(message), signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("签名验证: %v\n", valid)

	// 测试2：数据加密和解密
	fmt.Println("\n=== 测试2：数据加密解密 ===")
	secretData := "这是一段机密信息"
	fmt.Printf("原始数据: %s\n", secretData)

	// 使用公钥加密
	encrypted, err := rsax.EncryptWithPublicKey(rsaPub, []byte(secretData))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("加密结果: %s\n", encrypted[:50]+"...")

	// 使用私钥解密
	decrypted, err := rsax.DecryptWithPrivateKey(rsaPriv, encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("解密数据: %s\n", string(decrypted))

	// 测试3：演示正确的流程
	fmt.Println("\n=== 测试3：完整流程演示 ===")

	// 场景A：数字签名（身份验证）
	fmt.Println("\n场景A：数字签名（验证数据来源）")
	fmt.Println("1. 发送方用私钥签名")
	fmt.Println("2. 接收方用公钥验证签名")
	fmt.Println("3. 确保数据未被篡改且来自正确发送方")

	// 场景B：数据加密（保护数据机密性）
	fmt.Println("\n场景B：数据加密（保护数据内容）")
	fmt.Println("1. 发送方用接收方的公钥加密")
	fmt.Println("2. 只有接收方的私钥能解密")
	fmt.Println("3. 确保只有接收方能查看数据")
}
