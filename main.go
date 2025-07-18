package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

var client = resty.New()

//go:embed index.html
var indexHtml []byte

func Decrypt(ciphertextB64, ivHex, t string) (string, error) {
	keyStr := GenerateKey(t)

	// 1. 解析 key（hex 转 []byte）
	key := []byte(keyStr)
	if len(key) != 32 {
		return "", errors.New("key 长度超过 32 字节，不能用于 AES-256")
	}
	// 2. 解析 IV
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", fmt.Errorf("iv 解码失败: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return "", errors.New("IV 长度必须为 16 字节（128 位）")
	}
	// 3. 解码 base64 密文
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("密文 base64 解码失败: %w", err)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("密文长度不是块大小的倍数")
	}

	// 4. 初始化 AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	// 5. CBC 解密
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 6. 去除 PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("去 padding 失败: %w", err)
	}

	return string(plaintext), nil
}

// PKCS7 Unpadding
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("无效的数据长度")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("无效的 padding 长度")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("padding 内容不合法")
		}
	}
	return data[:len(data)-padLen], nil
}


func h(charArray []rune, modifier interface{}) string {
	// 去重
	uniqueMap := make(map[rune]bool)
	var uniqueChars []rune
	for _, c := range charArray {
		if !uniqueMap[c] {
			uniqueMap[c] = true
			uniqueChars = append(uniqueChars, c)
		}
	}

	// 处理 modifier，截取字符串后部分转换成数字
	modStr := fmt.Sprintf("%v", modifier)
	if len(modStr) < 7 {
		panic("modifier 字符串长度不足7")
	}
	numPart := modStr[7:]
	numericModifier, err := strconv.Atoi(numPart)
	if err != nil {
		panic(err)
	}

	var builder strings.Builder
	for _, char := range uniqueChars {
		charCode := int(char)
		newCharCode := charCode - (numericModifier % 127) - 1
		newCharCode = abs(newCharCode)
		if newCharCode < 33 {
			newCharCode += 33
		}
		builder.WriteRune(rune(newCharCode))
	}

	return builder.String()
}

func GetParams(t interface{}) map[string]string {
	return map[string]string{
		"akv":    "2.8.1496",                      // apk_version_name 版本号
		"apv":    "1.3.6",                         // 内部版本号
		"b":      "XiaoMi",                        // 手机品牌
		"d":      "e87a4d5f4f28d7a17d73c524eaa8ac37", // 设备id 可随机生成
		"m":      "23046RP50C",                    // 手机型号
		"mac":    "",                             // mac地址
		"n":      "23046RP50C",                    // 手机型号
		"t":      fmt.Sprintf("%v", t),            // 时间戳
		"wifiMac": "020000000000",                 // wifiMac地址
	}
}

func GenerateKey(t interface{}) string {
	params := GetParams(t)

	// 按 key 排序
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 拼接除 "t" 外所有的值
	var concatenatedParams strings.Builder
	for _, k := range keys {
		if k != "t" {
			concatenatedParams.WriteString(params[k])
		}
	}

	// 调用 h 函数
	keyArray := []rune(concatenatedParams.String())
	hashedKeyString := h(keyArray, t)

	// MD5 加密，输出 hex
	md5Sum := md5.Sum([]byte(hashedKeyString))
	return hex.EncodeToString(md5Sum[:])
}

// 取绝对值
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// 获取二维码
func getQRCode(c *gin.Context) {
	body := map[string]interface{}{
		"scopes": "user:base,file:all:read,file:all:write",
		"width":  500,
		"height": 500,
	}
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(body).
		Post("https://api.extscreen.com/aliyundrive/qrcode")

	if err != nil || resp.StatusCode() != 200 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	var result map[string]interface{}
	json.Unmarshal(resp.Body(), &result)

	data := result["data"].(map[string]interface{})
	c.JSON(http.StatusOK, gin.H{
		"qr_link": data["qrCodeUrl"],
		"sid":     data["sid"],
	})
}

// 检查扫码登录状态并获取 token
func checkStatus(c *gin.Context) {
	sid := c.Query("sid")
	if sid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sid"})
		return
	}

	statusResp, err := client.R().
		Get("https://openapi.alipan.com/oauth/qrcode/" + sid + "/status")
	if err != nil || statusResp.StatusCode() != 200 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check status"})
		return
	}

	var statusData map[string]interface{}
	json.Unmarshal(statusResp.Body(), &statusData)

	if statusData["status"] == "LoginSuccess" {
		authCode := statusData["authCode"].(string)
		tokenInfo, err := getTokenFromCode(authCode)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "LoginFailed"})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"status":        "LoginSuccess",
				"refresh_token": tokenInfo["refresh_token"],
				"access_token":  tokenInfo["access_token"],
			})
		}
		return
	}

	c.JSON(http.StatusOK, statusData)
}

func getTokenFromCode(code string) (map[string]string, error) {
	t := time.Now().Unix()
	params := GetParams(strconv.FormatInt(t, 10))
	params["code"] = code
	params["Content-Type"] = "application/json"

	headers := map[string]string{}
	for k, v := range params {
		headers[k] = fmt.Sprintf("%v", v)
	}

	resp, err := client.R().
		SetHeaders(headers).
		SetBody(params).
		Post("https://api.extscreen.com/aliyundrive/v3/token")

	if err != nil || resp.StatusCode() != 200 {
		return nil, err
	}

	var tokenData map[string]interface{}
	json.Unmarshal(resp.Body(), &tokenData)


	if tokenData["code"].(float64) != 200 {
		return nil, errors.New(tokenData["message"].(string))
	}

	data := tokenData["data"].(map[string]interface{})
	ciphertext := data["ciphertext"].(string)
	iv := data["iv"].(string)

	plain, err := Decrypt(ciphertext, iv, strconv.FormatInt(t, 10))
	if err != nil {
		return nil, err
	}

	var token map[string]string
	json.Unmarshal([]byte(plain), &token)
	return token, nil
}

// GET /token
func getToken(c *gin.Context) {
	refresh := c.Query("refresh_ui")
	if refresh == "" {
		c.JSON(http.StatusOK, gin.H{
			"refresh_token": "",
			"access_token":  "",
			"text":          "refresh_ui parameter is required",
		})
		return
	}
	handleTokenRefresh(c, refresh)
}

// POST /token
func postToken(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.RefreshToken == "" {
		c.JSON(http.StatusOK, gin.H{
			"refresh_token": "",
			"access_token":  "",
			"text":          "refresh_token parameter is required",
		})
		return
	}
	handleTokenRefresh(c, body.RefreshToken)
}

func handleTokenRefresh(c *gin.Context, refresh string) {
	t := time.Now().Unix()
	params := GetParams(strconv.FormatInt(t, 10))
	params["refresh_token"] = refresh
	params["Content-Type"] = "application/json"

	headers := map[string]string{}
	for k, v := range params {
		headers[k] = fmt.Sprintf("%v", v)
	}

	resp, err := client.R().
		SetHeaders(headers).
		SetBody(params).
		Post("https://api.extscreen.com/aliyundrive/v3/token")

	if err != nil || resp.StatusCode() != 200 {
		c.JSON(http.StatusOK, gin.H{
			"refresh_token": "",
			"access_token":  "",
			"text":          "Failed to refresh token",
		})
		return
	}

	var tokenData map[string]interface{}
	json.Unmarshal(resp.Body(), &tokenData)
	data := tokenData["data"].(map[string]interface{})

	plain, err := Decrypt(data["ciphertext"].(string), data["iv"].(string), strconv.FormatInt(t, 10))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"refresh_token": "",
			"access_token":  "",
			"text":          err.Error(),
		})
		return
	}

	var token map[string]string
	json.Unmarshal([]byte(plain), &token)

	c.JSON(http.StatusOK, gin.H{
		"refresh_token": token["refresh_token"],
		"access_token":  token["access_token"],
		"text":          "",
	})
}


func main() {
	router := gin.Default()

	router.Static("/public", "./public")
	router.GET("/", func(c *gin.Context) {
		c.Writer.Write(indexHtml)
	})

	router.GET("/qr", getQRCode)
	router.GET("/check", checkStatus)
	router.GET("/token", getToken)
	router.POST("/token", postToken)

	router.Run(":8081")
}