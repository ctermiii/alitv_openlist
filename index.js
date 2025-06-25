import express from "express";
import { decrypt, getParams } from "./decode.js";
import path from "path";
import { fileURLToPath } from "url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
var app = express();
// 解析 JSON 请求体
app.use(express.json())
// 解析 URL 编码请求体（如表单数据）
app.use(express.urlencoded({ extended: true }))
async function refreshToken(refreshTokenValue) {
    const t = Math.floor(Date.now() / 1000);

    const sendData = {
        ...getParams(t),
        refresh_token: refreshTokenValue,
        "Content-Type": "application/json",
    };

    const headers = Object.fromEntries(
        Object.entries(sendData).map(([k, v]) => [k, String(v)])
    );

    const tokenResponse = await fetch(
        "https://api.extscreen.com/aliyundrive/v3/token",
        {
            method: "POST",
            headers: headers,
            body: JSON.stringify(sendData),
        }
    );

    if (!tokenResponse.ok) {
        throw new Error("Failed to refresh token");
    }

    const tokenData = await tokenResponse.json();
    const plainData = decrypt(tokenData.data.ciphertext, tokenData.data.iv, t);
    const tokenInfo = JSON.parse(plainData);

    return tokenInfo;
}

//检查登录状态获取token
app.get("/check", async function (req, res) {
    try {
        const { sid } = req.query;

        if (!sid) {
            throw new Error("invalid sid");
        }

        const statusResponse = await fetch(
            `https://openapi.alipan.com/oauth/qrcode/${sid}/status`
        );

        if (!statusResponse.ok) {
            throw new Error("Failed to check status");
        }

        const statusData = await statusResponse.json();

        if (statusData.status === "LoginSuccess" && statusData.authCode) {
            try {
                const t = Math.floor(Date.now() / 1000);
                const sendData = {
                    ...getParams(t),
                    code: statusData.authCode,
                    "Content-Type": "application/json",
                };

                const headers = Object.fromEntries(
                    Object.entries(sendData).map(([k, v]) => [k, String(v)])
                );

                const tokenResponse = await fetch(
                    "https://api.extscreen.com/aliyundrive/v3/token",
                    {
                        method: "POST",
                        headers: headers,
                        body: JSON.stringify(sendData),
                    }
                );

                if (!tokenResponse.ok) {
                    throw new Error("Failed to get token");
                }

                const tokenResult = await tokenResponse.json();
                const plainData = decrypt(
                    tokenResult.data.ciphertext,
                    tokenResult.data.iv,
                    t
                );
                const tokenInfo = JSON.parse(plainData);

                return res.json({
                    status: "LoginSuccess",
                    refresh_token: tokenInfo.refresh_token,
                    access_token: tokenInfo.access_token,
                });
            } catch (error) {
                return res.json({ status: "LoginFailed" });
            }
        }

        return res.json(statusData);
    } catch (error) {
        return res.json(
            { error: error.message || "Unexpected error" },
            { status: 500 }
        );
    }
});

//获取二维码
app.get("/qr", async function (req, res) {
    try {
        const response = await fetch(
            "https://api.extscreen.com/aliyundrive/qrcode",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scopes: [
                        "user:base",
                        "file:all:read",
                        "file:all:write",
                    ].join(","),
                    width: 500,
                    height: 500,
                }),
            }
        );

        if (!response.ok) {
            throw new Error("Failed to generate QR code");
        }

        const result = await response.json();

        return res.json({
            qr_link: result.data.qrCodeUrl,
            sid: result.data.sid,
        });
    } catch (error) {
        return res.json(
            { error: error.message || "Unknown error" },
            { status: 500 }
        );
    }
});

//刷新token
app.get("/token", async function (req, res) {
    try {
        const { refresh_ui } = req.query;

        if (!refresh_ui) {
            return res.json({
                refresh_token: "",
                access_token: "",
                text: "refresh_ui parameter is required",
            });
        }

        const tokenInfo = await refreshToken(refresh_ui);

        console.log("tokenInfo", tokenInfo);

        return res.json({
            refresh_token: tokenInfo.refresh_token,
            access_token: tokenInfo.access_token,
            text: "",
        });
    } catch (error) {
        return res.json({
            refresh_token: "",
            access_token: "",
            text: error.message || "Unexpected error",
        });
    }
});

//刷新token alist兼容
app.post("/token", async function (req, res) {
    try {

        console.log('req.body',req.body)

        const { refresh_token } = req.body;

        if (!refresh_token) {
            return res.json({
                refresh_token: "",
                access_token: "",
                text: "refresh_token parameter is required",
            });
        }

        const tokenInfo = await refreshToken(refresh_token);

        console.log("tokenInfo", tokenInfo);

        return res.json({
            refresh_token: tokenInfo.refresh_token,
            access_token: tokenInfo.access_token,
            text: "",
        });
    } catch (error) {
        return res.json({
            refresh_token: "",
            access_token: "",
            text: error.message || "Unexpected error",
        });
    }
});

// 网页扫码
app.get("/", function (req, res) {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

var server = app.listen(8081, function () {
    var port = server.address().port;
    console.log("应用实例，访问地址为 http://%s:%s", "localhost", port);
});
