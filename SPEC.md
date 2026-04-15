# iOS AppSigner — 规范文档

## 1. 项目概览

**项目名称**: iOS AppSigner Web  
**类型**: 本地 Web 签名工具  
**核心功能**: 通过浏览器上传 IPA/PList，在本地完成 iOS App 重签名，并直接安装到手机（无需第三方软件）  
**目标用户**: iOS 开发者 / 测试人员 / 高级用户

---

## 2. 页面结构

### 页面清单

| 路由 | 文件 | 说明 |
|------|------|------|
| `/` | index.html | 主页（桌面端/移动端自适应） |
| `/sign` | POST API | 处理签名请求 |
| `/install/<task_id>` | install.html | 移动端安装引导页 |
| `/download/<task_id>` | API | 下载签名后的 IPA |

### 设备检测逻辑

- **桌面端**（PC/Mac）：显示完整签名操作界面
- **移动端**（iPhone/Android）：显示扫码/提示页，提示"请在电脑浏览器打开"
- **检测方式**：User-Agent + 屏幕宽度双重判断

---

## 3. 功能模块

### 3.1 签名模式（二选一）

#### 模式 A — Apple ID 账号
- 输入 Apple ID 邮箱
- 输入密码（或 App 专用密码）
- 输入 Bundle ID（可选，默认继承原包）
- 输入版本号（可选）
- 需要本地运行 `ios-app-signer` 或类似工具生成签名证书（服务端调用命令行）

#### 模式 B — P12 证书
- 上传 `.p12` 证书文件
- 上传 `.mobileprovision` 描述文件
- 输入 P12 密码
- 输入 Bundle ID（可选）

### 3.2 文件上传
- 拖拽上传 / 点击上传 `.ipa` 文件
- 限制：单个文件 ≤ 500MB
- 支持文件格式：`.ipa`、`.plist`（自签场景）

### 3.3 签名执行
- 后端调用本地 `python-step/signer.py`
- 进度通过 Server-Sent Events（SSE）实时推送
- 完成后返回下载链接 + 二维码

### 3.4 签名后安装
- **桌面端**：显示下载链接 + 扫码安装
- **手机端**：点击"一键安装"直接触发 `itms-services://` 下载安装
- 安装后需在手机「设置 → 通用 → VPN与设备管理」信任证书

### 3.5 手机端提示
- 检测到手机浏览器时显示：
  - 大字提示"请使用电脑浏览器访问"
  - 二维码（当前页面 URL 生成）
  - 功能说明列表

---

## 4. 视觉设计

### 主题：Cyberpunk Terminal（赛博朋克终端）

#### 色彩系统
```
--bg-primary:    #0a0e17   深空蓝黑
--bg-secondary:  #111827   面板背景
--bg-card:       #1a2235   卡片背景
--border:        #2a3a55   边框
--accent-green:  #00ff88   主强调（霓虹绿）
--accent-cyan:   #00d4ff   次强调（电光蓝）
--accent-orange: #ff6b35   警告/未签名
--text-primary:  #e8f0ff   主文字
--text-muted:    #6b7a99   次要文字
--glow-green:    0 0 20px rgba(0,255,136,0.3)
--glow-cyan:     0 0 20px rgba(0,212,255,0.3)
```

#### 字体
- 标题/品牌：`Orbitron`（Google Fonts）— 科幻感
- 正文：`Rajdhani`（Google Fonts）— 几何感现代
- 代码/版本号：`JetBrains Mono`（Google Fonts）— 等宽

#### 动效
- 背景：缓慢漂移的网格线动画（CSS）
- 卡片：hover 时边框发光增强 + 轻微上浮
- 进度条：霓虹脉冲动画
- 扫描线：顶部循环扫描动画
- 页面加载：依次淡入

---

## 5. 技术架构

### 后端
- **框架**: Flask（Python）
- **签名工具**: `python-step/signer.py`（封装 ipatool/OpenSSL）
- **文件存储**: 本地临时目录 `temp/<task_id>/`
- **通信**: REST API + SSE 进度流

### 前端
- 纯 HTML + CSS + Vanilla JS（无框架依赖）
- CSS Grid / Flexbox 响应式布局
- Fetch API + SSE
- QRCode.js（内联 CDN）

### API 设计

#### POST /sign
```
Request: multipart/form-data
  - file: IPA 文件
  - mode: "apple_id" | "p12"
  - [apple_id] / [apple_password]: mode=apple_id 时
  - [p12_file] / [p12_password] / [mobileprovision]: mode=p12 时
  - [bundle_id] / [version]: 可选

Response: JSON
  - task_id: string
  - status: "queued" | "processing" | "done" | "error"
```

#### GET /status/<task_id>（SSE）
```
event: progress
data: {"step": "上传文件", "percent": 30}
event: progress
data: {"step": "正在签名", "percent": 70}
event: done
data: {"download_url": "/download/xxx", "qr": "/qr/xxx"}
event: error
data: {"message": "证书无效"}
```

#### GET /download/<task_id>
返回签名后的 IPA 文件

---

## 6. 安全与限制

- 仅限本地 `localhost` 使用（不暴露公网）
- 上传文件在 24h 后自动清理
- 签名仅限个人使用，不得传播盗版应用
- 手机端检测为前端提示，不做强制拦截（可绕过）

---

## 7. 文件结构

```
D:\ios-signer\
├── SPEC.md
├── app.py                    # Flask 主程序
├── requirements.txt
├── signer.py                 # 签名逻辑封装
├── pages/
│   ├── index.html            # 桌面端主页
│   ├── install.html          # 移动端安装页
│   └── style.css             # 共享样式
└── temp/                     # 临时文件目录（运行时创建）
```
