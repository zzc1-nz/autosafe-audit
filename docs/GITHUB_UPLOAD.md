# 上传到 GitHub 操作指南

> 仓库已在本地准备完毕（`main` 分支、1 次提交、47 个文件、1.71 MB），
> 只差「创建远程仓库 + 认证推送」这一步，需要你在本机手动完成。

---

## 为什么会卡在这一步

本机的 AI 会话运行在受限沙箱里，实测：

| 尝试 | 结果 |
|---|---|
| `git ls-remote https://github.com/...` | `schannel: SEC_E_NO_CREDENTIALS` —— git 的 Windows TLS 后端拿不到凭据 |
| `git -c http.sslBackend=openssl ...` | `sh.exe: couldn't create signal pipe, Win32 error 5` —— 沙箱禁止创建 conhost 管道 |
| 读取凭据管理器 | 无已保存的 GitHub 凭据 |

这属于环境限制（不是项目问题）。**认证必须由你完成**，之后的推送就是你机器上的正常 git 操作。

---

## 方案 A：用 GitHub 网页 + 命令行推送（推荐，最直接）

### 第 1 步：在 GitHub 网页创建空仓库

1. 打开 <https://github.com/new>
2. **Repository name** 填：`autosafe-audit`
3. **Description** 填：
   ```
   多 Agent 代码安全审计：token 边际收益递减与迭代深度优化
   ```
4. 可见性选 **Public**
5. **重要**：三个初始化选项（Add a README / .gitignore / license）**全部不要勾选**
   —— 本地已有这些文件，勾选会导致推送冲突
6. 点 **Create repository**

### 第 2 步：配置认证（三选一）

**方式 ① 用 PAT (Classic)（经典令牌）**

1. 打开 <https://github.com/settings/tokens/new>（直达 Classic 新建页）
2. **Note** 填 `autosafe-push`；**Expiration** 选 30 或 90 天
3. **Select scopes** 勾选：
   - 仓库是 **Public**：只勾 `public_repo` 就够（最小权限）
   - 以后要推 **Private** 仓库：勾 `repo`（包含全部子权限）
4. 点页面底部 **Generate token**
5. **立刻复制**以 `ghp_` 开头的令牌（只显示这一次）

推送时 git 询问密码，**粘贴这个令牌**（不是 GitHub 登录密码）。
更省事的做法见仓库外的 `push_with_pat.ps1` 一键脚本（预存凭据，之后免输）。

**方式 ② 用 Fine-grained Personal Access Token**

1. 打开 <https://github.com/settings/tokens?type=beta> → **Generate new token**
2. 名称任意（如 `autosafe-push`），过期时间选 30 天即可
3. **Repository access** 选 `Only select repositories` → 选中 `autosafe-audit`
4. **Permissions** → 展开 **Repository permissions** → 找到 **Contents** → 设为 **Read and write**
5. 生成后**立刻复制** token（只显示一次）

推送时当 git 提示输入密码，**粘贴这个 token**（不是你的 GitHub 登录密码）。

**方式 ③ 用 GitHub CLI（一次登录，以后都省事）**

```powershell
winget install --id GitHub.cli
gh auth login          # 选 GitHub.com → HTTPS → 用浏览器登录
```

### 第 3 步：推送

在**本项目目录**下打开 PowerShell（或 Git Bash），执行：

```powershell
cd C:\Users\24657\Documents\deepseek-harness\default-workspace\autosafe-audit

git remote add origin https://github.com/zzc1-nz/autosafe-audit.git
git push -u origin main
```

如果 git 弹窗要求登录，用方式 ① 的 token 作为密码。

---

## 方案 B：用 GitHub Desktop（纯图形界面，不想碰命令行选这个）

1. 下载安装 <https://desktop.github.com/>
2. 登录你的 `zzc1-nz` 账号
3. 菜单 **File → Add local repository**
4. 选择目录：`C:\Users\24657\Documents\deepseek-harness\default-workspace\autosafe-audit`
5. 点 **Publish repository**
6. 名称填 `autosafe-audit`，**取消勾选** `Keep this code private`
7. 点 **Publish**

---

## 推送成功后要做的 3 件事

### ① 验证仓库正常

打开 <https://github.com/zzc1-nz/autosafe-audit>，确认：

- [ ] README 能正常渲染，**两张内嵌图能显示出来**（fig1 / fig2）
- [ ] `results/figures/` 下 6 张 PNG 都在
- [ ] 右上角显示 **MIT license**
- [ ] 仓库名左侧的 About 区域还空着

### ② 填写 About 区域（对招聘方第一印象影响很大）

在仓库主页点右侧 **⚙️ 齿轮图标**（About 旁）：

- **Description**：
  ```
  多 Agent 代码安全审计：量化 token 边际收益递减，找出「再迭代一轮是否值得」的拐点
  ```
- **Topics**（逐个添加，最多 20 个）：
  ```
  llm security-audit multi-agent token-economics cost-benefit-analysis
  static-analysis bandit fuzzing python code-security agentic-ai
  ```

### ③ 可选的加分项

- 把仓库**置顶**（Pinned）：进入 <https://github.com/zzc1-nz> → 点 **Customize your pins** → 勾选 `autosafe-audit`
- 如果有其他项目，置顶 3–6 个最能代表能力的

---

## 后续更新代码时

```powershell
cd C:\Users\24657\Documents\deepseek-harness\default-workspace\autosafe-audit
git add -A
git commit -m "描述你改了什么"
git push
```

---

## 常见问题

**Q：`git push` 报 `remote: Support for password authentication was removed`**
→ 你输的是账号密码。改用 Personal Access Token（方案 A 第 2 步方式 ①）。

**Q：`git push` 报 `failed to push some refs` / `updates were rejected`**
→ 创建仓库时勾选了 README/.gitignore/license。解决：
```powershell
git pull --rebase origin main
git push -u origin main
```

**Q：README 里的图片不显示**
→ 检查 `results/figures/*.png` 是否真的推送了：`git ls-files results/figures/`
应该看到 6 个 PNG。若为空，说明 `.gitignore` 拦了，执行 `git add -f results/figures/`。

**Q：以后想换仓库名**
→ GitHub 设置里改名后，本地更新一下：
```powershell
git remote set-url origin https://github.com/zzc1-nz/新名字.git
```
