# src-recon-kit

**作者：Mosqui（蚊子）** · <https://github.com/3516381493>

做公益 SRC 攒下来的几个小工具，都是我自己在真实资产上跑过的版本，脱敏之后放出来。
共同点很简单：**只读、限速、只取证不利用**。它们不负责打穿目标，只负责把「本该不存在却存在」的东西找出来，剩下的交给人眼判断。

---

## 工具列表

| 文件 | 一句话 |
|---|---|
| `tools/leak_path_fleet.py` | 批量扫 8 条高确定性泄露路径：phpinfo 三个变体、`.git/config`、`.env`、`.svn/entries`、`.DS_Store`、Apache `server-status` |
| `tools/swagger_fleet.py` | 批量找对外暴露的 OpenAPI / Swagger 文档端点 |
| `tools/phpinfo_check.py` | 单目标 phpinfo 取证，输出 5 段，可直接贴报告 |
| `tools/git_leak_check.py` | 判定 `.git` 是真泄露还是 404 页，一路走到 blob 解压出源码 |

---

## 用法

全部只用标准库，不需要 `pip install`。

```bash
# 批量泄露路径
python tools/leak_path_fleet.py -i targets.txt -o hits.jsonl --rate 10 --threads 8

# 批量 swagger
python tools/swagger_fleet.py -i targets.txt -o swagger_hits.jsonl --threads 6

# 单目标 phpinfo 取证
python tools/phpinfo_check.py -u http://example.com/phpinfo.php --save out.txt

# .git 泄露完整性校验
python tools/git_leak_check.py -u https://example.com --save out.txt
```

`targets.txt` 一行一个根地址，`#` 开头是注释。示例见 `targets/example.txt`。

---

## 几个设计上的选择

**1. 判定必须分路径类型**

同一批目标里，`.svn/entries` 和 `phpinfo.php` 的「命中」长相完全不同。现代站点会把任意路径回落到 404 页或者 SPA 首页，所以不能只看状态码 200 就算命中。每个路径单独写判据，这是我的实测教训——939 站 × 8 路径扫出来 5 条命中的那一次，另外 3 条 svn 全是假的：

- 一个返回的是 Nuxt 生成的错误页（CSS 里还留着 `.error-page[data-v-xxxx]`）
- 一个复验时域名直接 DNS 解析失败
- 一个正文只有「请选择线路」几个字

**2. 令牌式限速，不用纯并发数控制**

`leak_path_fleet.py` 里是一个全局的时间槽，所有线程排队领，保证整体不超过 `--rate`。单纯限制线程数根本控不住速率，因为每个请求耗时不同。

**3. 只取够判断的那一段**

phpinfo 只读 200KB，swagger 读 400KB，`server-status` 到位就停。目的是取证，不是把目标的数据搬回家。

**4. 抓到的只是线索，不是漏洞**

`swagger_fleet.py` 会把只有 `api-docs` 字样、Content-Type 是 json 的结果标成 `maybe`，因为那种经常是前端自己写的假文档。真要报，得手工打开看里面有没有真接口。

---

## 实测记录

`leak_path_fleet.py` 在 939 个存活的公益 SRC 站点上跑过一遍（本机实测 2026-11-13）：7512 个请求，985 秒，命中 5 条，其中真命中 2 条 phpinfo。命中率 0.5% 这个量级，跟预期差不多——这条路子没技术含量，纯粹靠量，而且审核对这类低危通常只给 1~2 KB，指望它赚奖励不现实。

`swagger_fleet.py` 在同批 939 站上跑过（本机实测 2026-11-13）：894.6 秒，只有 1 条真命中，另外 4 条是假命中（WAF 验证页 / 未登录 403 / 空文档 238 字节 / 首页回落）。

数字放在这里的意思很直接：**别指望自动化工具替你挖到洞**。它能做的是把「明显该修但没人管」的配置问题挑出来，剩下的判断、取证、写报告，全是手工活。

---

## 使用边界

这些脚本只对**你自己有授权**的目标使用。公益 SRC 平台的项目、你自己的资产、明确许可的测试环境，都行；别人的站，不行。

代码里的所有请求都是 GET，不改数据、不传 payload、不爆破、不批量拉个人信息。如果你要改它去做别的，那责任在你。

---

## License

MIT，见 `LICENSE`。用得上就拿去用，改完记得标一下出处。
