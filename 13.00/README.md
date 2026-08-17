# PS4 FW 13.00 WebKit Exploit

基于 SlopKit 架构移植到 PS4 FW 13.00 的 WebKit 漏洞利用项目。

## 项目结构

```
13.00/
├── index.html              # 主页面
├── style.css               # 样式文件
├── README.md               # 文档
├── GoldHEN_v2.4b18.10.bin  # GoldHEN payload
└── src/
    ├── main.js             # 主入口
    ├── webkit/
    │   ├── core.js         # 核心 WebKit 漏洞利用
    │   ├── mem.js          # 内存原语
    │   ├── int64.js        # 64位整数库
    │   ├── rop.js          # ROP 链构建器
    │   ├── syscalls.js     # 系统调用封装
    │   ├── syscall_bridge.js # 系统调用桥接
    │   ├── offsets.js      # FW 13.00 特定偏移量
    │   └── offsets_loader.js # 偏移量加载器
    ├── kernel/
    │   └── kernel.js       # Poopsploit 内核漏洞利用
    ├── payloads/
    │   ├── loader.js       # ELF 加载器
    │   └── goldhen.js      # GoldHEN v2.4b18.10 支持
    └── utils/
        ├── config.js       # 运行时配置
        └── validation.js   # 输入验证
└── tests/
    ├── int64.test.js       # Int64 库测试
    ├── integration.test.js # 集成测试
    ├── offsets_loader.test.js # 偏移量加载器测试
    └── validation.test.js  # 验证测试
```

## 技术原理

### 漏洞利用链 (7 个阶段)

#### 阶段 1: WebKit 用户态漏洞利用 (core.js)
- 使用 `history.replaceState` 序列化/反序列化对象
- 通过 BigInt 数组进行堆喷射 (9,000,000 slots)
- 创建假的 JSCell 头进行类型混淆
- 实现任意地址读写

#### 阶段 2: 安装内存原语 (mem.js)
- 提供 read1/read2/read4/read8 读操作
- 提供 write1/write2/write4/write8 写操作
- 提供 leakval 泄漏对象地址
- 安装到 globalThis.p

#### 阶段 3: 泄漏地址
- 泄漏 WebKit 基址
- 泄漏 libkernel 基址
- 加载 FW 13.00 特定偏移量

#### 阶段 4: 内核漏洞利用 (kernel.js)
- **Poopsploit** 内核漏洞利用
- 使用 IPv6 路由头进行堆喷射
- 通过 setsockopt/getsockopt 触发内存损坏
- 创建 pipe buffer overlap 实现内核 R/W
- 初始化 ROP 链和系统调用桥接

#### 阶段 5: 权限提升
- 通过 allproc 链表遍历找到当前进程
- 修改 ucred 结构体实现提权 (uid=0, gid=0)
- 为后续 payload 加载做准备

#### 阶段 6: GoldHEN (goldhen.js)
- 加载 GoldHEN v2.4b18.10
- 启用调试设置
- 启动 FTP 服务器 (端口 2121)
- 启用自制软件
- 禁用系统更新
- 启用远程包安装
- 启用 VR 支持

#### 阶段 7: ELF 加载器 (loader.js)
- 在端口 9021 监听
- 接收 ELF 载荷
- 验证 ELF 头
- 解析程序头
- 执行载荷

## PS4 FW 13.00 特性

| 特性 | 值 |
|------|-----|
| WebKit 版本 | Safari 17.0 (AppWebKit/605.1.15) |
| 页大小 | 0x4000 (16 KB) |
| Gigacage | 已禁用 |
| StructureID 随机化 | 未启用 |
| CFI (控制流完整性) | 未启用 |
| JIT | 已禁用 |
| GoldHEN 版本 | v2.4b18.10 |
| 内核漏洞利用 | Poopsploit (IPv6 UAF) |
| 权限提升 | ucred patch |
| ROP 链 | Pipe buffer overlap |

## 使用方法

1. 将项目部署到 Web 服务器
2. 在 PS4 浏览器中打开 `index.html`
3. 点击 "运行" 按钮
4. 等待漏洞利用完成
5. GoldHEN 将自动加载
6. ELF 加载器将在端口 9021 启动
7. 发送 ELF 载荷到 PS4

## 开发状态

- [x] 项目结构创建
- [x] Int64 库
- [x] 核心 WebKit 漏洞利用框架
- [x] 内存原语
- [x] ROP 链构建器
- [x] 系统调用封装
- [x] FW 13.00 特定偏移量
- [x] Poopsploit 内核漏洞利用集成
- [x] Pipe buffer overlap 内核 R/W
- [x] ROP 链执行
- [x] 权限提升 (ucred patch)
- [x] ELF 加载器
- [x] GoldHEN v2.4b18.10 支持
- [x] 系统调用桥接抽象层
- [x] Web UI
- [x] 偏移量加载器与验证
- [x] 运行时配置
- [x] 单元测试与集成冒烟测试
- [ ] 真实偏移量测试
- [ ] 稳定性优化
- [ ] 真实 WebKit 验证
- [ ] 真实 syscall 桥接
- [ ] GoldHEN 13.00 兼容性验证

## 文件说明

| 文件 | 大小 | 说明 |
|------|------|------|
| `src/main.js` | ~12 KB | 主入口，协调所有阶段 |
| `src/webkit/core.js` | ~20 KB | WebKit 漏洞利用核心 |
| `src/webkit/mem.js` | ~8 KB | 内存读写原语 |
| `src/webkit/int64.js` | ~4 KB | 64位整数运算 |
| `src/webkit/rop.js` | ~8 KB | ROP 链构建与执行 |
| `src/webkit/syscalls.js` | ~6 KB | 系统调用封装 |
| `src/webkit/syscall_bridge.js` | ~8 KB | 系统调用桥接 |
| `src/webkit/offsets.js` | ~12 KB | FW 13.00 偏移量 |
| `src/kernel/kernel.js` | ~15 KB | Poopsploit 内核漏洞利用 |
| `src/payloads/loader.js` | ~10 KB | ELF 加载器 |
| `src/payloads/goldhen.js` | ~6 KB | GoldHEN 支持 |

**总计: ~90 KB**

## GoldHEN v2.4b18.10 功能

| 功能 | 说明 |
|------|------|
| Debug Settings | 启用调试设置菜单 |
| FTP Server | FTP 服务器 (端口 2121) |
| Homebrew Enabler | 启用自制软件 |
| Update Blocker | 禁用系统更新 |
| Remote Package Install | 启用远程包安装 |
| VR Support | 启用 VR 支持 |
| Rest Mode Support | 启用休息模式支持 |
| External HDD Support | 启用外接硬盘支持 |
| PayLoader Server | Payload 服务器 (端口 9090) |
| KLog Server | 内核日志服务器 (端口 3232) |

## 致谢

- Jordy (SlopKit)
- Egy, Sonic, Yenyen, Zeco, Gezine
- Echostretch, Ufm42
- TheFloW (Poopsploit)
- John Tornblom, Flatz, Idlesauce
- PS5 R&D Discord
- GoldHEN Team

## 注意事项

⚠️ 本项目仅供教育和研究目的使用。

⚠️ 使用本项目进行未经授权的访问是违法的。

⚠️ 请在自己的设备上进行测试。

## 技术细节

### JSCell 结构 (PS4 FW 13.00)

```
Offset  Size  Field
0x00    4     m_structureID
0x04    1     m_indexingType
0x05    1     m_type (CellType)
0x06    1     m_flags (InlineTypeFlags)
0x07    1     m_cellState
```

### Poopsploit 内核漏洞利用

- **漏洞类型**: IPv6 路由头 UAF
- **触发方式**: setsockopt/getsockopt
- **影响范围**: FW 9.00 - 13.00
- **内核利用**: Pipe buffer overlap 实现任意读写
- **权限提升**: ucred patch (uid=0, gid=0)

### GoldHEN 加载流程

1. 验证 GoldHEN 载荷
2. 映射到内存
3. 设置页权限
4. 跳转到入口点
5. 应用所有功能

### ELF 加载器

- **监听端口**: 9021
- **协议**: TCP
- **支持格式**: ELF64 AMD64
- **验证**: 魔数、类型、架构检查
- **解析**: 程序头、段信息、入口点

## 当前限制

⚠️ 本项目目前是**原型结构**，还不是可用的完整利用链。

主要限制包括：
- `offsets.js` 中的部分偏移量和 gadget 地址仍是占位值
- 系统调用桥接在未提供真实实现时进入只读回跳模式
- 浏览器利用路径在理论上是可能的，但需要针对 FW 13.00 的真实偏移量和验证过的 WebKit 利用原语

## 使本项目可用的必要条件

如果要继续开发为可用实现，需要补充以下内容：
1. **真实 FW 13.00 内核偏移量**，包括 `allproc`、`prison0`、`sysent`、ROP gadgets
2. **针对 PS4 Safari 17.0 / AppWebKit 605.1.15 的可用 WebKit 利用原语**
3. **从 JS 到内核的真实 syscall 桥接**
4. **与 FW 13.00 兼容的已验证 GoldHEN 载荷**
5. **针对 PS4 内存限制的稳定性调优**
