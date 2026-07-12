# Radar POV 分阶段优化计划

## 目标与约束

本计划用于逐步优化 `cs2-server-plugin/radar_pov.cpp` 中的 Demo 第一视角雷达功能。

已确认的硬性约束：

- 当前 7 个 hook 必须全部保留，不能以减少 hook 数量作为优化手段。
- 每次只处理一个小主题；代码检查和构建按阶段执行，Demo 实测按后文定义的里程碑集中执行。
- 不同时进行大规模拆文件、签名重写和运行时逻辑重构。
- 保持现有产品行为：地图随 POV 旋转、队友使用竞技颜色、敌人保持原生显示、隐藏 freecam 观战者图标、不强制雷达 cvar。
- 任一阶段出现行为回归，先回退该阶段，不把补丁叠加到未验证状态上。

## 当前基线

当前实现使用以下 7 个 MinHook detour：

1. `radar_update`
2. `getLocal`
3. `radar_demo_state`
4. `getEntityBySlot`
5. `findPlayerBySlot`
6. `setRadarIconType`
7. `radarIconColor`

开始优化前应保存一份当前可用版本的：

- Git commit ID。
- `client.dll` PE timestamp。
- 完整安装日志和第一次 POV radar update 日志。
- T、CT 两方 POV 的截图或录像。
- 切换观察目标、freecam、死亡和回合切换的测试结果。

## 阶段 1：严格执行 7-hook 完整安装

状态：**代码完成、等待阶段 1～3 合并后的 B 级里程碑验证**

### 目的

消除“只有部分 hook 安装成功，但代码仍报告 installed”的半成功状态。

### 修改范围

只修改 hook 目标完整性检查、安装结果和日志，不调整 detour 内部行为，不修改签名算法。

### 具体任务

- 将 7 个 hook 全部标记为必要组件。
- 在开始安装前确认 7 个 hook target 和它们依赖的 helper 均已解析。
- `findPlayerBySlot` 不再标注为 optional。
- 任意一个 hook 创建或启用失败时，本次安装整体失败。
- 只有 7 个 hook 全部生效后，才设置 `g_installed=true`。
- 最终日志明确输出 `7/7 hooks active`；失败日志指出具体缺失项。

### 暂时不做

- 不使用批量启用 API。
- 不重构 MinHook 生命周期。
- 不拆分 `radar_pov.cpp`。
- 不调整 pattern 或 resolver。
- 不优化热路径。

### 验收条件

- Windows Release x64 构建通过。
- 正常版本日志显示 7/7 hook 全部安装。
- 人为使任一 target 解析失败时，安装必须返回失败且 `installed=0`。
- 在阶段 1～3 合并后的 B 级测试中确认原有雷达行为不变。

### 本次执行记录

- 实际修改 commit ID：`92099e27d18d580175679f0c061ddd91cfe2c803`。
- 代码状态：已完成，等待阶段 1～3 合并后的 B 级里程碑验证。
- A 级检查：`git diff --check` 通过；POSIX 分支 `clang++ -fsyntax-only` 通过；Makefile dry-run 确认 `radar_pov.cpp` 已纳入构建。
- Windows Release x64 构建：当前 macOS 环境没有 `msbuild`/Windows SDK，留待 Windows 环境执行。
- Demo 测试：本阶段不单独启动 Demo，等待阶段 1～3 合并后统一执行 B 级测试。
- 下一步：阶段 1 已满足代码级验收，可进入阶段 2；在阶段 1～3 完成后执行 B 级测试。

## 阶段 2：精确回滚和精确卸载本功能 hook

前置条件：阶段 1 已通过 A 级验证；阶段 1～3 完成后统一进行 B 级测试。

### 目的

避免 `MH_DISABLE_ALL_HOOKS` 和无条件 `MH_Uninitialize()` 影响未来其他 MinHook 使用者。

### 修改范围

只管理本功能 7 个 target 的创建、回滚和卸载。

### 具体任务

- 保存本功能已经创建的 hook target 列表。
- 安装失败时，只 disable/remove 已由本次安装创建的 target。
- 正常卸载时逐个处理这 7 个 target。
- 记录本模块是否真正拥有 MinHook 初始化生命周期。
- 不再把 `MH_ALL_HOOKS` 作为 Radar POV 的默认卸载方式。

### 验收条件

- 在第 1 至第 7 个 hook 的任意安装点模拟失败，都能完整回滚。
- 失败后允许再次安装，不出现 `ALREADY_CREATED` 等残留状态。
- 正常卸载、再次安装均成功。
- 在阶段 1～3 合并后的 B 级测试中确认 Demo 行为不变。

### 本次执行记录

- 实际修改 commit ID：`fe38675`（`fix(radar-pov): precisely roll back owned hooks`）。
- 代码状态：已完成；已登记本功能创建的 hook target，安装失败和正常卸载均按 target 逐个 disable/remove，并记录 MinHook 生命周期所有权。
- A 级检查：`git diff --check` 通过；POSIX 分支 `clang++ -fsyntax-only` 通过（仅有该分支原有的未使用变量警告）；Makefile dry-run 确认 `radar_pov.cpp` 已纳入构建；当前 macOS 环境没有 `msbuild`/Windows SDK，Windows Release x64 构建留待 Windows 环境执行。
- Demo 测试：本阶段不单独启动 Demo，等待阶段 1～3 合并后的 B 级里程碑统一验证。
- 下一步：阶段 2 已满足代码级验收，可进入阶段 3。

## 阶段 3：7 个 hook 批量启用

前置条件：阶段 2 已通过。

### 目的

减少安装时多次暂停/恢复线程，并缩短部分 hook 已启用的时间窗口。

### 具体任务

- 先创建全部 7 个 hook。
- 使用 `MH_QueueEnableHook` 为本功能 target 排队。
- 最后只调用一次 `MH_ApplyQueued()`。
- 批量启用失败时沿用阶段 2 的精确回滚。

### 验收条件

- 安装日志能区分 create、queue、apply 三个阶段。
- 任一阶段失败都不会留下部分安装状态。
- 7 个 hook 的目标和 detour 行为不变。

### 本次执行记录

- 实际修改 commit ID：`05b771e`（`perf(radar-pov): batch-enable hooks`）。
- 代码状态：已完成；7 个 hook 现在先全部 `MH_CreateHook`，再逐个 `MH_QueueEnableHook`，最后只调用一次 `MH_ApplyQueued`。create、queue、apply 均有独立日志；任一阶段失败都复用阶段 2 的精确 target 回滚。
- A 级检查：`git diff --check` 通过；POSIX 分支 `clang++ -fsyntax-only` 通过（仅有该分支原有的未使用变量警告）；Makefile dry-run 确认 `radar_pov.cpp` 已纳入构建。
- Windows Release x64 构建：当前 macOS 环境没有 `msbuild`/Windows SDK，留待 B 级里程碑测试时执行。
- Demo 测试：本阶段不单独启动 Demo，等待阶段 1～3 合并后的 B 级里程碑统一验证。
- 下一步：阶段 3 已满足代码级验收；阶段 1～3 可进入 B 级验证，之后再进入阶段 4。

## 阶段 4：整理 Radar update 帧上下文

前置条件：前三阶段稳定。

### 目的

使 thread-local POV 状态在嵌套调用、异常和未来早退路径下保持一致。

### 具体任务

- 将分散的 thread-local 字段整理为 `RadarPovFrameContext`。
- 只在调用深度 `0 -> 1` 时准备 POV context。
- 只在调用深度 `1 -> 0` 时清理 context。
- 使用小型 RAII scope 保证计数和清理成对执行。
- 增加 `updateContext == nullptr` 防护。

### 验收条件

- 普通调用和人工构造的嵌套调用均能正确恢复 context。
- `g_povActive` 不会在外层 radar update 尚未结束时被内层提前清空。
- 在本阶段触发的 C 级测试中确认 Demo 行为不变。

## 阶段 5：加强 resolver 的唯一性和边界检查

前置条件：运行时逻辑已经稳定，且留有阶段 1 的基线日志。

### 目的

降低 CS2 更新后“解析到了错误函数但仍成功安装”的风险。

### 具体任务

- 所有函数扫描受 `client.dll` 或 `.text` section 边界限制。
- 多 pattern 命中时不再无条件选择第一个结果。
- 删除或严格验证纯顺序回退，例如 `earlyUnique[2]`。
- 每个 hook target 同时验证 pattern、调用关系、函数范围和关键结构特征。
- 日志打印 target RVA、解析来源和候选数量。

### 验收条件

- 当前 `client.dll` 仍解析到与基线相同的 7 个 RVA。
- 模糊或多候选结果会明确失败关闭，不会选择低置信度地址。
- 游戏更新后的失败日志足以定位具体 resolver。

## 阶段 6：只在必要时优化热路径

前置条件：已有实际 profiling 或明确的帧耗时证据。

### 可选任务

- 在最外层 radar update 中缓存 enabled/active 状态，内部 hook 读取 thread-local 快照。
- 当前帧缓存 player index 对应的 controller、team 和 ARGB。
- 降低非诊断模式下的原子日志计数开销。

不建议在没有 profiling 证据时提前缓存 Panorama panel/style 指针，这些对象可能重建。

## 阶段 7：最后再拆分文件

前置条件：功能和 resolver 已经过前述阶段验证。

建议按职责逐步拆分，而不是一次移动全部代码：

1. 先拆 resolver。
2. 再拆 MinHook 安装管理。
3. 最后视需要拆颜色处理。

每次拆分只做代码移动和必要声明调整，不同时改变运行逻辑。

## 分级验证规则

不再要求每个阶段都启动 Windows 游戏并重复完整 Demo 测试。验证分为以下三级。

### A 级：每个阶段都执行

这一级不需要启动游戏：

- [ ] `git diff` 只包含当前阶段范围。
- [ ] `git diff --check` 通过。
- [ ] Windows Release x64 构建通过；如果当前不在 Windows 环境，则至少保证项目文件和新增源码已正确纳入构建，并留待里程碑测试时统一构建。
- [ ] 对当前阶段能够通过代码或小型测试验证的失败路径进行检查。

### B 级：安装机制里程碑测试

阶段 1、2、3 可以连续完成，之后只启动一次游戏进行合并验证，不必每阶段各启动一次。

- [ ] 插件正常加载，没有安装异常。
- [ ] 日志显示全部 7 个 hook 安装成功。
- [ ] disable/re-enable 正常。
- [ ] 退出游戏时卸载正常。
- [ ] 没有半安装、重复创建或回滚残留日志。
- [ ] 进入任意一段 Demo，快速确认 POV 雷达仍能正常显示和旋转。

如果阶段 1、2 或 3 的代码审查、构建或故障注入发现问题，则先修复，不进入游戏测试。

### C 级：完整功能回归测试

只在以下情况执行完整 Windows 游戏测试：

- 完成阶段 4 的运行时上下文调整后。
- 完成阶段 5 的 resolver 调整后。
- 阶段 6 实际修改了热路径时。
- 阶段 7 全部拆分完成、准备结束本轮优化时。
- 任意阶段实际改变了 hook 条件、调用顺序、偏移、颜色逻辑或 POV 状态逻辑时。
- 日志或快速测试出现异常时。

完整测试清单：

- [ ] T、CT 至少各测试一个 POV。
- [ ] 地图旋转和观察目标方向一致。
- [ ] 队友竞技颜色正常，敌人没有套用队友颜色。
- [ ] freecam 观战者图标未出现。
- [ ] 至少切换一次观察目标。
- [ ] 至少覆盖一次死亡或回合切换。
- [ ] 日志中没有 hook 异常。

暂停、跳转 tick、连续加载第二个 Demo 等扩展场景只在相关代码被修改、发现疑似回归或最终发布前测试，不作为每个里程碑的必测项。

## 执行规则

后续每次只选择文档中的一个阶段实施。完成后在对应阶段下面补充：

- 实际修改的 commit ID。
- 构建结果。
- 本阶段是否需要 Demo 测试；如已执行则记录结果，否则注明等待哪个里程碑统一验证。
- 是否进入下一阶段。

阶段通过 A 级验证后即可标记为“代码完成、等待里程碑验证”，并可以继续同一里程碑内的下一阶段。阶段 1～3 在统一通过 B 级测试后标记为已验证；阶段 4 及之后按上面的 C 级触发规则决定是否需要完整测试。未经对应里程碑测试的修改不能作为最终稳定版本发布。
