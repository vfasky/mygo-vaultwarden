# 界面与交互规范

所有界面使用 `internal/ui/kit` 的共享控件（`controls.go`），保证按钮、选择、输入和提示在各窗口外观一致。控件建立在 MyGo 的无外观基础组件上，键盘、焦点和无障碍语义与原生控件相同。`go test ./internal/ui/kit` 中的 `TestControlsPreview` 可把全部控件渲染为图片（设置 `MYGO_UI_PREVIEW_DIR`）。

## 页面结构

- 顶部 `kit.PageHeader(c, 标题, 副标题, trailing)`：副标题一两句，说明这页做什么；模式切换等放在 trailing。
- 中间按任务分组：表单用 `kit.Section`，只读信息用 `kit.DetailCard` + `kit.DetailField`。
- 窗口底部用 `kit.ActionBar`：左侧放状态文字或已选数量，`ui.Spacer` 后依次放次要按钮、主按钮。编辑器在主窗口详情区时，页尾操作行同样右对齐。
- 页面内边距 20–24，分组之间 16，控件之间 8–12。

## 按钮

| 用途 | 控件 |
|---|---|
| 页面或分组唯一的主操作（保存、导出、确认导入） | `kit.Button(..., kit.ButtonPrimary, ...)`，即 `kit.Action(..., primary=true, ...)` |
| 其他操作、取消、返回 | `kit.ButtonSecondary` |
| 行内或链接式的轻操作（全选、清除、显示更多） | `kit.ButtonQuiet` |
| 删除、清空、撤销、永久删除 | `kit.ButtonDanger` |
| 只有图标（关闭、复制） | `kit.IconButton`，必须有 label |

- 按钮按内容宽度排列，不要拉满整行；只有登录等单列表单使用 `kit.WidePrimary`。
- 一个区域只有一个主按钮。危险操作放在主按钮之外，执行前需要确认的保持原有确认流程。
- 不可用时用 `disabled` 参数，不要隐藏后让布局跳动；需要说明原因时在附近用 `kit.Notice` 或 Field 提示。

## 选择与开关

| 场景 | 控件 |
|---|---|
| 切换页面模式（导出/导入、列表/网格） | `kit.Segmented(c.Key(...), &index, ...)` |
| 2–5 个互斥选项，需要说明 | `kit.ChoiceGroup` + `kit.Choice`（标题 + 一句说明） |
| 很多互斥选项 | `ui.Select` |
| 从列表中多选 | `kit.CheckRow`；条目多时放进 `ui.List`（行高 40），列表上方给出“全选/全不选”和“已选 n / 共 m” |
| 单个选项，随保存生效 | `kit.Checkbox` |
| 立即生效的设置 | `kit.SwitchRow` |

不要用侧栏导航项（`kit.NavItem`）充当选项，不要用 `✓` 文字或整行按钮模拟勾选。

## 输入与提示

- 文本输入：`kit.Field(c, 标签, 提示, func() { kit.Input(ui.TextInput(...)) })`；密码加 `.Password()`。标签简短，格式要求放在提示里。
- 需要用户注意的说明用 `kit.Notice`：`ToneInfo` 说明，`ToneWarning` 风险（如导出明文），`ToneDanger` 错误或不可恢复，`ToneSuccess` 完成。不要把多段灰色小字堆在页面顶部。
- 没有内容时用 `kit.EmptyState`。
- `a.status` 这类状态文字显示在窗口底部状态行或 `ActionBar` 左侧。

## 不再使用

- 在 kit 之外直接写 `ui.Button` / `ui.PrimaryButton` 并自行设置样式。
- 用 `kit.NavItem` 做格式、类型等选项。
- 用 `ui.Checkbox`（未统一外观），改用 `kit.Checkbox` / `kit.SwitchRow`。
- 宽度拉满、文字居中的按钮列表。

登录、解锁与注册页面（`ui_auth.go`、`internal/ui/account/registration.go`、`auth.go`、`device_login.go`）沿用现有的单列表单样式（`kit.FormInput`、`kit.WidePrimary`、`kit.TextLink`）。
