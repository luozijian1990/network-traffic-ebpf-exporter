# 引导视图补齐与复核

四张图补充共 14 个中文引导章节。两个流程图合并冗余泳道、移除垂直偏移，修复桌面纵向溢出；原有节点 ID 与业务连线保留。

## 交付与浏览器证据

| 文件 | 类型 | 章节数 | 校验 | 浏览器证据 |
| --- | --- | ---: | --- | --- |
| [ebpf-architecture.html](ebpf-architecture.html) | architecture | 3 | 9/9 showcase；0 errors；0 warnings | [passed](ebpf-architecture.visual-check.json) |
| [ebpf-workflow.html](ebpf-workflow.html) | workflow | 4 | 9/9 showcase；0 errors；0 warnings | [passed](ebpf-workflow.visual-check.json) |
| [conntrack-architecture.html](conntrack-architecture.html) | architecture | 3 | 9/9 showcase；0 errors；0 warnings | [passed](conntrack-architecture.visual-check.json) |
| [conntrack-workflow.html](conntrack-workflow.html) | workflow | 4 | 9/9 showcase；0 errors；0 warnings | [passed](conntrack-workflow.visual-check.json) |

浏览器检查在沙箱外使用 Archify 的原装 `visual-check` 完成：1440×900、1600×1000、1920×1080、2048×1320 均无横向和纵向溢出；端点尺寸均采集浅色与深色截图。

## 视觉与交互复核

- `visual_review: passed`：已查看每张图的浅色与深色实际截图，确认引导栏、章节名称与图中节点可见。
- 在本机 Chrome 的 eBPF 流程图中点击“启动挂载”，确认显示 `1 / 4`、章节说明、3 个故事节点、聚焦高亮，以及 `#view=startup-attachment` 链接。其余章节已核对嵌入配置与有效节点引用；未逐一点击全部 14 章。
- `correction_rounds: 1`：浏览器发现流程图纵向溢出后，调整泳道布局并重新校验、交付和检查。
- 每张图的 `*.visual-check.json` 仍保留自动证据固有的 `visualReview: pending`；本记录为独立的图像复核，不修改自动收据。

## SHA-256 与字节数

### ebpf-architecture

- specification_sha256: `5c5c5d8c4100c515b07051e46a701a957888d98869d959087b23e1738e08db30`
- specification_bytes: 3331
- artifact_sha256: `10cc1ed6c9be438874738d652317fa10ae57959cea5c6275c90a03ec3b06c4ff`
- artifact_bytes: 710695

### ebpf-workflow

- specification_sha256: `7affe7b061f05be14876144e784ec14bd2335046f43d31303b85849f72a89c62`
- specification_bytes: 6231
- artifact_sha256: `9067b03ed73eed5d7a80c02582f4228ba01c880080f84d1b1c7e793289b8729f`
- artifact_bytes: 717966

### conntrack-architecture

- specification_sha256: `580080cc3c5cb008adaddd64d96f5a1992edf3d78ed65f609269423f933e8055`
- specification_bytes: 3922
- artifact_sha256: `55cfe5b857d97027239eaa3441ca1332e6e587c1188ef7f8bae70a9fa07bb580`
- artifact_bytes: 714509

### conntrack-workflow

- specification_sha256: `f29a3b0f1e54df2d964e86e711e3874acf09c1da9b965177431443156da964d7`
- specification_bytes: 7301
- artifact_sha256: `f2695d41b027cc853b0ac9f3daabd7e104f918ee70209c70df55888e03ae3c07`
- artifact_bytes: 722284

