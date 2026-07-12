# ShadowTrace AI Agent 工程实施简介

## 一、项目定位

ShadowTrace 是一个独立部署的通用多 Agent 安全运营智能体系统。系统接收来自 Mock XDR、文件数据集或真实 XDR 数据传送适配器的安全事件、告警、资产与原始日志，由多个职责单一的 Agent 协作完成分诊、证据采集、攻击分析、风险评分、处置建议、处置验证和报告输出的完整闭环。

ShadowTrace 与深信服 XDR、安全 GPT 均保持解耦：

1. XDR 是可替换的数据源，也是生产环境事件处置的写回目标。ShadowTrace 的研判正文、报告、Prompt、decision_trace 与模型内部过程永不写回 XDR；经策略校验和审批通过的处置动作、目标、执行状态及最小结果摘要必须写回 Adapter 选定的单一可写来源对象。对 `disposition_policy=required` 的事件，当前闭环周期还必须有且仅有一条终态 `EVENT_STATUS_UPDATE` 获得 CONFIRMED，才可视为事件处置已回写并进入 CLOSED。P0 由 Mock 契约保证这一闭环；生产适配只有在正式接口确认可写对象、鉴权和操作映射并通过契约测试后才算完成。若目标版本确实不提供所需写能力，系统必须标记 `writeback_unsupported`、停止自动处置并阻塞生产闭环验收，不能用本地成功冒充已回写。
2. 大模型只通过统一 `LLMProvider` 调用。开发期可使用 MockLLM 或任意 OpenAI-compatible API，后续可新增深信服安全 GPT/AICP Provider，但 Agent 业务代码不得绑定某一模型厂商。
3. 开发与演示默认走 `MockXDRServer + MockToolProvider`。Mock 必须模拟外部 ID、分页游标、异步任务、设备能力、延迟、部分成功与失败回执，不能用“写入状态后立即读回成功”的自证方式伪造闭环。
4. 真实环境按三个可替换边界设计：`SourceAdapter` 只读接收 XDR 数据；`ToolProvider` 执行防火墙、EDR 等动作；`DispositionAdapter` 负责把获批的事件处置及最小执行结果同步到来源 XDR。其中只有只读接入是既定边界；live `DispositionAdapter` 及 `XDR_MANAGED` 是否可用，必须由正式资料或脱敏请求证据确认。每个 Action 只能选择一个 ShadowTrace 内部执行策略：能力已确认时可用 `XDR_MANAGED` 由 DispositionAdapter 提交实体动作，或用 `DIRECT_TOOL` 由 ToolProvider 执行后仅同步执行结果/事件状态；后一路径严禁再次映射成实体动作。二者禁止双下发，执行回执与外部同步回执分别建模。
5. 截图中观察到的页面字段只用于建立兼容的领域模型，不据此猜测或硬编码深信服私有 REST 路径。真实端点、鉴权与返回结构必须等获得正式接口文档或脱敏网络请求后再落入具体 Adapter。
6. 当前截图未展示“处置事件”下拉项，因此方案不预设厂商 operation_code。Mock 使用自有测试动作；真实 DispositionAdapter 必须从正式文档/配置映射 allowed_operations，未知操作默认不可用。

系统按事件类型抽象设计，至少支持以下安全事件类型，并允许通过新增场景包、适配器和处置模板扩展更多类型：

1. account_anomaly（账号异常）
2. host_compromise（主机失陷）
3. data_exfiltration（数据外泄）
4. insider_threat（内部威胁）
5. malicious_process（恶意进程）
6. suspicious_domain（可疑域名访问）
7. lateral_movement（横向移动）
8. other（其他 / 未分类）

"张三内鬼数据外泄"只是其中一个演示数据集（insider_data_exfiltration 场景包），用于演示和测试，不是系统架构的设计中心。所有模型、接口、Agent、知识库均按通用事件类型设计，禁止在场景包之外的代码中硬编码任何具体人物或具体实体名。

## 二、核心闭环

系统的保底闭环（P0 主链路）为：

1. 数据接入：MockXDRServer 或只读 SourceAdapter 提供 SourceIncident、SourceAlert、SourceAsset、SourceLog 与 SourceConnector，经归一化后由 EventService 创建内部 SecurityEvent，并分别保存不可变调查快照、当前来源状态和候选处置来源引用；来源可读不等于可写。
2. 分诊：TriageAgent 解析告警、抽取实体、判定事件类型与初始严重度。
3. 证据采集：EvidenceAgent 通过 ToolAgent 并发调用查询类工具，聚合证据并检测证据冲突。
4. 风险评分：RiskAgent 按六维加权模型输出 risk_score、severity 与校准后置信度。
5. 处置建议：ResponseAgent 根据当前 ToolProvider 的能力清单生成 L0-L5 分级处置计划，审批引擎判定自动执行或人工审批；XDR 原生预案与工单不作为 P0 前置。
6. 处置执行、写回与验证：默认由 Mock Provider 模拟同步或异步执行；DispositionSyncService 通过 ShadowTrace 自有 Mock Disposition API 写入选定外部对象并保存回执；VerifyAgent 分两阶段核验——先核验 IMMEDIATE 动作效果，再由 EventDispositionService 激活已有 deferred 终态 Action 并核验 XDR 写回状态。生产环境可在能力经证实后选择 XDR 托管或直连设备 Provider，切换时不修改 Agent；若没有已验证写能力，相关动作保持业务上的回写义务并被阻塞，不能降成“无需回写”。
7. 报告输出：ReportAgent 生成 15 章节结构化调查报告并持久化。

整个闭环由 SuperAgent 驱动 LangGraph 状态机编排，全过程记录 decision_trace（Agent 执行轨迹）、事件状态审计日志和工具调用审计日志，保证每一步可解释、可回溯。

在保底闭环之上，系统保留以下可演示亮点（P1）：多 Agent 自主调查闭环、可解释 decision_trace、工具调用审计、证据冲突处理、ReAct 重规划、攻击故事线生成、误报识别、一键演示脚本。

## 三、技术边界与优先级约定

技术边界：

1. 系统不以真实设备或 XDR 私有接口作为开发期 P0 前置。`SOURCE_MODE=mock_xdr` 与 `DISPOSITION_MODE=mock_xdr` 时，本地 MockXDRServer 同时提供读取和事件处置写回契约；真实环境分别配置只读 SourceAdapter 与最小权限 DispositionAdapter。
2. 工具目录按能力清单注册，不锁死总数量。默认由 MockToolProvider 实现；真实工具只通过独立 Provider 扩展。`TOOL_MODE=live` 时真实调用失败必须如实失败或转人工，严禁静默回退 Mock 后返回成功；`mixed` 模式必须逐工具显式配置 Provider。
3. LLM 调用必须通过统一适配层，支持 mock、openai_compatible、custom 三种模式。custom 用于未来深信服安全 GPT/AICP 或其他非完全兼容端点。所有依赖 LLM 的 Agent 必须有不依赖 LLM 的规则或模板降级路径。
4. 默认存储为 PostgreSQL（含 pgvector 扩展）+ Redis。向量检索一律使用 pgvector，不引入独立向量数据库。**P0 把 Redis 视为硬依赖**（检查点、EventContext 热缓存、Pub/Sub）；无 Redis 时仅允许开发降级为内存检查点，但不得宣称满足可恢复执行验收。
5. Neo4j、OpenSearch、Kafka（Redpanda）、Kubernetes、SOC 大屏均为可选增强（P2）。P0 不创建 Kafka/Redpanda skeleton，任何 P0/P1 能力不得以它们为硬前置；对应 Issue 必须提供降级路径。未来若引入消息总线，须作为独立可选 Issue，并复用同一推送信封与幂等契约。
6. 单租户、PC 端浏览器、中文界面；不做移动端、国际化、生产级高可用。外部 tenant/customer/branch 只作为来源隔离与追溯字段，不扩展为完整多租户权限系统。
7. `ALLOW_LIVE_SIDE_EFFECTS` 与 `ALLOW_XDR_WRITEBACK` 默认 false，只约束 live Provider。生产启用前必须完成权限、目标、幂等和审批校验。分析内容写回没有开关，始终禁止；事件处置写回只允许白名单字段。XDR 数据接入成功不代表具备联动或写回能力。
8. live 的 `XDR_MANAGED` 只有在 Adapter 能力已验证且两个开关均为 true 时才是候选路径；live 的 `DIRECT_TOOL` 设备动作需要 `ALLOW_LIVE_SIDE_EFFECTS`，随后结果同步还需已验证写能力和 `ALLOW_XDR_WRITEBACK`。开关只是本地安全栅栏，不能证明厂商支持相应接口。Mock 仅在 `SIMULATION_ENABLED=true` 且环境栅栏确认为非生产时运行，回执必须标记 `simulated=true`；任一 live 权限或能力缺失都不得用本地 Mock 成功替代。

优先级约定：

1. P0：从 Mock XDR 输入到分析、审批、异步处置、事件处置写回、两阶段验证与报告必须完整跑通；测试必须证明分析内容未出站、处置确已写回且未重复执行。
2. P1：冲奖亮点。必须可演示、可解释、可测试，不能只是概念；P1 失败不得阻断 P0 主链路。
3. P2：可选增强。未完成不影响 P0/P1 的交付、部署与演示。

## 四、全局统一命名约束

后续所有 Issue 必须遵守本节命名。同一概念只允许一个主名；外部输入中的同义字段只能在适配层映射为主名，不得在系统内部继续传播别名。

### 4.1 目录与包名

1. 仓库根目录：`backend/`（FastAPI 后端）、`frontend/`（React 前端）、`contracts/`（共享契约）、`infra/`（Docker Compose 与部署）、`scripts/`（开发与演示脚本）、`data/`（mock 数据与知识库数据）、`docs/`（文档）。
2. 后端包根为 `backend/app/`，子包固定为：`api/`、`agents/`、`models/`、`services/`、`tools/`、`providers/`（LLMProvider、ToolProvider）、`adapters/`（SourceAdapter 与 DispositionAdapter）、`mock_xdr/`、`ingestion/`、`data_generators/`、`rag/`、`orchestration/`、`core/`、`db/`。
3. 后端测试统一在 `backend/tests/`，单元测试按模块分目录（如 `tests/test_agents/`、`tests/test_tools/`），集成测试在 `backend/tests/integration/`。
4. 前端源码根为 `frontend/src/`，子目录固定为：`pages/`、`components/`、`services/`、`hooks/`、`stores/`、`types/`、`utils/`、`styles/`。
5. 契约目录：`contracts/schemas/`（JSON Schema）、`contracts/openapi/`（OpenAPI 文件）、`contracts/socketio/`（实时事件 Schema）。

### 4.2 API 与实时通道

1. 所有 REST API 路径前缀为 `/api/v1`。
2. 核心 REST 契约固定为方法+完整路径（均带 `/api/v1`）：事件 `POST /events`、`GET /events`、`GET /events/{event_id}`、`POST /events/{event_id}/investigate`、`POST /events/{event_id}/close`、`GET /events/{event_id}/report`、`GET /events/{event_id}/traces`、`GET /events/{event_id}/audit-logs`、`GET /events/{event_id}/tool-calls`、`GET /events/{event_id}/timeline`、`GET /events/{event_id}/graph`、`GET /events/{event_id}/decision-trace`、`GET /events/{event_id}/actions`；审批/裁决 `POST /actions/{action_id}/approve`、`POST /actions/{action_id}/reject`、`POST /actions/{action_id}/resolve-unknown`；来源 `POST /ingestion/source-records`、`GET /source-records/{source_record_id}`、`GET /connectors`、`PUT /events/{event_id}/disposition-source`、`POST /events/{event_id}/disposition-readiness/recheck`；处置 `GET /events/{event_id}/dispositions`、`GET /dispositions/{disposition_id}`、`GET /writebacks/{writeback_id}`、`POST /writebacks/{writeback_id}/retry`、`POST /writebacks/{writeback_id}/resolve`；平台 `GET /execution-jobs/{job_id}`、`GET /tool-calls`、`GET /tasks/{task_id}`、`GET /tools`、`GET /knowledge`、`GET /health`、`GET /stats`。retry 只重新入队同一 outbox；UNKNOWN 必须先查证。两个 resolve 端点仅管理员可用，必须提供 comment/evidence_ref 并做状态 CAS，绝不触发实体动作；source 选择与 readiness recheck 需 disposition_operator，使用事件版本 CAS，重算后只恢复原检查点，不直接执行。
3. 统一错误响应体字段：`error_code`、`error_message`、`details`。分页响应体字段：`total`、`page`、`page_size`、`items`。
4. SocketEventEnvelope 类型：event_created、state_change、agent_progress、agent_completed、agent_failed、tool_call_started、tool_call_completed、approval_required、approval_updated、action_executed、action_verified、risk_updated、report_generated、final_verdict_updated、disposition_submitted、writeback_updated；payload 不携带秘密或未脱敏 raw_result。
5. 扩展端点由对应功能 Issue 新增，遵循同一 `/api/v1` 前缀、错误体与分页约定并同步导出 OpenAPI：`/api/v1/events/{event_id}/trajectory`（ISSUE-066）、`/api/v1/events/{event_id}/chat`（ISSUE-076）、`/api/v1/search`（ISSUE-084）、`/api/v1/knowledge/reviews` 与 `/api/v1/knowledge/reviews/{review_id}/promote`、`/api/v1/knowledge/reviews/{review_id}/reject`（ISSUE-081）。

### 4.3 核心数据模型主名

1. `SecurityEvent`：ShadowTrace 内部唯一调查事件主模型。它不等同于 XDR 的 incident，也不覆盖外部告警、资产、工单和预案状态。
2. 外部来源模型固定为 `SourceIncident`、`SourceAlert`、`SourceAsset`、`SourceLog`、`SourceConnector` 与 `SourceReference`。这些模型允许保存 `raw_payload`，并通过 SourceAdapter 映射为内部模型；外部字段不得直接扩散到 Agent 业务层。
3. `SourceReference` 公共字段：`source_kind`、`source_product`、`source_tenant_id`、`connector_id`、`source_object_type`、`source_object_id`、`parent_source_object_id`、`source_status_raw`、`source_disposition`、`source_concurrency_token`（可空、不透明，只由 Adapter 解释）、`source_updated_at`、`schema_version`、`ingested_at`、`raw_payload_hash`。`source_kind` 是 canonical `SourceObjectKind`（incident、alert、asset、log、connector），用于内部判别联合；`source_object_type` 是 Adapter 提供的可空、不透明原生类型标识，用于 live 映射，二者不得互相猜测。调查快照中的引用不可变；当前状态只更新 `source_object.current_*`/`source_sync_state`。不得假定令牌一定是 ETag 或版本号。
4. `EntitySet`：六类实体容器，成员为 `AccountEntity`、`HostEntity`、`IPEntity`、`DomainEntity`、`ProcessEntity`、`FileEntity`，公共字段 `entity_id`、`entity_type`、`source_refs`。实体处置视角至少覆盖外网 IP、内网 IP、域名、主机、文件、进程六类目标。
5. `Evidence`：证据；`Action`：本地处置动作；`ActionExecutionJob`：异步动作任务；`SourceObjectLocator`：写回最小定位符；`DispositionCommand`：最小处置信封；`DispositionReceipt` 与 `DispositionOutboxRecord`：可靠投递与回执。
6. Agent 阶段输出模型主名：`TriageResult`、`EvidenceOutput`、`AttackStoryline`、`GraphOutput`、`RAGOutput`、`RiskAssessment`、`ResponsePlan`、`VerificationResult`、`MemoryOutput`、`ExecutionPlan`、`InvestigationResult`。
7. 字段命名一律 snake_case；时间字段为 ISO 8601 字符串或 timezone-aware datetime；分数字段约定：`risk_score` 取值 0-100，`confidence` 取值 0-1。

### 4.4 Agent 名称（12 个，类名固定）

1. `SuperAgent`（中枢编排）
2. `PlannerAgent`（执行计划生成）
3. `TriageAgent`（分诊）
4. `EvidenceAgent`（证据采集）
5. `GraphAgent`（实体关系图与攻击路径）
6. `RAGAgent`（知识增强研判）
7. `RiskAgent`（风险评分）
8. `ResponseAgent`（处置方案）
9. `VerifyAgent`（处置验证）
10. `ReportAgent`（报告生成）
11. `MemoryAgent`（知识沉淀）
12. `ToolAgent`（工具执行统一入口，落地实现为 `ToolExecutor`）

所有 Agent 继承 `BaseAgent`（位于 `backend/app/agents/base.py`），实现抽象方法 `async _run(input) -> output`，由基类模板方法 `execute` 统一包装（计时、轨迹、护栏、预算、工作记忆），执行轨迹统一写入 `agent_trace` 表。

### 4.5 工具名称与能力目录（snake_case，开放扩展）

工具总数不作为契约。P0 测试只断言必需工具集合存在、Schema 合法、Provider 能力匹配，不断言目录恰好等于某个数量。

1. 查询类基线（只读，不产生 Action）：`query_account_login`、`query_edr_process`、`query_file_access`、`query_network_flow`、`query_dns`、`query_asset_info`、`query_vuln_info`、`query_threat_intel`、`query_history_cases`。
2. 处置类基线：`block_ip`、`block_domain`、`isolate_host`、`quarantine_file`、`block_process`、`scan_host_for_virus`、`disable_account`、`force_logout`、`reset_password`、`revoke_token`、`create_ticket`、`notify_security_team`、`update_source_event_disposition`。最后一项是 deferred disposition-only response Action，只由 DispositionAdapter 执行，不经 ToolProvider：每个 required 计划必须预生成恰一项并纳入审批，实际受控终态值在效果验证后由 EventDispositionService 推导，再以 EVENT_STATUS_UPDATE 提交。Mock 必须支持；live 仅在正式 operation 映射确认后可 READY，否则整个 required 计划阻塞。
3. 验证类基线：`check_ip_block_status`、`check_domain_block_status`、`check_host_isolation_status`、`check_file_quarantine_status`、`check_process_block_status`、`check_virus_scan_status`、`check_account_status`、`check_new_alerts`、`check_traffic_drop`。
4. 回滚类基线：`unblock_ip`、`unblock_domain`、`restore_account`、`cancel_host_isolation`、`restore_file`、`close_false_positive_ticket`。`block_process`、`scan_host_for_virus` 等是否可回滚由 Provider capability 明示，禁止凭工具名猜测。
5. 系统级 Action：仅 `generate_report`，只记录 ShadowTrace 本地报告生成轨迹，不对应 XDR incident 或外部工具，不经 ToolExecutor，且永不写回。内部案例沉淀由 MemoryAgent（ISSUE-080）经 CaseKBService 完成，不另设 `create_internal_case` 系统 Action。
6. `writeback_required` 只表达业务义务，禁止由技术能力反向改写：system/query/verification 永远 false；response 仅由事件的 `disposition_policy` 推导；rollback 是否必须同步补偿由独立补偿策略推导。`writeback_readiness` 才根据稳定单一来源对象、配置、权限与 Adapter intent/operation 能力计算。required 但 readiness 非 READY 时必须阻断自动处置并给出 `writeback_unsupported` 等明确原因，不能把 required 降成 false；rollback 不复用普通写回，需同步时使用独立 `COMPENSATION_RECORD`。
7. `ResponseAgent` 只能生成当前 CapabilityManifest 中可用的处置工具。若来源事件要求写回而 DispositionAdapter 不可用，禁止自动执行；若动作已执行后才发生写回故障，则 ActionStatus 可为 SUCCESS，但 WritebackStatus 必须为 FAILED/UNKNOWN 并升级人工，整体闭环不得标成功。
8. Provider 可新增厂商工具，但必须提供稳定内部 tool_name、Schema、side_effect_level、idempotency、async_mode、rollback_supported 与 required_capabilities。ToolMeta 只声明 supported_execution_owners；具体 ProviderToolBinding 声明 provider/channel/owner，Action 生成时才冻结唯一 execution_owner。query/verification 的 owner 集合为空；response/rollback 可支持一个或两个 owner，但单个 Action 仍只能选一个。
9. 任一 side-effect ToolProvider 或 DispositionAdapter 若既不支持幂等键，也不能按外部 job/客户端请求号查证，相关动作不得自动执行/自动重试，只能经人工确认后单次提交；响应未知后必须停住，不能再点一次碰运气。
10. `FinalVerdict=false_positive` 与内部 `EventStatus=CLOSED` 都是 ShadowTrace 本地研判/编排语义，永不自动映射成 XDR ignored/误报/完成。若事件 disposition_policy=required，当前计划必须包含唯一、可审批且 deferred 的 `update_source_event_disposition` response Action；效果/判定确定后由 EventDispositionService 以 EVENT_STATUS_UPDATE 写入 Adapter 映射的最小受控状态。未知 operation 时不能根据 verdict 猜厂商动作，事件保持未完成/转人工（管理员仍可 force_local_close，但必须显示外部未同步）。

### 4.6 状态与等级枚举

1. `EventStatus`（14 态）：NEW、TRIAGING、COLLECTING_EVIDENCE、ANALYZING、SCORING、PLANNING_RESPONSE、WAITING_APPROVAL、EXECUTING_RESPONSE、VERIFYING、REPLANNING、CONTAINED、FAILED、REPORTING、CLOSED。该枚举只表示 ShadowTrace 内部调查编排状态。
2. `FinalVerdict`（判定标签，独立于 EventStatus）：none、possible_false_positive、false_positive、confirmed_threat。误报是判定标签，不是事件状态；高置信度误报事件仍经合法路径转移到 CLOSED。
3. `CaseLabel`（案例库兼容标签，由 FinalVerdict 派生）：true_positive、false_positive、uncertain。映射固定：confirmed_threat 对应 true_positive，false_positive 对应 false_positive，possible_false_positive 与 none 对应 uncertain。
4. `AgentStatus`：IDLE、PROCESSING、COMPLETED、FAILED、DEGRADED。`SuperAgentStatus`：IDLE、PLANNING、EXECUTING、REFLECTING、REPLANNING、FINISHED、FAILED。
5. `ActionStatus`（11 态）：PENDING、WAITING_APPROVAL、APPROVED、REJECTED、SUPERSEDED、EXECUTING、PARTIAL_SUCCESS、SUCCESS、FAILED、UNKNOWN、ROLLED_BACK。`ActionCategory`：system、response、verification、rollback。`ActionExecutionPhase`：IMMEDIATE、POST_VERIFY；只有 update_source_event_disposition 使用 POST_VERIFY。UNKNOWN 表示已提交但无法确认是否执行，禁止自动重试/回滚；只能经 Provider 查证或人工裁决转 PARTIAL_SUCCESS/SUCCESS/FAILED。SUPERSEDED 只允许从未外呼的候选/已批准 deferred Action 在新 plan_revision 生效时进入；已执行动作不得用 SUPERSEDED 抹去事实。逐目标部分成功必须为 PARTIAL_SUCCESS。
6. `Severity`（4 级）：low、medium、high、critical。分数映射：0-39 为 low，40-69 为 medium，70-89 为 high，90-100 为 critical。
7. `ActionLevel`（6 级）：L0、L1、L2、L3、L4、L5。仅在权限、来源、目标、capability、幂等/查证与 live 开关等硬门禁全部通过后，等级规则才可自动批准：L0/L1 自动；L2 需 confidence>=0.8；L3 需 high/critical 且 confidence>=0.85；L4/L5 永不自动。硬门禁不能被等级覆盖。
8. `EvidenceSource`（8 种）：identity、endpoint、data_security、network_flow、dns、asset、threat_intel、false_positive_match。
9. `ToolCategory`（4 种）：query、response、verification、rollback。
10. `ErrorCategory`（错误分类，8 值）：transient、permanent、user_input、system、llm、tool、budget、guardrail。
11. `GuardRailDimension`（输出护栏维度，4 值）：schema、grounding、policy、sanitization。
12. `BudgetScope`（预算作用域，3 值）：system、event、agent。
13. `QualityVerdict`（输出质量判定，3 值）：pass、warn、fail。
14. `SourceDisposition`：pending、processing、contained、completed、suspended、ignored、unknown，用于归一化外部事件处置标签；`source_status_raw` 始终保留原文。`DispositionPolicy` 只有 required、not_required，表示业务闭环是否要求外部同步；技术不支持不得篡改该政策。二者与 EventStatus 均无直接状态映射。
15. `ExecutionJobStatus`：QUEUED、RUNNING、PARTIAL_SUCCESS、SUCCESS、FAILED、TIMED_OUT、CANCELLED、UNKNOWN。
16. `WritebackReadiness`：NOT_REQUIRED、READY、SOURCE_UNRESOLVED、NOT_CONFIGURED、CAPABILITY_UNKNOWN、CAPABILITY_UNSUPPORTED、PERMISSION_DENIED、CONNECTOR_UNAVAILABLE；它描述提交前条件，不是外部回执。`OutboxDeliveryStatus`：READY、LEASED、WAITING_RETRY、DELIVERED、PAUSED、DEAD_LETTER，描述本地投递队列，不冒充外部事实。`WritebackStatus` 只有 PENDING、SENDING、ACCEPTED、CONFIRMED、PARTIAL、FAILED、CONFLICT、UNKNOWN，仅在已创建写回命令时取值，未要求或尚被 readiness 阻塞时为 null。`ConfirmationEvidence`：adapter_acknowledged、status_queried、readback_verified、manual_confirmed。CONFIRMED 只表示 Adapter 按已验证契约判为终态成功，并须展示证据等级；Mock P0 要求 readback_verified，live 无法回读时须明示较弱证据。**UI/统计不得把弱证据与 Mock readback_verified 显示为同级“绿色成功”**：至少区分 `evidence_tier`（strong=readback_verified，medium=status_queried，weak=adapter_acknowledged/manual_confirmed）。业务义务、提交准备度、本地投递、动作成功与外部写回事实相互正交。
17. `ConnectorStatus`：ONLINE、DEGRADED、OFFLINE、UNKNOWN；`CapabilityState`：UNKNOWN、SUPPORTED、UNSUPPORTED；`ConnectorCapability` 至少包含 LOG_INGESTION、QUERY、EVENT_DISPOSITION、ENTITY_RESPONSE，并为每项记录 CapabilityState。连接在线不等于具备写回权限。
18. `DispositionIntentKind` 是 ShadowTrace 内部信封分类，不是深信服公开枚举：ENTITY_ACTION_SUBMIT、EXECUTION_RESULT_RECORD、COMPENSATION_RECORD、EVENT_STATUS_UPDATE。`TargetExecutionStatus`：SUCCESS、FAILED、UNKNOWN、SKIPPED；`TargetWritebackStatus`：PENDING、ACCEPTED、CONFIRMED、FAILED、CONFLICT、UNKNOWN。`TERMINAL_SOURCE_DISPOSITIONS={contained, completed, suspended, ignored}`；pending、processing、unknown 绝不能满足终态事件处置门禁。整体 PARTIAL 由逐目标状态聚合，不作为单目标值。真实 Adapter 仅可映射正式接口已确认支持的 intent/operation；所有 live capability 默认 UNKNOWN。`DIRECT_TOOL` 只能使用 EXECUTION_RESULT_RECORD，严禁使用 ENTITY_ACTION_SUBMIT；EVENT_STATUS_UPDATE 由 deferred XDR_MANAGED Action 统一提交。对 required 事件，ENTITY_ACTION_SUBMIT/EXECUTION_RESULT_RECORD 是逐 Action 同步，不能替代唯一终态 EVENT_STATUS_UPDATE。
19. `ExecutionOwner`：XDR_MANAGED、DIRECT_TOOL。XDR_MANAGED 表示外部提交由 DispositionAdapter 负责：普通实体动作映射 ENTITY_ACTION_SUBMIT，唯一 deferred update_source_event_disposition 映射 EVENT_STATUS_UPDATE；DIRECT_TOOL 表示 ToolProvider 执行实体动作、DispositionAdapter 仅同步 EXECUTION_RESULT_RECORD。只有会产生外部副作用/处置的 response、rollback Action 必须且只能选择一个，system、verification Action 的 execution_owner 必须为 null。`ExecutionSubstate`：NONE、WAITING_APPROVAL、WAITING_EXECUTION、WAITING_WRITEBACK、MANUAL_RESOLUTION，只用于可恢复检查点，不替代 EventStatus。

### 4.7 ID 与键格式

1. `event_id`：`evt-{YYYYMMDD}-{8位十六进制}`，创建时由首个稳定来源五元组的规范化字符串 SHA256 前 8 位生成；纯文件告警才退化为内容哈希。event_id 创建后永不重算。只有 Mock 契约或 live Adapter 明确提供且验证了 Alert→Incident 关联时，后到 Incident 才通过 source_event_link 解析、promotion 或去重；没有显式关系时不得靠名称、时间或截图推断父子关系。不同连接器同名 ID 不得碰撞。
2. `evidence_id=evd-{8hex}`、`action_id=act-{8hex}`、`job_id=job-{8hex}`、`disposition_id=disp-{8hex}`、`writeback_id=wbk-{8hex}`、`trace_id=trc-{8hex}`、`report_id=rpt-{8hex}`（**同一 event_id 的报告 ID 稳定派生**：`rpt-` + SHA256(event_id)[:8]，保证幂等 upsert；禁止每次调用随机 new_report_id）、`call_id=call-{8hex}`、`case_id=case-{8hex}`；外部处置 job/record ID 原样存入回执。
3. Redis 键在既有键上增加 `shadowtrace:writeback:{writeback_id}`；PostgreSQL outbox 才是写回事实来源，Redis 仅缓存。
4. Pub/Sub 频道 shadowtrace:events:{event_id} 承载全部 16 种消息；Socket 网关按 event_id 路由并脱敏。
5. 核心环境变量在既有项上增加：`DISPOSITION_MODE`（mock_xdr、live、disabled）、`DISPOSITION_ADAPTER_KIND`、`DISPOSITION_BASE_URL`、`DISPOSITION_CREDENTIAL_REF`、`ALLOW_XDR_WRITEBACK`、`WRITEBACK_FIELD_ALLOWLIST`、`WRITEBACK_MAX_RETRIES`、`SIMULATION_ENABLED`。`SOURCE_READ_ONLY` 固定 true 只约束 SourceAdapter，不约束独立 DispositionAdapter；生产配置若启用 simulation 或 mock provider 必须启动失败。

### 4.8 工作流常量（全局唯一定义，位于 backend/app/models/workflow.py）

1. `MAX_REPLAN_COUNT = 3`（单事件最多 3 轮重规划）
2. `MAX_AGENT_RETRIES = 2`（单 Agent 最多重试 2 次）
3. `MIN_EVIDENCE_SOURCES = 3`（至少 3 个数据源成功才可正常研判）
4. `CONFIDENCE_THRESHOLD = 0.7`（置信度达标阈值）
5. `GLOBAL_EVIDENCE_TIMEOUT_S = 30.0`（证据采集全局超时）
6. `SINGLE_SOURCE_TIMEOUT_S = 10.0`（单数据源超时）
7. `APPROVAL_TIMEOUT_MINUTES = 30`（人工审批超时，可被环境变量覆盖）
8. `FP_HIGH_THRESHOLD = 0.9`、`FP_LOW_THRESHOLD = 0.7`（误报匹配高低阈值）
9. `WRITEBACK_SUBMIT_TIMEOUT_S = 10`、`WRITEBACK_CONFIRM_TIMEOUT_S = 120`、`WRITEBACK_MAX_RETRIES = 5`；重试采用带抖动指数退避，状态查询优先于重发。

### 4.9 结构化错误分类

1. 全系统统一异常基类 `ShadowTraceError`，字段 `error_code`、`category`（`ErrorCategory`）、`retryable`、`message`、`details`，方法 `to_response()` 输出 `error_code`、`error_message`、`details`。
2. 异常子类与默认分类固定：`ValidationError`(user_input)、`InvalidStateTransitionError`(permanent)、`InvalidVerdictStatusCombinationError`(permanent)、`ToolExecutionError`(tool)、`LLMError`(llm)、`BudgetExceededError`(budget)、`GuardrailViolationError`(guardrail)、`DependencyUnavailableError`(transient)、`InternalError`(system)。ISSUE-004 与 ISSUE-007 中的 `EventNotFoundError`、`InvalidStateTransitionError`、`InvalidVerdictStatusCombinationError`、`ApprovalRequiredError` 均为 `ShadowTraceError` 子类。
3. 全部 `error_code` 登记于 `ERROR_CODE_REGISTRY`（位于 `backend/app/core/errors.py`），命名为 snake_case 名词短语；新增错误码必须登记并归类。
4. 可重试性：transient 与部分 llm、tool 错误可重试；permanent、user_input、guardrail 不可重试。`ToolExecutor` 与 LLM 重试只对 `is_retryable` 为真的错误生效。

### 4.10 预算与成本

1. 预算与价格常量位于 `backend/app/models/workflow.py`：`GLOBAL_TOKEN_BUDGET`、`EVENT_TOKEN_BUDGET`、`EVENT_COST_BUDGET_USD`、`PER_AGENT_TOKEN_CAP`、`MODEL_PRICE_TABLE`（每千 token 单价，mock 模型为 0）。
2. 预算作用域枚举 `BudgetScope`：system、event、agent。预算用量以 `BudgetUsage` 写入 `EventContext.budget_usage`。
3. 环境变量：`BUDGET_ENABLED`（默认 true）、`GLOBAL_TOKEN_BUDGET`、`EVENT_TOKEN_BUDGET`、`EVENT_COST_BUDGET_USD`、`PER_AGENT_TOKEN_CAP`、`QUALITY_JUDGE_ENABLED`、`GUARDRAIL_MODE`（enforce、warn_only）、`WM_STRICT`。
4. 超预算抛 `BudgetExceededError`，由编排层生成“预算耗尽”报告；若没有 required 处置可按策略结案，若仍有未完成处置/写回则保持未闭环并转人工，不直接伪造 FAILED 或 SUCCESS。

### 4.11 工作记忆与字段归属

1. `EventContext` 每个产物字段有唯一 writer Agent，记录于 `FIELD_OWNERSHIP`（位于 `backend/app/services/working_memory.py`）；非 owner 写入被拒并抛 `GuardrailViolationError(error_code="working_memory_unauthorized_write")`。
2. `disposition_commands`、`disposition_receipts`、`writeback_summary` 仅由受信的 DispositionSyncService writer identity 写入，不接受调用方自报 `system`；Agent 只能提出候选处置，不能自行构造或发送 XDR 写回请求。`EventDispositionService`（ISSUE-059A）负责在效果验证后激活已有 deferred `update_source_event_disposition` Action、推导终态处置值，并委托 DispositionSyncService 提交 `EVENT_STATUS_UPDATE`；它不另建 Action，也不直接写 outbox。
3. 草稿区 `scratchpad`（追加型，上限 200 条 FIFO）镜像到 `EventContext.scratchpad`，工作记忆键为 `shadowtrace:wm:{event_id}`。
4. 所有产物字段读写统一经 `WorkingMemory`（建立在 `EventContextStore` 乐观锁之上），读写均留 `MemoryAccessLog`。

### 4.12 收敛与护栏常量

1. 收敛常量位于 `backend/app/models/workflow.py`：`GLOBAL_MAX_STEPS = 80`、`MAX_OSCILLATION = 2`、`MAX_DUPLICATE_TOOL_CALLS = 3`、`MAX_TOTAL_LLM_CALLS = 30`。GLOBAL_MAX_STEPS 同时覆盖 agent/tool/llm/replan 计步，必须高于单计划最大外部调用数并预留 Agent 状态步数。
2. `ConvergenceGuard` 跨 ReAct 轮次、重规划、Agent 重试统一计步，命中任一上限即强制收敛；收敛状态写 `EventContext.convergence_state`。
3. 收敛护栏与既有 `MAX_REPLAN_COUNT`、`MAX_AGENT_RETRIES`、ReAct `max_rounds` 共同作用，互为兜底。

### 4.13 输出 Guard Rails 与评估命名

1. 输出护栏维度 `GuardRailDimension`：schema、grounding、policy、sanitization；违规以 `GuardViolation`（`dimension`、`rule_name`、`severity`（block、warn）、`detail`）表示，block 级写 `EventContext.guard_violations`。
2. 输出质量评分 `OutputQualityScore`（`agent_name`、`score`、`verdict`（`QualityVerdict`）、`metrics`、`reasons`、`evaluated_by`）写 `EventContext.quality_scores`；规则指标名固定为 completeness、grounding_ratio、consistency、specificity。
3. 轨迹指标 `TrajectoryMetric` 名固定：redundant_tool_calls、loop_suspected、replan_effectiveness、avg_agent_latency_ms、evidence_yield、steps_to_verdict。
