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
3. `MIN_EVIDENCE_SOURCES = 3`（EvidenceAgent `collection_status` 的 PARTIAL_DONE 下限：parser-success 源 ≥3；`completed` 阈值为 5；CLOSED 门禁不看源数）
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

# Issues

### ISSUE-001：Monorepo 项目骨架与 Docker Compose 基础环境

优先级：
P0

目标：
建立 monorepo 仓库骨架、后端 FastAPI 最小应用、前端占位工程和 Docker Compose 本地环境。完成后开发者可一条命令拉起 PostgreSQL（含 pgvector）、Redis 和后端服务，并通过健康检查接口确认环境可用。

前置依赖：
无

输入上下文：
简介第 4.1 节目录约定、第 4.2 节 API 前缀约定、第 4.7 节环境变量名。技术栈固定：Python 3.11 + FastAPI + SQLAlchemy 2.0（异步）+ Pydantic v2 + pytest；Node 20 + React 18 + TypeScript + Vite。

文件范围：
1. `README.md`、`Makefile`、`.gitignore`、`.env.example`
2. `backend/pyproject.toml`、`backend/Dockerfile`、`backend/app/main.py`、`backend/app/core/config.py`、`backend/app/api/v1/__init__.py`、`backend/app/api/v1/health.py`
3. `frontend/package.json`、`frontend/Dockerfile`、`frontend/src/main.tsx`（占位页面）
4. `infra/docker-compose.yml`、`infra/docker-compose.dev.yml`
5. `backend/tests/test_infra/test_health.py`

统一命名：
1. FastAPI 应用实例名 `app`；配置类 `Settings`（pydantic-settings），通过 `get_settings()` 注入
2. Compose 服务名：`postgres`、`redis`、`backend`、`frontend`
3. 健康检查端点 `GET /api/v1/health`，响应字段 `status`、`postgres`、`redis`、`source_adapter`、`disposition_adapter`、`tool_provider`、`simulation_enabled`、`version`；三个组件字段含 status、mode 与 capability 摘要，绝不含凭证。
4. 环境变量：`DATABASE_URL`、`REDIS_URL`（默认指向 Compose 服务名）

实现步骤：
1. 创建目录骨架：`backend/`、`frontend/`、`contracts/`、`infra/`、`scripts/`、`data/`、`docs/`，并提交 `.gitkeep` 占位。
2. 初始化后端：pyproject.toml 声明 fastapi、uvicorn、sqlalchemy[asyncio]、asyncpg、redis、pydantic、pydantic-settings、alembic、pytest、pytest-asyncio、httpx、ruff、mypy。
3. 实现 `app/main.py` 创建 FastAPI 实例并挂载 `/api/v1` 路由；实现 `health.py`：检查 PostgreSQL（SELECT 1）与 Redis（PING）连通性。
4. 编写 `infra/docker-compose.yml`：postgres 使用 pgvector 官方镜像（pgvector/pgvector:pg16），redis 使用 redis:7，均配置 healthcheck；backend 依赖二者健康后启动。
5. 初始化前端 Vite + React + TypeScript 工程，仅保留一个显示 "ShadowTrace" 的占位页面。
6. 编写 Makefile 目标：`make up`、`make down`、`make test`、`make lint`、`make fmt`。
7. 编写 `.env.example` 列出第 4.7 节全部核心环境变量及默认值。

验收标准：
1. `docker compose -f infra/docker-compose.yml up -d` 后所有容器 healthy。
2. `curl http://localhost:8000/api/v1/health` 返回 200，`status` 为 "ok"，postgres、redis 均为 "ok"。
3. `make lint` 通过（ruff + mypy 零报错）。
4. `psql` 中 `CREATE EXTENSION IF NOT EXISTS vector` 执行成功。
5. 前端 `pnpm dev` 可启动并渲染占位页面。

测试与验证：
运行 `cd backend && pytest tests/test_infra/test_health.py -v`：用 httpx.AsyncClient 调用 health 端点，断言 200 与字段完整。手工验证 Compose 启动与 Makefile 命令。

降级策略：
无

---

### ISSUE-002：核心数据模型定义（SecurityEvent 与配套模型）

优先级：
P0

目标：
用 Pydantic v2 定义系统全部核心数据模型并导出 JSON Schema 到 contracts 目录，建立字段契约基线。本 Issue 预声明各模型的完整字段集（含后续阶段写入的字段）；后续 Issue 遵循加性演进：可回到本 Issue 增补字段并重新导出 Schema，但不得改名、改义或删除既有字段。

前置依赖：
ISSUE-001

输入上下文：
简介第 4.3 节模型主名、第 4.6 节枚举、第 4.7 节 ID 格式。Mock 数据、适配器、Agent、API 全部消费这些模型。

文件范围：
1. `backend/app/models/enums.py`：全部枚举
2. `backend/app/models/entities.py`：EntitySet 与六类实体
3. `backend/app/models/security_event.py`：SecurityEvent
4. `backend/app/models/source.py`：SourceIncident、SourceAlert、SourceAsset、SourceLog、SourceConnector、SourceReference
5. `backend/app/models/execution.py`：ActionExecutionJob、TargetExecutionResult、ExecutionSummary
6. `backend/app/models/disposition.py`：SourceObjectLocator、DispositionCommand、强类型 OperationParams、TargetDispositionResult、TargetWritebackResult、DispositionReceipt、DispositionOutboxRecord、WritebackSummary
7. `backend/app/models/evidence.py`：Evidence、EvidenceConflict、EvidenceGap
8. `backend/app/models/action.py`：Action、ImpactAssessment
9. `backend/app/models/report.py`：InvestigationReport
10. `backend/app/models/context.py`：EventContext
11. `backend/app/models/ids.py`：ID 生成函数
12. `scripts/export_schemas.py`、`contracts/schemas/`（导出产物）
13. `backend/tests/test_models/`：核心模型、来源对象、执行任务、写回信封与枚举测试

统一命名：
1. `enums.py` 必须覆盖本简介全部枚举：`EventStatus`、`FinalVerdict`、`CaseLabel`、`AgentStatus`、`SuperAgentStatus`、`ActionStatus`、`ActionCategory`、`ActionExecutionPhase`、`Severity`、`ActionLevel`、`EvidenceSource`、`ToolCategory`、`EventType`、`SourceObjectKind`、`SourceDisposition`、`DispositionPolicy`、`ExecutionJobStatus`、`WritebackReadiness`、`OutboxDeliveryStatus`、`WritebackStatus`、`ConfirmationEvidence`、`TargetExecutionStatus`、`TargetWritebackStatus`、`ExecutionOwner`、`ExecutionSubstate`、`DispositionIntentKind`、`ConnectorStatus`、`CapabilityState`、`ConnectorCapability`、`ErrorCategory`、`GuardRailDimension`、`BudgetScope`、`QualityVerdict`。测试比较声明集合与导出集合，防止新增枚举后清单漂移。
2. `SecurityEvent` 字段：event_id、event_type、title、description、status、severity、risk_score、confidence、final_verdict、entities、`creation_source_ref`（永不修改的首个 SourceReference 快照）、`source_reference_snapshots`（append-only，既有元素不改）、`current_primary_source_record_id`（可随 promotion 指向当前 source_object）、`disposition_source_ref`（当前可空 SourceObjectLocator，只能选一个；Action 生成时再冻结）、disposition_policy、raw_alert_ids、raw_alert_snapshot（仅 file fallback）、source_type、occurred_at、created_at、updated_at、closed_at、replan_count、degraded_flags、escalated、external_unsynced、event_context_snapshot、row_version（从 1 起的乐观锁版本）。来源选择、政策、状态、verdict 与其他可变事件字段每次成功更新均在同一事务 row_version+1；外部对象 ID/状态不得写入内部 event_id/status。
3. `SourceReference` 字段严格采用简介第 4.3 节命名并包含 connector_id 与可空、不透明的 `source_concurrency_token`；唯一身份五元组固定为 `(source_product, source_tenant_id, connector_id, source_kind, source_object_id)`，可空 adapter-native source_object_type 与令牌均不参与身份。`source_object` 另存 `current_source_status_raw`、`current_source_disposition`、`current_concurrency_token` 与 `source_sync_state`，禁止回写覆盖调查快照。
4. `SourceIncident`、`SourceAlert`、`SourceAsset`、`SourceLog` 均含 `reference`、`raw_payload`、`normalized`；Incident 可额外含标题、等级、GPT 研判标签、影响资产引用、关联 alert 引用；Alert 可额外含 incident 引用、XFF/source IP、日志/子告警引用；Asset 可额外含数值资产 ID、IP、主机名、资产名、资产组、责任人、业务系统、重要性、Agent 状态、首次/最近发现时间；Log 可额外含设备来源、时间、源/目的网络字段与分类。上述关联是 ShadowTrace 规范化模型的可空字段：Mock 可完整提供，live 只填 Adapter 明确取得的关系；字段缺失时保留 null，不根据截图、时间邻近或名称臆造。
5. `SourceConnector` 字段：connector_id、source_product、display_name、device_type、status、read_endpoint、disposition_endpoint（可空）、capabilities、disposition_policy_default、last_sync_at、schema_version、read_credential_ref、disposition_credential_ref（可空）、metadata。秘密只存引用；截图字段不直接当作既定认证协议。
6. `Evidence` 字段：`evidence_id`、`event_id`、`source`（EvidenceSource）、`evidence_type`、`description`、`confidence`、`timestamp`、`related_entities`、`source_ref`（可空）、`raw_data`、`mitre_technique`、`is_conflicting`。
7. `Action` 字段：action_id、event_id、plan_revision、action_fingerprint、action_category（system、response、verification、rollback）、action_name、tool_name、action_level、execution_phase、activation_condition（可空）、approved_operation_template_hash（可空）、approved_terminal_dispositions（list[SourceDisposition]）、target_type、target、parameters、status、auto_execute、reason、impact_assessment、playbook_id、provider_name、execution_owner（可空）、execution_job_id、tool_call_id、idempotency_key、writeback_required、writeback_applicable、writeback_readiness、writeback_block_reason（可空）、writeback_status（可空，由一对多写回记录派生）、disposition_source_ref（可空；一旦批准即冻结）、superseded_by_revision（可空）、executed_at、effect_verification_status、rollback_status、source_action_id、updated_at。writeback_required 是事件政策快照；writeback_applicable 表示该候选动作是否已被批准/选中而成为闭环分母：APPROVED 或任何已开始执行的 required Action 为 true，REJECTED 和从未批准的 SUPERSEDED 候选为 false，已执行后不能再改回 false。SOURCE_UNRESOLVED 候选允许 locator=null，但不得批准/dispatch；选择来源后必须新 revision/new Action 并 supersede 旧候选，禁止原地补 locator。update_source_event_disposition 固定 execution_phase=POST_VERIFY、activation_condition=after_effect_resolution，审批时展示允许的受控 SourceDisposition 集合并冻结 template hash；实际值必须属于获批集合且 hash/来源/operation 未变，否则开启新 approval_cycle。其他动作固定 IMMEDIATE。未要求时 applicable=false、readiness=NOT_REQUIRED、status=null；required 但不适用时仅保留政策预览，不要求 receipt；required+applicable 但尚未 READY/未创建命令时 status=null，不能伪造 UNSUPPORTED 状态；已有 required intents 时，全部 CONFIRMED 才 CONFIRMED，任一 CONFLICT→CONFLICT，任一 UNKNOWN→UNKNOWN，确认与失败并存→PARTIAL，全部终态失败→FAILED，其余按 SENDING、ACCEPTED、PENDING 的最高进行态展示。system/query/verification 固定 writeback_required=false、writeback_applicable=false 且 execution_owner=null；产生外部副作用/处置的 response、rollback 才必须二选一 owner。response 只按事件业务政策推导 required，再单独计算 readiness；rollback 按补偿同步政策推导 required。内部 parameters 可供 Agent 使用，但禁止原样进入出站信封。
8. `ActionExecutionJob` 同时是 direct_tool 的预持久化 dispatch intent，字段：`job_id`、`event_id`、`action_id`、`provider_name`、稳定 `idempotency_key`、`provider_job_id`（可空）、`status`、`claimed_by`、`lease_expires_at`、各时间、poll_after_ms、attempt、target_results、provider_code/message、raw_result。`ActionExecutionService` 路径先事务提交 RUNNING job（带 lease）；崩溃恢复通过 lease reclaim（ISSUE-173）+ 幂等键，不能用“本地无结果”推断“外部未执行”。独立的 ToolProvider→ToolResult 通道可将 ACCEPTED 映射为 QUEUED（见 `tools/adapters/base.py`），此为另一通道，不走 `ActionExecutionService`。`TargetExecutionResult.status` 只用 TargetExecutionStatus，并保留逐目标代码、消息、artifact_id 和脱敏 raw_result。
9. `SourceObjectLocator` 只含 source_product、source_tenant_id、connector_id、source_kind、可空 source_object_type、source_object_id。`DispositionCommand` 字段固定为 `disposition_id`、`action_id`（必填；EVENT_STATUS_UPDATE 也必须绑定获批 deferred Action）、`closure_cycle`（plan_revision）、`intent_kind`、`source_locator`、`operation_code`、`operation_params`、`target_results`、`operator_id`、`idempotency_key`、`source_concurrency_token`、`execution_owner`、`parent_disposition_id`、`supersedes_disposition_id`（可空）；operation_params 为按 operation_code 判别的强类型联合且 `extra="forbid"`。每个 intent 的 idempotency_key 都从稳定 action/event 基键、closure_cycle、intent_kind、operation_code、source_locator_hash、parent/supersedes ID 与确定性 intent_index 派生，不能直接复用 Action 的执行幂等键。出站 `TargetDispositionResult.status` 只用 TargetExecutionStatus，且对象只含 canonical_target、status、可空 allowlisted provider_code/message_code/artifact_ref，不允许自由 message/raw_result。Factory 必须从标准实体和受控执行结果重建命令，绝不复制 Action.parameters/reason、报告、Prompt、证据原文或 Provider raw_result。
10. `TargetWritebackResult` 与出站 TargetDispositionResult 分开：只含 canonical_target、TargetWritebackStatus、可空 provider_code/message_code/artifact_ref，不含自由 message/raw。`DispositionReceipt` 字段固定为 `writeback_id`、`sequence`、`disposition_id`、`action_id`、`source_record_id`、`status`、`confirmation_evidence`（可空）、`provider_record_id`（可空）、`provider_job_id`（可空）、`provider_code`（可空）、`provider_message`（可空）、`observed_at`、`submitted_at`、`confirmed_at`（可空）、`target_results`（list[TargetWritebackResult]）、`raw_result`、`truncated`、`simulated`。只有 status=CONFIRMED 时 confirmation_evidence 必填；未收到任何确认事实的 UNKNOWN 可为 null，Mock CONFIRMED 强制 readback_verified。不另设 receipt_id；receipt 以 `(writeback_id, sequence)` 追加保存，当前态取最大 sequence。一个 Action 可关联多条 DispositionCommand/DispositionOutboxRecord，每个 intent 独立拥有 disposition_id、writeback_id、idempotency_key 与状态，每个 writeback 又有多条状态 receipt；Action.writeback_status 仅为派生聚合值。raw_result 入库前必须递归脱敏、限长，绝不保存认证头、token、cookie 或密码。
11. `DispositionOutboxRecord` 字段固定为 outbox_id、writeback_id、disposition_id、action_id、event_id、closure_cycle、source_record_id、source_locator_hash、source_sequence、intent_kind、logical_slot、supersedes_disposition_id（可空）、superseded_by_disposition_id（可空）、idempotency_key、command_payload、command_payload_sha256、delivery_status（OutboxDeliveryStatus）、latest_writeback_status（可空）、attempt、next_retry_at、locked_by、locked_at、lease_expires_at、last_error_code、last_error_detail、created_at、updated_at、delivered_at（可空）。command_payload 创建后不可变；同一来源按 source_sequence 串行投递，过期租约回收后先查外部状态；superseding 只更新 lineage metadata，不改旧 payload/receipt。
12. `WritebackSummary` 字段固定为 event_id、closure_cycle、disposition_policy、required_action_count、applicable_action_count、blocked_action_ids、readiness_counts、aggregate_readiness、writeback_counts、aggregate_status（可空）、terminal_event_action_id（可空）、terminal_event_writeback_id（可空）、terminal_event_disposition、terminal_event_confirmed、external_unsynced、updated_at。只统计所有历史已执行的 applicable required Action 加当前 revision deferred Action；readiness 主阻塞优先级固定 PERMISSION_DENIED→SOURCE_UNRESOLVED→NOT_CONFIGURED→CAPABILITY_UNSUPPORTED→CAPABILITY_UNKNOWN→CONNECTOR_UNAVAILABLE→READY，完整 counts 同时返回。disposition_policy=not_required 时 aggregate_readiness=NOT_REQUIRED；required 但 Action 尚未物化/计数为空时，先用事件级 source/config/capability/health 计算阻塞值，绝不能空集合推导 READY；无实际命令时 aggregate_status=null。`ExecutionSummary` 字段固定为 event_id、plan_revision、action_counts、jobs、actions（每项含 action_id、action_status、execution_phase、writeback_required、writeback_applicable、writeback_readiness、writeback_status、target_results）、writeback_summary、updated_at。API、Verify、UI、CLOSED gate 和 stats 必须复用同一汇总服务，不得各自重算。
13. `EventContext` 字段全集固定为：`event`、`source_snapshot`、`source_sync_state`、`triage_result`、`false_positive_match`、`evidence_output`、`storyline`、`graph_output`、`rag_output`、`risk_assessment`、`execution_plan`、`response_plan`、`approval_records`、`disposition_only_intent`、`execution_substate`、`execution_summary`、`execution_jobs`、`verification_result`、`rollback_results`、`impact_assessments`、`report`、`memory_output`、`disposition_commands`、`disposition_receipts`、`writeback_summary`、`state_history`、`replan_count`、`budget_usage`、`guard_violations`、`convergence_state`、`quality_scores`、`scratchpad`、`degraded_flags`。`disposition_only_intent` 是受信工作流服务在 Action 生成前设置的布尔意图，不接受 API/LLM 自报。Schema 与 FIELD_OWNERSHIP 测试必须双向断言无遗漏；来源、内部编排、动作效果、外部写回四类状态分开。
14. ID 函数：new_event_id、new_evidence_id、new_action_id、new_job_id、new_disposition_id、new_writeback_id、new_trace_id、`report_id_for_event(event_id)`（稳定派生，见简介 4.7）、new_call_id、new_case_id。`new_report_id()` 若保留仅作别名且必须接收 event_id，禁止无参随机。

实现步骤：
1. 在 `enums.py` 中实现简介第 4.6 节全部枚举，值为小写 snake_case 字符串（EventStatus 用大写常量、小写字符串值，如 `NEW = "new"`）。
2. 实现六类实体模型，公共基类增加 `source_refs`；`EntitySet` 含 accounts、hosts、ips、domains、processes、files。网络实体在 `attributes.scope` 区分 external/internal，避免仅凭私网地址启发式覆盖来源事实。
3. 实现来源、连接器、执行任务和处置写回模型；DispositionCommand 使用字段 allowlist 与 `extra="forbid"`，增加序列化测试证明禁止字段无法进入出站 JSON。
4. 实现 EventSummary、SecurityEvent、Evidence、Action、InvestigationReport、EventContext，全部 `extra="forbid"`。
5. 实现 `ids.py`：内部事件 ID 由来源身份与发生日期哈希生成；同一外部对象重复传输必须幂等，不同租户同名 ID 不得碰撞。其余内部 ID 用带类型前缀的随机 ID。
6. 实现 `scripts/export_schemas.py`：遍历上述模型调用 `model_json_schema()` 写入 `contracts/schemas/{model_name}.json`。
7. 编写模型单元测试：除既有场景外，覆盖“业务 required 在 capability UNKNOWN/UNSUPPORTED 时仍保持 required，但 readiness 被阻塞”、manual 来源政策为 not_required、XDR_MANAGED/DIRECT_TOOL 互斥、出站字段白名单、写回部分成功和不透明并发令牌冲突。

验收标准：
1. 全部模型可导入且 `pytest backend/tests/test_models/ -v` 通过。
2. `python scripts/export_schemas.py` 为本 Issue 声明的全部模型生成 Schema；测试比较模型集合与文件集合，不使用易过期的固定数量。
3. `new_event_id` 对相同输入幂等，对不同输入产生不同 ID，格式符合 `evt-{YYYYMMDD}-{8hex}`。
4. EventStatus 14 个值、FinalVerdict 4 个值、CaseLabel 3 个值、ActionStatus 11 个值，以及本 Issue 声明的其余枚举均有快照/集合测试。
5. SecurityEvent 拒绝未知字段（extra="forbid" 生效）。

测试与验证：
运行 `cd backend && pytest tests/test_models/ -v`，全部通过且覆盖每个模型至少 1 个正例与 1 个反例。

降级策略：
无

---

### ISSUE-003：PostgreSQL Schema 与 Alembic 迁移

优先级：
P0

目标：
定义核心数据表与迁移，除事件、来源和动作外，显式保存可靠写回 outbox 与 XDR 回执。内部研判、动作执行和外部处置写回必须分别审计。

前置依赖：
ISSUE-001、ISSUE-002

输入上下文：
ISSUE-002 的模型字段即表字段口径；JSON 容器字段一律用 JSONB；pgvector 扩展已在 ISSUE-001 启用（向量表由 RAG 阶段 Issue 各自迁移添加）。

文件范围：
1. `backend/app/db/base.py`：`Base` 声明与命名约定
2. `backend/app/db/models.py`：全部 ORM 模型
3. `backend/app/db/session.py`：异步引擎与 `get_session()` 依赖
4. `backend/alembic.ini`、`backend/migrations/env.py`、`backend/migrations/versions/0001_initial_schema.py`
5. `backend/tests/test_db/test_migrations.py`

统一命名：
1. 18 张核心表：`security_event`、`source_object`、`source_event_link`、`source_connector`、`evidence`、`action`、`action_execution_job`、`action_target_result`、`disposition_outbox`、`disposition_receipt`、`report`、`agent_trace`、`event_audit_log`、`tool_call_log`、`llm_call_log`、`data_quality_error`、`event_context_journal`、`event_context_field_version`。
2. source_object 保存 SourceReference 全字段、normalized 与 raw_payload；source_connector 保存读写端点、分离的 credential refs、能力和水位；秘密本体不入库。
3. `action_execution_job` 与 `action_target_result` 保留 Provider 原始结果。
4. `source_event_link` 保存来源对象与内部事件的关联、角色（primary/related/provisional）和 promotion 状态；action 对 action_fingerprint 建唯一约束。source_object 保存 `next_outbox_sequence`，在行锁下 `UPDATE ... RETURNING` 分配；disposition_outbox 唯一约束 idempotency_key 与 `(source_record_id, source_sequence)`，保存 ISSUE-002 的完整不可变 command_payload、payload hash、delivery status、source sequence、重试与可回收租约。EVENT_STATUS_UPDATE 以 `(action_id, closure_cycle, intent_kind, logical_slot)` 建“active head（superseded_by_disposition_id IS NULL）”部分唯一约束：CONFLICT/token 刷新可在同 logical lineage 保留历史 physical command，但事务必须先把旧 head 标记 superseded 再插入新 head，最终只允许一个 confirmed active head。Worker 只有在同来源前序记录 DELIVERED、明确不可继续的终态经人工释放，或不存在前序时才能领取下一条。disposition_receipt 以 `(writeback_id, sequence)` 唯一并关联 action/source_object，保留轮询和回读历史。Outbox 写入与 Action 状态更新在同一事务，外部 HTTP 必须在提交后执行。
5. `agent_trace` 字段：`trace_id`（主键）、`event_id`、`agent_name`、`input_data`（JSONB）、`output_data`（JSONB）、`status`、`started_at`、`completed_at`、`duration_ms`、`error_detail`、`llm_model`、`llm_tokens_used`
6. `event_audit_log` 字段：`id`、`event_id`、`from_status`、`to_status`、`operator`、`reason`、`created_at`
7. `tool_call_log` 字段：`call_id`（主键）、`event_id`、`action_id`（可空，查询类工具调用无 action_id）、`tool_name`、`tool_category`、`parameters`（JSONB）、`result`（JSONB）、`status`、`started_at`、`completed_at`、`duration_ms`、`retry_count`、`error_detail`
8. `llm_call_log` 字段：`id`、`event_id`、`agent_name`、`model_name`、`prompt_tokens`、`completion_tokens`、`total_tokens`、`latency_ms`、`fallback_level`、`created_at`
9. `event_context_journal` 字段：`id`（主键，自增）、`event_id`、`field_name`、`value`、`version`、`created_at`；唯一约束 `(event_id, field_name, version)`。
10. `event_context_field_version` 字段：`event_id`、`field_name`、`current_version`；主键 `(event_id, field_name)`；是所有上下文字段版本的唯一分配源。

实现步骤：
1. 实现 `base.py` 与 `session.py`：`create_async_engine(DATABASE_URL)`，会话工厂 `async_session_factory`，FastAPI 依赖 `get_session()`。
2. 按统一命名实现 18 张核心表；为 outbox delivery_status/latest_writeback_status/next_retry_at/lease_expires_at/source_sequence、disposition_id、来源身份、job status、action_fingerprint 建索引；security_event.row_version 每次受控更新原子递增。
3. 初始化 Alembic（异步模板），生成迁移 `0001_initial_schema.py`，在迁移中执行 `CREATE EXTENSION IF NOT EXISTS vector`。
4. 在 Makefile 增加 `make migrate`（alembic upgrade head）和 `make migrate-down`。
5. 编写迁移测试：断言 18 张表、outbox 幂等/来源序列约束、EVENT_STATUS_UPDATE 单 active-head 部分约束与合法 superseding 事务、receipt `(writeback_id, sequence)` 唯一约束、Action fingerprint、source_event_link、Action/Source 外键、row_version CAS 及事务回滚行为。

验收标准：
1. `alembic upgrade head` 在全新数据库上执行成功，18 张核心表与索引创建完成。
2. `alembic downgrade base` 可完整回滚。
3. ORM 模型字段与 ISSUE-002 Pydantic 模型字段一一对应（名称与语义一致）。
4. `pytest backend/tests/test_db/ -v` 通过。

测试与验证：
`make migrate && cd backend && pytest tests/test_db/test_migrations.py -v`，使用 Compose 中的真实 PostgreSQL。

降级策略：
无

---

### ISSUE-004：REST API 契约定义与占位实现

优先级：
P0

目标：
按简介第 4.2 节核心端点定义请求与响应模型，提供返回静态示例数据的占位实现，并导出 OpenAPI 3.1 文件。完成后前后端可并行开发：核心端点路径与字段保持稳定，后续 Issue 可新增端点（遵循同一前缀、错误体与分页约定并同步导出 OpenAPI），但不得更改已定义端点的路径或字段语义。

前置依赖：
ISSUE-002

输入上下文：
ISSUE-002 的核心模型作为响应体内嵌结构；统一错误体与分页体字段见简介第 4.2 节。

文件范围：
1. `backend/app/api/v1/schemas.py`：API 层请求与响应模型
2. `backend/app/api/v1/events.py`、`source_records.py`、`connectors.py`、`execution_jobs.py`、`dispositions.py`、`actions.py`、`tools.py`、`knowledge.py`、`stats.py`
3. `backend/app/core/auth.py`：Principal、认证依赖与 RBAC；`backend/app/api/v1/errors.py`：异常类型与统一错误处理器
4. `scripts/export_openapi.py`、`contracts/openapi/openapi.json`
5. `backend/tests/test_api/test_contracts.py`、`test_authz.py`

统一命名：
1. `EventCloseRequest` 含 reason、可选 final_verdict/need_investigation、`force_local_close=false`；ActionApproveRequest/RejectRequest 只接受 comment 与 decision_id；`ResolveUnknownRequest` 与 `ResolveWritebackRequest` 只接受受限 resolution、comment、evidence_ref；`SelectDispositionSourceRequest` 只接受 source_record_id、expected_event_version、comment，`RecheckDispositionReadinessRequest` 只接受 expected_event_version。operator 必须由服务端认证主体生成。
2. 响应模型增加 `DispositionListResponse`、`DispositionResponse`、`WritebackResponse`；EventSummary/EventListItem 增加 `writeback_required`、派生 `writeback_readiness`、可空 `writeback_overall_status` 与 pending_writeback_count，明确 status 是本地 EventStatus。没有命令时 overall_status 必须为 null，由 readiness 区分 NOT_REQUIRED 与被阻塞；普通用户不可查看 raw_result，管理员也只能查看脱敏限长回执。
3. 列表查询参数：`page`（默认 1）、`page_size`（默认 20）、`status`、`severity`、`event_type`、`final_verdict`、`keyword`、`start_time`、`end_time`、`sort_by`、`sort_order`
4. 异常类：`EventNotFoundError`（404）、`InvalidStateTransitionError`（400）、`ApprovalRequiredError`（409）、`WritebackPendingError`（409）、`WritebackFailedError`（409）、`WritebackConflictError`（409）、`WritebackUnsupportedError`（422）、`DispositionPermissionDenied`（403）。readiness 非 READY 且无法通过请求本身修复时返回 writeback_unsupported，并在 details 给出枚举原因，不返回秘密配置。
5. `Principal` 字段：subject、display_name、roles；角色至少为 analyst、approver、disposition_operator、admin。approve/reject 需 approver，retry 需 disposition_operator，两个 resolve/force_local_close 需 admin。开发 Mock 可使用显式 DEV_AUTH_TOKEN 映射固定 Principal；生产默认拒绝 dev 身份。仅在可信代理开关和 allowlist 同时满足时接收身份头，客户端请求体永远不能指定 operator。

实现步骤：
1. 在 `schemas.py` 定义全部请求与响应模型，响应模型内嵌 ISSUE-002 模型。
2. connector 响应暴露能力与健康但绝不返回 credential ref/secret；Disposition API 只读取或受控重试 outbox，不允许绕过 ApprovalEngine 构造命令。`GET /source-records/{source_record_id}` 使用内部主键唯一定位来源对象。source 选择端点只允许从该事件已关联、可写且租户/connector 一致的 source_object 中选择；readiness recheck 只重算配置/权限/capability 并恢复既有检查点，不创建成功回执、不调用实体工具。Connector capability/config 变更后复用同一服务异步重扫受影响的 blocked 事件。
3. 实现统一异常处理器：捕获自定义异常映射为 `ErrorResponse`，未知异常映射为 500 加 `error_code="internal_error"`。
4. 实现 `scripts/export_openapi.py`：调用 `app.openapi()` 写入 `contracts/openapi/openapi.json`。
5. 编写契约测试：额外覆盖 DispositionCommand 禁止分析字段、来源对象类型限制、writeback retry 前置查证与幂等、action/writeback 两类 resolve 的状态 CAS 与权限、source 选择越权/跨租户拒绝、readiness recheck 幂等且不产生外呼、job partial_success 和 raw_result 脱敏。
6. 实现最小 AuthN/AuthZ 依赖并覆盖匿名、越权、伪造 operator、可信代理 allowlist 与生产禁用 DEV_AUTH_TOKEN；所有服务层审计使用 `Principal.subject`。

验收标准：
1. 简介第 4.2 节第 2 项核心端点列表的全部路径在 OpenAPI 文件中存在且方法正确（第 5 项扩展端点不在本 Issue 范围）。
2. 所有占位端点返回值通过对应响应模型校验。
3. 404 与 400 错误响应包含 `error_code`、`error_message`、`details` 三字段。
4. `python scripts/export_openapi.py` 产出合法 JSON（可被 `json.load` 解析且含 `openapi: 3.x`）。

测试与验证：
`cd backend && pytest tests/test_api/test_contracts.py -v`。

降级策略：
无

---

### ISSUE-005：Agent 输入输出 Schema 与 BaseAgent 基类

优先级：
P0

目标：
为 12 个 Agent 定义统一基类与各自的输入输出 Pydantic 模型，锁定 Agent 之间的数据传递契约。完成后任何 Agent 实现 Issue 不得新增或更名输入输出字段。

前置依赖：
ISSUE-002

输入上下文：
ISSUE-002 的核心模型与枚举；简介第 4.4 节 Agent 名称与第 4.3 节阶段输出模型主名。

文件范围：
1. `backend/app/agents/base.py`：`BaseAgent`、`AgentInput`、`AgentOutput`
2. `backend/app/models/agent_io.py`：全部阶段输入输出模型
3. `backend/tests/test_models/test_agent_schemas.py`

统一命名：
1. `BaseAgent` 接口：类属性 `agent_name: str`；基类模板方法 `async execute(self, input)`（统一计时、轨迹、护栏、预算与工作记忆包装），子类实现抽象方法 `async _run(self, input)` 返回对应输出模型；钩子 `pre_hooks`、`post_hooks`（list，默认空）；执行包装钩子 `_record_trace()`、`_apply_guardrails()`、`_check_budget()`，产物字段读写经 `WorkingMemory`（占位逻辑分别由 ISSUE-028、ISSUE-030、ISSUE-029、ISSUE-014 注入）
2. `TriageResult` 字段：`event_type`、`severity`、`need_investigation`、`entities`（EntitySet）、`ioc_list`、`reasoning`、`degraded`
3. `EvidenceOutput` 字段：`evidence_list`（list[Evidence]）、`conflicts`（list[EvidenceConflict]）、`gaps`（list[EvidenceGap]）、`success_sources`、`failed_sources`、`overall_confidence`、`collection_status`（completed、partial_done、degraded、failed 四值）
4. `AttackStoryline` 字段：`storyline_id`、`event_id`、`narrative_summary`、`phases`（list[StorylinePhase]）、`generated_by`（llm、rule 两值）；`StorylinePhase` 字段：`phase_order`、`phase_name`、`tactic`、`narrative`、`entries`（list[TimelineEntry]）；`TimelineEntry` 字段：`timestamp`、`description`、`evidence_id`、`technique_id`（可空）、`severity_hint`
5. `RAGOutput` 字段：`attack_techniques`（list，元素含 `technique_id`、`technique_name`、`tactics`（list，同一 technique 可属于多个 tactic）、`match_confidence`、`citation_id`）、`fp_similarity`（含 `max_score`、`matched_case_id`、`matched_pattern`）、`similar_cases`、`playbook_refs`、`citations`、`degraded`
6. `RiskAssessment` 字段：`risk_score`、`severity`、`confidence`、`risk_factors`（list[RiskFactor]：`factor_name`、`weight`、`raw_score`、`weighted_score`、`reasoning`）、`possible_false_positive`、`scoring_mode`（llm_and_rule、rule_only 两值）
7. `ResponsePlan` 字段：`plan_id`、`actions`（list[Action]，仅作为生成时快照；审批、执行、验证阶段须用各 action 的 `action_id` 回查 action 表获取最新状态，不依赖此处嵌入对象的 status 字段）、`strategy_summary`、`generated_by`（llm、template 两值）
8. `VerificationResult.results` 每项含 `action_id`、`effect_status`（verified、failed、skipped、unverifiable）、`writeback_required`、`writeback_readiness`、可空 `writeback_status`（仅八态）、`writeback_ids`、`verification_action_id`、`detail`；顶层含 `overall_status`、`failed_actions`、`failed_writebacks`、`blocked_writebacks`、`need_action_replan`、`need_writeback_recovery`、`need_manual_resolution`、`verification_phase`（effect、disposition 两值，表示最近完成的阶段）。writeback_required=false 时 readiness=NOT_REQUIRED、status=null 并视为满足；required 时只有 readiness=READY 且所有对应写回 CONFIRMED 才满足。未激活的 POST_VERIFY deferred Action 必须 effect_status=skipped（detail=`deferred_pending_activation`），不得进入 failed_actions。不得使用含混的 `need_replan`、用 not_required/unsupported 冒充回执状态，或使用未定义 `receipt_id`。
9. `MemoryOutput` 字段：`case_records`、`fp_rules`、`profile_updates`、`sigma_drafts`
10. `ExecutionPlan` 字段：`plan_id`、`event_id`、`steps`（list[PlanStep]：`step_order`、`step_goal`、`assigned_agent`、`required_tools`、`success_criteria`）、`budget`、`revision`、`revise_reason`（可空）、`degraded`
11. `InvestigationResult` 增加 `writeback_required`、`writeback_readiness`、可空 `writeback_overall_status`、`pending_writeback_ids`；final_status=CLOSED 不得被解释为 XDR 已处置完成。
12. `GraphOutput` 字段：`nodes`、`edges`、`central_entities`、`attack_path_candidates`（GraphAgent 输出；节点/边结构与 ISSUE-050 派生图一致）

实现步骤：
1. 实现 `BaseAgent` 抽象类：构造注入依赖（LLM 客户端、ToolExecutor、ContextStore、WorkingMemory、BudgetService、OutputGuard 等以 Optional 参数声明，本 Issue 仅占位类型）；`execute` 为基类实现的模板方法（包装计时、轨迹、护栏、预算与工作记忆），子类实现抽象方法 `_run`；提供 `_record_trace()`、`_apply_guardrails()`、`_check_budget()` 占位（分别由 ISSUE-028、ISSUE-030、ISSUE-029 实现真实逻辑），产物字段读写经 `WorkingMemory`（ISSUE-014）。
2. 在 `agent_io.py` 按统一命名实现全部模型，复用 ISSUE-002 的 Evidence、Action、EntitySet 等。
3. 将这些模型加入 `scripts/export_schemas.py` 的导出清单。
4. 编写 Schema 测试：每个模型正反例构造；验证 `EvidenceOutput.collection_status` 等受限字段拒绝越界值。

验收标准：
1. 12 个 Agent 的输入输出模型全部可导入且通过测试。
2. `contracts/schemas/` 中新增对应 JSON Schema 文件。
3. `BaseAgent` 不可直接实例化（抽象类约束生效）。

测试与验证：
`cd backend && pytest tests/test_models/test_agent_schemas.py -v`。

降级策略：
无

---

### ISSUE-006：开放工具契约、能力清单与异步执行 Schema

优先级：
P0

目标：
定义开放的 `ToolMeta`、`CapabilityManifest`、`ToolResult` 与异步任务 Schema，为基线工具编写输入输出契约。工具总数不锁死；Mock 与未来真实 Provider 共享内部契约，厂商字段只允许出现在 Provider 映射层和 raw_result。

前置依赖：
ISSUE-002

输入上下文：
简介第 4.5 节工具清单与第 4.6 节 ToolCategory、ActionLevel；Mock 与真实实现共用同一 Schema。

文件范围：
1. `backend/app/models/tool_meta.py`：`ToolMeta`、`ToolResult`
2. `backend/app/tools/specs/`：基线工具元数据定义文件（query、response、verification、rollback）
3. `contracts/schemas/tools/`（导出产物）
4. `backend/tests/test_models/test_tool_schemas.py`

统一命名：
1. `ToolMeta` 增加可空 `action_category`、`routing_kind`（tool_provider_only、owner_routed、disposition_only）、`supported_execution_owners`、`required_disposition_intent_by_owner` 与 capability requirements；`ProviderToolBinding` 字段为 tool_name、provider_name、execution_owner、execution_channel、capabilities。query 的 action_category=null/owner 集合空/routing=tool_provider_only；verification 的 action_category=verification/owner 集合空；普通 side-effect response/rollback 使用 owner_routed，同一 canonical tool 可同时支持 XDR_MANAGED 与 DIRECT_TOOL；update_source_event_disposition 是 disposition_only virtual meta，只支持 XDR_MANAGED→EVENT_STATUS_UPDATE，固定 POST_VERIFY，不注册 ToolProvider execute 实现。对普通 response，XDR_MANAGED→ENTITY_ACTION_SUBMIT、DIRECT_TOOL→EXECUTION_RESULT_RECORD；映射由 ActionExecutionService 校验。不得按 source type 硬编码 writeback_required，也不在 ToolMeta 固化厂商 operation_code，实际 operation 由已验证 Adapter capability 映射。
2. `CapabilityManifest` 增加 source_read、event_disposition、entity_response 三类 ShadowTrace 内部能力及 allowed_intents、allowed_operations、allowed_target_types、allowed_source_kinds、可选 allowed_native_source_object_types、supports_status_query、supports_lookup_by_idempotency、supports_idempotency、supports_concurrency_control；binding 按 intent+operation+source kind/native type 校验，每项状态为 UNKNOWN/SUPPORTED/UNSUPPORTED，live 默认 UNKNOWN。在线、可读、可写回、可执行必须分别表达。
3. `ToolResult` 字段：`call_id`、`tool_name`、`provider_name`、`status`（accepted、success、partial_success、failed、unknown、validation_error、auth_error、rate_limited、timeout、remote_error、circuit_open、unsupported）、`job_id`（ShadowTrace 内部预持久化 job ID）、`provider_job_id`（可空、Provider 外部任务号）、`data`、`target_results`、`provider_code`、`provider_message`、`raw_result`、`error_detail`、`execution_time_ms`、`confidence`。Provider 原始码与消息仅在受控本地回执保留并脱敏，不直接进入出站 command。
4. 查询类工具输入公共字段：`time_range`（`start`、`end`）；各工具主键参数：`query_account_login` 用 `account`、`query_edr_process` 用 `host_id`、`query_network_flow` 用 `src_ip` 或 `dst_ip`、`query_dns` 用 `domain`、`query_asset_info` 用 `ip` 或 `hostname`、`query_vuln_info` 用 `ip` 或 `hostname`、`query_threat_intel` 用 `indicator`、`query_file_access` 用 `account`、`query_history_cases` 用 `pattern_description`
5. 基线回滚映射见简介第 4.5 节。实际 `rollback_supported` 以 Provider manifest 为准；缺少能力时动作不可执行，不能替换为名称相似的工具。

实现步骤：
1. 实现 `ToolMeta` 与 `ToolResult` 模型。
2. 在四个 specs 文件中声明简介第 4.5 节基线 ToolMeta/virtual meta 并提供 `BASELINE_TOOL_METAS`；Provider 可在启动时追加工具，但不得覆盖不同 Schema 的同名工具。virtual disposition meta 只进入能力目录/审批预览，不要求或允许 async execute。
3. 处置等级：通知/建工单为 L1，IP/域名封禁为 L2，主机隔离/文件处置/进程阻断/账号禁用为 L3，密码重置/令牌撤销等为 L4；最终仍由审批和影响评估控制。
4. 将基线工具 Schema 导出到 `contracts/schemas/tools/{tool_name}.json`；异步工具输出引用 `ActionExecutionJob`。
5. 编写测试增加：生产策略 required 但 event_disposition 为 UNKNOWN/UNSUPPORTED 时义务 Action 仍物化且 readiness blocked；query/verification 可空 owner/category；virtual disposition meta 无 execute 且 ToolExecutor 拒绝调用；execution_owner 二选一；禁止 DIRECT_TOOL 与 XDR_MANAGED 同时下发；allowed source kind/native type 与写回字段白名单可验证。

验收标准：
1. 简介第 4.5 节基线工具均有 ToolMeta，允许 Provider 合法扩展，测试不锁死总数。
2. 导出的 Schema 文件集合与当前基线清单一致。
3. 回滚映射双向一致（处置工具声明的 rollback_tool_name 存在且类别为 rollback）。
4. `pytest backend/tests/test_models/test_tool_schemas.py -v` 通过。

测试与验证：
`cd backend && pytest tests/test_models/test_tool_schemas.py -v`。

降级策略：
无

---

### ISSUE-007：状态机定义与工作流常量

优先级：
P0

目标：
实现 ShadowTrace 内部状态矩阵。外部 XDR 状态不得覆盖内部状态；DispositionReceipt 只更新写回事实，source_object.current_* 只能由 SourceAdapter 回读或经同一 normalizer 验证的权威资源表示更新。两套状态相关联但不做一一映射。

前置依赖：
ISSUE-002

输入上下文：
简介第 4.6 节枚举、第 4.8 节工作流常量；状态机驱动整个事件生命周期。

文件范围：
1. `backend/app/models/workflow.py`
2. `backend/tests/test_models/test_state_machine.py`

统一命名：
1. 常量：`STATE_TRANSITIONS: dict[EventStatus, set[EventStatus]]`、`VERDICT_STATUS_RULES`、以及简介第 4.8 节全部工作流常量
2. 函数：`validate_transition(current, target, context=None)`；`TransitionContext` 含 `final_verdict`、`need_investigation`、服务端持久化的 `disposition_only_intent` 与写回门禁投影。TRIAGING→CLOSED 仅放行 not_required 的低危/误报；TRIAGING→PLANNING_RESPONSE 仅在（`final_verdict=false_positive` 或 triage `recommendation=close_as_fp`）且 `disposition_only_intent=true` 时放行最小来源事件处置。**禁止**仅凭 `need_investigation=false` 进入 disposition-only（低危 required 非误报必须走普通调查链或转人工，不得跳过证据/评分）。该 intent 必须由 WorkflowRuntimeService 根据事件政策、来源定位及 EVENT_STATUS_UPDATE readiness 在 Action 生成前写入，API/LLM 不能提供。`validate_verdict_status` 同样接收 context；另有 derive_case_label。
3. 异常：`InvalidStateTransitionError`、`InvalidVerdictStatusCombinationError`

实现步骤：
1. 定义 `STATE_TRANSITIONS` 矩阵，主路径：NEW 到 TRIAGING；TRIAGING 到 COLLECTING_EVIDENCE、CLOSED（仅 not_required 低危/误报）或 PLANNING_RESPONSE（**仅** disposition-only 的高置信误报来源状态同步）；COLLECTING_EVIDENCE 到 ANALYZING；ANALYZING 到 SCORING；SCORING 到 PLANNING_RESPONSE 或 REPORTING；PLANNING_RESPONSE 到 WAITING_APPROVAL 或 EXECUTING_RESPONSE；WAITING_APPROVAL 到 EXECUTING_RESPONSE 或 REPORTING；EXECUTING_RESPONSE 到 VERIFYING；VERIFYING 到 REPORTING、CONTAINED、REPLANNING 或 FAILED；REPLANNING 到 COLLECTING_EVIDENCE、PLANNING_RESPONSE、EXECUTING_RESPONSE、CONTAINED 或 FAILED；CONTAINED 到 REPORTING；FAILED 到 REPORTING；REPORTING 到 CLOSED。除 CLOSED/FAILED 外的任一非终态发生不可恢复编排错误时还允许统一转 FAILED，不能让异常处理本身因非法边失败；参数化测试覆盖每一来源态。CLOSED 为终态无出边。写回等待是 VERIFYING 内的 `execution_substate=waiting_writeback` 检查点，不得进入 REPLANNING。
2. 定义 `VERDICT_STATUS_RULES`：false_positive 事件通常禁止处于 PLANNING_RESPONSE、WAITING_APPROVAL、EXECUTING_RESPONSE、VERIFYING；Action 生成前的唯一例外是受信 `disposition_only_intent=true`，生成后还必须验证当前 plan 全部 response Action 均为 update_source_event_disposition，始终禁止实体副作用。TRIAGING→CLOSED 仅用于 disposition_policy=not_required。迟到误报分三档：
   - **(P0 最小·无副作用)** 尚无已创建 job/outbox 的 IMMEDIATE Action：`set_final_verdict(false_positive)`（允许在 TRIAGING/PLANNING_RESPONSE/WAITING_APPROVAL/REPORTING；若当前在 EXECUTING/VERIFYING 且尚无副作用则可先退回 PLANNING_RESPONSE）→若尚无 deferred 或现有 deferred 的 `approved_terminal_dispositions` **不含** `ignored`，必须 **新 plan_revision** 预生成/supersede 为仅含 `ignored`（及政策允许子集）的 deferred 并重新审批，**不得**强行激活威胁向终态集合上的旧 deferred→EventDispositionService 激活确认 EVENT_STATUS_UPDATE→REPORTING→CLOSED；
   - **(P0 中间态·已下发未闭环)** IMMEDIATE 已 EXECUTING/SUCCESS/UNKNOWN 或效果未验证：一律置当前 EventStatus 下合法的 `execution_substate=manual_resolution`（仅 WAITING_APPROVAL/EXECUTING_RESPONSE/VERIFYING 可写；否则先转入 CONTAINED 再人工），禁止 CLOSED，禁止假装回滚；审计标注 `late_fp_pending_rollback`；
   - **(P1 增强，依赖 ISSUE-061)** 已有已验证成功的实体处置：先「回滚效果→按补偿政策完成 required COMPENSATION_RECORD→CONTAINED→set_final_verdict→若获批集合不含 ignored 则新 revision deferred→激活 EVENT_STATUS_UPDATE→REPORTING→CLOSED」。
   任一 required 同步（含 P1 补偿）未确认时不得 CLOSED。P0 交付不得假装已实现实体回滚。旧 deferred 在新 revision 生效时未外呼则 SUPERSEDED。
3. 实现两个校验函数与 `derive_case_label` 映射（confirmed_threat 到 true_positive、false_positive 到 false_positive、其余到 uncertain）。
4. 声明简介第 4.8 节全部常量，可被环境变量覆盖（通过 Settings 读取）。
5. 固定五套子状态合法边并由所有服务共用条件 CAS 校验。`ACTION_STATUS_TRANSITIONS_BY_CATEGORY`：response 为 PENDING→WAITING_APPROVAL/APPROVED/REJECTED/SUPERSEDED，WAITING_APPROVAL→APPROVED/REJECTED/SUPERSEDED，APPROVED→EXECUTING/WAITING_APPROVAL/SUPERSEDED，EXECUTING→PARTIAL_SUCCESS/SUCCESS/FAILED/UNKNOWN，UNKNOWN→PARTIAL_SUCCESS/SUCCESS/FAILED；仅原 response Action 在回滚效果全部验证后由 SUCCESS/PARTIAL_SUCCESS→ROLLED_BACK。verification 为 PENDING→EXECUTING→SUCCESS/FAILED/UNKNOWN，UNKNOWN→SUCCESS/FAILED；rollback 走 PENDING→WAITING_APPROVAL/APPROVED→EXECUTING→PARTIAL_SUCCESS/SUCCESS/FAILED/UNKNOWN（含人工拒绝边），成功 rollback Action 不转 ROLLED_BACK，而是把 source_action_id 指向的原 Action 转 ROLLED_BACK；system 可原子创建为 SUCCESS，或 PENDING→EXECUTING→SUCCESS/FAILED。SUPERSEDED 只允许 job/outbox 均不存在的未外呼 PENDING/WAITING_APPROVAL/APPROVED Action；APPROVED→WAITING_APPROVAL 只用于执行前硬门禁/template 变化并开启新 approval_cycle；POST_VERIFY 的 APPROVED→EXECUTING 还要求 after_effect_resolution 已满足、approved template hash/来源/operation 未变。其他类别/边全部拒绝。另定义 `EXECUTION_SUBSTATE_TRANSITIONS`（与 EventStatus 绑定）：NONE↔WAITING_APPROVAL（仅 WAITING_APPROVAL 态）、NONE↔WAITING_EXECUTION（仅 EXECUTING_RESPONSE）、NONE↔WAITING_WRITEBACK（仅 VERIFYING）、任一可恢复子态→MANUAL_RESOLUTION、MANUAL_RESOLUTION→NONE（仅人工裁决/resume 后）。**TRIAGING/COLLECTING_EVIDENCE/ANALYZING/SCORING/PLANNING_RESPONSE/REPORTING 禁止写入非 NONE 的 execution_substate**；这些阶段的阻塞用 `degraded_flags`（如 `disposition_writeback_blocked`）与人工队列表达，不得滥用 `manual_resolution`。离开所属 EventStatus 时必须先清子态为 NONE。
6. `JOB_STATUS_TRANSITIONS` 为 QUEUED→RUNNING/CANCELLED，RUNNING→PARTIAL_SUCCESS/SUCCESS/FAILED/TIMED_OUT/CANCELLED/UNKNOWN，UNKNOWN→PARTIAL_SUCCESS/SUCCESS/FAILED/TIMED_OUT/CANCELLED（后两者仅 Provider 查证为终态）。`OUTBOX_DELIVERY_TRANSITIONS` 为 READY→LEASED，LEASED→DELIVERED/WAITING_RETRY/PAUSED/DEAD_LETTER，WAITING_RETRY 到期→LEASED，PAUSED 仅在状态查证或人工裁决后→READY/DEAD_LETTER；租约过期必须先 PAUSED 并 lookup，不能直接重发。
7. `WRITEBACK_STATUS_TRANSITIONS` 为 PENDING→SENDING/FAILED/CONFLICT（后两者表示发送前 guard/CAS 已阻断且确认未外发），SENDING→ACCEPTED/CONFIRMED/PARTIAL/FAILED/CONFLICT/UNKNOWN，ACCEPTED→CONFIRMED/PARTIAL/FAILED/CONFLICT/UNKNOWN，UNKNOWN/PARTIAL/FAILED/CONFLICT→CONFIRMED/FAILED（仅状态查证或管理员有证据裁决）。UNKNOWN→PENDING 仅当 lookup 明确“从未受理”，FAILED/PARTIAL→PENDING 仅当 Adapter 明示全量幂等或失败目标可安全重试；这会追加新 sequence receipt，旧失败事实不删除。CONFLICT 若需刷新 token/更改 command 必须创建 superseding disposition 和新 idempotency_key，不能改写旧 payload。CONFIRMED 为终态。
8. 在所有进入 CLOSED 的转移上执行统一硬门禁：报告必须存在；disposition_policy=required 时，至少存在一个 writeback_required=true 且 writeback_applicable=true 的 response/rollback Action（全拒绝或零 Action 不能利用空集合通过），每个适用 Action 都必须 readiness=READY、至少有一个对应 command，且全部 required intent 的聚合 status=CONFIRMED；此外当前 closure_cycle 必须恰有一条绑定当前 revision deferred Action 的 EVENT_STATUS_UPDATE，其 approved/actual SourceDisposition 均属于 TERMINAL_SOURCE_DISPOSITIONS，receipt=CONFIRMED，不能由其他 intent 替代。历史已执行 required Action 仍纳入分母，未外呼的旧 deferred Action 必须 SUPERSEDED。readiness 非 READY、status=null/进行中/失败/冲突/未知、终态命令为零或多条均拒绝。管理员强制本地关闭的唯一入口是 `StateMachineService.force_close`：API 的 `force_local_close=true` 只能调用该方法，经服务内部校验 admin 角色后绕过写回门禁，并写 `external_unsynced=true` 与永久审计；普通 `transition`/Agent 不能提供 force 标志，也不能自行把事件标 CLOSED。
9. 编写测试：全部合法边通过、全部非法边抛 `InvalidStateTransitionError`、五套子状态按类别/阶段的合法与非法边（含 TRIAGING 禁止 manual_resolution）、verdict 组合规则、迟到误报三档、case_label 派生、从 NEW 出发可达 CLOSED 的主路径连通性，以及零 Action、全拒绝和任意调用方尝试绕过 required 写回门禁均失败。
10. 编写隔离与关联测试：外部状态自然变化只更新 source_object.current_* 与 source_sync_state，不改冻结 source_snapshot；由本系统 writeback_id/受控相关键关联且回读匹配的变化可提升对应 DispositionReceipt 的 confirmation_evidence。无可靠相关键的外部变化不能冒充本系统处置成功。

验收标准：
1. 状态矩阵覆盖 14 个状态，CLOSED 无出边。
2. 非法转移（如 NEW 直接到 SCORING）抛出 `InvalidStateTransitionError`。
3. `false_positive` 判定与处置状态的非法组合抛出 `InvalidVerdictStatusCombinationError`。
4. `pytest backend/tests/test_models/test_state_machine.py -v` 通过。

测试与验证：
`cd backend && pytest tests/test_models/test_state_machine.py -v`。

降级策略：
无

---

### ISSUE-008：结构化错误分类体系（ShadowTraceError 与错误码注册表）

优先级：
P0

目标：
建立全系统统一的结构化错误体系：定义错误分类枚举、统一异常基类与错误码注册表，并提供异常归类与可重试判定工具。完成后所有 Agent、工具、服务、API 的错误都能被一致分类、记录与按类别处置。

前置依赖：
ISSUE-002

输入上下文：
简介第 4.6 节 `ErrorCategory` 枚举与第 4.9 节错误分类约定；统一错误响应体字段 `error_code`、`error_message`、`details`（简介第 4.2 节）。

文件范围：
1. `backend/app/core/errors.py`：`ShadowTraceError` 及子类、`ERROR_CODE_REGISTRY`、`classify_exception`、`is_retryable`
2. `backend/app/models/enums.py`（追加 `ErrorCategory`）
3. `backend/tests/test_core/test_errors.py`

统一命名：
1. `ErrorCategory`（枚举，8 值）：transient、permanent、user_input、system、llm、tool、budget、guardrail
2. `ShadowTraceError(Exception)` 字段：`error_code`、`category`（ErrorCategory）、`retryable`（bool）、`message`、`details`（dict）；方法 `to_response() -> dict`（输出 `error_code`、`error_message`、`details`）
3. 异常子类固定：`ValidationError`(user_input)、`InvalidStateTransitionError`(permanent)、`InvalidVerdictStatusCombinationError`(permanent)、`ToolExecutionError`(tool)、`LLMError`(llm)、`BudgetExceededError`(budget)、`GuardrailViolationError`(guardrail)、`DependencyUnavailableError`(transient)、`InternalError`(system)；ISSUE-004 的 `EventNotFoundError`、`ApprovalRequiredError` 与 ISSUE-007 的 `InvalidStateTransitionError`、`InvalidVerdictStatusCombinationError` 均为 `ShadowTraceError` 子类
4. `ERROR_CODE_REGISTRY: dict[str, ErrorCategory]`：登记全部 error_code（如 `event_not_found`、`invalid_state_transition`、`tool_timeout`、`llm_invalid_json`、`budget_exceeded`、`guardrail_failed`、`working_memory_unauthorized_write` 等）；error_code 命名规则为 snake_case 名词短语
5. 工具函数：`classify_exception(exc) -> ErrorCategory`、`is_retryable(exc) -> bool`、`register_error_code(code, category)`

实现步骤：
1. 在 `enums.py` 追加 `ErrorCategory`。
2. 在 `errors.py` 实现基类与 9 个子类（permanent 类别含 `InvalidStateTransitionError`、`InvalidVerdictStatusCombinationError` 两个），每个子类设定默认 category 与 retryable（transient 与部分 llm/tool 为可重试，permanent、user_input、guardrail 不可重试）。
3. 实现 `ERROR_CODE_REGISTRY` 并预登记当前文档出现的全部 error_code；提供 `register_error_code` 供后续 Issue 增补。
4. 实现 `classify_exception`：已知 `ShadowTraceError` 直接取 category；标准库异常（TimeoutError、ConnectionError）映射为 transient；其余为 system。
5. 实现 `is_retryable`：取异常 retryable 或按 category 默认。
6. 约定既有错误改造方向：ISSUE-024 ToolExecutor 重试只对 `is_retryable` 为真的错误生效；ISSUE-027 LLM 错误继承 `LLMError`；ISSUE-007 与 ISSUE-037 非法状态转移抛 `InvalidStateTransitionError`；API 异常处理器调用 `to_response()`。
7. 编写测试：每个子类的 category 与 retryable、`classify_exception` 各分支、注册表登记完整性、`to_response` 字段。
8. 写回错误分类：permission_denied/invalid_operation/version_conflict 为不可自动重试；rate_limited/5xx 为 transient；unknown_delivery 先查证；writeback_pending 是状态冲突而非系统异常。

验收标准：
1. 8 个错误类别与 9 个异常子类齐全且 category 映射正确（permanent 类别对应 2 个子类）。
2. `ERROR_CODE_REGISTRY` 覆盖文档中出现的全部 error_code，无未登记码。
3. `is_retryable` 对 transient 返回真、对 user_input 与 guardrail 返回假。
4. `to_response()` 输出字段与统一错误响应体一致。

测试与验证：
`cd backend && pytest tests/test_core/test_errors.py -v`。

降级策略：
无（基础设施，必须可用）。

---

### ISSUE-009：CI 基础管线

优先级：
P1

目标：
建立 GitHub Actions 管线，对每次 push 与 PR 自动执行后端 lint、后端测试（含 Compose 基础设施）、前端 lint 与构建、Docker 镜像构建四个阶段，保证主分支始终可构建。

前置依赖：
ISSUE-001

输入上下文：
ISSUE-001 的 Makefile 命令与 Compose 文件；后续所有 Issue 的测试均通过本管线执行。

文件范围：
1. `.github/workflows/ci.yml`
2. `Makefile`（新增 `make ci-lint`、`make ci-test`、`make ci-build`）

统一命名：
1. workflow 名 `ci`；job 名：`backend-lint`、`backend-test`、`frontend-build`、`docker-build`

实现步骤：
1. backend-lint：ruff check、ruff format --check、mypy。
2. backend-test：以 services 或 Compose 启动 postgres（pgvector 镜像）与 redis，执行 `pytest --cov=app`，上传覆盖率摘要。
3. frontend-build：`corepack enable`、`pnpm install --frozen-lockfile`、eslint、`tsc --noEmit`、`pnpm build`。
4. docker-build：`docker compose -f infra/docker-compose.yml build`，启动后做健康检查再关闭。
5. 为 pip 与 pnpm store 配置缓存；每个 job 超时 15 分钟。

验收标准：
1. push 与 PR 均触发管线且四个 job 全绿（在仅有骨架代码的仓库上）。
2. 故意引入 ruff 错误时 backend-lint 失败。
3. 本地 `make ci-lint && make ci-test` 与 CI 行为一致。

测试与验证：
推送一次提交观察 Actions 运行结果；本地运行 `make ci-lint`。

降级策略：
无法使用 GitHub Actions 时，以本地 `make ci-lint && make ci-test && make ci-build` 作为合入门禁，不阻塞后续 Issue。

---

### ISSUE-010：Mock XDR 场景状态机、数据生成框架与 HTTP 服务

优先级：
P0

目标：
实现独立 MockXDRServer：既提供数据读取，也提供 ShadowTrace 自有的最小事件处置写回 API；读取和写回使用不同测试权限/客户端。它不复刻厂商私有路径，而是覆盖版本/令牌冲突、同步或异步受理、部分成功、权限失败与状态回读等可能的集成故障，用于验证鲁棒性；这些行为不代表深信服真实接口事实。

前置依赖：
ISSUE-002

输入上下文：
ISSUE-002 的 Source* 规范化模型。截图分别展示安全事件、告警、资产、日志检索和产品接入等页面，但不能据此确认后台是否为独立 API 资源或具有何种关联；Mock 的对象边界是 ShadowTrace 为兼容与测试定义的内部契约。

文件范围：
1. `backend/app/mock_xdr/models.py`：`MockXDRScenario`、`ScenarioTick`、`MockFailureProfile`
2. `backend/app/mock_xdr/state.py`：虚拟时钟、对象版本、水位与游标状态机
3. `backend/app/mock_xdr/api.py`：读取路由与 disposition 写回路由
4. `backend/app/data_generators/base.py`：场景包与原始遥测生成接口
5. `backend/app/data_generators/identity_generator.py`、`endpoint_generator.py`、`dlp_generator.py`、`network_generator.py`、`asset_generator.py`、`threat_intel_generator.py`
6. `backend/app/data_generators/noise.py`：随机背景事件生成
7. `scripts/generate_mock_data.py`、`scripts/run_mock_xdr.py`
8. `backend/tests/test_mock_xdr/`、`backend/tests/test_data_generators/test_framework.py`

统一命名：
1. `MockXDRScenario` 字段：`scenario_id`、`name`、`base_time`、`source_tenant_id`、`incidents`、`alerts`、`assets`、`logs`、`connectors`、`telemetry_timeline`、`ticks`、`failure_profile`、`expected_outcome`。
2. `ScenarioTick` 字段：`offset_seconds`、`operation`（upsert、delete、connector_change）、`object_type`、`object_id`、`patch`。每次变更 source_updated_at 与 payload hash。
3. 输出文件名固定：`data/mock/identity_logs.json`、`endpoint_logs.json`、`dlp_logs.json`、`network_logs.json`、`dns_logs.json`、`asset_data.json`、`threat_intel.json`
4. 读取路由采用 `/mock-xdr/v1/...`；写回路由提供 `POST /mock-xdr/v1/dispositions`、异步模式的 `GET /mock-xdr/v1/disposition-jobs/{provider_job_id}`、按幂等键查证的 `GET /mock-xdr/v1/dispositions/by-idempotency/{key_hash}` 与来源对象处置回读，明确只是 Mock URL。请求采用 DispositionCommand 的最小字段；服务端递归拒绝分析/report/trace/Prompt/evidence 原文。
5. 故障配置：固定/抖动延迟、429、500、超时、重复页、迟到数据、乱序更新、字段缺失、schema_version 变化；确定性 seed 下可复现。

实现步骤：
1. 实现场景模型与一致性校验：Incident 可关联多个 Alert；Alert 反向指向 Incident；资产使用独立数字/字符串 ID；日志指向 alert/asset 时引用必须存在。
2. 实现六类遥测生成器与正常噪声，供 EvidenceAgent 深查；它们不能代替 SourceIncident/SourceAlert 对象。
3. 实现虚拟时钟与稳定游标。客户端重试同一 cursor 得到同一页；翻页不丢不重；水位只在成功提交后推进。
4. 固定 Mock 自身三张合法边表并复用全局子状态约束：SourceDisposition 允许 pending→processing→contained/completed/suspended/ignored/unknown，processing→contained/completed/suspended/ignored/unknown，unknown→processing/contained/completed/suspended/ignored（仅权威 poll/readback 或 test 控制且生成新 token）；TERMINAL_SOURCE_DISPOSITIONS 才禁止倒退，unknown 不是终态。异步 provider job 使用 JOB_STATUS_TRANSITIONS；ConnectorStatus 允许 ONLINE↔DEGRADED/OFFLINE/UNKNOWN，并要求恢复健康检查后才能回 ONLINE。每次权威对象状态变化都更新 current_concurrency_token/source_updated_at/readback，非法边返回 Mock 自定义 validation error 且不改状态。
5. Disposition 可按场景同步返回终态 receipt，也可返回带 provider_job_id 的异步 receipt；只有 Adapter capability 声明可查询时才轮询。相同幂等键返回同一受理结果；可注入不透明令牌冲突。每个 disposition_policy=required 的 Mock 事件当前 closure_cycle 必须只有一条 deferred Action/一个 EVENT_STATUS_UPDATE logical lineage，允许相同 payload 幂等重放及 CONFLICT 后按批准模板 supersede 的历史 attempt，但同时最多一个 active head，最终恰一 active head CONFIRMED；两个并行 active head 或不同终态 payload 必须拒绝。这是 ShadowTrace Mock 契约，不能据此推断真实 XDR 存在同名 API；控制端点只在 test/demo 启用。
6. 让 CLI 既可导出文件，也可 seed MockXDRServer；日志中输出对象数、外部 ID、schema version 与 seed，不输出凭证。

验收标准：
1. Incident、Alert、Asset、Log 在接口与存储上保持类型隔离，外部 ID 原样返回。
2. 1000 条对象分页摄取无丢失/无重复；同一游标重试幂等；字段更新能通过 updated_after 被发现。
3. 写回覆盖 WritebackStatus 的 ACCEPTED/CONFIRMED/PARTIAL/FAILED/CONFLICT，以及异步 provider job 的 QUEUED/RUNNING/终态；覆盖响应丢失后的幂等查证、目标部分成功和未授权字段拒绝，不把 provider job 状态混入 WritebackStatus。
4. 三张合法边表的正常、非法倒退、unknown 恢复、迟到确认和重复回执测试通过；required 事件缺 terminal logical lineage、出现两个 active head 或出现未获批的不同终态 payload 时测试失败，合法 superseding attempt 保留历史且最终只有一个 confirmed head。
5. 明确断言分析报告、decision_trace、Prompt 和 evidence raw data 从未出现在 MockXDR 收到的请求中。

测试与验证：
`cd backend && pytest tests/test_mock_xdr/ tests/test_data_generators/test_framework.py -v`。

降级策略：
无

---

### ISSUE-011：演示数据集场景包（内鬼数据外泄 + 两个泛化场景）

优先级：
P0

目标：
基于 ISSUE-010 交付三个可复现的 Mock XDR 场景包。每个场景同时包含外部 Incident、Alert、Asset、Log、Connector 及深查遥测，避免以一张扁平 raw_alert 代替 ShadowTrace 的规范化/Mock 对象关系；这不证明 live XDR 提供相同对象边界或关联。

前置依赖：
ISSUE-010

输入上下文：
ISSUE-010 的 `MockXDRScenario` 与遥测输出约定；场景内实体名只允许出现在场景包与生成产物中。

文件范围：
1. `backend/app/data_generators/scenarios/__init__.py`：场景注册表 `SCENARIO_REGISTRY`
2. `backend/app/data_generators/scenarios/insider_data_exfiltration.py`
3. `backend/app/data_generators/scenarios/account_anomaly_fp.py`
4. `backend/app/data_generators/scenarios/suspicious_domain_access.py`
5. `data/mock/`（生成产物样例，入库存档）
6. `backend/tests/test_data_generators/test_scenarios.py`

统一命名：
1. 场景 ID 固定：`insider_data_exfiltration`、`account_anomaly_fp`、`suspicious_domain_access`
2. 主场景实体固定：账号 `zhangsan`、主机 `PC-FIN-023`、外联 IP `45.153.12.88`、域名 `unknown-upload-example.com`、进程 `powershell.exe` 与 `7z.exe`、文件 `finance_report.zip`
3. `SCENARIO_REGISTRY: dict[str, MockXDRScenario]`

实现步骤：
1. 编写主场景时间线（至少 20 个关键事件）并创建一个 Incident、多个 Alert、数字型资产 ID 和原始日志引用；外部 ID 一律作为 opaque string，fixture 分别覆盖纯数字、UUID 与无前缀长字符串，生产代码不得解析 `incident-`/`alert-` 前缀。Incident 与 Alert 各自保留等级、来源状态、GPT 标签及更新时间，不强求安全 GPT 字段存在。
2. 在主场景中加入 2 条矛盾数据（identity 无登录记录但 endpoint 有该账号进程活动），用于证据冲突检测演示；`expected_verdict=confirmed_threat`、`expected_severity=critical`。
3. 编写 account_anomaly_fp 场景：运维账号在变更窗口内的批量登录行为，模式与已知误报规则一致；`expected_verdict=false_positive`、`expected_severity=low`。
4. 编写 suspicious_domain_access 场景：办公主机访问新注册域名但无数据外传；`expected_verdict=none`、`expected_severity=medium`（risk_score 落在 40-69，不得写成 confirmed_threat，因 VerdictResolver 要求 risk_score>=70 才确认威胁，对应 severity 至少 high）。
5. 注册三个场景到 `SCENARIO_REGISTRY`，生成样例数据存档至 `data/mock/`。
6. 每个场景至少配置一个仅日志上报连接器和一个具备联动/处置能力的 Mock 连接器；主机 Agent 未安装、设备离线、能力缺失、返回部分成功与 Provider 业务错误均有独立变体。示例业务错误只使用 Mock 自定义 `capacity_limit_exceeded`；如需演示截图中出现过的“黑名单总数超出”文案，必须放在带 `simulated_ui_observation=true` 的测试 fixture 中，不使用或推断真实 API code/schema。

验收标准：
1. `python scripts/generate_mock_data.py --scenario insider_data_exfiltration` 生成 7 个文件，主场景关键事件不少于 20 个且实体引用跨数据源一致。
2. 三个场景包均通过框架一致性校验与 Schema 校验。
3. 主场景包含恰好 2 条标注 `is_conflict_seed=true` 的矛盾记录。
4. 任一场景生成两次的输出完全一致（确定性）。

测试与验证：
`cd backend && pytest tests/test_data_generators/test_scenarios.py -v`；手工运行 CLI 检查 `data/mock/` 产物。

降级策略：
无

---

### ISSUE-012：SourceAdapter、DispositionAdapter 与 Mock XDR 双向适配

优先级：
P0

目标：
实现两个严格分离的接口：SourceAdapter 永远只读；DispositionAdapter 只允许事件处置写回。交付 Mock XDR 双向适配与 file fallback；Agent 不直接依赖任何 Adapter。

前置依赖：
ISSUE-002、ISSUE-011

输入上下文：
ISSUE-010/011 的 Mock XDR HTTP 契约、场景与 file fallback；归一化和写回信封 Schema 来自 contracts。

文件范围：
1. `backend/app/adapters/source/base.py`：`BaseSourceAdapter`、`SourcePage`
2. `backend/app/adapters/disposition/base.py`：`BaseDispositionAdapter`
3. `backend/app/adapters/registry.py`：`SourceAdapterRegistry`、`DispositionAdapterRegistry`
4. `backend/app/adapters/mock_xdr.py`：MockXDRSourceAdapter、MockXDRDispositionAdapter
5. `backend/app/adapters/file_source.py`：离线 fallback（无写回能力）
6. `backend/app/adapters/normalizers/`：深查遥测 normalizer
7. `backend/tests/test_adapters/`

统一命名：
1. BaseSourceAdapter 保持纯读取，不包含任何写方法；签名固定为 `capabilities()`、`async list_objects(object_types, cursor=None, updated_after=None, limit=100) -> SourcePage`、可选 `async get_object(source_kind, source_object_id)`、`async health_check() -> ConnectorStatus`。SourceIngester 只依赖这些方法，不调用厂商特有客户端。
2. `BaseDispositionAdapter` 方法：`capabilities()`（每个 intent/operation 的 CapabilityState=UNKNOWN、SUPPORTED、UNSUPPORTED，并声明 idempotency/status_query/concurrency/lookup_by_idempotency 支持）、`validate_command()`、`submit(command)->DispositionReceipt`、可选 `get_status(provider_job_id)`、可选 `lookup_submission(idempotency_key, source_locator)`、`health_check()`；不接受任意 dict，只接受 extra=forbid 的 DispositionCommand。submit 同时支持同步终态与异步受理，provider_job_id 可空；响应丢失时只有声明 lookup/status 能力才可自动查证，否则置 UNKNOWN 并转人工。
3. `SourcePage` 字段：`items`（Source* 判别联合）、`next_cursor`、`has_more`、`server_time`、`schema_version`。水位只有在批次验证与持久化成功后提交。
4. 异常：`AdapterNotFoundError`；校验失败记录写入 `data_quality_error` 表。

实现步骤：
1. 实现两套基类、注册中心与凭证引用；Mock 强制读写凭证分离。live 若厂商支持独立凭证则严格分离，否则必须验证单一凭证的最小授权范围并在风险清单记录，日志始终脱敏。
2. 实现 MockXDRSourceAdapter：按 Mock 内部定义的 incident→alert→asset/log 引用关系归一化，保留 raw payload；重试、429 backoff、cursor 和 watermark 语义与服务器一致；不得声称这是深信服后端关系。
3. 实现 FileSourceAdapter；六类遥测 normalizer 仅用于 Evidence 查询，不注册成六个独立 XDR。
4. 校验失败写 data_quality_error；未知字段保留于 raw_payload，schema_version 未支持时标记 connector degraded 并停止推进该对象类型水位。
5. 实现 MockXDRDispositionAdapter：命令白名单、幂等键、可选并发令牌、同步/异步回执、错误映射与脱敏 raw receipt 保存；live Adapter 的所有 capability 默认 UNKNOWN，只有正式文档或脱敏网络证据加契约测试才能切为 SUPPORTED。
6. 契约测试：读取等价、写回幂等、并发令牌冲突、禁止分析字段、file 来源 writeback_required=false；明确这些是 Mock 契约，不是厂商返回码/字段事实。

验收标准：
1. Agent 不导入 Adapter；EventService 只依赖来源模型，DispositionSyncService 只依赖 BaseDispositionAdapter。
2. Incident、Alert、Asset、Log 的外部 ID、父子关系、原始状态和 raw payload 可往返。
3. 写回超时不误判失败：进入 UNKNOWN 并用同一幂等键查证/重试；不得再次执行实体动作。

测试与验证：
`cd backend && pytest tests/test_adapters/ -v`。

降级策略：
无

---

### ISSUE-013：Redis 客户端、EventContext 存储与事件总线

优先级：
P0

目标：
封装异步 Redis 客户端，实现 EventContext 的 Hash 存储读写与基于 Pub/Sub 的事件总线。完成后 EventService 与各 Agent 通过统一接口读写共享上下文并发布完成信号。

前置依赖：
ISSUE-001、ISSUE-002

输入上下文：
简介第 4.7 节 Redis 键与频道命名；EventContext 字段见 ISSUE-002。

文件范围：
1. `backend/app/core/redis_client.py`：`RedisClient`
2. `backend/app/core/event_bus.py`：`EventBus`
3. `backend/app/services/context_service.py`：`EventContextStore`
4. `backend/tests/test_core/test_redis_client.py`、`test_event_bus.py`、`backend/tests/test_services/test_context_store.py`

统一命名：
1. `RedisClient`：基于 `redis.asyncio`，连接池 max_connections=20，方法 `get_client()`、`ping()`
2. `EventContextStore` 方法：`async init_context(event_id, event: EventSummary) -> InitResult`（`InitResult` 含 `redis_ok: bool` 与 `version: int`；先对 `event_context_field_version` 执行 UPSERT（`field_name="event"`）获取 `current_version`（首次为 1），再 INSERT `event_context_journal(field_name="event", version=current_version)` 作为持久化备份，最后写入 Redis Hash 初始字段（含 `{key}__version`）；Redis 写失败时 `redis_ok=false` 但 journal 与版本表均已持久化，不抛异常）、`async get(event_id, key)`（Redis 不可用时自动触发 `rebuild_context` 从 PostgreSQL 重建并缓存到内存；内存缓存附带 30 秒 TTL——过期后下次读重新触发 `rebuild_context` 拉取最新数据，避免多进程/多 worker 场景下长期使用陈旧缓存；Redis 恢复后清除内存缓存改走 Redis）、`async set(event_id, key, value, version=None) -> SetResult`（`SetResult` 含 `redis_ok: bool` 与 `version: int`，Redis 写失败时 `redis_ok=false` 但 journal 已持久化，不抛异常）、`async get_full_context(event_id) -> EventContext`、`async compare_and_set(event_id, key, expected_version, value)`、`async rebuild_context(event_id) -> EventContext`（从 PostgreSQL 各表重建 EventContext：读 security_event 构造 EventSummary、读 agent_trace/evidence/action/tool_call_log 等表回填对应字段；若事件已 CLOSED 且 `security_event.event_context_snapshot` 非空，直接从快照还原完整 EventContext；非 CLOSED 事件或快照为空时从 `event_context_journal` 各字段最新版本逐字段重建；**重建完成后始终以 `security_event.degraded_flags` 和 `security_event.replan_count` 覆盖 EventContext 对应字段**（security_event 为这两个镜像字段的权威来源）；Redis 可用时写回 Redis Hash 各字段值，**同时将 `event_context_field_version` 中各字段最新 `current_version` 写入对应 Redis `{key}__version`**（该表为所有路径唯一版本源，始终有数据；确保 Redis 缓存版本号与 DB 一致，后续 Redis 读从正确基线继续），不可用时仅存内存供本次请求使用）、`async set_closed_ttl(event_id)`（24 小时 TTL）、`async refresh_closed_snapshot(event_id)`（从 `security_event` 构造 EventSummary 作为 `event` 字段，从 `event_context_journal` 读取其余各字段最新版本合并为完整 EventContext，**再以 `security_event.degraded_flags` 和 `security_event.replan_count` 覆盖 EventContext 对应字段后**写回 `security_event.event_context_snapshot`，不依赖 Redis 或现有 snapshot 读取——确保后置 hook 刚写入 journal 的字段与 security_event 权威镜像字段均能正确进入最终快照；供 GraphAgent/StorylineService/MemoryAgent 在写入各自输出后调用）
3. 键格式：`shadowtrace:ctx:{event_id}`（Hash，field 即 EventContext 字段名，值为 JSON 字符串，并存伴随 field `{key}__version`）
4. EventBus 为全部 16 种 Socket 事件唯一入口；通用 publish_event 覆盖新增 disposition_submitted/writeback_updated，发布前统一脱敏。
5. 消息体字段：`timestamp`、`event_id`、`message_type`、`payload`

实现步骤：
1. 实现 `RedisClient` 与 JSON 序列化封装（orjson），健康检查 ping。
2. 实现 `EventContextStore`：Hash 读写、版本号字段（每次 set 自增）、`compare_and_set` 基于 `event_context_field_version` 条件 UPDATE 实现（见下方说明），冲突返回 False；变更日志追加到 `shadowtrace:ctx_log:{event_id}`。**降级缓存管理**：维护 `_degraded_cache_ts: dict[str, float]` 记录每个 event_id 内存缓存构建时间戳，`get()` 读取内存缓存前先检查 `time.monotonic() - _degraded_cache_ts[event_id] > 30`，超期则丢弃缓存并重新触发 `rebuild_context`；Redis 恢复（`ping()` 成功）时清除 `_degraded_cache_ts` 中对应条目。`init_context` 先对 `event_context_field_version` 执行 UPSERT（`field_name="event"`）获取 `current_version`，再 INSERT `event_context_journal(field_name="event", version=current_version)`，最后写入 Redis Hash 初始字段（含 `{key}__version`），返回 `InitResult(redis_ok, version)`；每次 `set` 写操作同步追加 `event_context_journal` 记录（event_id、field_name、value JSONB、version），作为 PostgreSQL 持久化备份；`set` 返回 `SetResult(redis_ok, version)`：Redis 写成功则 `redis_ok=true`，Redis 重试仍失败则 `redis_ok=false`（journal 已持久化，不抛异常，上层据此标记降级）。**版本分配规则**：`event_context_field_version` 为所有写入路径的唯一版本分配源。**事务约束**：所有写入路径（`set`、`init_context`、`compare_and_set`）的版本表操作与 `event_context_journal` INSERT 必须在同一个 PostgreSQL 事务内完成（`async with db.transaction()` 或等效连接级事务），确保版本号与对应值要么同时持久化、要么同时回滚——若 journal INSERT 失败则版本表 UPSERT/UPDATE 一并回滚，不出现"版本号已递增但无对应 journal 记录"的悬挂状态；Redis 写入在事务提交后执行（不在事务内），Redis 写失败不影响 PostgreSQL 已提交的版本与 journal 数据。每次 `set` 先执行 `INSERT INTO event_context_field_version (event_id, field_name, current_version) VALUES (?, ?, 1) ON CONFLICT (event_id, field_name) DO UPDATE SET current_version = event_context_field_version.current_version + 1 RETURNING current_version`（PostgreSQL UPSERT 原子操作，首条插入 version=1，后续自增；无需行锁或 advisory lock），拿到 `current_version` 后 INSERT journal 记录；Redis 可用时额外将 Redis Hash 字段值与 `{key}__version` 同步更新为 UPSERT 返回的 `current_version`（Redis `{key}__version` 仅作为高速缓存，非版本权威来源）；Redis 写失败则 `redis_ok=false`（journal 与版本表均已持久化，不抛异常）。若 journal INSERT 因唯一约束冲突（理论上不应发生，因版本号由 UPSERT 保证唯一），抛出异常（此为真正的 DB 故障，不属于 Redis 降级范畴，不应静默返回）。**`compare_and_set` 降级**：始终执行单条原子条件更新 `UPDATE event_context_field_version SET current_version = current_version + 1 WHERE event_id = ? AND field_name = ? AND current_version = ? RETURNING current_version`（WHERE 条件含 `current_version = expected_version`，确保只有版本匹配时才原子递增；无 RETURNING 行即版本不匹配，返回 False）；字段不存在时（`event_context_field_version` 无对应行）直接返回 False，不创建版本行与 journal 记录——CAS 语义要求对已存在的版本做比较，不存在即无可比较之值；首条版本记录只能由常规 `set` 路径的 UPSERT 创建（见上方版本分配规则），CAS 不承担首次写入职责；成功后 INSERT journal 记录；Redis 可用时额外同步 Redis Hash 字段值与 `{key}__version`（直接写入，无需 Redis 事务——Redis 为缓存，短暂不一致可接受）。
3. 实现 `EventBus` 的发布与订阅，频道名按简介第 4.7 节。
4. 编写测试（依赖 Compose 中真实 Redis）：上下文初始化与读写（含 `init_context` 写 `event_context_field_version` 与 journal `field_name="event"` 且返回 `InitResult`（含 version））、版本冲突、`compare_and_set` 对不存在字段返回 False 且无版本行与 journal 记录、TTL 设置、发布订阅往返、CLOSED 事件从 event_context_snapshot 快照还原、快照为空时降级逐表重建、Redis 不可用时 `set` 返回 `SetResult(redis_ok=false)` 且 journal 有对应记录、Redis 不可用时 `init_context` 返回 `InitResult(redis_ok=false, version=1)` 且 `event_context_field_version` 与 journal 均有 event 记录、`refresh_closed_snapshot` 从 journal 读最新字段写回 snapshot、**Redis 不可用时内存缓存 30 秒后自动从 PostgreSQL 刷新（模拟其他进程写入新 journal 后本进程读到最新值）**。
5. rebuild_context 与 refresh_closed_snapshot 必须合并 disposition_outbox/receipt 最新状态；CLOSED 后迟到回执也能刷新 writeback_summary，不依赖已过期 Redis。

验收标准：
1. EventContext 可写入、读取并还原为 Pydantic 模型。
2. `compare_and_set` 在版本不匹配时拒绝写入并返回 False。
3. 发布一条 state_change 消息后订阅方可在 1 秒内收到。
4. 关闭事件后 `shadowtrace:ctx:{event_id}` 的 TTL 为 24 小时左右。
5. CLOSED 事件 Redis TTL 过期后 `rebuild_context` 可从 `event_context_snapshot` 还原完整 EventContext。
6. Redis 不可用时 `set` 返回 `SetResult(redis_ok=false)` 且 `event_context_journal` 有对应记录，不抛异常。
7. `refresh_closed_snapshot` 在 Redis 不可用时仍可从 journal 读最新字段并写回 snapshot。

测试与验证：
`cd backend && pytest tests/test_core/ tests/test_services/test_context_store.py -v`。

降级策略：
Redis 不可用时 `EventContextStore.set` 写操作经指数退避重试（最多 3 次、间隔 0.1/0.5/2 秒），重试仍失败则返回 `SetResult(redis_ok=false, version=N)`（`N` 从 `event_context_field_version` 表 UPSERT 原子分配——该表为所有路径唯一版本源，详见实现步骤版本分配规则；不抛异常；journal 记录已持久化到 PostgreSQL）。上层服务（EventService、WorkingMemory、StateMachineService 以及所有调用 `EventContextStore.set`/`init_context` 的服务）检查 `SetResult`/`InitResult` 的 `redis_ok`，首次收到 `false` 时在 `security_event.degraded_flags` 中标记 `redis_context_unavailable=true`（PostgreSQL 持久化，系统测试可直接验收），图执行阶段同步写入 InvestigationState 的 `degraded_flags` 供路由函数读取。`EventContextStore.set` 每次写操作（无论 Redis 是否可用）同步追加一条 `event_context_journal` 记录（field_name + value JSONB），确保 PostgreSQL 始终保有 EventContext 各字段的完整历史副本。Redis 恢复后或 Redis TTL 过期后首次访问该事件时调用 `rebuild_context(event_id)`：已 CLOSED 事件优先从 `security_event.event_context_snapshot` 快照还原；非 CLOSED 事件或快照为空时从 `event_context_journal` 各字段最新版本逐字段重建（不依赖 agent_trace，因其异步写入且大对象会截断）。`refresh_closed_snapshot` 始终从 `event_context_journal` 读最新字段构造 EventContext 后写回 snapshot，不依赖 Redis 或现有 snapshot 读取，确保 Redis 不可用时后置 hook 产物仍能进入快照。EventBus 发布失败仅记录警告日志、不抛异常、不阻塞主流程（关键状态以 PostgreSQL 为准）。

---

### ISSUE-014：跨 Agent 工作记忆协议（WorkingMemory 与字段归属）

优先级：
P0

目标：
在 EventContext 之上建立跨 Agent 工作记忆协议：锁定每个上下文字段的唯一写入 Agent 与读取方、提供受控读写 API 与草稿区命名空间，杜绝越权写入与字段覆盖冲突。完成后各 Agent 通过统一契约共享中间状态，下游永远能消费上游产物。

前置依赖：
ISSUE-008、ISSUE-013

输入上下文：
ISSUE-013 的 `EventContextStore`（含乐观锁与版本）；ISSUE-002 的 `EventContext` 字段；简介第 4.11 节字段归属与工作记忆键约定。

文件范围：
1. `backend/app/services/working_memory.py`：`WorkingMemory`、`FIELD_OWNERSHIP`
2. `backend/app/models/working_memory.py`：`ScratchpadEntry`、`MemoryAccessLog`
3. `backend/app/services/degraded_flag_service.py`：`DegradedFlagService`（所有 degraded_flags 的唯一写 API）
4. `backend/tests/test_services/test_working_memory.py`、`test_degraded_flag_service.py`

统一命名：
1. `FIELD_OWNERSHIP` 必须逐项覆盖 ISSUE-002 的 EventContext 字段全集：triage_result→TriageAgent，evidence_output→EvidenceAgent，graph_output→GraphAgent，rag_output→RAGAgent，risk_assessment→RiskAgent，execution_plan→PlannerAgent，response_plan→ResponseAgent，verification_result→VerifyAgent，report→ReportAgent，memory_output→MemoryAgent；false_positive_match→FalsePositiveMatcher（含 P0 `RuleBasedFalsePositiveHook`，同一 writer identity），storyline→StorylineService，impact_assessments→ImpactAssessmentService；event/source_snapshot→EventService，source_sync_state→SourceIngester，approval_records→ApprovalEngine，disposition_only_intent/execution_substate→WorkflowRuntimeService，execution_summary/execution_jobs→ActionExecutionService，rollback_results→RollbackService，disposition_commands/disposition_receipts/writeback_summary→DispositionSyncService，state_history/replan_count→StateMachineService，budget_usage→BudgetService，guard_violations→OutputGuard，convergence_state→ConvergenceGuard，quality_scores→OutputQualityEvaluator，scratchpad→WorkingMemory，degraded_flags→DegradedFlagService。`EventDispositionService` 不直接拥有 EventContext 字段：它只 CAS 激活 deferred Action，并委托 DispositionSyncService 写 outbox/receipt/summary。任何未登记字段启动失败。
2. `WorkingMemory` 方法：`async read(event_id, key, reader) -> Any`、`async write(event_id, key, value, writer) -> None`（校验 writer 是否为 key 的 owner，违规抛 `GuardrailViolationError(error_code="working_memory_unauthorized_write")`）、`async append_scratchpad(event_id, agent_name, note)`、`async read_scratchpad(event_id) -> list[ScratchpadEntry]`、`async get_access_log(event_id) -> list[MemoryAccessLog]`
3. 草稿区键：`shadowtrace:wm:{event_id}`（Hash，存放 `scratchpad` 列表与非归属型临时键）；`scratchpad` 同步镜像到 EventContext.scratchpad
4. `ScratchpadEntry` 字段：`agent_name`、`timestamp`、`note`；`MemoryAccessLog` 字段：`timestamp`、`agent_name`、`op`（read、write 两值）、`key`、`allowed`

实现步骤：
1. 定义 FIELD_OWNERSHIP 覆盖 ISSUE-002 列出的全部 EventContext 字段，既检查 Schema 中每个字段都有 owner，也检查映射没有幽灵字段；受信 system writer 按服务名校验，不使用一个可被任意调用者冒用的宽泛 `system` 字符串。Agent 越权写入必须拦截。
2. 实现 `write`：校验 owner，合法则经 `EventContextStore.set`（带版本乐观锁）写入并记 `MemoryAccessLog(allowed=true)`；非法则记 `allowed=false` 并抛 `GuardrailViolationError`。
3. 实现 `read`：直读 `EventContextStore.get` 并记访问日志（read 不限权但留痕）；Redis 不可用时 `get` 内部透明触发 `rebuild_context` 从 PostgreSQL 回退读取，调用方（Agent、Service）无需感知降级。
4. 实现草稿区读写（追加型，供 ReAct 与 Agent 记录中间思考），容量上限 200 条 FIFO 滚动。
5. 约定接入：ISSUE-005 BaseAgent 通过 WorkingMemory 而非直接 EventContextStore 读写产物字段。
6. 实现 `DegradedFlagService.set_flag(event_id, flag_name, value, writer)`：校验 flag allowlist 和受信调用方后，统一更新 security_event 与 EventContext；后续 Issue 所称“标记 degraded_flags”均必须调用此服务，不得直接写字段。
7. 编写测试：owner 写入成功、越权写入被拒并留痕、读取留痕、草稿区追加与滚动、版本冲突重试、降级标记双写一致。

验收标准：
1. 非 owner Agent 写入归属字段被拒绝并抛 `GuardrailViolationError`，EventContext 不变。
2. owner 写入成功且 `MemoryAccessLog` 记录 allowed=true。
3. 草稿区超过 200 条时按 FIFO 滚动。
4. 字段归属表覆盖全部 EventContext 产物字段（测试断言无遗漏）。

测试与验证：
`cd backend && pytest tests/test_services/test_working_memory.py -v`（依赖 Compose 的 Redis）。

降级策略：
Redis 不可用时 WorkingMemory 检查 `EventContextStore.set` 返回的 `SetResult.redis_ok`，首次收到 `false` 时标记 `degraded_flags.redis_context_unavailable=true`（以 PostgreSQL `event_context_journal` 为 EventContext 字段事实来源，各独立表如 evidence/action/report 仍直接查询）；字段归属校验在非严格模式（环境变量 `WM_STRICT=false`）降级为告警放行，默认严格。

---

### ISSUE-015：EventService 统一事件创建服务

优先级：
P0

目标：
实现 EventService：从来源对象创建内部事件，保存不可变调查快照、当前来源对象关联和候选处置引用。EventService 本身不发外部请求，也不设置 Action.writeback_required；ResponseAgent 只按事件业务政策推导该义务，PolicyFilter 再根据稳定来源定位、配置、权限和 Adapter 能力计算 writeback_readiness。内部研判状态不会自动同步为 XDR 状态。

前置依赖：
ISSUE-003、ISSUE-007、ISSUE-012、ISSUE-013

输入上下文：
ISSUE-002 模型与 ID 生成、ISSUE-003 ORM 与会话、ISSUE-007 状态校验、ISSUE-013 EventContextStore。

文件范围：
1. `backend/app/services/event_service.py`：`EventService`
2. `backend/app/services/source_policy_resolver.py`：`SourcePolicyResolver`
3. `backend/tests/test_services/test_event_service.py`、`test_source_policy_resolver.py`

统一命名：
1. 方法：`async ingest_source_object(source_object) -> IngestResult`、`async create_event_from_source(primary_ref) -> SecurityEvent`、`async create_event(raw_alert, source_type="file")`（兼容）、查询与内部状态方法。
2. 首选去重键为来源身份五元组（含 connector_id）；同一明确来源对象的重复投递幂等。只有 Mock 契约或 live Adapter 提供已验证的显式关联时，关联 Alert 才向 source_reference_snapshots 追加新快照并建立 source_event_link；无显式关系时按独立来源对象处理。只有没有稳定外部 ID 的 file/manual 记录才使用 `(主实体, 1小时时间窗, raw_payload_hash)`。
3. 创建时初始状态固定为 `EventStatus.NEW`，`final_verdict=none`

实现步骤：
1. ingest_source_object 保持既有逻辑；事件记录单一 `disposition_source_ref`：只有已验证关系中的稳定 Incident 才可优先，孤立 Alert 可作为 provisional 候选，file/manual 为 null。`SourcePolicyResolver` 根据 connector 配置决定业务是否要求外部处置同步：P0 MockXDR 场景默认 required，file/manual 默认 not_required；live 必须显式配置。业务 required 但未定位可写对象或 capability 为 UNKNOWN/UNSUPPORTED 时仍保持 disposition_policy=required，同时把候选动作 writeback_readiness 置为对应阻塞值，禁止自动处置并转人工。
2. Alert 先到且没有显式父 Incident 时创建 provisional 事件。后到 Incident 只有携带 Mock 契约或 live Adapter 已验证的关联键时才写 source_event_link：若尚无审批/动作，可原子 promotion，保留 event_id/creation_source_ref，追加 Incident 快照并更新 current_primary_source_record_id 与事件级 disposition_source_ref；若已有审批或动作，禁止破坏性合并，保留两个事件并建立 related link，既有 Action 的来源继续冻结，后续切换须人工确认。没有显式关联键时不 promotion、不 related。
3. EventService 不暴露 `update_event_status` 写入口；所有状态改变统一调用 ISSUE-037 `StateMachineService.transition`，数据库行锁、审计、Context state_history 与 EventBus 只在该服务实现一次。
4. `set_final_verdict`：先用 `validate_verdict_status(verdict, 当前状态, context)` 校验组合。`false_positive` 在 VERIFYING/EXECUTING_RESPONSE 且已有 IMMEDIATE 副作用时非法；在 TRIAGING 且即将/正在 disposition-only（`disposition_only_intent` 将为 true 或已为 true）时合法；迟到误报已执行副作用路径须先经 StateMachineService 转入 CONTAINED（或 P0 中间态保持 manual）再调用。合法则更新 `security_event.final_verdict`、写审计，并经 EventBus 发布 `final_verdict_updated`（此为 final_verdict 写入与发布的唯一路径）。
5. `list_events`：支持 status、severity、event_type、final_verdict、keyword、时间范围过滤与分页排序。
6. 编写测试：创建（含幂等与去重/promotion）、查询过滤、状态只能经 StateMachineService 改变、verdict 设置、Redis 上下文初始化断言。

验收标准：
1. 同一明确来源对象或同一 delivery 重复提交不产生第二条事件；仅当 Adapter 提供已验证的显式 Incident/Alert 关联时，同一 Incident 的多个 Alert 才合并为一个内部事件，无关联时保持独立。
2. 创建后 PostgreSQL、Redis、审计日志三处数据一致。
3. 非法状态转移抛 `InvalidStateTransitionError` 且数据库无变化。
4. `pytest backend/tests/test_services/test_event_service.py -v` 通过。

测试与验证：
`cd backend && pytest tests/test_services/test_event_service.py -v`（依赖 Compose 的 PostgreSQL 与 Redis）。

降级策略：
Redis 写入失败时事件创建仍成功（PostgreSQL 为事实来源）：`init_context` 返回 `InitResult(redis_ok=false)` 后 `create_event` 在 `security_event.degraded_flags` 中标记 `redis_context_unavailable=true`，记录警告日志；后续访问该事件 EventContext 时若发现 Redis key 不存在，自动调用 `EventContextStore.rebuild_context(event_id)` 从数据库重建（`event` 字段始终从 `security_event` 构造 EventSummary）。

---

### ISSUE-016：SourceAdapter 摄取管道与文件 fallback

优先级：
P0

目标：
实现统一摄取管道：默认从 MockXDRSourceAdapter 增量拉取或接收推送信封，按来源对象入库并调用 EventService；文件目录仅作为离线 fallback。P0 不需要 Kafka。

前置依赖：
ISSUE-012、ISSUE-015

输入上下文：
ISSUE-011 数据文件、ISSUE-012 adapter_registry、ISSUE-015 EventService；`SOURCE_MODE` 环境变量（mock_xdr、live、file）。P0 不定义 kafka 模式。

文件范围：
1. `backend/app/ingestion/source_ingester.py`：`SourceIngester`
2. `backend/app/ingestion/push_receiver.py`：推送批次验证与幂等
3. `backend/app/ingestion/file_ingester.py`、`alert_builder.py`：fallback
4. `scripts/ingest_mock_data.py`：CLI 入口
5. `backend/tests/test_ingestion/test_file_ingester.py`

统一命名：
1. `SourceIngester.poll(adapter, object_types, batch_size) -> IngestionSummary`；摘要增加 accepted、duplicate、rejected、watermark_before/after。
2. `AlertBuilder.build(normalized_records) -> list[dict]`：把同一实体组合与时间窗内的可疑记录聚合为 raw_alert（字段 `alert_type`、`source_type`、`records`、`primary_entities`、`occurred_at`）
3. CLI：`python scripts/ingest_mock_data.py --path data/mock/ --scenario insider_data_exfiltration`。P0 不创建 Kafka skeleton；未来若引入消息总线，必须作为独立可选 Issue 并复用同一推送信封与幂等契约。

实现步骤：
1. 实现拉取循环：connector health→按对象类型分页→Schema 校验→事务内 source_object/EventService→成功后提交 watermark；进程重启从已提交水位恢复。
2. 推送入口按 connector_id、delivery_id 和逐对象来源身份幂等，支持批次部分接受。
3. FileIngester 将旧遥测聚合为 synthetic SourceAlert 后走同一 EventService，不建立第二套事件逻辑。
4. SourceAdapter 不可用时保持 degraded 并重试；只有显式 `SOURCE_MODE=file` 才切文件，不静默把旧文件当作最新生产数据。
5. 编写测试：增量、分页、断点恢复、乱序、迟到、重复推送、schema 不兼容和 file fallback。

验收标准：
1. 对主场景数据运行 CLI 后 `security_event` 表恰有 1 条主事件（去重生效），状态为 new。
2. `IngestionSummary` 统计与实际处理数一致。
3. 噪声记录不产生事件。
4. Adapter 故障不会推进水位；恢复后只补摄缺失对象。

测试与验证：
`cd backend && pytest tests/test_ingestion/ -v`；手工执行 `python scripts/ingest_mock_data.py --path data/mock/`。

降级策略：
Adapter 暂时不可用时保留最后水位并暴露 degraded，不自动切换到陈旧文件。只有运维显式设置 `SOURCE_MODE=file` 才启用离线输入。

---

### ISSUE-017：数据底座集成测试

优先级：
P0

目标：
对"生成场景数据、适配器归一化、EventService 入库、API 可查"的完整数据链路编写集成测试，作为核心 Agent 开发前的质量门禁。

前置依赖：
ISSUE-011、ISSUE-016

输入上下文：
ISSUE-010 至 ISSUE-016 的全部产出；Compose 提供 PostgreSQL 与 Redis。

文件范围：
1. `backend/tests/integration/conftest.py`：集成测试 fixtures（数据库迁移、清库、Redis 清理、场景数据生成）
2. `backend/tests/integration/test_data_pipeline.py`
3. `Makefile`（新增 `make integration-test`）

统一命名：
1. pytest 标记：`@pytest.mark.integration`
2. fixtures：`db_session`、`redis_client`、`mock_data_dir`、`clean_state`

实现步骤：
1. 实现 conftest：每个用例前清空业务表与 `shadowtrace:` 前缀键；按需生成场景数据到临时目录。
2. 场景一（主链路）：通过 Mock XDR HTTP 分页摄取 insider_data_exfiltration，断言一个 Incident 对应一个内部事件、关联多个 Alert、资产/日志引用完整、EventContext.source_snapshot 冻结、审计存在。
3. 场景二（部分数据源缺失）：仅保留 identity、endpoint、network 三个文件，断言管道完成且事件仍创建。
4. 场景三（坏数据与 schema 演进）：不支持版本进入 data_quality_error/connector degraded，其余对象正常入库且水位不越过坏批次。
5. 场景四（重复/断点）：同一 cursor 与 delivery 重放不增事件，进程重启后从已提交水位续传。

验收标准：
1. 4 个场景全部通过且整套测试 2 分钟内完成。
2. CI 中可通过 `make integration-test` 运行。

测试与验证：
`make integration-test`（等价 `cd backend && pytest tests/integration/test_data_pipeline.py -m integration -v`）。

降级策略：
无

---

### ISSUE-018：Tool Registry 核心引擎

优先级：
P0

目标：
实现工具注册中心 ToolRegistry：注册、查找、按类别列举、Schema 校验、Provider 能力合并与自动发现。Agent 只看到当前可用能力，不依赖固定工具数量。

前置依赖：
ISSUE-006

输入上下文：
ISSUE-006 的 `ToolMeta`、`ToolResult` 与 `BASELINE_TOOL_METAS`；execution_channel=tool_provider 的工具实现文件约定导出 `TOOL_META` 与 `async execute(params: dict) -> dict`，disposition_adapter virtual meta 无 execute。

文件范围：
1. `backend/app/tools/registry.py`：`ToolRegistry`、`RegisteredTool`
2. `backend/app/tools/base.py`：工具实现接口约定与装饰器
3. `backend/tests/test_tools/test_registry.py`

统一命名：
1. `ToolRegistry` 方法：`register(tool_meta, tool_impl=None)`、`register_binding(binding: ProviderToolBinding)`、`get_tool(tool_name) -> RegisteredTool`、`list_tools(category=None) -> list[ToolMeta]`、`list_bindings(tool_name)`、`resolve_binding(tool_name, execution_owner, required_capabilities) -> ProviderToolBinding`、`validate_input(tool_name, params)`、`validate_output(tool_name, result)`、`unregister(tool_name)`、`get_tool_stats()`。
2. `RegisteredTool` 字段：`tool_meta`、`tool_impl`（pure disposition-only virtual meta 时为 null）、`bindings`、`registered_at`、`call_count`、`error_count`、`healthy`；disposition-only virtual meta 只能被 ResponseAgent/审批目录读取，ToolExecutor 调用必须返回 `wrong_execution_channel`。owner_routed 工具可同时有 DIRECT_TOOL 与 XDR_MANAGED binding，Action 只冻结 resolve_binding 返回的一条。
3. 异常：`ToolAlreadyRegisteredError`、`ToolNotFoundError`、`ToolValidationError`
4. 模块级单例：`tool_registry`，通过 FastAPI 依赖 `get_tool_registry()` 注入

实现步骤：
1. 实现注册与查找逻辑：重复注册抛错、查找不存在抛 `ToolNotFoundError`。
2. 实现基于 jsonschema 的输入输出校验，错误信息包含字段路径与原因。
3. 实现自动发现：扫描 `backend/app/tools/{query,response,verify,rollback}/` 下 execution_channel=tool_provider 的模块，导入 `TOOL_META` 与 `execute` 并注册；另从 specs 加载 disposition_adapter virtual meta，不扫描/伪造 execute。
4. 实现 `list_tools` 类别过滤与 `get_tool_stats` 统计。
5. 编写测试：注册、重复注册、查找、类别过滤、校验失败详情、注销、同一 tool 双 owner binding、同 owner 冲突拒绝、capability 过滤、virtual meta 可列出但不能经 ToolExecutor 执行。

验收标准：
1. 用假工具完成注册、查找、注销全流程测试。
2. 输入缺字段、类型错误、枚举越界均被 `validate_input` 拦截并给出可读错误。
3. 自动发现机制对空目录不报错。

测试与验证：
`cd backend && pytest tests/test_tools/test_registry.py -v`。

降级策略：
无

---

### ISSUE-019：查询工具与内部证据投影（Mock/真实同路径）

优先级：
P0

目标：
实现查询类基线工具和 `EvidenceProjection`。Mock XDR/file/未来真实 Adapter 先把数据归一化到同一只读投影，查询工具只查投影；Agent 不感知数据来自文件还是真实 XDR。

前置依赖：
ISSUE-016、ISSUE-018

输入上下文：
ISSUE-006 的查询类输入输出 Schema；ISSUE-011 的数据文件与场景实体；工具文件导出 `TOOL_META` 与 `execute`。

文件范围：
1. `backend/app/tools/query/`：`query_account_login.py`、`query_edr_process.py`、`query_file_access.py`、`query_network_flow.py`、`query_dns.py`、`query_asset_info.py`、`query_vuln_info.py`、`query_threat_intel.py`、`query_history_cases.py`
2. `backend/app/services/evidence_projection.py`：来源遥测与 SourceObject 的可查询投影
3. `backend/app/tools/query/fixture_loader.py`：仅单测加载 fixture
4. `backend/tests/test_tools/test_query_tools.py`

统一命名：
1. 工具名与文件名一致（简介第 4.5 节）
2. `EvidenceProjection.query(source, entity, time_range, cursor, limit)` 返回记录、来源引用与采集水位；原始记录可追溯到 SourceLog/SourceAsset。
3. 数据源到工具映射保持，但数据由 ingestion 写入投影；fixture loader 只能用于测试 seed，不在运行时被 Agent 直接读取。

实现步骤：
1. 实现 EvidenceProjection 与 ingestion 写入钩子，记录 connector、source_ref、schema_version 与 watermark。
2. 按映射实现 9 个工具：参数、时间、实体与分页过滤；空结果为 success，但同时返回 data_freshness、watermark 与 coverage，避免把“没摄取到”误判为“没有证据”。
3. Mock 延迟/缺失/过期由场景注入；confidence 根据数据质量计算，不随机生成。
4. query_history_cases 在向量库不可用时执行简单关键词匹配并标注 `degraded=true`。
5. 编写测试：每个工具的有结果查询、空查询、时间过滤、Schema 合规。

验收标准：
1. 9 个工具被 Registry 自动发现注册，`list_tools(category="query")` 返回 9 项。
2. 以主场景实体查询时返回与场景包一致的预期数据（如 `query_account_login(account="zhangsan")` 包含凌晨异常登录记录）。
3. 不存在的实体返回空列表且 status 为 success。
4. 全部返回值通过 output Schema 校验。

测试与验证：
`cd backend && pytest tests/test_tools/test_query_tools.py -v`。

降级策略：
投影缺失或过期时返回 degraded 与 freshness/coverage，EvidenceAgent 形成 evidence gap；不得把连接器离线产生的空集当作肯定性证据。

---

### ISSUE-020：逼真异步 MockToolProvider 与处置工具

优先级：
P0

目标：
实现两种不重复下发的 Mock 处置模式：xdr_managed 直接由 MockXDRDispositionAdapter 受理并执行；direct_tool 由 MockToolProvider 执行后再写回 MockXDR。两种模式共享 Action/Job/Receipt 契约。

前置依赖：
ISSUE-012、ISSUE-013、ISSUE-018

输入上下文：
ISSUE-006 的处置类 Schema 与 action_level 声明；Mock 状态键 `shadowtrace:mock_tool_state`。

文件范围：
1. `backend/app/providers/tools/mock_provider.py`：`MockToolProvider`
2. `backend/app/tools/response/`：基线处置工具薄封装
3. `backend/app/tools/mock_state.py`：`MockEnvironmentState`、虚拟设备与异步任务队列
4. `backend/tests/test_tools/test_response_tools.py`

统一命名：
1. `MockEnvironmentState` 至少包含 blocked_ips、blocked_domains、isolated_hosts、quarantined_files、blocked_processes、scan_results、account/session/token 状态、tickets、notifications；每条状态含 provider、connector、版本、来源 action/job 和生效时间。
2. 方法：`async set_state(namespace, key, value)`、`async get_state(namespace, key)`、`async delete_state(namespace, key)`、`async clear_all()`
3. 工单 ID 格式：`TKT-{YYYY}-{4位序号}`；通知 ID：`ntf-{8位十六进制}`
4. 状态记录公共字段：`status`、`reason`、`executed_at`、`executed_by`

实现步骤：
1. Provider 启动时加载能力，并为每个工具声明 execution_owner；同一 action 的 xdr_managed 与 direct_tool 路径互斥。
2. direct_tool 通过 `ActionExecutionService` 在外部调用前持久化 RUNNING job/dispatch intent（带 lease）；崩溃恢复通过 lease reclaim（ISSUE-173）+ 幂等键；xdr_managed 不调用 MockToolProvider，而由 DispositionAdapter 的同步 receipt 或可选 provider job 映射为 ActionExecutionJob。
3. 支持 success、failed、partial_success、timed_out、cancelled、迟到成功及逐目标 code/message/artifact_id；raw_result 使用 ShadowTrace 自有中性 fixture，不仿造或依赖未经确认的厂商字段拼写。
4. 容量上限、重复封禁、目标不存在、设备离线、权限失败、瞬时错误均可配置；幂等键相同不得创建第二个副作用。
5. 编写契约测试：两种 execution_owner、无重复副作用、受理后异步生效、部分成功、能力缺失、响应丢失幂等重试、写回原始错误完整保留。

验收标准：
1. 基线处置工具均可按 manifest 注册；总数允许扩展。
2. action、job、逐目标结果与环境状态可相互追溯。
3. 非法参数返回 `status="validation_error"` 而非抛异常。
4. 重复封禁同一 IP 不报错且标注 already_applied。

测试与验证：
`cd backend && pytest tests/test_tools/test_response_tools.py -v`（每个用例前调用 `clear_all()`）。

降级策略：
无

---

### ISSUE-021：基于观测面的 Mock 验证工具

优先级：
P0

目标：
实现基线验证工具：先等待执行任务终态，再从独立的 Mock 观测面读取设备/端点/流量/新告警状态。验证不得仅检查执行器刚写入的同一键后自证成功。

前置依赖：
ISSUE-020

输入上下文：
ISSUE-020 的 MockEnvironmentState 只读观测投影与异步 job；验证类输出公共字段。

文件范围：
1. `backend/app/tools/verify/`：`check_ip_block_status.py`、`check_domain_block_status.py`、`check_host_isolation_status.py`、`check_file_quarantine_status.py`、`check_process_block_status.py`、`check_virus_scan_status.py`、`check_account_status.py`、`check_new_alerts.py`、`check_traffic_drop.py`
2. `backend/tests/test_tools/test_verify_tools.py`

统一命名：
1. 输出公共字段：`is_verified`、`detail`、`verified_at`、`verification_method`（device_query、endpoint_query、telemetry_observation、source_alert_delta）、`observed_version`、`source_refs`。
2. 失败注入键：`shadowtrace:mock_verify_override`（Hash，field 格式 `{tool_name}:{target}`，值 `"false"` 时强制验证失败）

实现步骤：
1. 实现简介第 4.5 节验证基线；设备查询与遥测观测使用从执行状态异步复制的只读 projection，并可配置复制延迟、永不生效、状态反转和新告警。
2. 实现 override 机制：存在覆盖记录时按覆盖值返回。
3. 验证工具一律只读，不修改任何状态。
4. 编写测试：处置后验证为真、未处置验证为假、注入失败生效。

验收标准：
1. 基线验证工具注册成功且按 target_type/capability 选择。
2. block_ip 后 check_ip_block_status 返回 `is_verified=true`；unblock 或未执行时返回 false。
3. override 注入后对应验证返回失败。

测试与验证：
`cd backend && pytest tests/test_tools/test_verify_tools.py -v`。

降级策略：
无

---

### ISSUE-022：异步 Mock 回滚与补偿工具

优先级：
P1

目标：
实现 Provider manifest 声明可回滚的基线 Mock 工具：回滚也创建异步任务并保留补偿历史；不可回滚动作明确升级人工，不能伪造成功。

前置依赖：
ISSUE-020、ISSUE-021

输入上下文：
ISSUE-006 的回滚映射与 CapabilityManifest；ISSUE-020 的 MockEnvironmentState。

文件范围：
1. `backend/app/tools/rollback/`：`unblock_ip.py`、`unblock_domain.py`、`restore_account.py`、`cancel_host_isolation.py`、`restore_file.py`、`close_false_positive_ticket.py`
2. `backend/tests/test_tools/test_rollback_tools.py`

统一命名：
1. 输出字段：`rolled_back`（bool）、`warning`（可空，目标不存在时为 `"target_not_found"`）、`rolled_back_at`
2. 回滚历史命名空间：`rollback_history`（保留被删除记录的副本与回滚时间）

实现步骤：
1. 回滚经 MockToolProvider 创建异步 job，生效后更新 projection 并把原记录副本写入 rollback_history；close_false_positive_ticket 将工单关闭。
2. 回滚不存在的目标返回 `rolled_back=false` 加 warning，不报错；重复回滚幂等。
3. 编写测试：处置、验证为真、回滚、验证为假的完整链路；回滚不存在目标；幂等。

验收标准：
1. manifest 声明的基线回滚工具注册成功。
2. "block_ip 到 check 为真，unblock_ip 到 check 为假"链路测试通过。
3. 回滚后 `rollback_history` 保留审计副本。

测试与验证：
`cd backend && pytest tests/test_tools/test_rollback_tools.py -v`。

降级策略：
无

---

### ISSUE-023：工具调用审计日志服务

优先级：
P0

目标：
实现 ToolCallLogService：把每次工具调用的完整上下文持久化到 `tool_call_log` 表并提供查询接口，支撑工具调用审计亮点与审计页面。

前置依赖：
ISSUE-003

输入上下文：
ISSUE-003 的 `tool_call_log` 表结构与 `ToolCallLogORM`。

文件范围：
1. `backend/app/services/tool_call_log_service.py`：`ToolCallLogService`
2. `backend/tests/test_services/test_tool_call_log.py`

统一命名：
1. 方法：`async log_start(call_id, event_id, action_id, tool_name, tool_category, parameters) -> str`、`async log_finish(call_id, status, result, error_detail, retry_count)`、`async get_logs_by_event(event_id) -> list`、`async get_logs_by_tool(tool_name, limit=50)`、`async get_log(call_id)`

实现步骤：
1. 实现开始与结束两段式写入（结束时补 `completed_at`、`duration_ms`、`status`、`result`）。
2. 实现三个查询方法，按 `started_at` 排序。
3. parameters/result/error_detail 入库前递归脱敏 password、token、cookie、authorization、secret 等键；超过 1MB 截断并标注。审计保存“调用过何种凭证引用”，不保存秘密值。
4. 编写测试：两段式写入、按事件与按工具查询、大对象截断。

验收标准：
1. 工具调用后审计记录包含足以复盘的脱敏参数/结果投影、耗时与重试次数；秘密、完整 raw payload 和超限内容仅以引用/哈希表示。
2. 按 event_id 查询返回该事件全部调用记录且按时间排序。

测试与验证：
`cd backend && pytest tests/test_services/test_tool_call_log.py -v`。

降级策略：
无

---

### ISSUE-024：工具执行引擎 ToolExecutor（超时、重试、熔断、审计）

优先级：
P0

目标：
实现工具执行的唯一入口 ToolExecutor（即 ToolAgent 的落地实现），封装参数校验、超时、指数退避重试、独立熔断器与审计日志写入。完成后所有 Agent 只能通过它调用工具。

前置依赖：
ISSUE-008、ISSUE-018、ISSUE-023

输入上下文：
ISSUE-018 的 tool_registry；ISSUE-006 的 ToolResult 状态枚举；审计写入接口见 ISSUE-023。

文件范围：
1. `backend/app/tools/executor.py`：`ToolExecutor`
2. `backend/app/tools/circuit_breaker.py`：`CircuitBreaker`
3. `backend/app/tools/retry.py`：`RetryPolicy`
4. `backend/tests/test_tools/test_executor.py`

统一命名：
1. `ToolExecutor.call` 显式接收 tool_name、params、event_id、action_id、execution_job_id、idempotency_key、timeout、retry_policy；call_nature 必须由 Registry 中受信 ToolMeta 派生，不接受调用方自报 query 来绕过门禁。副作用调用缺 action_id/execution_job_id/idempotency_key 时拒绝；executor 只能以 CAS 更新传入的既有 ActionExecutionJob，禁止另建 job 或把 provider_job_id 写入内部 job_id。routing_kind=disposition_only 或 owner/channel 不匹配时 fail-closed 拒绝。
2. `RetryPolicy` 字段：`max_retries=3`、`backoff_base=2.0`、`backoff_multiplier=2.0`；退避公式 `delay = backoff_base * (backoff_multiplier ** attempt)`
3. `CircuitBreaker`：三态 CLOSED、OPEN、HALF_OPEN；`failure_threshold=5`、`recovery_timeout_s=60`；按 tool_name 独立实例
4. 熔断返回 ToolResult(status=circuit_open)；查询工具超时返回 timeout。side effect 在“请求可能已送达但响应超时”时必须返回 unknown 并保留预持久化 job/idempotency_key，只有确认请求未发出时才可返回 timeout/failed。
5. 模块级单例 `tool_executor`，FastAPI 依赖 `get_tool_executor()`

实现步骤：
1. 实现执行流程：validate_input、校验预创建 job/action/owner binding、熔断检查、在每次实际 dispatch 前调用 ConvergenceGuard.record_step（包括最终失败、超时和重试尝试）、经 EventBus 发布 `tool_call_started`、`asyncio.wait_for` 包裹执行、validate_output、把 ToolResult.provider_job_id/逐目标结果 CAS 写回同一 job、成功失败计数、审计写入（开始与结束各一次更新）、经 EventBus 发布 `tool_call_completed`。
2. 查询工具可按 retryable 重试；副作用工具只有 Provider 明示幂等且沿用同一 idempotency_key 时才可重试提交。否则超时/连接中断返回 UNKNOWN，先查询 external job，严禁通用重试器再次下发。
3. 实现三态熔断器与恢复探测。
4. 超时优先级：调用方入参，其次 ToolMeta.default_timeout_s。
5. 暴露调用回调挂载点：dispatch 前强制执行 ConvergenceGuard.record_step/should_stop，完成后按实际用量调用 BudgetService.charge_tool；不能只在成功后计步，否则失败重试可绕过收敛上限。本 Issue 通过窄 Protocol 注入，避免反向依赖具体实现。
6. 编写测试：正常调用、超时、重试退避间隔、熔断打开与半开恢复、审计记录条数、预创建 job 绑定、virtual channel 拒绝、Provider accepted 后崩溃恢复仍只有一条内部 job。

验收标准：
1. 正常调用返回 success 且生成 1 条 `tool_call_log` 记录。
2. 连续失败 5 次后第 6 次直接返回 circuit_open；60 秒后半开探测可恢复。
3. 重试间隔符合指数退避（用时间打桩验证）。
4. `pytest backend/tests/test_tools/test_executor.py -v` 通过。

测试与验证：
`cd backend && pytest tests/test_tools/test_executor.py -v`（用注册假工具模拟 sleep 与异常）。

降级策略：
审计服务写入失败时仅记录错误日志，不影响工具调用返回；熔断状态进程内存储，重启后重置为 CLOSED。

---

### ISSUE-025：工具系统集成测试收口

优先级：
P1

目标：
对 Registry、Executor、当前基线 Mock 工具、能力清单、异步任务与审计服务做系统级测试收口；测试必需集合与行为，不冻结工具总数。

前置依赖：
ISSUE-019、ISSUE-020、ISSUE-021、ISSUE-022、ISSUE-024

输入上下文：
全部工具实现与执行引擎；ISSUE-011 场景数据作为查询工具输入。

文件范围：
1. `backend/tests/test_tools/conftest.py`：工具测试 fixtures（mock 状态清理、确定性模式）
2. `backend/tests/integration/test_tool_system.py`
3. `Makefile`（新增 `make test-tools`）

统一命名：
1. pytest 标记：`@pytest.mark.tool_system`

实现步骤：
1. 链路一：查询链 query_account_login、query_edr_process、query_network_flow、query_threat_intel 顺序调用，断言各自数据与审计记录。
2. 链路二：处置验证回滚链 block_ip、check_ip_block_status、unblock_ip、check_ip_block_status，断言验证结果先真后假。
3. 链路三：7 路查询经 `asyncio.gather` 并发调用，断言全部成功且总耗时小于串行。
4. 链路四：异常链（注入超时工具）触发重试、熔断与恢复。
5. 断言必需工具集合是注册集合的子集、名称唯一、不可用能力不会出现在 ResponseAgent 的可执行清单；不断言总数。

验收标准：
1. 4 条链路测试全部通过，工具模块语句覆盖率不低于 80%。
2. `make test-tools` 3 分钟内完成。

测试与验证：
`make test-tools`（等价 `cd backend && pytest tests/test_tools/ tests/integration/test_tool_system.py -v`）。

降级策略：
无

---

### ISSUE-026：厂商无关 live ToolProvider 与 DispositionAdapter 候选契约

优先级：
P2

目标：
定义厂商无关的 live 动作执行与事件处置同步候选契约，明确 XDR_MANAGED/DIRECT_TOOL 两种 ShadowTrace 内部策略、最小权限、幂等、回执查证和最小出站字段；交付本地示例证明替换路径。深信服 live DispositionAdapter 在取得正式接口文档或脱敏网络证据前保持阻塞，本文不宣称已知其 URL、鉴权、错误码或写能力。

前置依赖：
ISSUE-024

输入上下文：
ISSUE-006 的 ToolMeta/CapabilityManifest；`TOOL_MODE`（mock、live、mixed）；Agent 层代码不得因 Provider 切换而修改。

文件范围：
1. `backend/app/tools/adapters/base.py`：`BaseToolAdapter`、`AdapterConfig`
2. `backend/app/adapters/disposition/http_adapter.py`：示例 DispositionAdapter
3. `backend/app/tools/adapters/file_state_firewall.py`：`FileStateFirewallAdapter`
4. `docs/tool-adapter-guide.md`
5. `backend/tests/test_tools/test_adapters.py`

统一命名：
1. `BaseToolAdapter` 方法：`async execute(params, idempotency_key) -> ToolResult`、可选 `async get_job_status(provider_job_id) -> ToolResult`、可选 `async lookup_by_idempotency(idempotency_key) -> ToolResult | None`、`async health_check() -> bool`、`validate_config() -> bool`；capability 必须分别声明 status query、idempotency lookup 和 idempotent execute 支持，未声明的方法调用返回 unsupported。
2. `AdapterConfig` 字段：`endpoint`、`auth_type`、`credential_ref`（环境变量名引用，不存明文）、`timeout_s`、`tls_verify`、`enabled`
3. 错误映射目标以 ISSUE-006 当前 ToolResult status 枚举为唯一来源，不在本 Issue 重复计数。

实现步骤：
1. 实现两类适配器与分离配置；禁止复用只读 Source 凭证做写回，除非正式接口文档明确同一授权且 scope 校验通过。
2. 实现示例适配器复用 `block_ip` 的 Schema：把封禁状态写入本地 JSON 文件，仅验证替换机制，不代表任何真实外部系统。
3. 在 Registry 自动发现中支持 `TOOL_MODE`：mock 全 Mock；live 只加载显式真实 Provider；mixed 按逐工具路由表选择，响应中始终标明实际 Provider。
4. 健康检查失败的工具标记 `available=false` 并阻止提交。`live` 模式严禁自动回退 Mock；`mixed` 仅可按预配置路由到 Mock，且 UI/审计显著标注 simulated。
5. 编写 generic HTTP profile 测试：两种 execution_owner、XDR 托管不再直连设备、直连设备完成后仅同步一次结果、provider_job_id 轮询、按 idempotency 查证、超时/崩溃恢复，以及示例 409/401/403/5xx 分类。这些 HTTP 状态只是候选 Adapter 测试，不是深信服接口事实；真实 Adapter 必须按已确认协议重新建立错误映射契约测试。

验收标准：
1. 示例适配器可被自动发现并经 ToolExecutor 调用，Agent 层零修改。
2. `TOOL_MODE` 三种取值均有测试覆盖。
3. live Provider 不可用时返回 unsupported/remote_error 或转人工，不产生 Mock 成功回执。

测试与验证：
`cd backend && pytest tests/test_tools/test_adapters.py -v`。

降级策略：
Provider 不可用时冻结相关动作并转人工；只有开发者显式选择 `TOOL_MODE=mock` 或 mixed 路由时才执行模拟动作。

---

### ISSUE-027：厂商无关 LLMProvider（mock、OpenAI-compatible、custom）

优先级：
P0

目标：
实现统一 LLMProvider：支持 MockLLM、任意 OpenAI-compatible API 与 custom Provider、结构化输出、模型 fallback 链和调用日志。深信服安全 GPT 未来只作为一个可选 Provider，任何 Agent 不导入其 SDK 或字段。

前置依赖：
ISSUE-003、ISSUE-008

输入上下文：
环境变量 `LLM_MODE`、`LLM_API_BASE_URL`、`LLM_API_KEY`、`LLM_PRIMARY_MODEL`、`LLM_FALLBACK_MODELS`、`LLM_TIMEOUT_SECONDS`；`llm_call_log` 表（ISSUE-003）。

文件范围：
1. `backend/app/core/llm/base.py`：`BaseLLMClient`、`LLMResponse`、`LLMMessage`
2. `backend/app/providers/llm/openai_compatible.py`、`custom.py`
3. `backend/app/core/llm/mock_client.py`：`MockLLMClient`
4. `backend/app/core/llm/factory.py`：`get_llm_client()`
5. `backend/app/core/llm/golden/`：按 prompt_key 与 scenario_id 组织的预设响应 JSON
6. `backend/tests/test_core/test_llm_client.py`

统一命名：
1. `BaseLLMClient.chat(messages: list[LLMMessage], *, event_id: str, agent_name: str, prompt_key: str, scenario_id: str | None = None, temperature=0.3, max_tokens=4096, json_mode=False, response_model: type[BaseModel] | None = None) -> LLMResponse`；event_id/agent_name/prompt_key 为必填审计与路由上下文，不从 Prompt 正文猜测。
2. `LLMResponse` 字段：`content`、`parsed`（response_model 解析结果，可空）、`model_name`、`prompt_tokens`、`completion_tokens`、`total_tokens`、`latency_ms`、`fallback_level`（0 主模型、1 备模型、2 mock）、`degraded_reason`
3. `MockLLMClient` 响应路由键：`prompt_key`（由调用方在 messages 元数据传入，如 `triage_extract`、`risk_score`、`report_generate`）加 `scenario_id`
4. 统一错误类型：`LLMTimeoutError`、`LLMAuthError`、`LLMRateLimitedError`、`LLMInvalidJSONError`、`LLMProviderError`（均继承 ISSUE-008 的 `LLMError`，category 为 llm）

实现步骤：
1. 实现 OpenAI-compatible Provider（httpx 异步）与 custom 协议基类；本地推理服务若兼容同协议只需配置 base_url。
2. 实现 JSON mode：要求模型输出 JSON 并用 response_model 解析；解析失败做一次"修复重试"（把错误 JSON 与报错回传请求修正），仍失败抛 `LLMInvalidJSONError`。
3. 实现 fallback 链：主模型超时或出错依次尝试 `LLM_FALLBACK_MODELS`，全部失败且 `LLM_MODE` 非 mock 时抛错由 Agent 降级逻辑接管；`fallback_level` 如实标注。
4. 实现 MockLLMClient：从 golden 目录按 prompt_key 与 scenario_id 加载预设响应，未命中时返回该 prompt_key 的默认响应；完全确定性。
5. 每次实际模型请求（含失败与修复重试）发送前调用 ConvergenceGuard.record_step/should_stop，完成后写 `llm_call_log`（agent_name、event_id、prompt_key、token 用量、延迟、fallback_level、status）；失败请求也留最小审计，不能只统计成功调用。
6. 暴露调用回调挂载点：请求前强制 ConvergenceGuard，完成后按实际 token 供 BudgetService.charge_llm 接入；messages 发送前可经 PromptBudgeter（ISSUE-031）裁剪，不可用时朴素截断。
7. 编写测试：mock 模式确定性、JSON mode 解析与修复、fallback 切换（respx 模拟超时）、调用日志落库。

验收标准：
1. `LLM_MODE=mock` 下 `chat()` 返回确定性响应且不发起任何网络请求。
2. JSON mode 输出可解析为指定 Pydantic 模型。
3. 主模型超时后自动切换备模型且 `fallback_level=1`。
4. 每次调用在 `llm_call_log` 留有记录。

测试与验证：
`cd backend && pytest tests/test_core/test_llm_client.py -v`。

降级策略：
同一已配置 Provider 的模型 fallback 全部不可用时由规则/模板降级并明确 degraded；运行时不得静默改用 MockLLM 伪装真实分析。MockLLM 仅在 `LLM_MODE=mock` 的测试/演示环境启用。

---

### ISSUE-028：AgentTrace 与事件审计服务（decision_trace 基础）

优先级：
P0

目标：
实现 AgentTraceService 与 EventAuditLogService：记录输入摘要、结构化结论、证据引用、规则/模型版本、动作与耗时。decision_trace 用可审计决策依据解释结果，不保存或展示模型隐藏思维链。

前置依赖：
ISSUE-003、ISSUE-005

输入上下文：
ISSUE-003 的 `agent_trace` 与 `event_audit_log` 表；ISSUE-005 的 BaseAgent `_record_trace()` 占位。

文件范围：
1. `backend/app/services/agent_trace_service.py`：`AgentTraceService`
2. `backend/app/services/event_audit_log_service.py`：`EventAuditLogService`
3. `backend/app/agents/base.py`（接通 `_record_trace`）
4. `backend/tests/test_services/test_agent_trace.py`、`test_event_audit_log.py`

统一命名：
1. `AgentTraceService` 方法：`async log_trace(event_id, agent_name, input_data, output_data, status, started_at, completed_at, error_detail=None, llm_model=None, llm_tokens_used=None) -> str`、`async get_traces_by_event(event_id)`、`async get_trace(trace_id)`
2. `EventAuditLogService` 方法：`async log_transition(event_id, from_status, to_status, operator, reason) -> str`、`async get_logs_by_event(event_id)`
3. `decision_basis` 约定：记录 `input_summary`、`evidence_refs`、`rules_applied`、`model_name`、`structured_conclusion`、`selected_action`、`confidence`、`warnings`。Prompt 正文、秘密、完整 raw payload 与自由文本内部推理默认不落库；必要调试内容须脱敏并受短 TTL/管理员权限控制。

实现步骤：
1. 实现两个服务的写入与查询（异步、不阻塞主路径）。
2. 在 BaseAgent 中实现 `execute` 的包装逻辑：子类实现 `_run()`，基类负责计时、经 EventBus 发布 `agent_progress`（执行开始）、成功完成时发布 `agent_completed`、异常捕获时发布 `agent_failed`、状态判定与 `_record_trace` 写入。
3. input_data 与 output_data 不得直接 `model_dump()` 全量落库；先经 `TraceProjection` 生成 allowlist 摘要（对象 ID、结构化结论、证据引用、计数、规则/模型版本），递归删除 raw_payload/raw_data/source_snapshot 原文、Prompt、秘密与隐藏推理，再限长。需要复盘的原始数据只保存受权限控制的 source/evidence 引用。
4. 编写测试：trace 写入与查询、异常 Agent 的 FAILED 轨迹、审计日志写入排序。

验收标准：
1. 任一继承 BaseAgent 的假 Agent 执行后 `agent_trace` 有完整记录（含耗时与状态）。
2. Agent 抛异常时轨迹状态为 failed 且含 error_detail。
3. 按 event_id 查询轨迹按 started_at 升序返回。

测试与验证：
`cd backend && pytest tests/test_services/test_agent_trace.py tests/test_services/test_event_audit_log.py -v`。

降级策略：
轨迹写入失败仅记录错误日志，不中断 Agent 执行。

---

### ISSUE-029：全局 Token/Cost 预算服务（BudgetService）

优先级：
P0

目标：
建立 system、event、agent 三级 Token 与成本预算：实时累计每次 LLM 与工具调用的 token 与成本，超限按类别熔断并抛预算异常，预算用量写入 EventContext。完成后系统对资源消耗有硬约束，杜绝失控调用。

前置依赖：
ISSUE-008、ISSUE-024、ISSUE-027、ISSUE-028

输入上下文：
简介第 4.10 节预算常量、`MODEL_PRICE_TABLE` 与环境变量；ISSUE-027 `LLMResponse` 的 token 字段；ISSUE-024 ToolExecutor 调用计数；ISSUE-008 `BudgetExceededError`。

文件范围：
1. `backend/app/services/budget_service.py`：`BudgetService`、`BudgetUsage`
2. `backend/app/models/budget.py`：`BudgetScope`、`BudgetSnapshot`
3. `backend/app/core/llm/base.py`（接入消耗回调）、`backend/app/tools/executor.py`（接入计数回调）
4. `backend/tests/test_services/test_budget_service.py`

统一命名：
1. `BudgetScope`（枚举）：system、event、agent
2. `BudgetService` 方法：`async charge_llm(event_id, agent_name, model_name, prompt_tokens, completion_tokens) -> BudgetSnapshot`、`async charge_tool(event_id, agent_name, tool_name) -> BudgetSnapshot`、`async check(event_id, agent_name) -> None`（超限抛 `BudgetExceededError(error_code="budget_exceeded")`）、`async get_usage(event_id) -> BudgetUsage`、`allocate_event_budget(severity) -> int`、`async reset_event(event_id)`
3. 预算常量（简介第 4.10 节，位于 `backend/app/models/workflow.py`）：`GLOBAL_TOKEN_BUDGET`、`EVENT_TOKEN_BUDGET`、`EVENT_COST_BUDGET_USD`、`PER_AGENT_TOKEN_CAP`；`MODEL_PRICE_TABLE: dict[str, tuple[float, float]]`（每千 prompt/completion token 单价，mock 模型单价为 0）
4. Redis 计数键：`shadowtrace:budget:system`（全局累计）、`shadowtrace:budget:event:{event_id}`（事件级 Hash：tokens、cost_usd、tool_calls、按 agent 细分）
5. `BudgetUsage` 字段：`event_tokens`、`event_cost_usd`、`tool_calls`、`per_agent`（dict）、`system_tokens`

实现步骤：
1. 实现成本计算：按 `MODEL_PRICE_TABLE` 把 token 折算成本（mock 模式成本恒为 0，仅累计 token）。
2. 实现三级累计与 `check`：event token 超 `EVENT_TOKEN_BUDGET`、event cost 超 `EVENT_COST_BUDGET_USD`、单 agent 超 `PER_AGENT_TOKEN_CAP`、system 超 `GLOBAL_TOKEN_BUDGET` 任一触发即抛 `BudgetExceededError`，details 标明触发 scope 与当前值。
3. 在 `LLMClient.chat` 成功后调用 `charge_llm`，在 `ToolExecutor.call` 成功后调用 `charge_tool`；调用前 `check`。
4. 每次累计后把 `BudgetUsage` 写入 EventContext 的 `budget_usage` 字段。
5. 并入原自适应调查增强设计的"按事件严重度动态分配预算"：`allocate_event_budget(severity)` 按 low/medium/high/critical 在默认 `EVENT_TOKEN_BUDGET` 基础上缩放事件级上限。
6. 环境变量 `BUDGET_ENABLED=false` 时只累计不熔断。
7. 编写测试：token 累计与成本折算、event/agent/system 各级超限熔断、按严重度分配、`BUDGET_ENABLED=false` 不熔断、用量写入 EventContext。

验收标准：
1. LLM 与工具调用后 `budget_usage` 实时更新且数值正确。
2. 事件 token 超 `EVENT_TOKEN_BUDGET` 时下一次 `check` 抛 `BudgetExceededError`，details 含 scope=event。
3. critical 事件分配的预算高于 low 事件。
4. `BUDGET_ENABLED=false` 下永不抛预算异常。

测试与验证：
`cd backend && pytest tests/test_services/test_budget_service.py -v`。

降级策略：
Redis 计数不可用时退化为数据库/进程内计数并记告警；`BUDGET_ENABLED=false` 时全链路不受预算约束仅留统计。预算熔断由 SuperAgent 捕获并生成“预算耗尽”报告；若尚有 required 处置或写回，事件必须转人工/保持未闭环，不得因报告已生成就标记生产成功。

---

### ISSUE-030：Agent 输出 Guard Rails（OutputGuard 校验层）

优先级：
P0

目标：
建立 Agent 输出的集中校验层：对每个 Agent 输出做 schema、grounding、policy、sanitization 四维校验，输出违规清单并按严重度决定放行、修正或拒绝。完成后系统对幻觉、越权目标、未引用断言、敏感泄漏有统一防线。

前置依赖：
ISSUE-005、ISSUE-008、ISSUE-028

输入上下文：
简介第 4.6 节 `GuardRailDimension`、第 4.13 节 `GuardViolation`；ISSUE-005 BaseAgent 的 `_apply_guardrails()` 占位钩子；ISSUE-008 `GuardrailViolationError`。

文件范围：
1. `backend/app/core/guardrails.py`：`OutputGuard`、`OutboundDispositionGuard`、规则模型
2. `backend/app/agents/base.py`（接通 `_apply_guardrails`）
3. `backend/tests/test_core/test_guardrails.py`

统一命名：
1. `GuardRailDimension`（枚举）：schema、grounding、policy、sanitization
2. `GuardViolation` 字段：`dimension`、`rule_name`、`severity`（block、warn 两值）、`detail`
3. `GuardResult` 字段：`passed`、`violations`（list[GuardViolation]）、`sanitized_output`
4. `OutputGuard.validate(agent_name, output, context) -> GuardResult`；规则集 `GUARD_RULES: dict[str, list[GuardRule]]` 按 agent_name 配置
5. 内置规则增加 `disposition_field_allowlist`、`disposition_source_match`、`disposition_approved_action`、`no_analysis_content_outbound`，全部为不可降级 block。

实现步骤：
1. 实现 `OutputGuard` 与四维规则引擎；block 级违规聚合后抛 `GuardrailViolationError`（details 含 violations），warn 级仅记录并返回 sanitized_output。
2. 配置 `GUARD_RULES`：grounding 与 entity_target_exists 应用于 evidence_agent、risk_agent、response_agent、graph_agent、report_agent；citation_present 应用于 rag_agent、report_agent；no_pii_leak 应用于 report_agent 与对外文本。
3. 接通 BaseAgent：`execute` 包装在子类 `_run` 产出后调用 `_apply_guardrails`，block 违规使该 Agent 轨迹状态记为 failed 并把违规写入 EventContext 的 `guard_violations`。
4. `GUARDRAIL_MODE=warn_only` 只影响 Agent 输出质量规则；OutboundDispositionGuard 永远 enforce，任何配置都不能允许分析内容出站。
5. 编写测试增加：在 reason/parameters/raw 批量注入 report、prompt、trace、evidence、API key，确认写回前全部被阻断或秘密脱敏。

验收标准：
1. 引用不存在证据的 Agent 输出被 grounding 规则以 block 级拦截并抛 `GuardrailViolationError`。
2. 处置动作 target 不在 EntitySet 时被拦截。
3. block 违规写入 `guard_violations` 且 Agent 轨迹为 failed。
4. GUARDRAIL_MODE=warn_only 只放宽 Agent 输出质量规则；OutboundDispositionGuard 违规始终抛错并阻止 outbox。

测试与验证：
`cd backend && pytest tests/test_core/test_guardrails.py -v`。

降级策略：
普通 OutputGuard 可 warn-only；OutboundDispositionGuard 必须 fail-closed，其自身异常同样阻止 outbox 创建/发送并升级人工。

---

### ISSUE-031：上下文压缩与溢出保护（PromptBudgeter 与 ContextCompressor）

优先级：
P1

目标：
建立 LLM 提示词的 token 预算与溢出保护：估算 token、在预算内拼装提示、超限时按优先级摘要或滑窗压缩历史与证据，避免超出模型上下文窗口。完成后长事件的 LLM 调用稳定不溢出。

前置依赖：
ISSUE-027、ISSUE-029

输入上下文：
ISSUE-027 `LLMClient` 与 `LLMMessage`；ISSUE-029 预算约束；各 Agent 在调用 LLM 前构造提示。

文件范围：
1. `backend/app/core/context_compressor.py`：`PromptBudgeter`、`ContextCompressor`
2. `backend/app/core/llm/base.py`（提供 token 估算工具 `estimate_tokens`）
3. `backend/tests/test_core/test_context_compressor.py`

统一命名：
1. `estimate_tokens(text: str) -> int`（启发式：CJK 字符按 1 token、其余按 4 字符 1 token 近似，确定性）
2. `PromptBudgeter.fit(messages, max_input_tokens) -> list[LLMMessage]`：在预算内裁剪，超限触发压缩
3. `ContextCompressor` 方法：`summarize_evidence(evidence_list, max_tokens) -> str`（规则摘要：按 confidence 与时间保留要点）、`sliding_window(history, max_items) -> list`、`compress_context(event_context, max_tokens) -> dict`
4. 压缩优先级固定：先滑窗裁剪历史对话，再摘要证据，再截断原始数据，系统提示与当前目标不动

实现步骤：
1. 实现确定性 `estimate_tokens`（不依赖外部分词器，CJK 字符按 1 token、其余按每 4 字符 1 token 近似）。
2. 实现 `PromptBudgeter.fit`：计算总 token，超 `max_input_tokens` 时按优先级压缩直至达标，无法达标则硬截断并标注 `compressed=true`。
3. 实现 `ContextCompressor` 三个方法；证据摘要为规则式（不强制依赖 LLM），可选 LLM 摘要在不可用时回退规则式。
4. 约定接入：依赖 LLM 的 Agent 在构造 messages 后统一过 `PromptBudgeter.fit`；P0 Agent 在本 Issue 未完成时使用朴素截断兜底。
5. 编写测试：token 估算确定性、超长输入被压缩到预算内、压缩优先级顺序、证据摘要保留高 confidence 要点、系统提示不被裁剪。

验收标准：
1. 超长 messages 经 `fit` 后总 token 不超过给定上限。
2. 压缩按"历史、证据、原始数据"优先级进行且系统提示保留。
3. `estimate_tokens` 对相同输入确定且单调。
4. 证据摘要保留 confidence 最高的若干条。

测试与验证：
`cd backend && pytest tests/test_core/test_context_compressor.py -v`。

降级策略：
压缩组件不可用时各 Agent 回退朴素尾部截断（保留系统提示与目标），主链路不中断；本 Issue 未完成不影响 P0（P0 Agent 自带截断兜底）。

---

### ISSUE-032：TriageAgent 实现

优先级：
P0

目标：
实现分诊 Agent：解析告警、抽取实体（LLM 主路径 + 正则降级）、判定事件类型与初始严重度、产出 IOC 列表，并预留误报匹配钩子。完成后事件可从 NEW 进入研判流程。

前置依赖：
ISSUE-015、ISSUE-027、ISSUE-028

输入上下文：
ISSUE-005 的 `TriageResult`；ISSUE-002 的 EntitySet 与 EventType；MockLLM 的 prompt_key 为 `triage_extract`。

文件范围：
1. `backend/app/agents/triage_agent.py`：`TriageAgent`
2. `backend/app/agents/prompts/triage_prompt.py`
3. `backend/app/agents/rules/entity_extraction_rules.py`：正则规则集
4. `backend/tests/test_agents/test_triage_agent.py`

统一命名：
1. `TriageAgent.agent_name = "triage_agent"`；输入为 `SecurityEvent` 与冻结的规范化 `EventContext.source_snapshot`，输出 `TriageResult`；只有 file fallback 才读取兼容字段 `raw_alert_snapshot`
2. 钩子列表：`pre_triage_hooks`、`post_triage_hooks`（继承 BaseAgent 的 pre_hooks、post_hooks 命名为别名），钩子输出只能写 EventContext 的 `false_positive_match` 字段，不得直接改事件状态
3. 严重度规则常量：`SEVERITY_RULES`（数据外泄类加外部 IP 为 high；恶意进程类为 high；单次登录失败为 low；默认 medium）
4. `need_investigation`：severity 为 medium 及以上为 true

实现步骤：
1. 实现告警解析：从冻结的规范化 `source_snapshot` 读取事件/告警类型与关键字段，映射到 EventType 枚举；file fallback 才从 `raw_alert_snapshot` 读取兼容 alert_type。
2. 实现 LLM 实体抽取：JSON mode 输出 EntitySet（prompt 含实体类型定义与 2 个 few-shot 示例）；超时 15 秒。
3. 实现正则降级：IP、域名、账号、主机名、文件名、进程名六类正则；LLM 失败时启用并置 `degraded=true`。
4. 实现严重度规则引擎与 IOC 提取（IP、域名、文件 hash、URL）。
5. 执行 pre 与 post 钩子；P0 默认注册 `RuleBasedFalsePositiveHook`（按场景/fixture 稳定签名写 `false_positive_match`，不依赖向量库）；ISSUE-078 交付后替换/叠加为完整 Matcher。输出写 EventContext 的 `triage_result` 字段。
6. 编写测试：主场景实体抽取（断言 zhangsan、PC-FIN-023、45.153.12.88 被抽出）、LLM 异常降级、各严重度规则分支、空告警处理、RuleBasedFalsePositiveHook 对 account_anomaly_fp 签名写出 close_as_fp。

验收标准：
1. 主场景告警抽取出至少账号、主机、IP、域名四类实体。
2. 主场景 severity 判定为 high 或 critical 且 `need_investigation=true`；单次登录失败告警为 low 且 false。
3. Mock LLM 抛异常时正则降级生效且结果可用。
4. TriageResult 写入 EventContext 且 agent_trace 有记录。

测试与验证：
`cd backend && pytest tests/test_agents/test_triage_agent.py -v`（LLM_MODE=mock）。

降级策略：
LLM 不可用时自动切换正则抽取与规则严重度判定，`TriageResult.degraded=true`，主链路不中断。

---

### ISSUE-033：EvidenceAgent 顺序证据采集

优先级：
P0

目标：
实现证据采集 Agent 的顺序版本：按固定顺序调用 7 路查询工具，解析为 Evidence 列表，完成去重与时间线排序。先保证逻辑正确，并发升级由 ISSUE-034 完成。

前置依赖：
ISSUE-019、ISSUE-024、ISSUE-028、ISSUE-032

输入上下文：
ISSUE-005 的 `EvidenceOutput`；输入为 EventContext 中的 `triage_result`（实体与时间范围）；7 路查询顺序固定：query_account_login、query_edr_process、query_file_access、query_network_flow、query_dns、query_asset_info、query_threat_intel。

文件范围：
1. `backend/app/agents/evidence_agent.py`：`EvidenceAgent`
2. `backend/app/agents/evidence_parser.py`：`EvidenceParser`
3. `backend/tests/test_agents/test_evidence_agent.py`

统一命名：
1. `EvidenceAgent.agent_name = "evidence_agent"`；输出 `EvidenceOutput`
2. `EvidenceParser.parse(tool_name, tool_result) -> list[Evidence]`：source 映射固定（query_account_login 对应 identity、query_edr_process 对应 endpoint、query_file_access 对应 data_security、query_network_flow 对应 network_flow、query_dns 对应 dns、query_asset_info 对应 asset、query_threat_intel 对应 threat_intel）
3. 去重键：`(source, evidence_type, timestamp)`，保留 confidence 较高者
4. `collection_status` 判定：成功源数 5 至 7 为 completed；3 至 4 为 partial_done（置信度惩罚 0.10）；1 至 2 为 degraded（惩罚 0.25）；0 为 failed

实现步骤：
1. 从 EventContext 读取实体与时间范围，按固定顺序经 ToolExecutor 串行调用 7 路查询，单路失败记入 `failed_sources` 不中断。
2. 实现 EvidenceParser：把工具数据逐条转为 Evidence（描述用模板生成，如"账号 {account} 于 {time} 从 {ip} 登录"）。
3. 实现去重与按 timestamp 升序排序（精度截到秒）。
4. 计算 `overall_confidence`：证据平均 confidence 乘 0.75 加来源多样性奖励（min(unique_sources, 5) / 5.0 * 0.15）加数量奖励（min(count, 6) / 6.0 * 0.1）减状态惩罚；结果再 `min(1.0, ...)` 截断，保证不超过 1。
5. 将 evidence_list 批量 upsert 到 `evidence` 表（冲突键 `(event_id, evidence_id)` 保留 confidence 较高者），确保后续 GraphAgent 边回链、StorylineService TimelineEntry.evidence_id 查询可达。
6. 输出写 EventContext 的 `evidence_output` 字段。
7. 编写测试：7 路全成功、2 路失败（partial_done）、全失败（failed）、去重与排序正确性、evidence 表写入条数与 evidence_list 一致。

验收标准：
1. 主场景下至少 5 个数据源返回有效证据且时间线单调递增。
2. 部分失败时 collection_status 与惩罚值符合判定规则。
3. EvidenceOutput 写入 EventContext 且 evidence 表可查到全部 evidence_id，agent_trace 记录含每路查询耗时。

测试与验证：
`cd backend && pytest tests/test_agents/test_evidence_agent.py -v`。

降级策略：
任意单路工具失败仅记入 failed_sources；全部失败时输出 `collection_status="failed"` 并由上游决定是否升级人工，不抛异常。

---

### ISSUE-034：EvidenceAgent 并发采集与证据冲突检测

优先级：
P0

目标：
把证据采集升级为 asyncio.gather 并发模式（全局超时 30 秒、单源超时 10 秒），并实现三规则证据冲突检测与置信度惩罚。完成后证据采集延迟显著下降且具备冲突处理亮点。

前置依赖：
ISSUE-033

输入上下文：
ISSUE-033 的顺序实现与解析器；工作流常量 `GLOBAL_EVIDENCE_TIMEOUT_S`、`SINGLE_SOURCE_TIMEOUT_S`；`EVIDENCE_MODE` 环境变量（sequential、concurrent，默认 concurrent）。

文件范围：
1. `backend/app/agents/evidence_agent.py`（升级）
2. `backend/app/agents/conflict_detector.py`：`ConflictDetector`
3. `backend/tests/test_agents/test_evidence_concurrent.py`

统一命名：
1. `ConflictDetector.detect(evidence_list) -> list[EvidenceConflict]`；`EvidenceConflict` 字段：`conflict_id`、`rule_name`、`severity`（high、medium 两值）、`evidence_ids`、`description`
2. 三条冲突规则名固定：`iam_absent_but_edr_active`（identity 无登录但 endpoint 有该账号进程，high）、`network_silent_but_dlp_upload`（network_flow 无外联但 data_security 有上传，medium）、`asset_isolated_but_edr_active`（asset 标记隔离但 endpoint 有进程活动，high）
3. 冲突证据 confidence 乘惩罚因子 0.7 且 `is_conflicting=true`

实现步骤：
1. 把 7 路查询封装为任务列表，`asyncio.gather(*tasks, return_exceptions=True)` 并发执行，外层 `asyncio.wait_for` 全局 30 秒；单路超时由 ToolExecutor 的 timeout_s=10 控制。
2. 全局超时后保留已完成结果，未完成源记入 failed_sources。
3. 实现 ConflictDetector 三条规则；冲突写入 `EvidenceOutput.conflicts` 并应用惩罚。冲突检测完成后同步更新 `evidence` 表中受影响行的 `is_conflicting=true` 与降权后 `confidence`，确保 evidence 表与内存态一致。
4. 失败源生成 `EvidenceGap`（字段 `source`、`impact`、`description`）。
5. 保留 `EVIDENCE_MODE=sequential` 配置开关用于调试。
6. 编写测试：并发与顺序结果一致性、全局超时、注入主场景矛盾数据触发 `iam_absent_but_edr_active`、置信度计算、evidence 表 is_conflicting 与 confidence 与内存态一致。

验收标准：
1. 并发模式 7 路总耗时不超过最慢单路加 2 秒。
2. 主场景的 2 条矛盾数据触发至少 1 个 high 冲突且对应证据被降权。
3. 全局超时后已完成的查询结果仍被保留。

测试与验证：
`cd backend && pytest tests/test_agents/test_evidence_concurrent.py -v`。

降级策略：
并发路径异常时可经 `EVIDENCE_MODE=sequential` 回退顺序模式；冲突检测失败不阻塞采集，仅记录告警并跳过惩罚。

---

### ISSUE-035：RiskAgent 六维风险评分

优先级：
P0

目标：
实现风险评分 Agent：六维加权评分的 LLM 与规则双路计算、置信度校准与严重等级映射。完成后事件具备 0-100 风险分与四级严重度。

前置依赖：
ISSUE-015、ISSUE-027、ISSUE-028、ISSUE-034

输入上下文：
ISSUE-005 的 `RiskAssessment` 与 `RiskFactor`；输入为 EventContext 的 `evidence_output`、`triage_result`，以及可选的 `storyline` 与 `rag_output`（缺失时按无增强计算）；MockLLM prompt_key 为 `risk_score`。

文件范围：
1. `backend/app/agents/risk_agent.py`：`RiskAgent`
2. `backend/app/agents/risk_scoring_engine.py`：`RiskScoringEngine`（规则路）
3. `backend/app/agents/prompts/risk_prompt.py`
4. `backend/app/agents/confidence_calibration.py`：`calibrate_confidence`
5. `backend/app/agents/verdict_resolver.py`：P0 `VerdictResolver`
6. `backend/tests/test_agents/test_risk_agent.py`、`test_verdict_resolver.py`

统一命名：
1. `RiskAgent.agent_name = "risk_agent"`；输出 `RiskAssessment`
2. 六维 factor_name 与权重固定：`asset_impact` 0.25、`behavior_anomaly` 0.20、`evidence_confidence` 0.20、`attack_stage` 0.15、`data_sensitivity` 0.10、`threat_intel` 0.10
3. 双路合并公式：`final = 0.6 * llm_score + 0.4 * rule_score`（按维度合并）；LLM 失败时 `scoring_mode="rule_only"`，规则分占 100%
4. 置信度校准：`calibrated = min(1.0, raw_confidence / temperature)`，temperature 默认 1.2 可配置
5. 严重等级映射按简介第 4.6 节分数区间
6. `VerdictResolver.resolve(risk_assessment, false_positive_match=None, rag_output=None)`：优先级固定（与 ISSUE-047 一致，P0 即生效）——`false_positive_match.recommendation=close_as_fp` → `false_positive`；否则若具备受控高置信误报证据且 risk_score < 40 → `false_positive`；中等误报信号 → `possible_false_positive`；risk_score >= 70 → `confirmed_threat`；其余 → `none`。**不得**在已有 close_as_fp 时因 risk_score>=70 覆盖为 confirmed_threat。

实现步骤：
1. 实现规则引擎：asset_impact 按资产价值映射（critical=100、high=75、medium=50、low=25）；behavior_anomaly 按异常行为类型叠加；evidence_confidence 取 EvidenceOutput.overall_confidence 乘 100；attack_stage 按证据 mitre_technique 映射阶段位置（越接近 Exfiltration 或 Impact 越高）；data_sensitivity 按敏感标签映射（restricted=100、confidential=75、internal=50、public=25，批量访问加成）；threat_intel 按情报 reputation 与标签。
2. 实现 LLM 路：JSON mode 只要求每维提供可展示的简短证据依据与分数，不请求或保存隐藏思维链，输出裁剪到 0-100。
3. 合并双路、校准置信度、映射 severity，每维输出 RiskFactor（含 reasoning）。
4. 输出写 EventContext 的 `risk_assessment` 字段，同步回写 `SecurityEvent.risk_score`、`severity`、`confidence`；随后调用 P0 VerdictResolver 并统一经 EventService.set_final_verdict 落库/发布，确保高风险主链不会以 final_verdict=none 结案。
5. 编写测试：主场景分数不低于 70 且 verdict=confirmed_threat、误报场景分数低于 40、LLM 失败规则兜底、边界值（全 0 与全 100）、severity 区间映射及 verdict 唯一写入口。

验收标准：
1. 主场景 risk_score 不低于 70 且 severity 为 high 或 critical。
2. LLM 失败时 `scoring_mode="rule_only"` 且流程不中断。
3. 六维 RiskFactor 权重和为 1.0 且每维含 reasoning。
4. 校准后 confidence 不超过 1.0 且低于原始值（temperature 大于 1 时）。

测试与验证：
`cd backend && pytest tests/test_agents/test_risk_agent.py -v`。

降级策略：
LLM 不可用时使用纯规则评分；`rag_output` 与 `storyline` 缺失时对应维度按基线计算，不阻塞评分。

---

### ISSUE-036：ReportAgent 结构化报告生成（15 章节）

优先级：
P0

目标：
实现报告 Agent：从 EventContext 汇总全部研判数据生成 15 章节 Markdown 报告与结构化 JSON，LLM 生成为主、Jinja2 模板降级，持久化到 report 表。

语义补丁（ISSUE-204）：`EventStatus.REPORTING` 表示报告阶段可达，不蕴含报告字节已存在；跳过 ReportAgent 时须持久化 `report_generated=false`，guidance 显示「分析完成·报告未生成」（禁止「报告生成中」）。

前置依赖：
ISSUE-018、ISSUE-027、ISSUE-028、ISSUE-035

输入上下文：
ISSUE-002 的 `InvestigationReport`；EventContext 全字段；MockLLM prompt_key 为 `report_generate`。处置与验证章节在数据缺失时使用占位文案。

文件范围：
1. `backend/app/agents/report_agent.py`：`ReportAgent`
2. `backend/app/agents/prompts/report_prompt.py`
3. `backend/app/agents/templates/report_template.md.j2`
4. `backend/app/agents/report_section_builder.py`：`ReportSectionBuilder`
5. `backend/tests/test_agents/test_report_agent.py`

统一命名：
1. `ReportAgent.agent_name = "report_agent"`；输出 `InvestigationReport`（字段 `report_id`、`event_id`、`report_markdown`、`report_json`、`generated_by`（llm、template 两值）、`generated_at`、`content_sha256`）
2. 15 章节 key 固定（report_json 的 sections 数组按序）：`overview`、`severity_level`、`risk_scoring`、`involved_accounts`、`involved_assets`、`involved_processes`、`involved_files`、`involved_external_addresses`、`evidence_chain`、`attack_storyline`、`attack_mapping`、`executed_actions`、`verification_results`、`recommendations`、`appendix_index`
3. 占位文案常量：`PLACEHOLDER_NO_ACTIONS = "暂无处置动作"`、`PLACEHOLDER_NO_VERIFICATION = "暂无验证结果"`、`PLACEHOLDER_LOW_RISK_NO_EVIDENCE = "低危快结案：未执行证据采集"`

实现步骤：
1. ReportSectionBuilder 按 ToolCategory=response 统计处置，不锁死名称；执行章节分别列 action_status、效果验证、writeback_status 与外部回执引用。报告正文只保存在 ShadowTrace，不进入 DispositionCommand。
2. 实现 LLM 生成：对证据做摘要后入 Prompt（控制 token），recommendations 章节要求 3 至 5 条具体建议；超时 30 秒。
3. 实现模板降级：Jinja2 渲染同样 15 章节。
4. 计算 content_sha256，用稳定 `report_id=report_id_for_event(event_id)` 写 report 表与 EventContext 的 `report` 字段，经 EventBus 发布 `report_generated`。同一 event_id 的报告必须按该 report_id 幂等 upsert（disposition-only 快路径可能已有 triage 阶段报告，REPORTING 只刷新处置/写回章节与 content_sha256，不插入第二行）。同时向 `action` 表写入一条系统级 Action（`action_category=system`、`action_name=generate_report`、`tool_name` 为空、`action_level=L0`、`target="system"`、`parameters={}`、`status=SUCCESS`、`auto_execute=true`、`writeback_required=false`、`writeback_applicable=false`、`writeback_readiness=NOT_REQUIRED`、`writeback_status=null`、`reason="报告自动生成"`、`impact_assessment` 为空、`executed_at` 为当前时间、`source_action_id` 为空）；同一闭环周期重复进入 REPORTING 时 generate_report Action 亦按 fingerprint 幂等，不重复插入。
5. 编写测试：15 章节齐全且非空、关键信息正确（事件类型、实体名、分数）、模板降级、数据缺失时占位生效。

验收标准：
1. 报告恰好含 15 个章节且顺序与 key 固定。
2. 主场景报告包含 zhangsan、PC-FIN-023、45.153.12.88 等关键信息与六维评分明细。
3. LLM 失败时模板报告生成成功且 `generated_by="template"`。
4. 报告持久化后可按 report_id 与 event_id 查询。

测试与验证：
`cd backend && pytest tests/test_agents/test_report_agent.py -v`。

降级策略：
LLM 不可用时 Jinja2 模板渲染兜底；个别章节数据缺失时输出占位文案，不阻塞报告生成。

---

### ISSUE-037：事件状态流转服务 StateMachineService

优先级：
P0

目标：
实现状态机驱动的状态流转服务：合法性校验、行级锁更新、审计日志、EventContext 同步与消息发布，并处理 CLOSED、WAITING_APPROVAL、REPLANNING 的特殊副作用。

前置依赖：
ISSUE-007、ISSUE-015、ISSUE-028

输入上下文：
ISSUE-007 的校验函数与常量；ISSUE-013 的 EventBus 与 ContextStore；ISSUE-028 的 EventAuditLogService。

文件范围：
1. `backend/app/services/state_machine_service.py`：`StateMachineService`
2. `backend/tests/test_services/test_state_machine_service.py`

统一命名：
1. 方法：`async transition(event_id, target_status, operator, reason, context: TransitionContext | None = None) -> None`（调用方 context 只能提供待验证的业务输入，不能设置 disposition_only_intent、写回已完成或 force 标志；这些值必须从 DB/EventContext/认证主体重算）、`async force_close(event_id, principal, reason) -> None`（唯一管理员强制本地关闭入口，内部写 external_unsynced=true）、`async get_current_status(event_id) -> EventStatus`、`async get_transition_history(event_id)`
2. operator 取值约定：Agent/受信服务名，或人工操作的 `principal:{subject}`；不得用无法追责的笼统 `manual`，system_timeout 等自动主体使用固定受信服务标识。
3. 特殊副作用：任何转入 CLOSED 的请求先执行 ISSUE-007 的报告/required 写回硬门禁，再设置 `closed_at`、将完整 EventContext 序列化为 JSON 写入 `security_event.event_context_snapshot`（供 Redis TTL 过期后按需读取）并调用 `set_closed_ttl`；转入 REPLANNING 时 `security_event.replan_count` 自增并校验不超过 `MAX_REPLAN_COUNT`，同时经 `EventContextStore.set` 将更新后的 `replan_count` 写入 EventContext（journal 持久化），确保 `rebuild_context`/`refresh_closed_snapshot` 覆盖逻辑与 journal 值一致（进入 REPLANNING 由已有的 `state_change` 消息表达，不新增事件类型）；转入 WAITING_APPROVAL 时仅发布 `state_change`（`approval_required` 由 ApprovalEngine 按 action 粒度发布，携带完整 payload，StateMachineService 不重复发布）。管理员 `force_local_close` 请求只能映射到本服务的 `force_close` 显式分支，认证、未同步标记和审计都在本服务完成；禁止经普通 `transition` 传入 force。

实现步骤：
1. 实现 transition：行锁读当前状态；从 DB/EventContext 构造 TransitionContext。TRIAGING→PLANNING_RESPONSE 时读取由 WorkflowRuntimeService 预先持久化的 disposition_only_intent，并重算事件政策、来源定位和 readiness，不要求尚未生成的 Action；Action 生成后的后续转移再回查当前 plan_revision，确认全部 response Action 均为 update_source_event_disposition。进入 CLOSED 时在同一行锁事务内重算报告与 required 写回门禁。调用方传入 context 只能收窄权限，服务端不能信任客户端布尔值或完成声明。
2. 实现三类特殊副作用。
3. 高置信度误报路径：只有 disposition_policy=not_required 时允许 TRIAGING 直达 CLOSED；required 时必须先走 disposition_only 链并确认 EVENT_STATUS_UPDATE。审计 reason 必须含匹配案例 ID。
4. 编写测试：完整生命周期流转、Action 生成前 disposition_only 合法边、伪造 intent 拒绝、所有入口的 CLOSED 写回门禁、管理员强制本地关闭审计、verdict 组合拒绝、REPLANNING 超限拒绝、审计与消息断言、并发转移竞态（两个协程同时转移只成功一个）。

验收标准：
1. 主路径 NEW 至 CLOSED 全链路合法流转且每步有审计记录。
2. 非法转移抛 `InvalidStateTransitionError` 且库内状态不变。
3. `replan_count` 达 3 后再次转入 REPLANNING 被拒绝。
4. 并发转移不产生脏状态。

测试与验证：
`cd backend && pytest tests/test_services/test_state_machine_service.py -v`。

降级策略：
EventBus 发布失败仅记录警告；`EventContextStore.set` 同步 `state_history` 返回 `SetResult(redis_ok=false)` 时在 `security_event.degraded_flags` 中标记 `redis_context_unavailable=true`，不回滚数据库（PostgreSQL 为事实来源）。

---

### ISSUE-038：事件生命周期 API 实现

优先级：
P0

目标：
把 ISSUE-004 的占位端点替换为真实实现：创建事件、触发研判（顺序管线后台执行）、查询事件、关闭事件、获取报告、轨迹与审计日志。完成后基础闭环可全程通过 HTTP 驱动。

前置依赖：
ISSUE-004、ISSUE-032、ISSUE-033、ISSUE-035、ISSUE-036、ISSUE-037

输入上下文：
ISSUE-015 EventService、ISSUE-037 StateMachineService、四个核心 Agent；编排器接入前以顺序管线驱动（SuperAgent 在 ISSUE-054 接管）。

文件范围：
1. `backend/app/api/v1/events.py`（真实实现）
2. `backend/app/services/analysis_only_pipeline.py`：`AnalysisOnlyPipeline`（临时只分析顺序管线）
3. `backend/tests/test_api/test_events_api.py`

统一命名：
1. `AnalysisOnlyPipeline.run(event_id)`：仅按 TriageAgent、EvidenceAgent、RiskAgent、ReportAgent 顺序执行并经 StateMachineService 推进分析状态。它只允许 `ALLOW_LIVE_SIDE_EFFECTS=false` 且 `ALLOW_XDR_WRITEBACK=false` 的开发/离线模式；需要处置的高风险事件生成报告后保持 REPORTING 并标 `analysis_only_complete=true`，不能因为报告生成就标记为 CLOSED。
2. `POST /api/v1/events/{event_id}/investigate` 返回 202 与 `{"task_id": event_id}`，用 FastAPI BackgroundTasks 执行（Celery 接入见 ISSUE-056）
3. 错误码增加 `writeback_pending`、`writeback_failed`、`writeback_conflict`、`writeback_unsupported`、`disposition_permission_denied`。

实现步骤：
1. 实现 11 个端点接入真实服务：POST /events、GET /events、GET /events/{id}、POST /events/{id}/investigate、POST /events/{id}/close、GET /events/{id}/report、GET /events/{id}/traces、GET /events/{id}/audit-logs、GET /events/{id}/tool-calls、GET /events/{id}/actions（含 status 过滤，查询 action 表返回 ActionListResponse）、GET /tool-calls（全局工具调用审计，支持 tool_name、status 过滤与分页）。
2. close 只允许 REPORTING→CLOSED、FAILED→REPORTING→CLOSED、或 TRIAGING 下 **disposition_policy=not_required** 的无需调查/高置信误报快结案；其他中间态拒绝。**required 误报不得经本端点直关**，须走 disposition-only 编排链（`begin_disposition_only`→审批→空 IMMEDIATE→VERIFYING→终态写回）。若请求改变 final_verdict，必须经 EventService.set_final_verdict 并重新生成报告后再关闭。另检查 disposition_policy 与 required writeback：PENDING/SENDING/ACCEPTED/UNKNOWN 返回 writeback_pending；PARTIAL/FAILED 返回 writeback_failed；CONFLICT 返回 writeback_conflict；required 但没有 disposition Action/能力则返回 writeback_unsupported。仅管理员 force_local_close 可本地关闭并留下外部未同步标识。只有 file/manual 或显式 not_required 的低危/误报无 Action 才可直接本地关闭。
3. 实现 AnalysisOnlyPipeline：逐 Agent 执行、状态推进、`need_investigation=false` 时允许本地短路关闭；短路关闭前必须调用 ReportAgent 生成标准 15 章节低危快结案报告（证据、处置、验证章节使用占位文案，overview 与 recommendations 说明低危原因），写 report 表与 EventContext 的 `report` 字段并发布 `report_generated`。任何要求外部处置的事件不得通过该管线宣称生产闭环完成。
4. 错误处理映射统一错误体。
5. 编写 API 测试：创建返回 201、高风险 analysis_only 研判 202 后轮询至 REPORTING、not_required 低危轮询至 CLOSED、详情与库一致、分页过滤、404/400 及 close 写回门禁。

验收标准：
1. 通过 API 完成"创建、研判、查报告"分析流程（LLM_MODE=mock）；高风险 analysis_only 事件最终为 REPORTING 且报告可查，只有 not_required 低危/误报可 CLOSED。生产处置 CLOSED 由 ISSUE-064 验收。
2. 分页响应 total、page、page_size、items 字段正确。
3. traces 与 audit-logs 端点返回该事件完整记录。

测试与验证：
`cd backend && pytest tests/test_api/test_events_api.py -v`。

降级策略：
BackgroundTasks 模式下进程重启会丢失进行中任务，状态保持在中间态；ISSUE-056 引入 Celery 后由租约与检查点恢复。

---

### ISSUE-039：基础闭环集成测试（告警到报告）

优先级：
P0

目标：
对"告警输入、分诊、证据、评分、报告"的研判闭环（到报告，不含处置执行）编写集成测试，覆盖黄金路径、低危短路、数据源降级与 LLM 降级四类场景。处置、审批、执行、验证、回滚闭环由 ISSUE-064 端到端覆盖，两者共同构成 P0 主链路。

前置依赖：
ISSUE-014、ISSUE-017、ISSUE-029、ISSUE-030、ISSUE-038

输入上下文：
ISSUE-011 三个场景包；MockLLM golden 响应；ISSUE-038 的 API 与管线。

文件范围：
1. `backend/tests/integration/test_e2e_basic_loop.py`
2. `backend/tests/integration/conftest.py`（扩展 Mock LLM fixtures）

统一命名：
1. pytest 标记：`@pytest.mark.e2e_basic`

实现步骤：
1. 场景一（黄金路径）：摄取主场景并走 analysis_only，断言状态序列 NEW、TRIAGING、COLLECTING_EVIDENCE、ANALYZING、SCORING、REPORTING，且不会出现 CLOSED；EventContext 的 P0 分析输出非空、risk_score 不低于 70、verdict=confirmed_threat、报告含关键信息并标 analysis_only_complete。
2. 场景二（低危短路）：使用 disposition_policy=not_required 的 file fallback 单次登录失败告警，断言 NEW、TRIAGING、CLOSED 且无证据采集；同时断言 report 表与 EventContext.report 均存在标准 15 章节低危快结案报告。XDR required 的低危/误报状态同步由 ISSUE-078 专项覆盖，不能复用本地直关断言。
3. 场景三（数据源降级）：打桩 3 个查询工具失败，断言 collection_status=partial_done，仍生成报告并按风险停在 REPORTING 或合法本地关闭。
4. 场景四（LLM 降级）：打桩 LLM 全部失败，断言正则分诊、规则评分、模板报告兜底，且不因降级绕过处置/写回门禁。
5. 断言全程 agent_trace 与 event_audit_log 完整。
6. 断言健壮性接线：研判后 budget_usage 非空、黄金路径 guard_violations 为空、各 Agent 无工作记忆越权。ConvergenceGuard 尚未交付，不在本 Issue 前向依赖；ISSUE-052 完成后由 ISSUE-055/064 复跑并追加 total_steps 断言。

验收标准：
1. 4 个场景全部通过，黄金路径端到端 60 秒内完成（mock 模式）。
2. CI 可运行（`pytest -m e2e_basic`）。
3. 黄金路径预算用量已记录、无 block 级护栏违规、无工作记忆越权写；ISSUE-052 接入后的复跑再要求 total_steps 在 GLOBAL_MAX_STEPS 内。

测试与验证：
`cd backend && pytest tests/integration/test_e2e_basic_loop.py -m e2e_basic -v`。

降级策略：
无

---

### ISSUE-040：Socket.IO 实时事件推送

优先级：
P1

目标：
实现基于 python-socketio 的实时推送并定义全部 16 种事件 payload Schema。

前置依赖：
ISSUE-013、ISSUE-037

输入上下文：
简介第 4.2 节 SocketEventEnvelope 与事件类型枚举；Redis Pub/Sub 频道（简介第 4.7 节）。

文件范围：
1. `backend/app/core/socketio_manager.py`：`SocketIOManager`
2. `backend/app/core/socketio_events.py`：事件处理与房间管理
3. `contracts/socketio/events.schema.json`
4. `backend/tests/test_api/test_socketio.py`

统一命名：
1. 命名空间：`/events`；房间名：`event:{event_id}` 与全局房间 `global`
2. 信封字段：`type`、`event_id`、`sequence`（按 event_id 单调递增）、`timestamp`、`payload`
3. 16 种事件在 events.schema.json 定义；writeback_updated 只含 disposition_id、writeback_id、status、provider_code 和时间，不含 raw_result。

实现步骤：
1. 用 `socketio.AsyncServer` 挂载到 FastAPI ASGI 应用（`socketio.ASGIApp`）。
2. 实现连接、断开与 join 房间逻辑：连接建立时服务端自动 `enter_room(sid, "global")`（无需客户端请求）；客户端发送 `subscribe` 事件携带 event_id 加入 `event:{event_id}` 房间。
3. 后台任务 `PSUBSCRIBE shadowtrace:events:*` 订阅全部事件 Redis Pub/Sub 频道，把总线消息转为统一信封并广播至对应 `event:{event_id}` 房间与 `global` 房间。
4. sequence 用 Redis INCR 按 event_id 维护。
5. 编写 events.schema.json 覆盖 16 种类型并逐一做信封与脱敏测试。

验收标准：
1. 触发一次状态转移后订阅客户端 1 秒内收到 `state_change` 消息。
2. 16 种事件类型在 Schema 文件中全部定义且测试逐一校验。
3. 多客户端订阅同一事件房间均能收到广播。

测试与验证：
`cd backend && pytest tests/test_api/test_socketio.py -v`。

降级策略：
Socket.IO 不可用时前端回退轮询 REST API（看板与详情页均不以推送为硬前置）；推送丢失不影响后端状态。

---

### ISSUE-041：嵌入服务与知识库向量存储（pgvector 主路径）

优先级：
P1

目标：
实现统一嵌入服务 EmbeddingService（mock、local、remote 三模式）与基于 pgvector 的知识块存储 KnowledgeStore，提供向量写入与相似度检索能力。完成后四类知识库具备统一的存取底座。

前置依赖：
ISSUE-003

输入上下文：
环境变量 `EMBEDDING_MODE`（mock、local、remote）；pgvector 扩展已在 ISSUE-003 启用；嵌入维度统一 1024。

文件范围：
1. `backend/app/core/embedding/service.py`：`EmbeddingService`
2. `backend/app/core/embedding/mock_embedder.py`：`MockEmbedder`
3. `backend/app/db/orm/knowledge.py`：`KnowledgeChunkORM`
4. `backend/migrations/versions/0002_knowledge_chunk.py`
5. `backend/app/services/knowledge_store.py`：`KnowledgeStore`
6. `backend/tests/test_core/test_embedding.py`、`backend/tests/test_services/test_knowledge_store.py`

统一命名：
1. `EmbeddingService` 方法：`async embed_texts(texts: list[str]) -> list[list[float]]`、`async embed_query(text: str) -> list[float]`；维度常量 `EMBEDDING_DIM = 1024`
2. `MockEmbedder`：对文本 SHA256 做确定性伪随机投影生成 1024 维单位向量（同文本同向量）
3. `knowledge_chunk` 表字段：`chunk_id`（格式 `chk-{8位十六进制}`）、`kb_name`、`content`、`metadata`（JSONB）、`embedding`（vector(1024)）、`created_at`；`kb_name` 枚举固定：`attack_kb`、`fp_case_kb`、`history_case_kb`、`playbook_kb`
4. `KnowledgeStore` 方法：`async upsert_chunks(kb_name, chunks: list[KnowledgeChunk])`、`async vector_search(kb_name, query_embedding, top_k=10) -> list[RetrievedChunk]`、`async keyword_search(kb_name, query_text, top_k=10) -> list[RetrievedChunk]`、`async count(kb_name) -> int`
5. `RetrievedChunk` 字段：`chunk_id`、`kb_name`、`content`、`metadata`、`score`、`retrieval_method`（vector、keyword 两值）

实现步骤：
1. 实现 MockEmbedder（零外部依赖、完全确定性）与 remote 模式（OpenAI-compatible embeddings 端点，httpx）；local 模式与 remote 共用协议、指向本地端点。
2. 编写 Alembic 迁移：建表、`ivfflat` 余弦索引、`kb_name` 索引、content 的 GIN 全文索引（`to_tsvector('simple', content)`）。
3. 实现 KnowledgeStore：批量 upsert（按 chunk_id 幂等）、余弦相似度检索（`embedding <=> :q` 排序）、PostgreSQL 全文检索（ts_rank 排序）。
4. 编写测试：mock 嵌入确定性、upsert 幂等、向量检索召回（相同文本最近邻）、关键词检索、kb_name 隔离。

验收标准：
1. `EMBEDDING_MODE=mock` 下嵌入完全确定且无网络请求。
2. 写入 100 条样例后向量检索 top_k 返回有序结果且同文本得分最高。
3. 不同 kb_name 的数据互不可见。

测试与验证：
`cd backend && pytest tests/test_core/test_embedding.py tests/test_services/test_knowledge_store.py -v`。

降级策略：
只有显式 `EMBEDDING_MODE=mock` 的测试/演示环境可使用 MockEmbedder。remote/local 不可用时禁止自动改用伪随机 Mock 向量，RAG 管线标注 `vector_unavailable` 并回退纯关键词检索；若关键词也不可用则返回无增强结果，不伪造语义相关性。

---

### ISSUE-042：ATT&CK 战术技术知识库

优先级：
P1

目标：
构建内置的 MITRE ATT&CK 技术子集知识库：随仓库附带精选技术条目数据，灌入 attack_kb，并提供按技术 ID 精确查询接口。完成后证据与故事线可映射到标准战术阶段。

前置依赖：
ISSUE-041

输入上下文：
KnowledgeStore 与 attack_kb；数据文件随仓库附带、离线可用，覆盖与演示场景相关的常见技术（不少于 60 条），每条含技术 ID、名称、战术列表、描述、检测建议，并在 manifest 固定 ATT&CK 数据版本。

文件范围：
1. `data/knowledge/attack_techniques.json`
2. `backend/app/services/attack_kb_service.py`：`AttackKBService`
3. `backend/scripts/load_attack_kb.py`
4. `backend/tests/test_services/test_attack_kb.py`

统一命名：
1. 数据条目字段：`technique_id`（如 `T1078`）、`technique_name`、`tactics`（list，同一 technique 可属多个 tactic）、`description`、`detection`、`attack_version`。不把 collection/exfiltration 合并，也不在代码硬编码 tactic 总数；允许集合以仓库锁定的官方 ATT&CK STIX/manifest 版本为准。
2. `AttackKBService` 方法：`async load_from_file(path)`、`async get_technique(technique_id) -> dict | None`、`async search_techniques(query_text, top_k=5) -> list[RetrievedChunk]`
3. chunk metadata 必含 `technique_id`、`tactics` 与 `attack_version`；chunk_id 由 technique_id+attack_version 哈希派生保证幂等
4. Makefile 命令：`make load-kb`（执行全部知识库加载脚本）

实现步骤：
1. 编写 `attack_techniques.json`：不少于 60 条，必须覆盖演示场景相关技术（T1078 合法账号、T1005 本地数据收集、T1560 数据压缩加密、T1567 经 Web 服务外泄、T1071 应用层协议、T1048 备用协议外传、T1041 经 C2 通道外泄、T1110 暴力破解、T1566 钓鱼、T1059 命令与脚本解释器等）。
2. 实现加载脚本：读文件、生成嵌入、upsert 到 attack_kb；重复执行幂等。
3. 实现按 technique_id 精确查询（走 metadata 过滤）与语义检索。
4. 编写测试：加载条数、幂等性、T1078 精确查询、"数据外泄"语义检索命中外泄类技术。

验收标准：
1. `make load-kb` 后 attack_kb 不少于 60 条。
2. `get_technique("T1078")` 返回完整条目。
3. 重复加载不产生重复 chunk。

测试与验证：
`cd backend && pytest tests/test_services/test_attack_kb.py -v`。

降级策略：
知识库为空时依赖方（故事线、RAGAgent）跳过 ATT&CK 映射并标注 `attack_mapping_unavailable`，不阻塞主链路。

---

### ISSUE-043：误报案例库与历史案例库

优先级：
P1

目标：
构建误报案例库 fp_case_kb 与历史案例库 history_case_kb：定义案例数据模型、种子数据与检索服务，并实现已关闭事件自动沉淀为历史案例。完成后误报识别与相似案例参考具备数据来源。

前置依赖：
ISSUE-041

输入上下文：
KnowledgeStore；CaseLabel 枚举（简介第 4.6 节）；case_id 格式 `case-{8位十六进制}`；ISSUE-011 的 account_anomaly_fp 场景作为误报种子素材。

文件范围：
1. `data/knowledge/fp_cases.json`、`data/knowledge/history_cases.json`
2. `backend/app/models/case.py`：`FalsePositiveCase`、`HistoryCase`
3. `backend/app/services/case_kb_service.py`：`CaseKBService`
4. `backend/scripts/load_case_kb.py`
5. `backend/tests/test_services/test_case_kb.py`

统一命名：
1. `FalsePositiveCase` 字段：`case_id`、`pattern_summary`、`alert_signature`（告警特征摘要文本）、`entity_pattern`（涉及实体类型与特征）、`fp_reason`、`confirmed_by`、`confirmed_at`
2. `HistoryCase` 字段：`case_id`、`event_id`（可空，种子数据为空）、`event_type`、`case_label`（CaseLabel）、`summary`、`key_entities`、`final_verdict`、`risk_score`、`resolution`、`closed_at`
3. `CaseKBService` 方法：`async search_fp_cases(alert_text, top_k=5)`、`async search_history_cases(query_text, event_type=None, top_k=5)`、`async archive_event_as_case(event_id) -> str`（事件结案后调用，组装 HistoryCase 并入库）
4. 种子数据规模：fp_cases 不少于 10 条（含运维批量改密、备份任务夜间大流量等模式）、history_cases 不少于 16 条（八类 EventType 每类至少 2 条）

实现步骤：
1. 定义两个 Pydantic 模型与 JSON 种子文件。
2. 实现加载脚本：案例文本化（summary 加实体特征拼接）后嵌入并 upsert，metadata 保留结构化字段；幂等。
3. 实现两个检索方法（向量检索，metadata 里的 event_type 过滤）与 `archive_event_as_case`（从事件、风险评分、报告组装案例）。
4. 编写测试：种子加载、误报场景告警文本检索命中对应模式案例、event_type 过滤、结案沉淀后可检索。

验收标准：
1. 两库种子各不少于 10 条且加载幂等。
2. account_anomaly_fp 场景的告警文本检索 fp_case_kb 时 top1 为运维改密模式案例且 score 不低于 0.5。
3. `archive_event_as_case` 后新案例立即可检索。

测试与验证：
`cd backend && pytest tests/test_services/test_case_kb.py -v`。

降级策略：
案例库为空时误报匹配返回 no_match、相似案例返回空列表，不影响研判主链路。

---

### ISSUE-044：处置剧本知识库（SOAR Playbook）

优先级：
P1

目标：
构建处置剧本知识库 playbook_kb：按事件类型与严重度组织标准处置步骤，每步绑定统一工具名与 ActionLevel，供 ResponseAgent 检索引用。完成后处置建议有据可依。

前置依赖：
ISSUE-041

输入上下文：
KnowledgeStore；工具名与 ActionLevel（简介第 4.5、4.6 节）；八类 EventType。other 的剧本只能包含保守查询、工单和通知步骤。

文件范围：
1. `data/knowledge/playbooks.json`
2. `backend/app/models/playbook.py`：`Playbook`、`PlaybookStep`
3. `backend/app/services/playbook_kb_service.py`：`PlaybookKBService`
4. `backend/scripts/load_playbook_kb.py`
5. `backend/tests/test_services/test_playbook_kb.py`

统一命名：
1. `Playbook` 字段：`playbook_id`（格式 `pb-{8位十六进制}`）、`playbook_name`、`event_type`、`min_severity`（生效的最低严重度）、`description`、`steps`
2. `PlaybookStep` 字段：`step_order`、`action_name`、`tool_name`（运行时必须命中 CapabilityManifest）、`action_level`、`precondition`、`expected_outcome`、`required_capabilities`；知识库可引用当前不可用工具，但 ResponseAgent 必须过滤。
3. `PlaybookKBService` 方法：`async search_playbooks(event_type, severity, query_text=None, top_k=3) -> list[Playbook]`、`async get_playbook(playbook_id)`
4. 剧本规模：不少于 12 个，覆盖八类 EventType 每类至少 1 个，数据外泄与内鬼威胁按严重度各分 2 个

实现步骤：
1. 编写 playbooks.json：步骤工具名与 ActionLevel 必须与简介一致（如数据外泄高危剧本：disable_account L3、isolate_host L3、block_ip L2、block_domain L2、create_ticket L1、notify_security_team L1）。
2. 实现加载脚本（描述文本嵌入、结构化字段入 metadata、幂等）与检索服务（event_type 与 min_severity 过滤后按语义相关度排序，返回完整 Playbook 结构）。
3. 实现加载时静态校验：非法 tool_name 或 action_level 与 ToolMeta 声明不一致即报错拒绝入库。
4. 编写测试：加载校验拦截非法剧本、按事件类型与严重度检索、返回结构完整性。

验收标准：
1. 不少于 12 个剧本入库且全部步骤通过工具名与等级校验，八类 EventType 各有至少 1 个剧本。
2. `search_playbooks("data_exfiltration", "high")` 返回含 disable_account 与 block_ip 步骤的剧本。
3. 包含非法 tool_name 的剧本被加载脚本拒绝并报具体错误。

测试与验证：
`cd backend && pytest tests/test_services/test_playbook_kb.py -v`。

降级策略：
剧本库为空时 ResponseAgent 回退内置默认规则（按事件类型映射基础动作集），标注 `playbook_unavailable`。

---

### ISSUE-045：RAG 混合检索管线

优先级：
P1

目标：
实现完整 RAG 检索管线：查询改写、向量与关键词混合检索、RRF 融合、重排序与引用追踪，统一封装为 RetrievalPipeline 供 RAGAgent 调用。

前置依赖：
ISSUE-027、ISSUE-041、ISSUE-042、ISSUE-043、ISSUE-044

输入上下文：
KnowledgeStore 双检索接口；四个知识库；MockLLM prompt_key 为 `query_rewrite`。

文件范围：
1. `backend/app/rag/query_rewriter.py`：`QueryRewriter`
2. `backend/app/rag/hybrid_retriever.py`：`HybridRetriever`
3. `backend/app/rag/rrf_fusion.py`：`rrf_fuse`
4. `backend/app/rag/reranker.py`：`Reranker`、`MockReranker`
5. `backend/app/rag/citation_tracer.py`：`CitationTracer`
6. `backend/app/rag/pipeline.py`：`RetrievalPipeline`
7. `backend/tests/test_rag/test_pipeline.py`

统一命名：
1. `RetrievalPipeline.retrieve(query: str, kb_names: list[str], top_k=5) -> RetrievalResult`
2. `RetrievalResult` 字段：`query`、`rewritten_queries`、`chunks`（list[RetrievedChunk]，同时含 raw_rrf_score 与归一化后 0-1 score）、`citations`、`degraded_steps`（被降级跳过的步骤名列表）
3. `QueryRewriter.rewrite(query) -> list[str]`：返回原查询加最多 2 个改写（LLM JSON mode；失败时仅返回原查询）
4. `rrf_fuse(result_lists, k=60)`：先计算 `raw_rrf_score = sum(1 / (k + rank_i))`，再以本次有效结果列表数的理论最大值 `len(result_lists)/(k+1)` 归一化到 0-1；下游阈值只使用 normalized score，禁止直接把约 0.0x 的原始 RRF 分数与 0.3/0.7/0.9 阈值比较。
5. `Reranker.rerank(query, chunks, top_k) -> list[RetrievedChunk]`：`RERANK_MODE`（mock、remote）环境变量控制；MockReranker 按原 score 与查询词重叠率加权（确定性）
6. `Citation` 字段：`citation_id`（格式 `cit-{8位十六进制}`）、`chunk_id`、`kb_name`、`quoted_text`、`relevance_score`

实现步骤：
1. 实现 QueryRewriter（带 15 秒超时与失败兜底）。
2. 实现 HybridRetriever：对每个查询变体并发执行向量与关键词双路检索（每路 top_k*2）。
3. 实现 RRF 融合去重（按 chunk_id）并保存 raw/normalized 双分数；零结果与单结果边界显式处理，Reranker 输出也重新裁剪到 0-1。
4. 实现 Reranker 两模式与 CitationTracer（从最终 chunks 生成引用，quoted_text 截取命中片段不超过 200 字）。
5. 组装 RetrievalPipeline：改写、检索、融合、重排、引用五步，每步失败记入 degraded_steps 并跳过（检索步失败除外）。
6. 编写测试：全链路确定性结果、RRF 数学正确性（手工构造排名验证）、改写失败兜底、重排序失败跳过、引用片段可定位回原 chunk。

验收标准：
1. mock 模式下同一查询两次调用返回完全一致结果。
2. RRF 融合分数与手工计算一致。
3. 任一非检索步骤失败时管线仍返回可用结果且 degraded_steps 如实记录。
4. 每个最终 chunk 均可生成含 quoted_text 的引用。

测试与验证：
`cd backend && pytest tests/test_rag/test_pipeline.py -v`。

降级策略：
查询改写失败用原查询；重排序失败用 RRF 排序；向量检索失败回退纯关键词检索；全部检索失败返回空结果并由 RAGAgent 标注降级。

---

### ISSUE-046：RAGAgent 实现

优先级：
P1

目标：
实现知识增强 Agent：基于事件上下文并发检索四类知识库，产出攻击技术匹配、误报相似度、历史案例参考与剧本建议的结构化输出，写入 EventContext 供 RiskAgent 与 ResponseAgent 消费。

前置依赖：
ISSUE-028、ISSUE-045

输入上下文：
ISSUE-005 的 `RAGOutput` Schema；EventContext 的 `triage_result` 与 `evidence_output`；RetrievalPipeline。

文件范围：
1. `backend/app/agents/rag_agent.py`：`RAGAgent`
2. `backend/app/agents/rag_query_builder.py`：`RAGQueryBuilder`
3. `backend/tests/test_agents/test_rag_agent.py`

统一命名：
1. `RAGAgent.agent_name = "rag_agent"`；输出 `RAGOutput`，字段：`attack_techniques`（list，元素含 technique_id、technique_name、tactics（list）、match_confidence、citation_id）、`fp_similarity`（含 `max_score`、`matched_case_id`、`matched_pattern`，无匹配时 max_score=0.0）、`similar_cases`（list[HistoryCase 摘要]）、`playbook_refs`（list[playbook_id]）、`citations`（list[Citation]）、`degraded`
2. `RAGQueryBuilder.build_queries(triage_result, evidence_output) -> dict[str, str]`：按 kb_name 生成四条查询文本（攻击技术查询拼证据行为摘要；误报查询拼告警特征；案例查询拼事件类型与实体特征；剧本查询拼事件类型与严重度）
3. 误报相似度判定沿用全局常量：max_score 不低于 `FP_HIGH_THRESHOLD` 为高置信误报候选，介于 `FP_LOW_THRESHOLD` 与高阈值之间为可疑误报

实现步骤：
1. 实现 RAGQueryBuilder 四类查询构造。
2. 实现 RAGAgent：`asyncio.gather` 并发检索四库（单库失败不中断）、组装 RAGOutput、聚合引用。
3. attack_techniques 的 match_confidence 取重排后 score 裁剪到 0 至 1；只保留 score 不低于 0.3 的技术。
4. 输出写 EventContext 的 `rag_output` 字段。
5. 编写测试：主场景命中外泄类技术（T1567 或 T1048 至少其一）、误报场景 fp_similarity.max_score 不低于 0.7、单库失败局部降级、全库失败 degraded=true 且输出结构完整。

验收标准：
1. 主场景 RAGOutput 含至少 2 个攻击技术匹配且每项有 citation_id。
2. 误报场景 fp_similarity 命中对应模式案例。
3. 任一知识库失败时其余三库结果正常返回。
4. rag_output 写入 EventContext 且 agent_trace 有记录。

测试与验证：
`cd backend && pytest tests/test_agents/test_rag_agent.py -v`。

降级策略：
全部知识库不可用时输出空 RAGOutput（degraded=true），下游按无增强模式继续。

---

### ISSUE-047：RAG 与风险评分、误报判定集成测试

优先级：
P1

目标：
把 RAGOutput 接入 RiskAgent 的 threat_intel 与 attack_stage 维度增强，并增强 P0 VerdictResolver 的误报证据输入，编写 RAG 子系统集成测试收口；不得在 P1 建立第二个 verdict 写入口。

前置依赖：
ISSUE-035、ISSUE-046

输入上下文：
RiskAgent 已支持可选 `rag_output` 入参（缺失按基线）；ISSUE-035 的 VerdictResolver、FinalVerdict 与 FP 阈值常量；AnalysisOnlyPipeline/LangGraph。

文件范围：
1. `backend/app/agents/risk_agent.py`（增强 rag_output 消费逻辑）
2. `backend/app/agents/verdict_resolver.py`：增强既有 `VerdictResolver`
3. `backend/app/services/analysis_only_pipeline.py` 与 LangGraph（接入 RAGAgent，顺序为 Evidence 之后、Risk 之前）
4. `backend/tests/integration/test_rag_integration.py`

统一命名：
1. RiskAgent 增强规则：attack_stage 维度有 ATT&CK 匹配时按最深战术阶段计分；threat_intel 维度叠加 `min(10, len(attack_techniques) * 3)` 加成（封顶 100）
2. `VerdictResolver.resolve(risk_assessment, false_positive_match=None, rag_output=None) -> FinalVerdict`（**不得缩短签名**）：优先级固定为 `false_positive_match.recommendation=close_as_fp` → `false_positive`；否则若 `rag_output.fp_similarity.max_score` 不低于 FP_HIGH_THRESHOLD 且 risk_score 低于 40 → `false_positive`；max_score 介于两阈值之间 → `possible_false_positive`；risk_score 不低于 70 → `confirmed_threat`；其余 → `none`。RAG 只增强、不覆盖 ISSUE-035/078 的前置匹配。
3. pytest 标记：`@pytest.mark.rag`

实现步骤：
1. 在 RiskAgent 中实现两维度增强（rag_output 缺失时保持原逻辑，已有测试不得回归）。
2. 增强既有 VerdictResolver（保持 ISSUE-035 签名与写入入口），判定结果统一委托 `EventService.set_final_verdict` 写入与发布（不直接操作 `security_event.final_verdict` 或 EventContext，避免双写入路径）。
3. Pipeline 接入 RAGAgent（其失败不阻塞，降级为无增强评分）。
4. 集成测试：主场景接入 RAG 后 risk_score 不低于无 RAG 基线且 verdict=confirmed_threat；误报用 disposition_policy=not_required 的 file fixture 验证合法本地 CLOSED，XDR required 的误报写回由 ISSUE-078 覆盖；前置 `false_positive_match` 优先于 rag fp_similarity；RAG 故障时仍生成基础分析结果/报告且不绕过处置门禁。

验收标准：
1. 主场景 verdict 为 confirmed_threat，误报场景为 false_positive。
2. RAGAgent 故障时基础闭环测试（ISSUE-039）全部仍通过。
3. `pytest -m rag` 通过。

测试与验证：
`cd backend && pytest tests/integration/test_rag_integration.py -m rag -v && pytest tests/integration/test_e2e_basic_loop.py -m e2e_basic -v`。

降级策略：
rag_output 缺失或降级时 VerdictResolver 仍消费 `false_positive_match`（若有），否则仅依据 risk_score 判定，主链路不中断。

---

### ISSUE-048：LangGraph StateGraph 工作流骨架

优先级：
P0

目标：
用 LangGraph 定义研判工作流 StateGraph：节点对应 Agent 执行、边对应 EventStatus 转移、条件路由覆盖低危短路、审批等待与重规划分支，检查点持久化到 Redis。完成后多 Agent 编排有了可恢复的图执行底座。

前置依赖：
ISSUE-037、ISSUE-038

输入上下文：
EventStatus 14 态与转移矩阵（ISSUE-007）；StateMachineService；EventContext；检查点键 `shadowtrace:checkpoint:{event_id}`。

文件范围：
1. `backend/app/orchestration/graph_state.py`：`InvestigationState`
2. `backend/app/orchestration/workflow_graph.py`：`build_investigation_graph`
3. `backend/app/orchestration/workflow_runtime.py`：`WorkflowRuntimeService`（execution_substate 唯一 writer）
4. `backend/app/orchestration/checkpointer.py`：`RedisCheckpointer`
5. `backend/tests/test_orchestration/test_workflow_graph.py`

统一命名：
1. `InvestigationState` 增加 `source_snapshot`、`disposition_only_intent`、`execution_substate` 与 `execution_plan`，其余调查/处置字段保持；`execution_substate` 至少含 none、waiting_approval、waiting_execution、waiting_writeback、manual_resolution，用于不扩张 EventStatus 的可恢复暂停。
2. 节点名预留 `planner_node`，本 Issue 使用只读直通占位且只能消费已产生的 triage_result；ISSUE-049 立即替换为真实 PlannerAgent。P0 主序为 triage→planner→evidence→risk；rag/graph/storyline 是 P1 可选节点。
3. 条件路由中 `route_after_triage`（与 ISSUE-007 `validate_transition` 同构，禁止更宽）：
   - 无需调查/高置信误报且 `disposition_policy=not_required` → `close_node`；
   - **高置信误报**（`false_positive_match.recommendation=close_as_fp`）且 `disposition_policy=required` 且 Adapter 对 EVENT_STATUS_UPDATE readiness=READY → `WorkflowRuntimeService.begin_disposition_only(event_id)` 在**同一事务**内：① `EventService.set_final_verdict(false_positive)`；② 将 `SecurityEvent.confidence` 至少提升为 `false_positive_match.max_score`；③ 持久化 `disposition_only_intent=true`；再走 `planner_node` 生成确定性最小 ExecutionPlan，经合法 TRIAGING→PLANNING_RESPONSE 进入 disposition-only `response_node`；
   - 同上但 readiness 非 READY → 保持 TRIAGING、`disposition_policy=required`、写入 `degraded_flags.disposition_writeback_blocked=<readiness>` 并通知人工，**不得**置 `execution_substate=manual_resolution`，也不得本地直关、不得对主链威胁事件置 disposition_only；
   - 其余（含 required 低危非误报、confirmed_threat 主链）→ 普通 `planner_node`（证据→评分→实体处置）。
   `route_after_planner` 根据已持久化 intent 决定去 response 或 evidence，不能由 LLM 自报。**严禁**仅凭 `policy=required` 就把主场景导入 disposition-only。
4. `build_investigation_graph(agents: dict, services: dict) -> CompiledGraph`：依赖注入，不在模块级实例化
5. P0 最小 FP 生产者：ISSUE-032 默认注册 `RuleBasedFalsePositiveHook`（不依赖 ISSUE-043/078 知识库）：对 fixture/场景标注的稳定签名做确定性匹配，可写出 `false_positive_match`；完整向量检索 Matcher 仍由 ISSUE-078 替换增强。

实现步骤：
1. 定义 InvestigationState 与节点包装器；实现 `WorkflowRuntimeService.begin_disposition_only`（同事务 set_final_verdict + confidence + disposition_only_intent）与 `set_execution_substate`（校验 EventStatus 绑定），以检查点+EventContext journal 原子记录。triage_node 后的 planner_node 本 Issue 为普通路径写最小占位 execution_plan；disposition-only 路径写稳定 `plan_id=pln-{hash(event_id|disposition_only|revision)}`、revision=0、单一 response_agent 步骤的确定性占位；ISSUE-049 替换后实现同一契约。close_node 只调用 StateMachineService 的中央 CLOSED 门禁，不另造较弱规则。
2. 实现五个条件路由函数（纯函数、可单测）。
3. 实现 RedisCheckpointer：实现 LangGraph BaseCheckpointSaver 协议，按事件键存取检查点（TTL 7 天）。
4. response_node、approval_wait_node、execute_node、verify_node、replan_node 本 Issue 先以直通占位实现（读 state 原样返回并推进状态），真实逻辑由 ISSUE-057 至 ISSUE-062 替换。
5. 编写测试：图编译成功且节点边与设计一致、黄金路径节点执行顺序、低危短路路径、disposition-only 同事务写入 final_verdict=false_positive、readiness 阻塞写 degraded_flags 而非非法子态、伪造 disposition_only_intent 被拒、确定性最小 plan 重放不变、路由函数全分支单测、检查点写入与从中断点恢复。

验收标准：
1. 图编译无环错误，P0 黄金路径按 triage、planner、evidence、risk、response、approval、execute、verify、report、close 顺序执行；安装 P1 RAG 后才在 evidence 与 risk 间插入 rag。
2. not_required 低危/误报 fixture 可经 route_after_triage 与 close_node 走完骨架；**required 高置信误报**经 begin_disposition_only 后 `final_verdict=false_positive` 且 intent 已持久化，并路由到 disposition-only 占位；在 ISSUE-057 至 ISSUE-062 真实节点交付前必须停在人工/不得 CLOSED，不能由直通占位伪造写回。required 主链威胁事件断言 **不会** 进入 disposition_only。确认后 CLOSED 由 ISSUE-062/064 验收（064 场景五可注入或走 RuleBasedFalsePositiveHook）。
3. 人为中断后从 Redis 检查点恢复并继续执行至结束。
4. 路由函数分支覆盖率 100%。

测试与验证：
`cd backend && pytest tests/test_orchestration/test_workflow_graph.py -v`。

降级策略：
Redis 检查点不可用时退化为内存检查点（进程重启不可恢复，记录警告），**且该次运行不得计入 P0 可恢复执行验收**；图执行异常时事件转入 FAILED 并保留 error 信息。

---

### ISSUE-049：PlannerAgent 调查计划生成

优先级：
P0

目标：
实现规划 Agent：根据分诊结果生成结构化调查计划（步骤、所需工具、预算），并支持在重规划时基于失败原因生成修订计划。完成后 SuperAgent 拥有可执行的计划输入。

前置依赖：
ISSUE-027、ISSUE-028、ISSUE-032

输入上下文：
ISSUE-005 的 `ExecutionPlan` Schema；EventContext 的 `triage_result`；MockLLM prompt_key 为 `plan_generate` 与 `plan_revise`。

文件范围：
1. `backend/app/agents/planner_agent.py`：`PlannerAgent`
2. `backend/app/agents/prompts/planner_prompt.py`
3. `backend/app/agents/rules/default_plans.py`：`DEFAULT_PLANS`（按事件类型的规则计划）
4. `backend/app/orchestration/workflow_graph.py`：替换 ISSUE-048 planner_node 占位
5. `backend/tests/test_agents/test_planner_agent.py`、`backend/tests/test_orchestration/test_planner_node.py`

统一命名：
1. `PlannerAgent.agent_name = "planner_agent"`；输出 `ExecutionPlan`，字段：`plan_id`（格式 `pln-{8位十六进制}`）、`event_id`、`steps`（list[PlanStep]）、`budget`（含 `max_tool_calls=30`、`max_llm_calls=20`、`max_duration_s=300`）、`revision`（从 0 起）、`revise_reason`（可空）、`degraded`
2. `PlanStep` 字段：`step_order`、`step_goal`、`assigned_agent`（12 个 Agent 名枚举）、`required_tools`（统一工具名列表）、`success_criteria`
3. 方法：`async plan(event_context) -> ExecutionPlan`、`async plan_disposition_only(event_context) -> ExecutionPlan`、`async revise(event_context, failure_reason: str, previous_plan: ExecutionPlan) -> ExecutionPlan`
4. `DEFAULT_PLANS`：八类 EventType 各一份最小规则计划（LLM 失败时兜底）；other 使用保守只读调查模板，任何新增 EventType 缺默认计划时启动测试失败。

实现步骤：
1. 实现 LLM 规划：JSON mode 输出 ExecutionPlan，prompt 含可用 Agent 与工具清单约束；输出中的 assigned_agent 与 required_tools 严格校验，非法值剔除并记警告。`plan_disposition_only` 不调用 LLM，使用 event_id、当前 source locator 与 revision 生成稳定单步计划，步骤只允许 response_agent/update_source_event_disposition。
2. 实现 revise：携带上一版计划与失败原因，revision 自增，revise_reason 必填。
3. 实现 P0 规则兜底计划（如数据外泄类：evidence_agent 七路查询、risk_agent 评分、response_agent 处置规划）；只有运行时注册 RAGAgent 且 P1 开关启用时才插入 rag_agent 步骤，缺失不使计划非法。
4. 计划写 EventContext 的 execution_plan 字段，并替换 ISSUE-048 planner_node 占位；恢复重放时按 event_id+revision 幂等读取/写入，不重复调用 LLM。
5. 编写测试：主场景计划含证据采集与评分步骤、非法工具名被剔除、revise 后 revision 自增且保留 revise_reason、LLM 失败规则兜底、disposition-only plan 重放稳定且只含唯一允许步骤。

验收标准：
1. 主场景计划不少于 4 步且每步 assigned_agent 与 required_tools 合法。
2. revise 产出的计划 revision=1 且体现失败原因（修订计划与原计划步骤集合不完全相同）。
3. LLM 失败时返回对应事件类型的 DEFAULT_PLANS 且 degraded=true。

测试与验证：
`cd backend && pytest tests/test_agents/test_planner_agent.py -v`。

降级策略：
LLM 不可用时使用 DEFAULT_PLANS 规则计划，主链路不中断。

---

### ISSUE-050：GraphAgent 实体关系图构建（PostgreSQL 派生）

优先级：
P1

目标：
实现图谱 Agent：从证据集派生实体节点与关系边，存入 PostgreSQL 关系表并输出图结构与简单图分析（中心实体、攻击路径候选）。不依赖 Neo4j。

前置依赖：
ISSUE-003、ISSUE-028、ISSUE-034

输入上下文：
EvidenceOutput；六类实体类型（account、host、ip、domain、process、file）；Neo4j 写入为 P2 增强（ISSUE-082），本 Issue 仅 PostgreSQL。

文件范围：
1. `backend/app/db/orm/graph.py`：`GraphNodeORM`、`GraphEdgeORM`
2. `backend/migrations/versions/0003_graph_tables.py`
3. `backend/app/agents/graph_agent.py`：`GraphAgent`
4. `backend/app/agents/graph_builder.py`：`GraphBuilder`
5. `backend/tests/test_agents/test_graph_agent.py`

统一命名：
1. `graph_node` 表字段：`node_id`（格式 `node-{8位十六进制}`，由 event_id 加实体类型加实体值哈希派生）、`event_id`、`entity_type`、`entity_value`、`properties`（JSONB）；`graph_edge` 表字段：`edge_id`（格式 `edge-{8位十六进制}`）、`event_id`、`source_node_id`、`target_node_id`、`relation_type`、`evidence_id`、`occurred_at`
2. `relation_type` 枚举（8 种）：`logged_in_from`（account 到 ip）、`logged_in_to`（account 到 host）、`executed`（host 到 process）、`accessed`（process 或 account 到 file）、`connected_to`（host 到 ip）、`resolved`（domain 到 ip）、`requested`（host 到 domain）、`uploaded_to`（file 到 ip 或 domain）
3. `GraphAgent.agent_name = "graph_agent"`；输出 `GraphOutput`（契约在 ISSUE-005 锁定），字段：`nodes`、`edges`、`central_entities`（按度数 top3）、`attack_path_candidates`（list，元素为按时间排序的 node_id 链）
4. `GraphBuilder.build(evidence_list) -> tuple[list[GraphNode], list[GraphEdge]]`：每种 EvidenceSource 一个抽取规则

实现步骤：
1. 编写迁移建两表（event_id 索引、node 去重唯一约束）。
2. 实现 GraphBuilder：从七类证据抽取节点与边（identity 证据产生 logged_in_from 与 logged_in_to；endpoint 产生 executed；data_security 产生 accessed 与 uploaded_to；network_flow 产生 connected_to；dns 产生 resolved 与 requested），每条边回链 evidence_id。
3. 实现度数统计与攻击路径候选：沿时间递增方向做受限深度（不超过 6）的路径搜索，返回最长 3 条。
4. 输出写 EventContext 的 `graph_output` 字段并持久化两表。
5. 编写测试：主场景节点边数量与类型断言、节点幂等去重、中心实体为 zhangsan 或 PC-FIN-023、攻击路径含 account 到 ip 的完整链、空证据输出空图。

验收标准：
1. 主场景图含全部六类实体中至少四类、边不少于 8 条且全部回链 evidence_id。
2. attack_path_candidates 至少 1 条按时间单调递增的路径。
3. 重复执行不产生重复节点。

测试与验证：
`cd backend && pytest tests/test_agents/test_graph_agent.py -v`。

降级策略：
图构建失败仅记录降级标记，研判与报告按无图模式继续（报告实体章节回退证据列表）。

---

### ISSUE-051：攻击故事线生成服务

优先级：
P1

目标：
实现攻击故事线服务：把证据时间线、ATT&CK 映射与实体关系融合为分阶段叙事 Storyline（LLM 叙事加规则兜底），写入 EventContext 主要供前端时间轴消费。

前置依赖：
ISSUE-027、ISSUE-042、ISSUE-046、ISSUE-050

输入上下文：
EvidenceOutput、RAGOutput（attack_techniques）、GraphOutput；MockLLM prompt_key 为 `storyline_generate`；前端时间轴组件将消费本输出（ReportAgent 的 `attack_storyline` 章节使用证据时间线兜底，见 ISSUE-036）。

文件范围：
1. `backend/app/services/storyline_service.py`：`StorylineService`
2. `backend/app/models/storyline.py`：`AttackStoryline`、`StorylinePhase`、`TimelineEntry`（实现 ISSUE-005 已锁定的同名 Schema，从 agent_io.py 迁移或复用）
3. `backend/app/agents/prompts/storyline_prompt.py`
4. `backend/tests/test_services/test_storyline.py`

统一命名：
1. `AttackStoryline` 字段：`storyline_id`（格式 `sty-{8位十六进制}`）、`event_id`、`narrative_summary`（不超过 300 字总叙述）、`phases`（list[StorylinePhase]）、`generated_by`（llm、rule 两值）
2. `StorylinePhase` 字段：`phase_order`、`phase_name`（5 阶段固定枚举：initial_access、collection、staging、exfiltration、post_action；不适用的阶段省略）、`tactic`（关联 ATT&CK 战术，可空）、`narrative`、`entries`（list[TimelineEntry]）
3. `TimelineEntry` 字段：`timestamp`、`description`、`evidence_id`、`technique_id`（可空）、`severity_hint`
4. `StorylineService.generate(event_context) -> AttackStoryline`

实现步骤：
1. 实现规则路：证据按时间排序后用规则分桶到 5 阶段（登录类归 initial_access、文件批量访问归 collection、压缩加密归 staging、外联上传归 exfiltration、其余时间最晚的归 post_action），模板生成各阶段叙述。
2. 实现 LLM 路：输入证据摘要、技术匹配与图路径，JSON mode 输出 AttackStoryline；每条 entry 的 evidence_id 必须存在于输入证据，否则剔除。
3. technique_id 从 RAGOutput 匹配结果按描述相似度回填。
4. 结果经 WorkingMemory 写 EventContext 的 `storyline` 字段（writer identity 固定为 `StorylineService`，与 ISSUE-014 FIELD_OWNERSHIP 一致；禁止使用笼统 `system` 字符串）。因 StorylineService 为 P1 后置 hook（见 ISSUE-054 编排流程），在 LangGraph 图执行完成（含 report_node）之后运行，故 ReportAgent 的 `attack_storyline` 章节不保证消费该字段，始终使用证据时间线兜底（见 ISSUE-036 fallback）；storyline 主要供前端时间轴组件消费。
5. 编写测试：主场景 5 阶段齐全且时间单调、entry 均回链真实 evidence_id、LLM 失败规则兜底、证据不足 3 条时仅输出 narrative_summary 与单阶段。

验收标准：
1. 主场景故事线含 initial_access 到 exfiltration 至少 4 个阶段且叙事含关键实体名。
2. 全部 TimelineEntry 的 evidence_id 可在 evidence 表中查到。
3. LLM 失败时 `generated_by="rule"` 且结构完整。

测试与验证：
`cd backend && pytest tests/test_services/test_storyline.py -v`。

降级策略：
RAGOutput 或 GraphOutput 缺失时按纯证据时间线生成；LLM 失败规则兜底；服务整体失败时报告章节回退证据时间线列表。

---

### ISSUE-052：循环收敛护栏（ConvergenceGuard）

优先级：
P0

目标：
建立跨循环的收敛保证：统一计数 ReAct 轮次、重规划次数与 Agent 重试，检测动作振荡与重复工具调用、检测停滞，超限强制收敛。完成后系统在任何编排路径下都不会无限循环或资源失控。

前置依赖：
ISSUE-007、ISSUE-008

输入上下文：
简介第 4.12 节收敛常量与第 4.8 节 `MAX_REPLAN_COUNT`、`MAX_AGENT_RETRIES`；ISSUE-008 错误体系；护栏状态写入 EventContext 的 `convergence_state`。

文件范围：
1. `backend/app/orchestration/convergence_guard.py`：`ConvergenceGuard`、`ConvergenceState`、`StopDecision`
2. `backend/tests/test_orchestration/test_convergence_guard.py`

统一命名：
1. 常量（简介第 4.12 节，位于 `backend/app/models/workflow.py`）：`GLOBAL_MAX_STEPS=80`、`MAX_OSCILLATION=2`、`MAX_DUPLICATE_TOOL_CALLS=3`、`MAX_TOTAL_LLM_CALLS=30`
2. `ConvergenceGuard` 方法：`record_step(event_id, step_type, signature) -> None`（step_type 取 react_round、replan、agent_retry、tool_call、llm_call 五值）、`should_stop(event_id) -> StopDecision`、`get_state(event_id) -> ConvergenceState`、`reset(event_id)`
3. `StopDecision` 字段：`stop`（bool）、`reason`（global_max_steps、oscillation、duplicate_tool_calls、max_llm_calls、none 五值）、`detail`
4. `ConvergenceState` 字段：`total_steps`、`react_rounds`、`replan_count`、`llm_calls`、`tool_call_signatures`（dict 计数）、`recent_actions`（振荡检测滑窗）
5. 振荡定义：最近动作序列 A、B、A、B 往复达 `MAX_OSCILLATION` 次；重复工具调用定义：同一 `(tool_name, params 指纹)` 调用次数超 `MAX_DUPLICATE_TOOL_CALLS`

实现步骤：
1. 实现按 event_id 的状态累计（Redis 或 EventContext 持久化），`record_step` 更新计数与指纹。
2. 实现 `should_stop`：依次检查 global_max_steps、max_llm_calls、duplicate_tool_calls、oscillation，命中返回对应 reason。
3. 并入原自适应调查增强设计的"低置信度补查最多 1 次防循环"：补查作为一种 react_round 计入全局步数，受同一护栏约束。
4. 约定接入：BaseLLMClient 每次网络尝试、ToolExecutor 每次 dispatch、ISSUE-053 ReAct 每轮、ISSUE-054 SuperAgent 每个 Agent step、ISSUE-062 重规划每次都先 `record_step` 再 `should_stop`；命中即停止并把 `convergence_state` 写入 EventContext。若尚有 required 处置/写回未完成，事件转人工并在报告注明未闭环，不能仅以“提前收敛出报告”标成功。
5. 编写测试：全局步数超限、LLM 调用超限、重复工具调用超限、A/B 振荡检测、正常流程不误停、状态写入。

验收标准：
1. 步数达 `GLOBAL_MAX_STEPS` 时 `should_stop` 返回 stop 且 reason=global_max_steps。
2. 同一工具同参调用超 `MAX_DUPLICATE_TOOL_CALLS` 被判定 duplicate_tool_calls。
3. A/B 往复动作被判定 oscillation。
4. 正常 3 轮收敛场景不触发任何停止。

测试与验证：
`cd backend && pytest tests/test_orchestration/test_convergence_guard.py -v`。

降级策略：
护栏状态存储不可用时退化为进程内计数（仍保证单进程内收敛）；护栏自身异常时按"不强制停止但记告警"处理，由 `MAX_REPLAN_COUNT` 与 ReAct `max_rounds` 兜底防循环。

---

### ISSUE-053：ReAct 循环引擎

优先级：
P1

目标：
实现通用 ReAct 引擎：观察、思考、行动、反思的多轮循环，基于置信度与预算的继续或停止判定，反思结论可触发补充行动。完成后 SuperAgent 具备自主迭代调查能力。

前置依赖：
ISSUE-024、ISSUE-027、ISSUE-028、ISSUE-052

输入上下文：
工作流常量 CONFIDENCE_THRESHOLD 与 MAX_REPLAN_COUNT；MockLLM prompt_key 为 `react_think` 与 `react_reflect`；行动通过 ToolExecutor 或 Agent 调用执行。

文件范围：
1. `backend/app/orchestration/react_engine.py`：`ReActEngine`
2. `backend/app/models/react.py`：`ReActRound`、`ReActResult`、`ReActAction`
3. `backend/tests/test_orchestration/test_react_engine.py`

统一命名：
1. `ReActEngine.run(goal: str, context: dict, executor: ReActActionExecutor, max_rounds=5) -> ReActResult`
2. `ReActRound` 字段：`round_index`、`observation`、`thought`、`action`（ReActAction，可空表示停止）、`action_result`、`reflection`、`confidence`
3. `ReActAction` 字段：`action_type`（call_tool、call_agent、finish 三值）、`target_name`、`params`、`rationale`
4. 停止条件（满足其一）：confidence 不低于 CONFIDENCE_THRESHOLD、达到 max_rounds、LLM 返回 finish、预算耗尽（轮内工具调用计数超 budget）
5. `ReActResult` 字段：`rounds`、`final_confidence`、`stop_reason`（confidence_met、max_rounds、finished、budget_exhausted、converged、error 六值）、`outputs`
6. `ReActActionExecutor` 协议：`async execute(action: ReActAction) -> dict`（由调用方注入，引擎不直接依赖具体 Agent）；P1 只提供 `ReadOnlyReActExecutor`，仅允许 ToolCategory=query 和显式白名单内的只读调查 Agent。response、verification、rollback、ApprovalEngine、ActionExecutionService 以及任何 side_effect 工具一律拒绝。

实现步骤：
1. 实现单轮流程：组装观察（上下文加上一轮结果摘要）、LLM 思考输出 ReActAction（JSON mode）、执行行动、LLM 反思输出 confidence 与缺口描述。
2. 实现停止判定与轮次记录；每轮写 agent_trace 的 decision_basis（观察摘要、证据引用、候选动作、选中动作、置信度），不保存隐藏思维链。每轮先调用 ConvergenceGuard 的 record_step 再 should_stop。
3. 非法 action（未知 target_name、非 query 工具、具副作用 Agent）由 executor 在执行前拒绝，记录 `react_action_denied` 并视为本轮失败；连续 2 轮失败提前停止（stop_reason=error）。ReAct 永远不能创建/审批/执行 Action，所有处置仍只能走 ResponseAgent→PolicyFilter→ApprovalEngine→ActionExecutionService。
4. MockLLM golden 设计为主场景 3 轮收敛（第 1 轮补查威胁情报、第 2 轮补查 DNS、第 3 轮 confidence 0.85 收敛）。
5. 编写测试：3 轮收敛、max_rounds 截断、finish 提前停止、非法 action 容错、轨迹完整；恶意或错误 LLM 选择 block_ip/isolate_host/ResponseAgent 时均被拒且 action/tool_call/外部副作用为零。

验收标准：
1. mock 模式主场景 3 轮收敛且 stop_reason 为 confidence_met。
2. 每轮 ReActRound 字段齐全且 agent_trace 含可审计 decision_basis。
3. 预算与轮次上限可阻止无限循环（全部测试有限时间结束）。

测试与验证：
`cd backend && pytest tests/test_orchestration/test_react_engine.py -v`。

降级策略：
LLM 不可用时引擎直接返回 stop_reason=error 的空结果，调用方（SuperAgent）回退固定计划顺序执行，不阻塞主链路。

---

### ISSUE-054：SuperAgent 编排接管

优先级：
P0

目标：
实现总指挥 SuperAgent：以 LangGraph 工作流为骨架驱动全部 Agent，持有事件级租约防止重复编排，集成 PlannerAgent 计划与可选 ReAct 迭代，并替换 ISSUE-038 的临时 AnalysisOnlyPipeline 作为生产闭环入口。

前置依赖：
ISSUE-029、ISSUE-048、ISSUE-049、ISSUE-052

输入上下文：
build_investigation_graph；租约键 `shadowtrace:lease:event:{event_id}`；环境变量 `ORCHESTRATION_MODE`（analysis_only、graph，默认 graph）、`REACT_ENABLED`（默认 false，P1 ISSUE-053 安装后才可显式启用）。

文件范围：
1. `backend/app/agents/super_agent.py`：`SuperAgent`
2. `backend/app/orchestration/lease.py`：`EventLease`
3. `backend/app/api/v1/events.py`（investigate 端点切换到 SuperAgent）
4. `backend/tests/test_agents/test_super_agent.py`

统一命名：
1. `SuperAgent.agent_name = "super_agent"`；状态机用 `SuperAgentStatus`（简介第 4.6 节）；方法：`async investigate(event_id) -> None`
2. `EventLease`：`async acquire(event_id, owner_id, ttl_s=600) -> bool`（SET NX EX）、`async renew(event_id, owner_id)`、`async release(event_id, owner_id)`；owner_id 格式 `worker-{8位十六进制}`
3. 编排流程固定：acquire 租约、冻结本次 source_snapshot、启动 LangGraph；图内先 Triage 再 Planner。RAG、Graph、Storyline、ReAct 作为能力开关挂载，未实现或失败不阻塞 P0 主链。结束时刷新快照并释放租约。
4. 重复触发返回错误码 `investigation_in_progress`（HTTP 409）

实现步骤：
1. 实现 EventLease（含续约后台任务，执行中每 60 秒续约）。
2. 实现 SuperAgent：状态推进按 SuperAgentStatus、异常时事件转 FAILED 并释放租约、全程 agent_trace。Planner 不在图外预执行；可选增强通过 hooks 注入。
3. ReAct 集成：goal 由计划生成（如"补全证据缺口并确认外泄路径"），executor 只能注入 ISSUE-053 的 ReadOnlyReActExecutor，严禁直接包装 ToolExecutor；`REACT_ENABLED=true` 但 ISSUE-053 未注册时启动配置失败。
4. 切换 investigate 端点：默认走 SuperAgent；`ORCHESTRATION_MODE=analysis_only` 仅保留开发/离线分析路径，并在任一 live 写回/副作用开关开启时启动失败。
5. 更新 ISSUE-039 基础闭环测试在 graph 模式下复跑通过。
6. 编写测试：图骨架黄金路径、并发触发仅一个获得租约（另一个 409）、执行中崩溃后租约过期可重新触发、REACT_ENABLED 开关两态、analysis_only 环境栅栏。

验收标准：
1. 本 Issue 的 graph 骨架把主场景从 NEW 推进到 REPORTING 且各 P0 分析 Agent 轨迹完整；ISSUE-062 替换处置节点后，同一用例升级为动作效果与 required 写回确认后才 CLOSED。
2. 同一事件并发触发两次只执行一次编排。
3. ISSUE-039 的 4 个场景在 graph 模式全部通过。

测试与验证：
`cd backend && pytest tests/test_agents/test_super_agent.py -v && ORCHESTRATION_MODE=graph pytest tests/integration/test_e2e_basic_loop.py -m e2e_basic -v`。

降级策略：
live 闭环中 LangGraph 执行异常时保持检查点并转 FAILED/人工恢复，不得自动切成 analysis_only 后冒充完成；ReAct 失败自动回退固定计划执行；租约 Redis 不可用时退化为数据库行锁/租约表（若该路径未实现则拒绝重复触发，不用弱状态检查冒险执行）。

---

### ISSUE-055：多 Agent 编排集成测试

优先级：
P0

目标：
对 SuperAgent、PlannerAgent、LangGraph、可选 ReAct 与共享上下文的协同编写集成测试：覆盖黄金路径、Agent 失败重试、检查点恢复与上下文一致性四类场景，冻结编排层行为。

前置依赖：
ISSUE-054

输入上下文：
全部已实现 Agent 与编排组件；MockLLM golden；工作流常量 MAX_AGENT_RETRIES。

文件范围：
1. `backend/tests/integration/test_orchestration.py`
2. `backend/tests/test_orchestration/conftest.py`

统一命名：
1. pytest 标记：`@pytest.mark.orchestration`

实现步骤：
1. 场景一（黄金路径全编排）：在本 Issue 尚未接入 ISSUE-057 至 062 的阶段，主场景经 SuperAgent 执行到 REPORTING，断言节点顺序与 P0 分析字段；ISSUE-062 收口复跑时才要求动作效果与 required 写回均确认后 CLOSED。rag_output、graph_output 与 storyline 属 P1，按安装状态断言。
2. 场景二（Agent 失败重试）：打桩 EvidenceAgent 首次抛异常第二次成功，断言重试 1 次后继续且 agent_trace 含失败与成功两条记录。
3. 场景三（检查点恢复）：在 risk_node 前强制中断进程内执行，从检查点恢复后断言不重复执行已完成节点且最终完成。
4. 场景四（上下文一致性）：两个 Agent 并发写 EventContext 不同字段，断言乐观锁无丢失更新；版本冲突重试生效。
5. 全部场景断言 event_audit_log 状态转移序列合法（逐条经 validate_transition 校验）。

验收标准：
1. 4 个场景全部通过，黄金路径 90 秒内完成（mock 模式）。
2. 编排模块语句覆盖率不低于 75%。
3. CI 可运行（`pytest -m orchestration`）。

测试与验证：
`cd backend && pytest tests/integration/test_orchestration.py -m orchestration -v`。

降级策略：
无

---

### ISSUE-056：Celery 异步任务队列与可恢复执行

优先级：
P1

目标：
引入 Celery（Redis broker）承载研判任务：investigate 端点改为投递任务，worker 崩溃后凭租约过期与 LangGraph 检查点自动恢复，提供任务状态查询。完成后长研判不再依赖 API 进程存活。

前置依赖：
ISSUE-054

输入上下文：
EventLease 与 RedisCheckpointer；docker-compose 已含 Redis；`CELERY_BROKER_URL` 默认复用 `REDIS_URL`。

文件范围：
1. `backend/app/core/celery_app.py`：`celery_app`
2. `backend/app/tasks/investigation_tasks.py`：`run_investigation`
3. `backend/app/api/v1/events.py`（investigate 端点投递 Celery 任务）
4. `infra/docker-compose.yml`（新增 worker 服务）
5. `backend/tests/test_tasks/test_investigation_tasks.py`

统一命名：
1. 任务名：`shadowtrace.run_investigation`；签名 `run_investigation(event_id: str)`；队列名：`investigation`
2. 任务配置：`acks_late=True`、`max_retries=2`、`retry_backoff=True`、软超时 600 秒
3. `POST /api/v1/events/{event_id}/investigate` 响应改为 `{"task_id": "<celery task id>"}`；新增 `GET /api/v1/tasks/{task_id}` 返回 `{"task_id", "state", "event_id"}`（state 为 Celery 原生状态字符串）
4. 环境变量 `TASK_MODE`（celery、background，默认 background；启用 optional worker profile 时显式设 celery）
5. worker 启动命令：`celery -A app.core.celery_app worker -Q investigation -c 2`

实现步骤：
1. 配置 celery_app（Redis broker 与 result backend、任务路由到 investigation 队列）。
2. 实现 run_investigation：内部新建事件循环执行 `SuperAgent.investigate`；租约被占用时任务直接成功返回 skipped（幂等）。
3. 改造端点支持 TASK_MODE 两模式与任务状态查询端点。
4. docker-compose 新增 worker 服务（与 backend 同镜像、不同命令）。
5. 编写测试（Celery eager 模式为主）：任务投递与执行、重复投递幂等、状态查询；手工验证 worker 容器模式。

验收标准：
1. `TASK_MODE=celery` 下经 API 触发研判并达到当前图阶段的正确终态（ISSUE-062 前高风险为 REPORTING，完整处置链接入后且 required 写回确认才 CLOSED）。
2. 同一事件重复投递不产生并行编排。
3. worker 执行中被 kill 后，租约过期再次投递可从检查点恢复完成。
4. eager 模式测试通过，CI 不要求真实 worker。

测试与验证：
`cd backend && pytest tests/test_tasks/test_investigation_tasks.py -v`；手工验证：`docker compose up -d worker` 后经 API 触发并轮询任务状态。

降级策略：
开发者可显式把 `TASK_MODE` 改为 background 使用 FastAPI BackgroundTasks（重启丢任务的限制随之恢复）。已配置 celery 时 broker 故障返回 503/任务不可用并保留事件状态，不得运行时静默切 background 造成重复投递。

---

### ISSUE-057：ResponseAgent 处置方案生成

优先级：
P0

目标：
实现处置 Agent：根据风险评估与剧本知识生成结构化处置方案 ResponsePlan，每个动作绑定统一工具名与 ActionLevel，动作落库为 PENDING 状态。完成后系统具备从研判到处置建议的衔接。

前置依赖：
ISSUE-006、ISSUE-018、ISSUE-027、ISSUE-028、ISSUE-035

输入上下文：
ResponsePlan、风险/实体/来源资产上下文与运行时 CapabilityManifest；MockLLM prompt_key 为 response_plan。XDR 原生预案只可作为未来可选知识输入，不是执行依赖。

文件范围：
1. `backend/app/agents/response_agent.py`：`ResponseAgent`
2. `backend/app/agents/prompts/response_prompt.py`
3. `backend/app/agents/rules/default_response_rules.py`：`DEFAULT_RESPONSE_RULES`
4. `backend/tests/test_agents/test_response_agent.py`

统一命名：
1. `ResponseAgent.agent_name = "response_agent"`；输出 `ResponsePlan`（plan_id 格式 `rsp-{8位十六进制}`）
2. Action 只能使用 manifest 中可用且目标匹配的工具；写入 provider、execution_owner、disposition_source_ref 与稳定幂等键。`writeback_required` 只由事件业务政策推导，`writeback_readiness` 再由单一稳定来源定位、配置、权限与 Adapter intent/operation 能力计算；生产要求写回但 readiness 非 READY 时仍保留 required，动作只作为待人工方案，禁止自动执行成“本地成功、XDR 不知情”。
3. `DEFAULT_RESPONSE_RULES`：八类 EventType 分别提供按严重度的保守规则动作集（LLM 与剧本均不可用时兜底；如数据外泄 high 至少含 disable_account、block_ip、create_ticket、notify_security_team）；other 默认只生成工单/通知，不自动产生破坏性动作。事件 disposition_policy=required 时，无论来源动作集为何，都必须追加且仅追加一条 `execution_phase=POST_VERIFY` 的 update_source_event_disposition；not_required 时不得追加。
4. 动作排序约定：action_level 升序（低风险动作在前），同级按剧本 step_order

实现步骤：
1. 实现剧本引用路径：rag_output.playbook_refs 非空时取首个剧本步骤为基础动作集，目标实体从 EntitySet 回填。
2. LLM 只提出候选动作；PolicyFilter 同时校验当前 source locator、Disposition capability、execution_owner 互斥、target、side effect 与审批规则。所有候选 parameters 先通过对应 Tool Schema；出站 command 仍由 Factory 独立重建。
3. 实现规则兜底；普通 severity=low 调查最多生成 create_ticket。由 route_after_triage 标记 disposition_only 的**高置信误报**闭环则只生成唯一 update_source_event_disposition，禁止混入工单或实体动作；普通 required 计划在动作尾部追加同类唯一 deferred Action。该 Action 的 approved_terminal_dispositions 只能取 `TERMINAL_SOURCE_DISPOSITIONS={contained, completed, suspended, ignored}` 的政策允许子集，审批预览与 template hash 一并冻结；Mock profile 将其定为 L2。disposition-only 路径跳过 RiskAgent 时，审批用的 confidence **不得**读空值：evaluate 必须使用 `max(SecurityEvent.confidence 或 0, false_positive_match.max_score 或 0)`，close_as_fp 且 max_score≥FP_HIGH_THRESHOLD 时视为满足 L2 自动批准阈值；live Adapter 可按正式 operation 的风险提高等级但不得降低全局审批下限。
4. 以当前 execution_plan.revision 作为 plan_revision/closure_cycle，计算 `action_fingerprint=sha256(event_id|plan_revision|tool_name|target_type|canonical_target|normalized_params_hash|execution_owner|source_locator_hash|execution_phase|approved_template_hash)`，并由 fingerprint 派生稳定动作执行基键；每个 Disposition intent 再按 ISSUE-002 规则派生自己的 idempotency_key。在同一数据库事务中 upsert ResponsePlan 对应 Action、追加 EventContext journal 并提交。来源切换必须新 revision；节点重放/Agent retry/Celery late-ack 返回原 action_id。重规划启用新 revision 时，对旧 revision 中从未创建 job/outbox 的 deferred Action 原子置 SUPERSEDED、writeback_applicable=false 并记录 superseded_by_revision；任何已 dispatch Action 不得 supersede。
5. 编写测试：主场景方案含 disable_account 与 block_ip 且等级正确、低危 not_required 单工单、required 计划每个 revision 恰一条 POST_VERIFY Action、disposition-only 计划只有该 Action、审批模板只含终态子集、非法动作剔除、八类规则兜底、LLM 失败走模板、同一节点重放三次仍只有一组 Action、新 revision 只 supersede 未外呼 deferred Action。

验收标准：
1. 主场景在完整 Mock 能力下产生覆盖关键实体的方案；能力缺失变体不包含不可执行工具。验收不锁死动作数量。
2. 动作落库后可经 `GET /api/v1/events/{event_id}/actions` 查询（端点在 ISSUE-038 真实实现，本 Issue 仅负责 action 表写入）。
3. LLM 与剧本均不可用时规则方案可用且流程不中断。

测试与验证：
`cd backend && pytest tests/test_agents/test_response_agent.py -v`。

降级策略：
剧本库不可用回退 LLM 直接生成；LLM 不可用回退 DEFAULT_RESPONSE_RULES；两者均不可用时仍输出规则最小动作集，主链路不中断。

---

### ISSUE-058：分级审批引擎

优先级：
P0

目标：
实现处置动作分级审批引擎：按 ActionLevel 与置信度判定自动执行或转人工审批，提供审批与拒绝 API、审批超时处理与 Socket.IO 通知。同一 `plan_revision` 的全部 response Action（含 deferred POST_VERIFY 终态 Action）必须全部完成审批后，才能进入执行；完成后高危动作受控、低危动作自动放行。

前置依赖：
ISSUE-004、ISSUE-037、ISSUE-057

输入上下文：
ActionLevel 自动执行规则与 APPROVAL_TIMEOUT_MINUTES；ActionStatus 11 态（含 SUPERSEDED）；approval 实时事件；ISSUE-004 Principal/RBAC。

文件范围：
1. `backend/app/services/approval_engine.py`：`ApprovalEngine`
2. `backend/app/api/v1/actions.py`：审批相关端点
3. `backend/app/db/orm/approval.py`：`ApprovalRecordORM`
4. `backend/migrations/versions/0004_approval_record.py`
5. `backend/tests/test_services/test_approval_engine.py`

统一命名：
1. `ApprovalEngine` 方法：`async evaluate(action: Action, risk_assessment: RiskAssessment, approval_cycle: int) -> ApprovalDecision`、`async approve(action_id, principal, comment, decision_id) -> None`、`async reject(action_id, principal, comment, decision_id) -> None`、`async handle_timeout(action_id, approval_cycle) -> None`、`async scan_timeouts() -> list[event_id]`、`async require_manual_review(action_id, reason: str, approval_cycle: int) -> None`、`async is_plan_fully_decided(event_id, plan_revision) -> bool`。operator 只取 Principal.subject。
2. `ApprovalDecision` 字段：`decision`（auto_approve、require_approval、auto_reject 三值）、`rule_applied`、`reason`
3. `approval_record` 表字段：`approval_id`（格式 `apv-{8位十六进制}`）、`action_id`、`event_id`、`plan_revision`、`approval_cycle`、`decision_id`（决定前可空）、`required_level`、`decision`、`operator`、`comment`、`detail`（JSONB，可空，存影响评估等附加信息）、`requested_at`、`decided_at`、`timeout_at`；唯一约束 `(action_id, approval_cycle)`，非空 decision_id 另做唯一约束。
4. 判定规则固定：硬门禁先于等级；通过后 L0/L1 自动、L2 按 0.8、L3 按 high/critical+0.85、L4/L5 人工。Provider 无幂等且不可查证时即便 L0/L1 也转人工单次提交；审批超时拒绝（operator=system_timeout）。
5. approve/reject 请求体为 comment、decision_id；operator 从认证上下文取得。重复 decision_id 幂等，已由另一审批者处理时返回 409 并展示当前决定。
6. 计划级门禁：只统计当前 `plan_revision` 且 `action_category=response`、status 非 SUPERSEDED 的 Action。全部达到 APPROVED/REJECTED 终态审批结果后，才允许事件离开 WAITING_APPROVAL。**`auto_approve` 计入已决出，与人工 approve 等价，不要求进入 WAITING_APPROVAL 或发布 approval_required。**至少一个 APPROVED 且（若 disposition_policy=required）当前 revision 的 deferred `update_source_event_disposition` 也必须为 APPROVED，才转 EXECUTING_RESPONSE；deferred 被拒绝/超时则禁止执行任何实体处置，事件转 REPORTING，或在仍处 WAITING_APPROVAL 时置 `execution_substate=manual_resolution`（**不得把 manual_resolution 当作 EventStatus**），并标注终态写回未批准。全部 REJECTED/超时才转 REPORTING。SUPERSEDED 不计入分母。disposition-only 审批置信度来源见 ISSUE-057（fp max_score / 事件 confidence），禁止因跳过 RiskAgent 而无法 auto_approve。

实现步骤：
1. evaluate 展示前重新校验 capability、来源定位、目标权限与策略；按 `(action_id, approval_cycle)` upsert approval_record。重复 evaluate 返回既有决定/请求，不重复改变 Action 或发布 `approval_required`。decision 为 auto_approve 时动作直接置 APPROVED，auto_reject 时置 REJECTED；require_approval 时动作转 WAITING_APPROVAL 并只发布一次 `approval_required`。事件状态转移使用幂等守卫。
2. approve/reject 校验 Principal 角色、decision_id 幂等、当前 approval_cycle 和 WAITING_APPROVAL 状态，并以条件 UPDATE 原子决定；同 decision_id 重放返回原结果，另一 decision_id 抢先完成则 409。完成单条决定后调用 `is_plan_fully_decided`：未全部决出则保持 WAITING_APPROVAL；全部决出后按统一命名第 6 条转移，并调用注入的 `resume_investigation(event_id)` 钩子（由 ISSUE-062 WorkflowRuntimeService 提供；058 仅依赖可选回调，未注入时记录警告但不丢审批事实）。禁止“部分 APPROVED 就开始执行 IMMEDIATE 动作”。
3. 实现超时处理：P0 由 backend 内可恢复的 periodic scanner 每 60 秒扫描，并在每次审批 API/任务恢复时补扫；多实例用数据库 advisory lock 保证单执行。ISSUE-056 启用后可把同一 scan_timeouts 方法交给 Celery Beat，业务语义不变。超时导致 deferred 拒绝时，同 revision 其余已 APPROVED 的 IMMEDIATE Action 不得自动执行，必须保持未 dispatch；计划级决出后同样触发 resume 钩子。
4. 编写测试：六级判定全分支、审批通过与拒绝流转、evaluate 重放不重复通知、decision_id 重放幂等、并发审批仅一人成功、能力在等待期间撤销后重新审批、超时拒绝、同一 revision 多 Action 必须全部决出才 EXECUTING、required 事件 deferred 未批准时零实体执行、计划决出后 resume 钩子被调用、Socket 消息断言。

验收标准：
1. 硬门禁全部通过的 L0/L1 写 auto_approve 决策记录但不进入 WAITING_APPROVAL、不发布 approval_required，并置 APPROVED；缺幂等/查证能力、权限或来源能力时不得自动放行。
2. L4 动作必然进入 WAITING_APPROVAL 且收到 `approval_required` 推送。
3. 审批超时后动作为 REJECTED 且 operator 为 system_timeout。
4. 非 WAITING_APPROVAL 状态的动作调用审批端点返回 400。
5. 多个 L4 动作同时 require_approval 时不触发非法状态转移（事件仅转入 WAITING_APPROVAL 一次，每个动作均收到独立 `approval_required` 推送）。
6. 同一 plan_revision 全部 response Action 决出后：至少一个 APPROVED（且 required 时 deferred 亦 APPROVED）→EXECUTING_RESPONSE；deferred 未批准→不得执行实体处置；全部 REJECTED/超时→REPORTING。

测试与验证：
`cd backend && pytest tests/test_services/test_approval_engine.py -v`。

降级策略：
Socket 推送失败不影响审批状态落库；演示环境可设 `APPROVAL_TIMEOUT_MINUTES=1` 快速演示超时路径。

---

### ISSUE-059：处置执行与可靠事件写回服务

优先级：
P0

目标：
实现 ActionExecutionService 与 DispositionSyncService：按 execution_owner 与 execution_phase 选择唯一执行路径，以预持久化 dispatch intent 和事务 outbox 将处置可靠同步至 Mock/已验证 live Adapter，并分别维护动作效果、执行回执和写回回执。受理、执行成功、写回确认三者不得混为一谈；执行阶段只推进 IMMEDIATE 动作的提交/本地执行，写回确认主要放在 VERIFYING/闭环阶段（由 ISSUE-060 与 ISSUE-059A 收口）。

前置依赖：
ISSUE-012、ISSUE-024、ISSUE-030、ISSUE-058

输入上下文：
ActionStatus 11 态；ToolExecutor、DispositionAdapter、Principal/RBAC、live 双开关与 EventStatus.EXECUTING_RESPONSE；ActionExecutionPhase（IMMEDIATE / POST_VERIFY）。

文件范围：
1. `backend/app/services/action_execution_service.py`：ActionExecutionService
2. `backend/app/services/disposition_sync_service.py`：DispositionSyncService、OutboxWorker
3. `backend/app/services/disposition_command_factory.py`：严格白名单组装
4. `backend/app/api/v1/dispositions.py`：查询与受控重试真实实现
5. `backend/tests/test_services/test_action_execution.py`、`test_disposition_sync.py`

统一命名：
1. ActionExecutionService 方法：execute_plan、execute_action、get_actions_by_event、resolve_unknown；DispositionSyncService 增加 `resolve_writeback(writeback_id, resolution, principal, comment, evidence_ref)`。Action 人工裁决只接受 partial_success/success/failed；writeback 人工裁决只接受 confirmed/failed，且 confirmed 必须有独立外部证据并写 confirmation_evidence=manual_confirmed。两者均需 admin、状态 CAS 与完整审计，绝不再次调用实体工具。
2. `ExecutionSummary` 增加 jobs 与按八态聚合的 writeback_counts/writeback_ids；每项同时展示 action_status、execution_phase、逐目标结果与聚合 writeback_status，不能只按 pending/failed 粗分。
3. 状态映射固定：APPROVED→EXECUTING；ExecutionJob SUCCESS→Action SUCCESS，PARTIAL_SUCCESS→Action PARTIAL_SUCCESS，FAILED/TIMED_OUT/CANCELLED→Action FAILED（仅在 Provider 明确终态时），响应丢失或无法确认→Action UNKNOWN。UNKNOWN 只可在查证/管理员裁决后转 PARTIAL_SUCCESS/SUCCESS/FAILED，禁止自动回到 APPROVED。
4. 三条互斥执行路径（execute_plan 只调度 `execution_phase=IMMEDIATE` 且已 APPROVED 的 response/rollback Action；`POST_VERIFY` deferred Action 保持 APPROVED 直至 ISSUE-059A 激活）：
   - `XDR_MANAGED` 普通实体动作：同一事务置 EXECUTING 并写入 `intent_kind=ENTITY_ACTION_SUBMIT` 的 outbox，提交后由 Worker 调 Adapter；execution_receipt 与 sync receipt 分字段保存。
   - `update_source_event_disposition`：不在本 Issue 的 execute_plan 中提交；仅由 EventDispositionService（ISSUE-059A）在效果验证后激活，提交 `EVENT_STATUS_UPDATE`。
   - `DIRECT_TOOL`：先事务创建 RUNNING ActionExecutionJob（带 lease，claim → RUNNING + lease → Provider → 终态）再经 ToolExecutor 本地/设备执行；崩溃恢复通过 lease reclaim（ISSUE-173）+ 幂等键；任务终态后另建 `intent_kind=EXECUTION_RESULT_RECORD` 最小结果同步，严禁使用 ENTITY_ACTION_SUBMIT。
5. 执行阶段子状态：execute_node 仅在 IMMEDIATE job 未达 Provider 可观测终态（或 DIRECT_TOOL 尚未得到执行结果）时置 `execution_substate=waiting_execution` 并持久化检查点；**不得**因写回尚未 CONFIRMED 而在 EXECUTING_RESPONSE 阻塞。写回 ACCEPTED/PENDING 可继续转入 VERIFYING；`waiting_writeback` 只允许出现在 VERIFYING（ISSUE-060/062）。**空 IMMEDIATE 规则**：当前 revision 无待执行的 IMMEDIATE response Action（典型 disposition-only：仅有已 APPROVED 的 POST_VERIFY deferred）时，execute_plan 为空操作并**立即** `EXECUTING_RESPONSE→VERIFYING`，不得卡在 EXECUTING_RESPONSE。到 execution deadline 后仍 UNKNOWN 时进入 manual_resolution，不得自动重规划或重下发。

实现步骤：
1. 在 APPROVED→EXECUTING 原子领取前再次校验最新 Principal/批准周期、connector health 与 capability、业务策略、单一 source locator、当前 source_concurrency_token、目标 allowlist、Provider 路由以及 live 双开关；任一变化使动作冻结并进入新 approval_cycle/人工处理。条件 UPDATE 保证只有一个 worker 领取。领取集合显式排除 `execution_phase=POST_VERIFY`。
2. 按统一命名第 4 条实现三条路径；XDR_MANAGED 禁止调用 direct ToolProvider；DIRECT_TOOL 崩溃恢复先按幂等键查询 Provider，不支持时保持 UNKNOWN。
3. DispositionCommandFactory 只从标准实体、批准记录和已脱敏结果重建强类型 payload，绝不复制 Action.reason/自由 parameters/raw_result。OutboundDispositionGuard 在 outbox 写入前和发送前各 fail-closed 校验一次。
4. OutboxWorker 短事务用 SKIP LOCKED 领取并写 locked_by/lease_expires_at；租约过期可回收，但重发前必须按 provider_job_id 或同一幂等键查证。手工 retry 只把同一 outbox 重新入队，不能直接并发调用 Adapter；UNKNOWN 且无查询/幂等能力时 retry 端点拒绝。
5. ActionExecutionService 不假设 FINALIZE/RESULT_UPDATE，也**不得**在效果验证前自行创建 EVENT_STATUS_UPDATE；终态事件写回唯一入口是 ISSUE-059A。
6. outbox 生命周期独立于 EventStatus/CLOSED 与 Redis TTL；迟到回执刷新 CLOSED snapshot。**编排恢复契约（P0）**：当某 writeback 进入终态（CONFIRMED/FAILED/CONFLICT/经裁决的终态）且事件当前 `execution_substate=waiting_writeback`（或 waiting_execution 且相关 job 已终态）时，DispositionSyncService/OutboxWorker 必须在同一处理路径调用注入的 `WorkflowRuntimeService.resume_investigation(event_id)`（幂等；062 提供实现，059 声明回调接口）。禁止仅写 receipt 却永不恢复图执行。
7. P0 使用 backend 周期 worker + PostgreSQL 租约；Celery 仅替换调度。
8. 编写两种拓扑、Provider 受理后本地崩溃、丢响应、幂等、并发领取、租约回收、TOCTOU、冲突、部分成功、禁止字段、迟到确认、execute_plan 跳过 POST_VERIFY、执行阶段不因写回未确认而 waiting_writeback、**终态回执触发 resume** 的测试；在写 outbox 前与真正发送前分别验证 OutboundDispositionGuard fail-closed。

验收标准：
1. 主场景可观察 action job 与 writeback receipt；Mock XDR 的选定单一来源对象出现 simulated 处置记录且 current source state/concurrency token 按场景更新，冻结 source_snapshot 不变。
2. 注入 1 个失败动作后其余 IMMEDIATE 动作仍完成，summary.failed 为 1；deferred POST_VERIFY Action 仍为 APPROVED、无 outbox。
3. 每个必写回的 IMMEDIATE 动作有对应 ENTITY_ACTION_SUBMIT 或 EXECUTION_RESULT_RECORD；出站 JSON 只含白名单字段。
4. 每次外部调用前均已有 job/dispatch intent；陈旧 EXECUTING 按稳定幂等键恢复查证。无幂等或查询能力的未知状态触发人工复核，绝不根据“无本地结果”自动重试。
5. EXECUTING_RESPONSE→VERIFYING 不要求写回已 CONFIRMED；waiting_writeback 不出现在执行阶段；disposition-only（零 IMMEDIATE）执行节点空跑后立即进入 VERIFYING。

测试与验证：
`cd backend && pytest tests/test_services/test_action_execution.py -v`。

降级策略：
动作已执行但写回失败时保留 Action SUCCESS、writeback_status=FAILED/UNKNOWN，事件不得宣称完整闭环；只有 Adapter 明示支持幂等提交或可按外部 job/幂等键查证时才按策略恢复/重试，否则立即保持 UNKNOWN 并升级人工。分析和报告仍可生成，但必须标注“XDR 处置未确认”。

---

### ISSUE-059A：EventDispositionService 事件终态处置激活服务

优先级：
P0

目标：
正式落地 EventDispositionService：在实体动作效果验证通过（或 disposition-only / 无实体动作路径判定已确定）后，**激活当前 plan_revision 上获批终态集合兼容推导值的** deferred `update_source_event_disposition` Action，推导受控终态 SourceDisposition，再经 DispositionAdapter/`DispositionSyncService` 提交唯一的 `EVENT_STATUS_UPDATE`。若当前 deferred 的 `approved_terminal_dispositions` 不含推导值（典型：威胁向 `{contained,completed}` 遇迟到误报需 `ignored`），**禁止**改写旧 Action；必须由编排层先新 revision + ResponseAgent 生成新 deferred 并 supersede 旧条、完成审批后，再调用本服务激活新 Action。

前置依赖：
ISSUE-057、ISSUE-058、ISSUE-059

输入上下文：
Action.execution_phase=POST_VERIFY、activation_condition=after_effect_resolution、approved_terminal_dispositions、approved_operation_template_hash；FinalVerdict；VerificationResult 阶段一效果结论；DispositionSyncService；ISSUE-007 的 POST_VERIFY APPROVED→EXECUTING 前置条件。

文件范围：
1. `backend/app/services/event_disposition_service.py`：`EventDispositionService`
2. `backend/app/services/terminal_disposition_resolver.py`：`TerminalDispositionResolver`
3. `backend/tests/test_services/test_event_disposition_service.py`

统一命名：
1. `EventDispositionService` 方法：
   - `async activate_and_submit(event_id, plan_revision, principal_or_system) -> DispositionActivationResult`
   - `async get_deferred_action(event_id, plan_revision) -> Action | None`
   - `async derive_terminal_disposition(event_id) -> SourceDisposition`
2. `DispositionActivationResult` 字段：`action_id`、`activated`、`skipped_reason`（可空：not_required、already_submitted、effect_not_ready、not_approved、capability_blocked、`terminal_not_in_approved_set`）、`derived_disposition`（可空）、`disposition_id`（可空）、`writeback_id`（可空）。
3. `TerminalDispositionResolver` 映射固定（仅输出 `TERMINAL_SOURCE_DISPOSITIONS` 子集，且必须属于该 Action 的 `approved_terminal_dispositions`）：
   - `FinalVerdict.false_positive` → `ignored`（若策略不允许 ignored，则 fail-closed 转人工，不猜厂商值）
   - `FinalVerdict.confirmed_threat` 且全部适用实体效果 verified → `contained`；若业务政策要求结案完成态则 `completed`
   - 部分成功/仍有风险残留 → `suspended`（仅当获批集合包含）
   - disposition-only 路径**只允许** false_positive→ignored（见 ISSUE-007/048 收窄）；不再存在“低危 none + disposition-only”合法组合
   - 推导值不在获批集合 → `skipped_reason=terminal_not_in_approved_set`，由编排新 revision，**本服务不新建 Action**
   - 其余无法安全映射 → 不激活，`need_manual_resolution`
4. 激活语义：定位当前 revision 唯一 `tool_name=update_source_event_disposition` 且未 SUPERSEDED 的 Action；要求 status=APPROVED、writeback_applicable=true、readiness=READY、template hash/来源/operation 未变、推导值∈approved_terminal_dispositions；CAS APPROVED→EXECUTING 后，由 Factory 重建 `EVENT_STATUS_UPDATE` 命令，委托 DispositionSyncService 写入 outbox。成功提交后 Action 按回执推进 SUCCESS/FAILED/UNKNOWN。
5. `after_effect_resolution` 判定：普通计划=阶段一效果无 need_action_replan/manual；disposition-only=`final_verdict` 已为 `false_positive` 且当前 plan 无 IMMEDIATE response Action。verify 阶段不得重复 `set_final_verdict`。
6. 未激活的 deferred Action 不得计入 VerifyAgent 的 failed_actions；其 writeback_status 在激活前保持 null。

实现步骤：
1. 实现 TerminalDispositionResolver：只读 FinalVerdict、VerificationResult 阶段一汇总、获批终态集合与 Adapter operation 能力；输出非法或不在获批集合时拒绝。
2. 实现 activate_and_submit：事务内行锁 Action + 事件；校验 after_effect_resolution；CAS 激活；调用 DispositionCommandFactory + DispositionSyncService；发布 `disposition_submitted`。
3. 幂等：同一 `(action_id, closure_cycle, EVENT_STATUS_UPDATE, logical_slot)` 若已有 active head，重放返回原 disposition_id/writeback_id，不重复外呼。
4. 编写测试：普通 required 计划效果通过后激活既有 Action；disposition-only 误报路径激活为 ignored；获批集合不含 ignored 时返回 terminal_not_in_approved_set 且零外呼；未批准/未 READY 拒绝；重复调用幂等；断言 intent 仅为 EVENT_STATUS_UPDATE。

验收标准：
1. 文档与实现一致：终态写回只激活已有 deferred Action，零“另建 Action”。
2. Mock required 主路径在激活后恰好一条 CONFIRMED 的 EVENT_STATUS_UPDATE，绑定该 deferred Action。
3. 能力缺失时保持 required 义务并 blocked，不降级 not_required。

测试与验证：
`cd backend && pytest tests/test_services/test_event_disposition_service.py -v`。

降级策略：
Adapter 不支持具体 operation 时返回 capability_blocked，事件保持未闭环并转人工；管理员仍只能经 force_close 本地关闭并标记 external_unsynced。

---

### ISSUE-060：VerifyAgent 处置效果验证

优先级：
P0

目标：
实现两阶段验证：阶段一核验 IMMEDIATE 实体动作效果；阶段二在效果满足后调用 EventDispositionService 激活 deferred 终态写回，再核验必需的 DispositionReceipt 是否 CONFIRMED。只有两阶段均满足才算处置闭环成功。未激活的 deferred Action 不得当成失败动作。

前置依赖：
ISSUE-021、ISSUE-028、ISSUE-059、ISSUE-059A

输入上下文：
VerificationResult、ActionExecutionJob、CapabilityManifest 与运行时 ToolMeta；验证映射按工具元数据/target_type 注册，不维护仅覆盖固定九项的封闭表。

文件范围：
1. `backend/app/agents/verify_agent.py`：`VerifyAgent`
2. `backend/app/agents/rules/verification_mapping.py`：`VERIFICATION_MAPPING`
3. `backend/tests/test_agents/test_verify_agent.py`

统一命名：
1. `VerifyAgent.agent_name = "verify_agent"`；输出 `VerificationResult`
2. `VERIFICATION_MAPPING: dict[str, str | None]`：以稳定 `tool_name + target_type` 查验证 Tool，不使用可变 action_name；免验证项为 None，Provider manifest 可扩展但必须通过 Schema 校验。
3. 单动作结果只使用 ISSUE-005 的 `effect_status`、`writeback_required`、`writeback_readiness` 与可空 `writeback_status`；验证类 Action 的自身 status 表示验证工具是否成功运行，不能替代 effect_status。
4. 两阶段契约：
   - **阶段一（效果）**：只评估 `execution_phase=IMMEDIATE` 且已进入执行态的 response Action；映射验证工具并独立观测。POST_VERIFY deferred Action 在未激活前标记 `effect_status=skipped`（detail=`deferred_pending_activation`），**不得**进入 failed_actions，也不得因“尚未执行”触发 need_action_replan。
   - **阶段二（终态写回）**：当阶段一无 need_action_replan/manual（效果侧）且 disposition_policy=required 时，调用 `EventDispositionService.activate_and_submit`；再评估该 Action 的 EVENT_STATUS_UPDATE 及所有 applicable required IMMEDIATE 写回。激活失败（capability_blocked/not_approved 等）→ need_manual_resolution；写回未终态 → need_writeback_recovery；禁止把“未激活”解释为动作执行失败。
5. 写回映射固定：writeback_required=false→readiness=NOT_REQUIRED、status=null，视为满足；required 且 readiness 非 READY→status=null、blocked_writebacks 记录原因、need_manual_resolution=true；required+READY 时才解释八态：CONFIRMED→confirmed，PENDING/SENDING/ACCEPTED→waiting 且 need_writeback_recovery=true，UNKNOWN→先查证、无法查证时 need_manual_resolution=true，PARTIAL/FAILED→按安全重试能力决定 recovery/manual，CONFLICT→need_manual_resolution=true。任何 status 非 CONFIRMED 或尚无 status 的 required 写回都不能 overall success。
6. 顶层三分流固定：仅效果 failed/unverifiable 或执行 FAILED/PARTIAL_SUCCESS 需要 `need_action_replan=true`；纯写回问题只置 `need_writeback_recovery`/`need_manual_resolution`，绝不置 action replan。overall_status 为 success、partial、failed、waiting、manual_resolution 五值。阶段二等待终态写回确认时 overall_status=waiting 且 execution_substate 可置 waiting_writeback。

实现步骤：
1. 阶段一：读取 IMMEDIATE Action 的 job 与 disposition/outbox/receipt；XDR_MANAGED 与 DIRECT_TOOL 都必须结合独立观测验证，不能用提交方写入的状态自证效果。Action UNKNOWN 直接进入人工查证；PARTIAL_SUCCESS 按逐目标验证并进入 partial/action replan。
2. 阶段二：调用 EventDispositionService；追加全局写回检查。若独立观测与已同步执行结果不一致，只在 Adapter 明确支持时创建新的 EXECUTION_RESULT_RECORD 修正命令；不得调用不存在的通用 RESULT_UPDATE/FINALIZE。EVENT_STATUS_UPDATE 只能来自 059A 激活路径。
3. 为每个验证动作创建 `action_category=verification`、`writeback_required=false` 的 Action。验证工具正常运行且观察为 true/false 时，该验证 Action 均可为 SUCCESS，观察结论分别映射 effect_status verified/failed；工具调用异常/超时则验证 Action 为 FAILED/UNKNOWN，effect_status=unverifiable。原处置 Action 的执行 status 保持原值。
4. 组装唯一 VerificationResult Schema，所有 ID 使用 writeback_ids；写 EventContext 并发布 `action_verified`。route_after_verify 使用三布尔字段，不从 overall_status 猜路由。
5. 编写测试：两阶段全通过；阶段一失败不调用 activate；deferred 未激活不进 failed_actions；阶段二激活后写回 waiting/failed/conflict 只触发 writeback 分流；八态写回真值表；免验证动作 skipped；disposition-only 路径阶段一空实体但阶段二仍激活；验证观察为 false 与验证工具异常两种 Action status 区分。

验收标准：
1. 主场景动作效果与终态写回均确认后 overall_status=success；人为只让设备成功但写回失败时不得 success。
2. 注入 1 项效果验证失败后 need_action_replan=true 且 failed_actions 准确，且 EventDispositionService 未被调用；只注入写回失败时 need_action_replan=false 且动作执行次数不变。
3. create_ticket 动作 effect_status=skipped，验证 Action.writeback_required=false。
4. 未激活 deferred Action 的 effect_status=skipped，不出现在 failed_actions。

测试与验证：
`cd backend && pytest tests/test_agents/test_verify_agent.py -v`。

降级策略：
验证工具全部不可用时输出 overall_status=failed、全部 unverifiable，事件转人工复核标记（escalated=true），不阻塞报告生成。

---

### ISSUE-061：回滚补偿服务（Saga 模式）

优先级：
P1

目标：
实现动作回滚以及按独立业务政策要求的外部补偿同步。回滚不是删除历史：必须持久化 rollback Action、按需产生一条或多条补偿 writeback（COMPENSATION_RECORD），并在回滚效果独立验证通过后把原动作转为 ROLLED_BACK。live 能力未确认时只执行允许的本地/设备回滚并保留“外部补偿未同步”，不得宣称已完成 XDR 补偿写回。

前置依赖：
ISSUE-022、ISSUE-059、ISSUE-059A

输入上下文：
回滚映射（block_ip→unblock_ip、block_domain→unblock_domain、disable_account→restore_account、isolate_host→cancel_host_isolation、quarantine_file→restore_file、create_ticket→close_false_positive_ticket；force_logout、reset_password、revoke_token、notify_security_team 默认不可回滚）；ActionStatus 的 ROLLED_BACK。Provider capability 可进一步收窄，不得凭名称扩大。

文件范围：
1. `backend/app/services/rollback_service.py`：`RollbackService`
2. `backend/app/agents/rules/rollback_mapping.py`：`ROLLBACK_MAPPING`
3. `backend/tests/test_services/test_rollback_service.py`

统一命名：
1. 方法：`async rollback_action(action_id, operator, reason) -> RollbackResult`、`async rollback_event(event_id, operator, reason) -> list[RollbackResult]`、`async compensate(event_id, failed_action_id) -> list[RollbackResult]`（Saga：回滚 failed_action 之前已成功的动作）
2. `RollbackResult` 字段：`action_id`（原 Action）、`rollback_action_id`（新持久化的 rollback Action）、`rollback_tool`、`rollback_effect_status`（verified、failed、unverifiable、not_supported）、`compensation_writeback_required`、`compensation_writeback_readiness`、`compensation_writebacks`（list，元素含 writeback_id、disposition_id、status、intent_kind=COMPENSATION_RECORD；可空列表）、`compensation_writeback_status`（可空聚合值、仅 WritebackStatus）、`rolled_back`、`warning`、`audit_log_id`。无需同步时 readiness=NOT_REQUIRED、compensation_writebacks 为空、status=null；必须同步但能力不支持时 required 仍为 true、readiness=CAPABILITY_UNSUPPORTED、status=null。兼容字段 `compensation_writeback_id` 仅在恰好一条补偿写回时填充，否则为 null。
3. 回滚 Action 持久化：每次成功发起的回滚必须插入 `action_category=rollback` 的 Action（source_action_id=原 action_id、plan_revision=当前或补偿专用 revision、execution_owner 继承或按能力重选、writeback_required 由补偿政策推导），经审批门禁（若需要）后执行；不可只改原 Action 而不留 rollback 行。
4. 原动作何时变 ROLLED_BACK：仅当对应 rollback Action 执行达 SUCCESS/PARTIAL_SUCCESS，且独立验证 `rollback_effect_status=verified`（或免验证项 skipped 且执行成功）之后，才 CAS 原 Action SUCCESS/PARTIAL_SUCCESS→ROLLED_BACK，并写 `rollback_status=completed`。验证失败时原 Action 保持原状，rollback Action 记 FAILED/UNKNOWN，rolled_back=false。
5. 多条补偿 writeback：按原 Action 关联的每条 applicable 外部写回（ENTITY_ACTION_SUBMIT / EXECUTION_RESULT_RECORD）可各生成一条 COMPENSATION_RECORD（parent_disposition_id 指向原 disposition）；同一 rollback Action 可对应多条 writeback，聚合 status 规则与 ISSUE-002 一致。EVENT_STATUS_UPDATE 的迟到误报终态仍走 EventDispositionService；若当前 deferred 获批集合不含 `ignored`，编排须先新 revision 生成含 ignored 的 deferred 并 supersede 旧条后再激活，本服务不伪造终态 Action。**P1 迟到误报 CLOSED 门禁**：凡路径要求补偿同步的，全部 applicable COMPENSATION_RECORD 必须 CONFIRMED 后，才允许激活/确认 deferred EVENT_STATUS_UPDATE；补偿失败不得跳过直接 CLOSED。
6. 不可回滚动作返回 `rolled_back=false`、`warning="not_rollbackable"`，不创建 rollback Action。
7. rollback_event 仅作用于当前 ResponsePlan 中 action_category=response、source_action_id 为空且效果已确认成功的 IMMEDIATE 动作，按 manifest 可回滚能力与 executed_at 逆序执行。UNKNOWN 与 PARTIAL_SUCCESS 在逐目标状态未查清前禁止自动回滚。POST_VERIFY deferred Action 不走实体回滚映射。

实现步骤：
1. 按原 action.execution_owner 回滚：XDR_MANAGED 只有 Adapter 明确支持对应撤销 operation 时才提交补偿实体动作（intent 按 owner 映射）；DIRECT_TOOL 先预持久化 rollback job 后执行回滚工具。效果撤销验证通过后，仅为每条需同步的原写回创建 COMPENSATION_RECORD；否则保留本地永久审计并显示 external compensation unsupported。实体补偿与结果记录不得并行双发同一副作用。
2. 每次回滚写 event_audit_log（operator 与 reason 必填）并发布 `action_executed`（payload 标注 rollback=true、rollback_action_id）。
3. 单项回滚失败不中断批量回滚，结果如实返回。
4. 编写测试：单动作回滚后验证工具返回假且原 Action 未 ROLLED_BACK；验证通过后原 Action ROLLED_BACK 且存在 rollback Action 行；一条原 Action 多 disposition 时产生多条 COMPENSATION_RECORD；事件级逆序批量回滚；不可回滚项 warning；Saga 补偿只回滚失败点之前的动作；审计完整。

验收标准：
1. 误报场景使可回滚效果经独立验证撤销后，原动作转 ROLLED_BACK，且 action 表可查到对应 rollback Action；Mock capability 开启时收到关联原 disposition_id 的一条或多条 COMPENSATION_RECORD。live 未确认能力时不得发送，UI 分别展示“效果已回滚”和“外部补偿不支持/未确认”，不能合称闭环完成。
2. 回滚顺序与执行顺序严格相反（测试用时间戳断言）。
3. 每次回滚有审计记录与实时推送。

测试与验证：
`cd backend && pytest tests/test_services/test_rollback_service.py -v`。

降级策略：
回滚工具失败时保留原动作 SUCCESS 状态并把失败明细写审计，提示人工介入；不可回滚动作仅审计告知。

---

### ISSUE-062：重规划触发与 REPLANNING 闭环集成

优先级：
P0

目标：
把验证失败到重新处置的闭环接入 LangGraph：实现 replan_node 真实逻辑（PlannerAgent.revise 修订计划、ResponseAgent 重新生成方案、重执行与重验证），受 MAX_REPLAN_COUNT 约束，超限升级人工。同时把 ISSUE-048 的 response、approval、execute、verify 占位节点替换为真实实现。

前置依赖：
ISSUE-036、ISSUE-049、ISSUE-052、ISSUE-054、ISSUE-057、ISSUE-058、ISSUE-059、ISSUE-059A、ISSUE-060

输入上下文：
route_after_verify 路由（ISSUE-048）；StateMachineService 的 REPLANNING 副作用（ISSUE-037）；`escalated` 字段（InvestigationResult）。

文件范围：
1. `backend/app/orchestration/workflow_graph.py`（替换 5 个占位节点）
2. `backend/app/orchestration/replan_handler.py`：`ReplanHandler`
3. `backend/app/orchestration/writeback_recovery_handler.py`：`WritebackRecoveryHandler`
4. `backend/tests/test_orchestration/test_replan_loop.py`、`test_writeback_recovery.py`

统一命名：
1. `ReplanHandler` 只接收 execution_failed/effect_not_verified 两类动作问题。写回 waiting/failed/unknown/conflict 交由独立 `WritebackRecoveryHandler` 操作同一 outbox/idempotency_key，绝不进入 REPLANNING，也绝不重新执行 DIRECT_TOOL；冲突先回读 current source state 并转人工决策。
2. 真实节点接线：response_node 调 ResponseAgent；approval_wait_node 调 ApprovalEngine 并以 execution_substate=waiting_approval 检查点暂停（须等当前 plan_revision 全部 response Action 决出，含 deferred；auto_approve 计入已决出）；execute_node 调 ActionExecutionService（仅 IMMEDIATE；若无 IMMEDIATE 则空跑并立即转 VERIFYING）；verify_node 调 VerifyAgent 两阶段验证（阶段二内经 EventDispositionService 激活 deferred）。`route_after_verify` 真值表固定：need_manual_resolution→保持 VERIFYING+manual_resolution 并通知人工；否则 need_writeback_recovery→保持 VERIFYING+waiting_writeback，由回执/Worker 恢复同一检查点；否则 need_action_replan→StateMachineService 转 REPLANNING 后走 replan_node；三者均 false 且 overall success→REPORTING。禁止按 overall_status 模糊推断。执行阶段不得进入 waiting_writeback。
3. 超限处理：replan_count 达 MAX_REPLAN_COUNT 且仍失败时，ReplanHandler 写入 `security_event.escalated=true`（持久化，报告生成时据此包含人工升级说明）、事件经 CONTAINED（部分处置成功）或 FAILED（全部失败）进入 report_node
4. 审批恢复入口：审批端点完成后调用 `resume_investigation(event_id)`（从检查点恢复图执行）
5. Action/writeback resolve 或迟到终态回执完成后，WorkflowRuntimeService 原子清除对应 execution_substate，再调用同一 `resume_investigation(event_id)`；重复回调幂等，且恢复前重新读取数据库当前态。

实现步骤：
1. 替换 5 个占位节点为真实实现，保持节点名与路由不变。
2. 实现重规划与写回恢复分流；WritebackRecoveryHandler 受 WRITEBACK_MAX_RETRIES、Adapter idempotency/lookup 能力和租约约束，不消耗调查 replan_count。PENDING/SENDING/ACCEPTED 等待回执，UNKNOWN 先查证，FAILED/PARTIAL 仅在可安全重试时重入队，CONFLICT 转人工；任一分支动作执行次数保持不变。
3. 实现审批中断恢复：approval_wait_node 检测待审批动作时图执行暂停（检查点落 Redis），approve 或 reject 后经 resume_investigation 继续。重规划后若新方案含 L4 动作，状态经 REPLANNING 到 PLANNING_RESPONSE 再到 WAITING_APPROVAL，approval_wait_node 再次暂停等待审批，审批通过后恢复执行。
4. 编写测试：注入效果验证失败使其重规划 1 轮后成功；3 轮全失败后经合法 REPLANNING→CONTAINED/FAILED 进入报告；分别注入八种 writeback 状态断言从不进入 REPLANNING、不增加 replan_count、不新增 Action；审批中断与恢复全流程（含重规划后 L4 动作再次审批）。

验收标准：
1. 动作效果失败可重规划；仅外部写回失败/等待时事件停在可恢复 VERIFYING 子状态，动作执行次数保持 1，写回使用同一 outbox/幂等键恢复。
2. 重规划严格不超过 3 轮，超限事件 escalated=true 且报告含人工升级说明。
3. 含 L4 动作的方案在审批通过后从中断点恢复执行。
4. ISSUE-039 与 ISSUE-055 既有集成测试全部仍通过。

测试与验证：
`cd backend && pytest tests/test_orchestration/test_replan_loop.py -v && pytest -m orchestration -v`。

降级策略：
PlannerAgent.revise 失败时只允许使用带新 revision 的确定性替代计划，并排除已成功或 UNKNOWN 的副作用动作；没有安全替代时直接升级人工，绝不原样重放旧计划。审批/写回恢复失败时保持对应 execution_substate，可受控重触发 resume。

---

### ISSUE-063：决策轨迹聚合 API（decision_trace）

优先级：
P1

目标：
实现决策轨迹聚合服务与 API：把 Agent、工具、模型、状态、审批、动作执行、处置命令与写回回执按时间合并为统一 decision_trace 时间线，支撑可解释性展示与评委追问。

前置依赖：
ISSUE-023、ISSUE-028、ISSUE-058

输入上下文：
四类日志表、approval_record、action_execution_job、disposition_outbox 与 disposition_receipt；`GET /api/v1/events/{event_id}/decision-trace` 路径（简介第 4.2 节）。

文件范围：
1. `backend/app/services/decision_trace_service.py`：`DecisionTraceService`
2. `backend/app/api/v1/decision_trace.py`
3. `backend/tests/test_services/test_decision_trace.py`

统一命名：
1. `DecisionTraceService.get_decision_trace(event_id) -> DecisionTrace`
2. `DecisionTrace` 字段：`event_id`、`entries`（list[DecisionTraceEntry]）、`summary`（含 `agent_count`、`tool_call_count`、`llm_call_count`、`total_tokens`、`state_transition_count`、`approval_count`、`action_execution_count`、`disposition_count`、`writeback_count`、`total_duration_ms`）
3. `DecisionTraceEntry` 字段：`entry_id`、`entry_type`（agent_execution、tool_call、llm_call、state_transition、approval、action_execution、disposition、writeback 八值）、`timestamp`、`actor`、`title`、`detail`（脱敏结构化投影，不是 raw payload）、`ref_id`
4. API 查询参数：`entry_type`（可多值过滤）、`page`、`page_size`（默认 50）

实现步骤：
1. 实现八类数据查询与归一化为 DecisionTraceEntry（title 用模板生成，如"TriageAgent 完成分诊：severity=high"）。
2. 按 timestamp 升序合并（同时间戳按 entry_type 固定次序），计算 summary。
3. 实现 API（分页与类型过滤），接入 OpenAPI 导出。本 API 的归并结果同时作为 TrajectoryAnalyzer（ISSUE-066）的输入源。
4. 编写测试：完整研判后八类条目齐全且时间有序、过滤与分页、单一数据源故障、空事件返回空轨迹。

验收标准：
1. 主场景 decision_trace 含八种 entry_type 且条目数与各源记录数一致。
2. summary 统计与明细一致（条目计数对得上）。
3. `entry_type=tool_call` 过滤只返回工具调用条目。

测试与验证：
`cd backend && pytest tests/test_services/test_decision_trace.py -v`。

降级策略：
任一数据源查询失败时跳过该源并在响应 `details` 中标注缺失源，其余条目正常返回。

---

### ISSUE-064：处置验证闭环端到端测试

优先级：
P0

目标：
对研判、审批、两种执行拓扑、MockXDR 写回、两阶段验证（效果→EventDispositionService 激活终态写回）与故障分流编写 P0 端到端测试；这些测试验证内部契约与未来适配边界，不代表已经完成深信服 live 兼容。误报回滚作为 ISSUE-061 完成后的增强场景。

前置依赖：
ISSUE-062

输入上下文：
全部处置链组件（含 ISSUE-059A）；ISSUE-011 三个场景包；MockLLM golden。

文件范围：
1. `backend/tests/integration/test_e2e_response_loop.py`

统一命名：
1. pytest 标记：`@pytest.mark.e2e_response`

实现步骤：
1. 场景一（XDR_MANAGED）：获批 IMMEDIATE 动作只提交 MockXDR 一次；VERIFYING 阶段二激活 deferred Action 后恰有一条 EVENT_STATUS_UPDATE CONFIRMED（confirmation_evidence=readback_verified、simulated=true）；断言 action 表 deferred 行在激活前后为同一 action_id；MockToolProvider 调用次数为 0。
2. 场景二（人工审批）：同一 plan_revision 多 Action（含 deferred）必须全部决出才进入执行；注入低置信度使 L3 转人工，经 API 批准后恢复；另测 deferred 拒绝时零实体执行。
3. 场景三（direct_tool）：MockToolProvider 只执行一次，随后 EXECUTION_RESULT_RECORD 写回；阶段二仍激活 deferred EVENT_STATUS_UPDATE；注入首次 HTTP 响应丢失，断言同一幂等键查证成功且无第二次设备副作用。
4. 场景四（失败分流）：用 Mock 故障配置分别注入动作效果失败、通用 HTTP 5xx 和并发令牌冲突；仅动作效果失败触发替代处置且不得调用 EventDispositionService；写回故障不得重执行原动作；未激活 deferred 不得计入 failed_actions。
5. 场景五（required 误报 disposition-only，P0）：可用 fixture 注入或走 ISSUE-032 `RuleBasedFalsePositiveHook`；断言 begin_disposition_only 后 `final_verdict=false_positive`、不进证据采集、零 IMMEDIATE、execute 空跑直达 VERIFYING、deferred 激活为 ignored、报告按稳定 report_id 单份、CLOSED；并断言主链 insider 场景**不会**误入 disposition_only。完整向量 Matcher 仍由 ISSUE-078 验收。
6. 可选增强：ISSUE-061 完成时追加迟到误报回滚、rollback Action 持久化及多条 COMPENSATION_RECORD；ISSUE-063 完成时追加轨迹聚合。

验收标准：
1. 5 个 P0 场景全部通过，且测试断言任何出站请求均不含分析内容；required 闭环均含确认的终态 EVENT_STATUS_UPDATE。
2. CI 可运行（`pytest -m e2e_response`）。

测试与验证：
`cd backend && pytest tests/integration/test_e2e_response_loop.py -m e2e_response -v`。

降级策略：
无

---

### ISSUE-065：Agent 输出质量评估（OutputQualityEvaluator）

优先级：
P1

目标：
建立 Agent 输出质量评估：以规则指标为主、可选 LLM-judge 为辅，对关键 Agent 输出打分并写入上下文，低分可触发护栏复核或重规划。完成后系统对自身研判质量可量化、可观察。

前置依赖：
ISSUE-027、ISSUE-028、ISSUE-036

输入上下文：
简介第 4.13 节 `OutputQualityScore` 与第 4.6 节 `QualityVerdict`；ISSUE-027 LLM（judge 用 prompt_key `quality_judge`，mock golden 确定性）；评估分写 EventContext 的 `quality_scores`。

文件范围：
1. `backend/app/services/output_quality_evaluator.py`：`OutputQualityEvaluator`
2. `backend/app/agents/prompts/quality_judge_prompt.py`
3. `backend/tests/test_services/test_output_quality.py`

统一命名：
1. `QualityVerdict`（枚举）：pass、warn、fail
2. `OutputQualityScore` 字段：`agent_name`、`score`（0-1）、`verdict`（QualityVerdict）、`metrics`（dict）、`reasons`、`evaluated_by`（rule、llm 两值）
3. `OutputQualityEvaluator.evaluate(agent_name, output, context) -> OutputQualityScore`
4. 规则指标固定（metric 名）：`completeness`（必填字段齐全度）、`grounding_ratio`（带证据/引用的断言占比）、`consistency`（与上游一致性，如 severity 与 risk_score 区间一致）、`specificity`（是否含具体实体而非空泛描述）
5. 阈值：score 不低于 0.75 为 pass，0.5 至 0.75 为 warn，低于 0.5 为 fail

实现步骤：
1. 实现规则评估：四指标加权（completeness 0.3、grounding_ratio 0.3、consistency 0.25、specificity 0.15）得 score。
2. 实现可选 LLM-judge：`QUALITY_JUDGE_ENABLED=true` 且 LLM 可用时对 score 做校准（取规则与 judge 均值），否则纯规则。
3. 评估对象固定为 triage_result、evidence_output、risk_assessment、report；分数写 `quality_scores`（dict 按 agent_name）。
4. fail 级输出由编排层决定触发一次重规划或转人工（接入点在 ISSUE-062）。
5. 编写测试：完整高质量输出 pass、缺字段 completeness 下降、伪造无证据断言 grounding_ratio 下降、severity 与分数矛盾 consistency 下降、judge 开关两态确定性。

验收标准：
1. 高质量主场景输出评为 pass，残缺输出评为 warn 或 fail。
2. 四指标可独立解释且加权得分正确。
3. `QUALITY_JUDGE_ENABLED=false` 时纯规则评估且确定性。
4. 评估分写入 `quality_scores`。

测试与验证：
`cd backend && pytest tests/test_services/test_output_quality.py -v`。

降级策略：
LLM judge 不可用时回退纯规则评分；评估自身失败仅记告警、不阻塞主链路；本 Issue 未完成不影响 P0。

---

### ISSUE-066：轨迹分析（TrajectoryAnalyzer 与分析 API）

优先级：
P1

目标：
基于决策轨迹做执行质量分析：统计总步数、冗余与重复工具调用、循环迹象、重规划有效性与各阶段耗时，产出结构化指标并提供 API。完成后多 Agent 调查过程的效率与健康度可被量化评估。

前置依赖：
ISSUE-028、ISSUE-063

输入上下文：
ISSUE-063 的 decision_trace 聚合数据（agent、tool、llm、state、approval、action_execution、disposition、writeback 八类条目）；简介第 4.13 节 `TrajectoryMetric`；`/api/v1/events/{event_id}/trajectory` 路径。

文件范围：
1. `backend/app/services/trajectory_analyzer.py`：`TrajectoryAnalyzer`、`TrajectoryReport`
2. `backend/app/api/v1/trajectory.py`：`GET /api/v1/events/{event_id}/trajectory`
3. `backend/tests/test_services/test_trajectory_analyzer.py`

统一命名：
1. `TrajectoryAnalyzer.analyze(event_id) -> TrajectoryReport`
2. `TrajectoryReport` 字段：`event_id`、`total_steps`、`agent_invocations`、`tool_calls`、`llm_calls`、`metrics`（dict[TrajectoryMetric, float]）、`findings`（list 文本提示）
3. `TrajectoryMetric`（指标名固定）：`redundant_tool_calls`、`loop_suspected`、`replan_effectiveness`、`avg_agent_latency_ms`、`evidence_yield`、`steps_to_verdict`
4. findings 规则：冗余调用超阈值、疑似循环、重规划无改善等给出文本提示

实现步骤：
1. 从 decision_trace 拉全部条目，按类型聚合计数与耗时。
2. 计算各 `TrajectoryMetric`：重复工具调用按 `(tool_name, params 指纹)` 统计；replan_effectiveness 对比重规划前后 verification 是否由失败转成功；evidence_yield 用有效证据数除以查询调用数。
3. 生成 findings 文本提示（与 ISSUE-052 收敛信号互补，用于事后复盘）。
4. 实现 API 并接入 OpenAPI 导出；ISSUE-072 工具审计页消费该接口展示。
5. 编写测试：构造含重复调用的轨迹断言 redundant_tool_calls、含重规划改善的轨迹断言 replan_effectiveness、正常轨迹无 loop_suspected、API 返回结构。

验收标准：
1. 重复工具调用被准确计数。
2. 重规划由失败转成功时 replan_effectiveness 为正。
3. 正常 3 步收敛轨迹 loop_suspected 为 0。
4. `GET /api/v1/events/{event_id}/trajectory` 返回完整 `TrajectoryReport`。

测试与验证：
`cd backend && pytest tests/test_services/test_trajectory_analyzer.py -v`。

降级策略：
decision_trace 缺失时返回空报告并标注 `insufficient_trace`，不报错；本 Issue 未完成不影响 P0。

---

### ISSUE-067：前端脚手架与 API 接入层

优先级：
P0

目标：
搭建 React 前端工程：Vite、TypeScript、路由、全局布局、类型化 API 客户端与 Socket.IO 客户端封装。完成后各页面 Issue 只需实现业务组件。

前置依赖：
ISSUE-004

输入上下文：
`contracts/openapi/openapi.json` 与 `contracts/socketio/events.schema.json`；前端目录约定（简介第 4.1 节）；ISSUE-001 的前端占位工程。

文件范围：
1. `frontend/package.json`、`frontend/vite.config.ts`、`frontend/tsconfig.json`
2. `frontend/src/App.tsx`、`frontend/src/router.tsx`、`frontend/src/layouts/MainLayout.tsx`
3. `frontend/src/services/apiClient.ts`、`frontend/src/services/eventApi.ts`、`frontend/src/services/socketClient.ts`
4. `frontend/src/types/`：`event.ts`、`action.ts`、`report.ts`、`trace.ts`、`socket.ts`
5. `frontend/src/stores/eventStore.ts`
6. `frontend/tests/services/apiClient.test.ts`

统一命名：
1. 技术栈固定：React 18、Vite 5、TypeScript 5、Ant Design 5、zustand（状态）、axios（HTTP）、socket.io-client、ECharts（图表）；包管理用 pnpm
2. 路由路径固定：`/events`（看板）、`/events/:eventId`（详情）、`/approvals`（审批中心）、`/tools-audit`（工具审计）
3. `apiClient`：axios 实例，baseURL 读 `VITE_API_BASE_URL`（默认 `http://localhost:8000/api/v1`），统一错误拦截（解析 error_code 与 error_message 并 toast）
4. `eventApi` 除事件方法外增加 getSourceRecord、listConnectors、getExecutionJob、listDispositions、getDisposition、getWriteback、retryWriteback、resolveUnknownAction、resolveWriteback；retry 只重入队安全可查证的同一 outbox，两个 resolve 仅管理员界面显示。来源、内部、动作和写回状态使用不同类型。
5. TypeScript 类型字段与后端 JSON Schema 完全一致（snake_case 不转换）
6. P0 数据刷新使用 10 秒轮询；若 ISSUE-040 已启用则 socketClient 提供实时增量并保留轮询兜底。前端构建不得因 Socket 服务缺失失败。

实现步骤：
1. 初始化 Vite 工程与依赖，配置路由与 MainLayout（侧边导航、顶栏、内容区）。
2. 实现 apiClient 错误拦截与 eventApi 全部方法。
3. 依据 contracts JSON Schema 手写核心 TypeScript 类型（字段名与枚举值逐一对齐）。
4. 实现 socketClient 与 eventStore（事件列表与当前事件缓存、socket 增量更新入口）。
5. 配置 vitest 与测试：apiClient 错误处理、eventApi 路径正确性（mock axios）、socketClient 订阅去重。

验收标准：
1. `pnpm dev` 启动且四个路由可访问（空页面占位）。
2. `pnpm build` 与 `pnpm test` 通过，tsc 零错误。
3. eventApi 全部方法路径与 OpenAPI 一致（测试断言 URL）。

测试与验证：
`cd frontend && pnpm install && pnpm test && pnpm build`。

降级策略：
Socket 连接失败时 store 自动启用 10 秒轮询兜底，页面功能不受阻。

---

### ISSUE-068：事件看板页

优先级：
P0

目标：
实现事件看板：事件列表、状态与严重度筛选、分页、实时状态更新与"触发研判"操作。完成后系统有了第一个可演示的业务界面。

前置依赖：
ISSUE-038、ISSUE-067

输入上下文：
`GET /api/v1/events` 分页响应；EventStatus 14 态与 Severity 4 级；socket 的 `event_created` 与 `state_change`。

文件范围：
1. `frontend/src/pages/EventListPage.tsx`
2. `frontend/src/components/event/EventTable.tsx`、`StatusBadge.tsx`、`SeverityTag.tsx`、`VerdictTag.tsx`
3. `frontend/tests/pages/EventListPage.test.tsx`

统一命名：
1. 状态颜色约定：NEW 灰、进行中状态（TRIAGING 至 VERIFYING、REPLANNING、REPORTING）蓝、WAITING_APPROVAL 橙、CONTAINED 青、CLOSED 绿、FAILED 红
2. 严重度颜色：low 绿、medium 黄、high 橙、critical 红
3. 列固定：event_id、title、event_type、severity、status（标注“本地状态”）、final_verdict、risk_score、writeback_overall_status（与 WritebackSummary.aggregate_status 同源，无命令时为 null）、created_at、操作列。CLOSED 旁若 external_unsynced 或终态写回未确认，必须显示“本地已关/外部未确认”；若已 CONFIRMED 但 confirmation_evidence 非 readback_verified，显示“已同步（弱证据）”，不得只显示绿色成功。统计徽标与详情页、CLOSED 门禁必须复用同一 WritebackSummary / ExecutionSummary 服务，禁止前端自行按 Action 列表重算。
4. 筛选参数与 API 查询参数同名：`status`、`severity`、`event_type`、`page`、`page_size`

实现步骤：
1. 实现列表加载、筛选与分页（URL 查询参数同步，可刷新保持）。
2. 实现三个标签组件（颜色与文案集中常量定义）。
3. 订阅 global 房间：event_created 插入新行，state_change/writeback_updated 原位更新本地状态与外部同步徽标。
4. 实现"触发研判"按钮（调用 triggerInvestigation，409 时提示进行中）。
5. 编写测试（vitest 与 testing-library，mock API）：渲染、筛选请求参数、socket 更新行、触发研判调用。

验收标准：
1. 看板展示 mock 后端事件并可按状态与严重度筛选。
2. 后端状态变更 1 秒内（或轮询周期内）反映到列表。
3. 触发研判后该行状态进入 TRIAGING。

测试与验证：
`cd frontend && pnpm test -- EventListPage`；手工验证：启动前后端，摄取演示数据后看板可见三个场景事件。

降级策略：
Socket 不可用时回退轮询刷新（ISSUE-067 机制），交互不变。

---

### ISSUE-069：事件详情页框架与研判概览

优先级：
P0

目标：
实现独立 Agent 的事件详情页：显示来源对象、内部研判与本地动作，并用 DispositionReceipt 展示 Adapter 声明的外部同步结果与证据等级；不得仅凭本地 Action SUCCESS 或一次 HTTP ACK 宣称“已写入 XDR”。Mock 回执必须显著标注 simulated。

前置依赖：
ISSUE-059、ISSUE-068

输入上下文：
`GET /api/v1/events/{event_id}`（含 EventContext 摘要）、`/traces`；风险六维 RiskFactor；EntitySet 六类实体。

文件范围：
1. `frontend/src/pages/EventDetailPage.tsx`
2. `frontend/src/components/event/EventOverviewCard.tsx`、`RiskScorePanel.tsx`、`EntityList.tsx`、`EvidenceList.tsx`
3. `frontend/src/hooks/useEventDetail.ts`
4. `frontend/tests/pages/EventDetailPage.test.tsx`

统一命名：
1. Tab key 固定：`source`、`timeline`、`graph`、`evidence`、`actions`、`writeback`、`audit`、`report`。
2. `useEventDetail(eventId)`：并行加载并返回 `{ event, traces, actions, executionJobs, dispositions, writebacks, loading, refresh }`，订阅该事件房间自动局部刷新
3. RiskScorePanel：六维雷达图（ECharts radar），维度名用 factor_name 中文映射常量 `RISK_FACTOR_LABELS`
4. EvidenceList 列：evidence_id、source、evidence_type、timestamp、description、confidence、is_conflicting（冲突行高亮）

实现步骤：
1. 实现页面骨架与 Tab 路由 hash 同步；未实现 Tab 显示占位（注明由对应功能补充）。
2. Source Tab 展示冻结调查快照与当前来源状态、连接器读/写能力；“外部同步/写回”Tab 展示 disposition_id、writeback_id、action_id、execution_owner、execution_phase、writeback_status、可空 provider_job_id、逐目标结果、重试与冲突，并单独高亮当前 closure_cycle 的终端 EVENT_STATUS_UPDATE（terminal_event_* 字段）；不展示分析正文。Actions Tab 区分 IMMEDIATE 与 POST_VERIFY（deferred 未激活显示“待效果验证后激活”，不得显示为失败）。
3. 实现六维雷达图与各维 reasoning 的悬浮提示。
4. 实现证据 Tab：列表、来源筛选、冲突高亮与冲突说明展示（EvidenceOutput.conflicts）。
5. 订阅事件房间：`risk_updated`、`state_change`、`final_verdict_updated`、`action_executed`、`action_verified`、`disposition_submitted`、`writeback_updated` 触发相应资源局部刷新。
6. 编写测试：数据渲染、Tab 切换、冲突证据高亮。

验收标准：
1. 主场景详情页展示实体、风险分、六维雷达与证据列表。
2. 冲突证据行有视觉标识并可查看冲突原因。
3. 研判过程中状态与评分实时更新。

测试与验证：
`cd frontend && pnpm test -- EventDetailPage`；手工验证主场景详情页各区域数据正确。

降级策略：
EventContext 字段缺失时对应区域显示"暂无数据"占位，不报错白屏。

---

### ISSUE-070：攻击故事线时间轴组件

优先级：
P1

目标：
实现攻击故事线 Tab：分阶段垂直时间轴展示 AttackStoryline，条目可展开关联证据详情，阶段标注 ATT&CK 战术。完成后"攻击故事线生成"亮点可视化。

前置依赖：
ISSUE-051、ISSUE-069

输入上下文：
`GET /api/v1/events/{event_id}/timeline`（返回 AttackStoryline，本 Issue 实现该端点的后端读取逻辑：从 EventContext 的 storyline 字段读取）；StorylinePhase 5 阶段枚举。

文件范围：
1. `backend/app/api/v1/timeline.py`（timeline 端点真实实现）
2. `frontend/src/components/storyline/StorylineTimeline.tsx`、`PhaseSection.tsx`、`TimelineEntryItem.tsx`
3. `frontend/tests/components/StorylineTimeline.test.tsx`

统一命名：
1. 阶段中文标签常量 `PHASE_LABELS`：initial_access 初始访问、collection 数据收集、staging 数据集结、exfiltration 数据外泄、post_action 后续动作
2. 阶段颜色：initial_access 蓝、collection 黄、staging 橙、exfiltration 红、post_action 紫
3. TimelineEntryItem 展示：timestamp、description、technique_id 徽标（可点击显示技术名）、severity_hint 着色、展开后显示 evidence_id 关联证据原文

实现步骤：
1. 实现 timeline 端点（storyline 缺失时 404 加 error_code `storyline_not_ready`）。
2. 实现垂直时间轴：阶段分区、narrative 摘要、条目排序渲染。
3. 实现条目展开加载证据详情（复用 EvidenceList 数据）。
4. 顶部展示 narrative_summary 与 generated_by 标识（rule 生成时标注"规则生成"）。
5. 编写测试：5 阶段渲染、条目展开、storyline 未就绪占位。

验收标准：
1. 主场景时间轴按阶段分区展示且时间单调递增。
2. 每条目可展开查看关联证据，technique_id 徽标可见。
3. storyline 未生成时显示占位而非报错。

测试与验证：
`cd frontend && pnpm test -- StorylineTimeline`；后端 `pytest tests/test_api/ -k timeline -v`；手工验证主场景时间轴完整呈现五阶段叙事。

降级策略：
storyline 缺失时 Tab 回退展示证据时间排序列表（复用证据数据），标注"故事线未生成"。

---

### ISSUE-071：实体关系图组件

优先级：
P1

目标：
实现实体关系图 Tab：力导向图展示 GraphOutput 的节点与边，支持节点类型着色、边关系标签、中心实体高亮与攻击路径候选播放。完成后图谱分析能力可视化。

前置依赖：
ISSUE-050、ISSUE-069

输入上下文：
`GET /api/v1/events/{event_id}/graph`（本 Issue 实现该端点：读 graph_node 与 graph_edge 表返回 `{nodes, edges, central_entities, attack_path_candidates}`）；六类实体与 8 种 relation_type。

文件范围：
1. `backend/app/api/v1/graph.py`（graph 端点实现）
2. `frontend/src/components/graph/EntityGraph.tsx`、`GraphLegend.tsx`、`AttackPathPlayer.tsx`
3. `frontend/tests/components/EntityGraph.test.tsx`

统一命名：
1. 节点颜色常量 `ENTITY_COLORS`：account 蓝、host 绿、ip 橙、domain 紫、process 黄、file 青
2. 边标签中文映射常量 `RELATION_LABELS`（8 种 relation_type 各一）
3. ECharts graph 系列，布局 force；中心实体节点放大 1.5 倍加描边

实现步骤：
1. 实现 graph 端点（空图返回空数组而非 404）。
2. 实现力导向图渲染：节点 tooltip 显示实体属性、边 tooltip 显示关联 evidence_id。
3. 实现图例与节点类型过滤开关。
4. 实现攻击路径播放：选择候选路径后按时间序逐条高亮节点与边（500ms 间隔）。
5. 编写测试：节点边渲染数量、类型过滤、路径播放高亮顺序。

验收标准：
1. 主场景关系图展示至少四类实体节点与 8 条以上边。
2. 中心实体明显高亮，点击边可见关联证据 ID。
3. 攻击路径播放按时间顺序高亮完整链路。

测试与验证：
`cd frontend && pnpm test -- EntityGraph`；后端 `pytest tests/test_api/ -k graph -v`；手工验证主场景图谱与路径播放。

降级策略：
graph_output 缺失时显示"图谱未生成"占位；节点超过 200 个时关闭力导向动画改静态布局。

---

### ISSUE-072：工具调用审计页与决策轨迹视图

优先级：
P1

目标：
实现工具、动作、Disposition outbox/receipt 和决策轨迹的统一审计视图，能解释“做了什么、是否生效、是否写回 XDR”。

前置依赖：
ISSUE-063、ISSUE-065、ISSUE-066、ISSUE-069

输入上下文：
`/tool-calls` 与 `/decision-trace` 端点；DecisionTraceEntry 八种 entry_type。

文件范围：
1. `frontend/src/pages/ToolAuditPage.tsx`
2. `frontend/src/components/audit/ToolCallTable.tsx`、`ToolCallDetailDrawer.tsx`、`DecisionTraceTimeline.tsx`
3. `frontend/tests/pages/ToolAuditPage.test.tsx`

统一命名：
1. entry_type 中文标签常量 `TRACE_TYPE_LABELS`：agent_execution Agent 执行、tool_call 工具调用、llm_call 模型调用、state_transition 状态转移、approval 审批、action_execution 动作执行、disposition 处置命令、writeback 外部同步
2. 审计列增加 provider、execution_owner、disposition_id、writeback_status；Action success 与 writeback confirmed 使用不同徽标。
3. DetailDrawer 展示参数与结果 JSON（折叠树组件），截断内容标注 truncated

实现步骤：
1. 实现全局工具审计页：按工具名与状态筛选、分页。
2. 实现调用详情抽屉（参数、结果、错误明细、重试次数）。
3. 实现 DecisionTraceTimeline：八类条目混合时间线、类型筛选、点击跳转对应详情（tool_call 开抽屉、agent_execution 显示 decision_basis 与证据引用、writeback 显示 confirmation_evidence）。
4. 把 DecisionTraceTimeline 接入事件详情页 audit Tab。并展示 TrajectoryAnalyzer（ISSUE-066）的轨迹指标摘要与各 Agent 质量分（ISSUE-065 的 `quality_scores`）。
5. 订阅 `tool_call_started` 与 `tool_call_completed` 实时追加条目。
6. 编写测试：列表筛选、抽屉内容、轨迹时间线渲染与类型过滤。

验收标准：
1. 主场景研判后审计 Tab 展示八类轨迹条目且时间有序。
2. 任一工具调用可查看经字段级脱敏和限长后的参数与结果；秘密、完整 raw payload 与隐藏推理不可见。
3. 决策依据、证据引用、规则/模型版本、置信度与警告在 Agent 条目中可见；隐藏思维链不展示。

测试与验证：
`cd frontend && pnpm test -- ToolAuditPage`；手工验证主场景审计时间线完整。

降级策略：
decision-trace 端点失败时审计 Tab 回退仅展示工具调用列表。

---

### ISSUE-073：审批中心 UI

优先级：
P1

目标：
实现审批中心页与审批操作组件：待审批动作列表、动作详情（目标、理由、等级、超时倒计时）、批准与拒绝操作、实时新审批提醒。完成后人工审批链路可演示。

前置依赖：
ISSUE-058、ISSUE-067

输入上下文：
`approval_required` 与 `approval_updated` 实时事件；approve 与 reject 端点；`GET /api/v1/events/{event_id}/actions` 过滤 WAITING_APPROVAL。

文件范围：
1. `frontend/src/pages/ApprovalCenterPage.tsx`
2. `frontend/src/components/approval/ApprovalCard.tsx`、`ApprovalActionModal.tsx`
3. `frontend/src/stores/approvalStore.ts`
4. `frontend/tests/pages/ApprovalCenterPage.test.tsx`

统一命名：
1. ApprovalCard 展示 action、目标、等级、execution_phase（IMMEDIATE/POST_VERIFY）、execution_owner、将写回的 XDR 来源对象及出站字段预览、超时；deferred 终态 Action 标注“效果验证后激活，须先批准”；分析内容明确标注“仅本地保存，不写回”。
2. ApprovalActionModal 显示当前登录审批者且不可编辑，只提交 comment 与 decision_id。
3. approvalStore：`pendingApprovals` 列表，socket 事件增删；事件级进度展示“本 revision 已决出 x/y”，提醒同一计划须全部审批完才进入执行。

实现步骤：
1. 实现审批中心页：聚合各事件 WAITING_APPROVAL 动作（初始全量拉取加 socket 增量），含 deferred POST_VERIFY Action。
2. 实现审批卡片与倒计时（超时后卡片置灰标注"已超时"）。
3. 实现批准与拒绝弹窗与提交反馈（成功后卡片移除）；若同事件仍有待批 Action，提示计划尚未全部决出。
4. 全局提醒：任意页面收到 `approval_required` 时顶栏铃铛角标加 toast。
5. 编写测试：列表渲染、批准提交参数、超时置灰、socket 增删、deferred Action 展示。

验收标准：
1. L4 动作产生审批时审批中心 1 秒内出现卡片与全局提醒；required 计划的 deferred Action 同步可见。
2. 批准后后端动作转 APPROVED 且卡片消失；仅当同 revision 全部决出（含 deferred）后研判才恢复执行。
3. 拒绝必须填写 comment，否则不可提交。

测试与验证：
`cd frontend && pnpm test -- ApprovalCenterPage`；手工验证：构造含 L4 动作的事件，完成审批后流程继续至 CLOSED。

降级策略：
Socket 不可用时审批列表 10 秒轮询刷新；倒计时仅前端展示，超时判定以后端为准。

---

### ISSUE-074：报告预览与导出

优先级：
P1

目标：
实现报告 Tab：15 章节 Markdown 渲染、章节目录导航、Markdown 文件下载与浏览器打印导出 PDF。完成后调查报告可直接交付演示。

前置依赖：
ISSUE-036、ISSUE-069

输入上下文：
`GET /api/v1/events/{event_id}/report` 返回 InvestigationReport；15 章节 key 与顺序（ISSUE-036）。

文件范围：
1. `frontend/src/components/report/ReportViewer.tsx`、`ReportToc.tsx`、`ReportExportButtons.tsx`
2. `frontend/src/utils/exportMarkdown.ts`
3. `frontend/tests/components/ReportViewer.test.tsx`

统一命名：
1. Markdown 渲染用 react-markdown 加 remark-gfm；章节锚点 id 用 15 章节 key
2. 导出文件名格式：`shadowtrace-report-{event_id}.md`
3. `generated_by` 为 template 时顶部展示"模板生成（LLM 降级）"提示条

实现步骤：
1. 实现 ReportViewer（report_markdown 渲染）与左侧 Toc（15 章节锚点跳转、滚动联动高亮）。
2. 实现 Markdown 下载（Blob）与打印导出（print CSS 隐藏导航元素）。
3. 报告未生成时展示状态占位（REPORTING 中显示生成中）。
4. 编写测试：渲染、目录跳转、下载文件名、未就绪占位。

验收标准：
1. 主场景报告 15 章节完整渲染且目录可跳转。
2. 下载的 md 文件内容与 report_markdown 一致。
3. 打印预览不含侧边导航等界面元素。

测试与验证：
`cd frontend && pnpm test -- ReportViewer`；手工验证主场景报告渲染、下载与打印。

降级策略：
report_markdown 渲染异常时回退 report_json 的章节纯文本展示。

---

### ISSUE-075：Agent 实时状态流视图

优先级：
P1

目标：
实现事件详情页的 Agent 实时状态面板：展示 12 个 Agent 的当前状态、进度消息与执行耗时，研判过程实时滚动。完成后"多 Agent 自主调查"过程对评委可见。

前置依赖：
ISSUE-040、ISSUE-069

输入上下文：
socket 的 `agent_progress`、`agent_completed`、`agent_failed`（payload 含 `agent_name`、`status`、`message`、`progress_percent` 可空）；AgentStatus 5 态；agent_trace 历史数据。

文件范围：
1. `frontend/src/components/agent/AgentStatusPanel.tsx`、`AgentStatusCard.tsx`、`AgentActivityFeed.tsx`
2. `frontend/src/stores/agentStatusStore.ts`
3. `frontend/tests/components/AgentStatusPanel.test.tsx`

统一命名：
1. AgentStatus 颜色：IDLE 灰、PROCESSING 蓝（脉冲动画）、COMPLETED 绿、FAILED 红、DEGRADED 橙
2. Agent 中文标签常量 `AGENT_LABELS`（12 个 Agent 名各一，如 triage_agent 分诊、evidence_agent 证据采集）
3. ActivityFeed 条目：timestamp、agent_name、message，最多保留 200 条滚动

实现步骤：
1. 实现 agentStatusStore：socket 三类事件更新各 Agent 状态与 feed。
2. 实现状态卡片栅格（12 个 Agent 固定位次）与活动流（自动滚到最新）。
3. 页面加载时用 traces 数据回放历史状态（已完成研判也能看到执行过程摘要）。
4. 把面板嵌入事件详情页概览区下方（研判进行中默认展开，CLOSED 后折叠）。
5. 编写测试：socket 事件驱动状态变更、feed 追加与上限、历史回放。

验收标准：
1. 触发研判后各 Agent 卡片按执行顺序变为 PROCESSING 再 COMPLETED。
2. Agent 失败时卡片变红且 feed 含错误消息。
3. 已结案事件加载后能看到基于 trace 的状态回放结果。

测试与验证：
`cd frontend && pnpm test -- AgentStatusPanel`；手工验证主场景研判全程状态流动画。

降级策略：
Socket 不可用时面板基于 traces 轮询数据每 10 秒刷新，无实时动画。

---

### ISSUE-076：对话式查询入口（Chatbot）

优先级：
P2

目标：
实现事件详情页的对话式查询面板：自然语言提问事件相关问题（证据、评分依据、处置理由），后端基于 EventContext 与 LLM 回答并附引用。可选增强，不阻塞任何主链路。

前置依赖：
ISSUE-027、ISSUE-063、ISSUE-069

输入上下文：
EventContext 全量数据与 DecisionTrace；MockLLM prompt_key 为 `event_qa`。

文件范围：
1. `backend/app/api/v1/chat.py`：`POST /api/v1/events/{event_id}/chat`
2. `backend/app/services/event_qa_service.py`：`EventQAService`
3. `frontend/src/components/chat/EventChatPanel.tsx`
4. `backend/tests/test_api/test_chat.py`、`frontend/tests/components/EventChatPanel.test.tsx`

统一命名：
1. 请求体：`question`、`history`（list，元素含 `role`（user、assistant 两值）与 `content`，最多 10 轮）；响应：`answer`、`references`（list，元素含 `ref_type`（evidence、trace、report 三值）与 `ref_id`）
2. `EventQAService.answer(event_id, question, history) -> ChatAnswer`
3. 上下文组装顺序固定：事件概要、风险评分摘要、证据摘要（最多 20 条）、决策轨迹摘要（最多 20 条）

实现步骤：
1. 实现 EventQAService：组装上下文、LLM 回答（JSON mode 输出 answer 与 references）、references 校验（无效 ref_id 剔除）。
2. 实现 chat 端点（事件不存在 404；LLM 不可用 503 加 error_code `qa_unavailable`）。
3. 实现前端聊天面板：消息列表、输入框、引用点击跳转（evidence 跳证据 Tab、trace 跳审计 Tab）。
4. 编写测试：mock 模式问答确定性、引用校验、前端消息渲染与引用跳转。

验收标准：
1. mock 模式下提问"为什么判定为高危"返回含评分依据的回答与至少 1 个引用。
2. 无效引用被剔除不展示。
3. 本功能整体关闭（路由不挂载）时其余页面与测试不受影响。

测试与验证：
`cd backend && pytest tests/test_api/test_chat.py -v`；`cd frontend && pnpm test -- EventChatPanel`。

降级策略：
LLM 不可用时面板显示"问答暂不可用"；该功能任何故障不影响其他页面。

---

### ISSUE-077：前端集成验证

优先级：
P1

目标：
对前端全部页面做集成验证：基于真实后端（mock 模式）的浏览器端到端测试，覆盖看板、详情、时间轴、关系图、审批、报告六条用户路径，冻结前端行为。

前置依赖：
ISSUE-070、ISSUE-071、ISSUE-072、ISSUE-073、ISSUE-074、ISSUE-075

输入上下文：
docker compose 全栈环境；ISSUE-011 演示数据；Playwright。

文件范围：
1. `frontend/e2e/playwright.config.ts`
2. `frontend/e2e/tests/`：`event-board.spec.ts`、`event-detail.spec.ts`、`storyline.spec.ts`、`graph.spec.ts`、`approval.spec.ts`、`report.spec.ts`
3. `frontend/e2e/fixtures/seed.ts`（经 API 摄取演示数据与触发研判）
4. `Makefile`（新增 `make test-e2e-frontend`）

统一命名：
1. 关键元素 data-testid 约定：`event-table`、`event-row-{event_id}`、`risk-radar`、`storyline-timeline`、`entity-graph`、`approval-card-{action_id}`、`report-viewer`、`agent-status-panel`

实现步骤：
1. 配置 Playwright（chromium、baseURL 指向本地前端、全局 setup 执行 seed）。
2. 路径一：看板筛选与跳转详情。路径二：详情页概览、雷达图与证据冲突高亮。路径三：时间轴五阶段与条目展开。路径四：关系图渲染与路径播放。路径五：L4 审批从提醒到批准后状态恢复。路径六：报告渲染与下载。
3. 各页面组件补齐 data-testid。
4. 接入 CI 可选 job（手动触发，不阻塞主流水线）。

验收标准：
1. 六条路径测试在全栈 mock 环境全部通过。
2. `make test-e2e-frontend` 一条命令完成环境检查与测试执行。
3. 任一失败输出截图与 trace 便于定位。

测试与验证：
`docker compose up -d && make test-e2e-frontend`。

降级策略：
无

---

### ISSUE-078：误报匹配前置过滤 FalsePositiveMatcher

优先级：
P1

目标：
实现误报前置匹配器：在分诊阶段把告警特征与误报案例库比对，高置信度命中时建议直接结案、中置信度标注可疑误报继续研判。完成后"误报识别"亮点贯穿分诊到结案。

前置依赖：
ISSUE-032、ISSUE-043、ISSUE-047

输入上下文：
TriageAgent 的 pre_triage_hooks 与 EventContext 的 `false_positive_match` 字段（ISSUE-032 预留）；CaseKBService 的 search_fp_cases；FP_HIGH_THRESHOLD 与 FP_LOW_THRESHOLD；VerdictResolver。

文件范围：
1. `backend/app/services/false_positive_matcher.py`：`FalsePositiveMatcher`
2. `backend/app/agents/triage_agent.py`（注册钩子）
3. `backend/app/agents/verdict_resolver.py`（消费前置匹配结果）
4. `backend/tests/test_services/test_fp_matcher.py`

统一命名：
1. `FalsePositiveMatcher.match(source_snapshot: dict, entities: EntitySet) -> FPMatchResult`（XDR 场景使用冻结的规范化 source_snapshot；只有 file fallback 才传兼容 raw_alert_snapshot）
2. `FPMatchResult` 字段：`matched`、`max_score`、`matched_case_id`、`matched_pattern`、`recommendation`（close_as_fp、investigate_with_flag、no_match 三值）
3. recommendation 判定：max_score 不低于 FP_HIGH_THRESHOLD 为 close_as_fp；介于两阈值之间为 investigate_with_flag；其余 no_match
4. Matcher/钩子**只**写 EventContext 的 `false_positive_match`（writer identity 固定为 `FalsePositiveMatcher`，含 ISSUE-032 `RuleBasedFalsePositiveHook`），**不得**在钩子内直接改 EventStatus / 调 set_final_verdict / 写报告。`close_as_fp` 的后续动作由编排承担：`disposition_policy=not_required` 时由 `route_after_triage`→`close_node` 经 `EventService.set_final_verdict` 与报告幂等 upsert 后 TRIAGING→CLOSED；`required` 时由 ISSUE-048 `begin_disposition_only` 同事务完成 set_final_verdict + confidence 提升 + `disposition_only_intent`，再经 ResponseAgent 预生成唯一 deferred（获批终态含 ignored）→审批→空 IMMEDIATE→VERIFYING→EventDispositionService 激活 EVENT_STATUS_UPDATE→REPORTING→CLOSED。REPORTING 对已有报告按 `report_id_for_event` 幂等刷新。capability UNKNOWN/UNSUPPORTED 时转人工并保持未闭环。本 Issue 用向量检索增强/替换 RuleBasedFalsePositiveHook，**不改变** begin_disposition_only 契约。

实现步骤：
1. 实现匹配器：告警文本化（alert_type 加关键字段加实体特征）后检索 fp_case_kb，取 top1 分数判定。
2. 注册为 pre_triage_hooks：在实体抽取后执行，结果只写 EventContext，不直接改状态。
3. 接通 route_after_triage 的高置信误报短路（ISSUE-048 路由已预留该分支）与 VerdictResolver 的前置匹配优先逻辑（前置 close_as_fp 优先于评分判定）。
4. 编写测试：file 误报场景可本地 CLOSED；MockXDR required 场景零实体副作用但恰有一条 readback_verified 的 CONFIRMED EVENT_STATUS_UPDATE 后 CLOSED；能力缺失时不关闭且转人工；中分数继续研判、no_match 无影响、案例库空时 no_match。所有出站请求不含 matched_case_id、相似度、报告或理由。

验收标准：
1. account_anomaly_fp 场景命中已知模式后跳过证据采集；Mock EVENT_STATUS_UPDATE 同步确认后全程不超过 10 秒，且没有实体处置动作。
2. 结案审计 reason 含 matched_case_id，报告说明误报依据。
3. 主场景（真阳性）不被误杀（no_match 正常研判）。

测试与验证：
`cd backend && pytest tests/test_services/test_fp_matcher.py -v && pytest -m e2e_basic -v`。

降级策略：
误报案例库不可用时钩子返回 no_match，研判按正常流程进行，零影响。

---

### ISSUE-079：处置影响评估服务

优先级：
P1

目标：
实现影响评估服务：在动作执行前估算业务影响（影响面、可逆性、业务中断风险），评估结果注入审批请求与报告。完成后高危处置的审批决策有量化依据。

前置依赖：
ISSUE-057、ISSUE-058

输入上下文：
Action 与 EntitySet；资产数据（query_asset_info 的 asset_value 与 business_role）；`approval_required` payload 的 `impact_assessment` 字段（ISSUE-040 已预留，可空）。

文件范围：
1. `backend/app/services/impact_assessment_service.py`：`ImpactAssessmentService`
2. `backend/app/services/approval_engine.py`（注入评估结果）
3. `backend/tests/test_services/test_impact_assessment.py`

统一命名：
1. 方法：`async assess(action: Action, event_context) -> ImpactAssessment`
2. `ImpactAssessment` 字段：`action_id`、`impact_score`（0-100）、`affected_scope`（描述影响对象与范围）、`reversible`（bool，按回滚映射判定）、`business_disruption`（none、low、medium、high 四值）、`assessment_detail`
3. 规则固定：isolate_host 对 asset_value=critical 的主机 business_disruption=high；disable_account 对管理员账号为 high；block_ip 对内网 IP 为 medium、外网 IP 为 low；create_ticket 与 notify_security_team 为 none
4. impact_score 计算：基础分（按 action_level：L0 与 L1 为 10、L2 为 30、L3 为 50、L4 为 70、L5 为 90）加资产价值加成（critical 加 20、high 加 10）封顶 100

实现步骤：
1. 实现规则评估（资产信息经 query_asset_info 查询，失败时按 medium 资产估算并标注）。
2. 接入 ApprovalEngine：evaluate 前先评估，结果存 approval_record 的 detail 并随 `approval_required` 推送。
3. 评估结果写 EventContext 的 `impact_assessments` 字段（list）供报告 recommendations 章节引用。
4. 编写测试：四类规则分支、impact_score 计算、资产查询失败降级、审批 payload 含评估。

验收标准：
1. 隔离 critical 主机的动作评估为 business_disruption=high 且审批卡片可见评估详情。
2. reversible 与回滚映射一致（force_logout 为 false）。
3. 资产信息不可用时评估仍产出且标注估算。

测试与验证：
`cd backend && pytest tests/test_services/test_impact_assessment.py -v`。

降级策略：
评估服务异常时审批照常进行（impact_assessment 为空），仅损失展示信息。

---

### ISSUE-080：MemoryAgent 知识沉淀

优先级：
P1

目标：
实现记忆 Agent：事件结案后自动沉淀历史案例、提炼误报规则候选与实体画像更新，形成"越用越聪明"的闭环。完成后系统具备持续学习能力。

前置依赖：
ISSUE-043、ISSUE-047、ISSUE-062

输入上下文：
ISSUE-005 的 `MemoryOutput`；CaseKBService.archive_event_as_case；EventContext 全量数据（含 `graph_output` 与 `storyline`）；触发点为 SuperAgent 后置 hook 完成并刷新快照后异步启动（确保 MemoryAgent 读取的上下文包含 GraphAgent 与 StorylineService 产物）。

文件范围：
1. `backend/app/agents/memory_agent.py`：`MemoryAgent`
2. `backend/app/services/profile_service.py`：`ProfileService`
3. `backend/app/db/orm/profile.py`：`EntityProfileORM`
4. `backend/migrations/versions/0005_entity_profile.py`
5. `backend/tests/test_agents/test_memory_agent.py`

统一命名：
1. `MemoryAgent.agent_name = "memory_agent"`；输出 `MemoryOutput`（case_records、fp_rules、profile_updates、sigma_drafts）
2. `entity_profile` 表字段：`profile_id`（格式 `prf-{8位十六进制}`）、`entity_type`、`entity_value`、`event_count`、`last_event_id`、`risk_history`（JSONB，最近 10 次评分）、`behavior_tags`、`updated_at`
3. fp_rules 元素字段：`rule_summary`、`alert_signature`、`confidence`、`source_event_id`（仅生成候选，入 fp_case_kb 需人工确认，状态字段 `pending_review=true`）
4. sigma_drafts 元素为 Sigma 规则 YAML 字符串（仅 confirmed_threat 事件生成，规则 title 含 event_id）

实现步骤：
1. 实现结案后挂载：SuperAgent 后置 hook 完成并调用 `refresh_closed_snapshot` 后异步触发 MemoryAgent（失败不影响结案）；MemoryAgent 成功完成后再次调用 `EventContextStore.refresh_closed_snapshot(event_id)` 刷新快照（确保 `event_context_snapshot` 包含 `memory_output`）。
2. 案例沉淀保留 effect_status 与 writeback_status；只有 effect verified 且（not_required 或 required writeback confirmed，含终态 EVENT_STATUS_UPDATE）的动作可标记为 successful_response；force_close / external_unsynced 事件禁止沉淀为成功剧本；其他只能作为失败/待确认经验，禁止训练成成功剧本。history_case 入库条件：事件已 CLOSED、存在报告、final_verdict 非 none（或低危 not_required 快结案），且非 external_unsynced。
3. 实现误报规则候选提炼：verdict 为 false_positive 时从告警特征生成 fp_rule 候选（LLM 总结加规则模板兜底，prompt_key 为 `memory_fp_rule`）。候选一律标记 pending 并交由 MemoryGovernance（ISSUE-081）复核入库，不直接写入 fp_case_kb。
4. 实现 Sigma 草稿生成：confirmed_threat 事件按证据特征生成基础检测规则草稿。
5. 编写测试：真阳性结案沉淀案例与画像、误报结案产出 fp_rule 候选、Sigma 草稿语法可解析（yaml.safe_load）、MemoryAgent 失败不影响事件 CLOSED。

验收标准：
1. 主场景结案后 history_case_kb 新增案例且 zhangsan 画像 event_count 自增。
2. 误报场景结案后存在 pending_review 的 fp_rule 候选。
3. MemoryAgent 抛异常时事件状态仍为 CLOSED 且审计有失败记录。

测试与验证：
`cd backend && pytest tests/test_agents/test_memory_agent.py -v`。

降级策略：
任一沉淀步骤失败仅记录告警跳过，绝不影响结案主链路；LLM 不可用时 fp_rule 用模板生成。

---

### ISSUE-081：记忆治理（MemoryGovernance 与复核工作流）

优先级：
P1

目标：
建立长期记忆治理：对 MemoryAgent 沉淀的案例、误报规则与画像做保留分层、去重、冲突解决与人工复核晋升，防止记忆库无序膨胀与脏数据污染检索。完成后"越用越聪明"的记忆是可治理、可信的。

前置依赖：
ISSUE-043、ISSUE-080

输入上下文：
ISSUE-080 MemoryAgent 输出（case_records、fp_rules、profile_updates）与 `pending_review` 标记；ISSUE-043 案例库与误报库；CaseLabel 与 FinalVerdict 映射（简介第 4.6 节）。

文件范围：
1. `backend/app/services/memory_governance.py`：`MemoryGovernance`
2. `backend/app/api/v1/memory.py`：复核相关端点
3. `backend/app/db/orm/memory_review.py`：`MemoryReviewORM`
4. `backend/migrations/versions/0006_memory_review.py`
5. `backend/tests/test_services/test_memory_governance.py`

统一命名：
1. `MemoryGovernance` 方法：`async ingest_candidate(candidate) -> str`、`async dedupe(kb_name) -> int`、`async resolve_conflict(kb_name, key) -> None`、`async promote(review_id, operator) -> None`、`async demote(review_id, operator, reason) -> None`、`async apply_retention(kb_name) -> int`、`async list_pending(kb_name=None) -> list`
2. `memory_review` 表字段：`review_id`（格式 `rev-{8位十六进制}`）、`kb_name`、`candidate_type`（fp_rule、history_case、profile 三值）、`payload`（JSONB）、`status`（pending、promoted、demoted 三值）、`confidence`、`created_at`、`decided_at`、`operator`
3. 保留分层：history_case 永久；fp_rule 须 promoted 才进 fp_case_kb；profile risk_history 仅留最近 N 次；低 confidence 候选 TTL 30 天未复核自动 demote
4. 去重键：fp_rule 用 `alert_signature` 归一化指纹；history_case 用 `(event_type, 关键实体集合)` 指纹
5. 冲突解决：同指纹多候选保留 confidence 最高且最新者，其余 demote

实现步骤：
1. 建 `memory_review` 表与 ORM。
2. 实现候选入库：MemoryAgent 的 `pending_review` 项改为经 `ingest_candidate` 进入复核队列，不直接进检索库。
3. 实现去重、冲突解决与保留策略（apply_retention 定期或结案后触发）。
4. 实现 promote/demote 与复核端点（`GET /api/v1/knowledge/reviews`、`POST /api/v1/knowledge/reviews/{review_id}/promote`、`/reject`）；promote 时写入对应知识库并嵌入。
5. 编写测试：候选入队不直接进库、重复候选去重、同指纹冲突保留最优、promote 后可被检索、TTL 到期自动 demote、画像 risk_history 截断。

验收标准：
1. MemoryAgent 候选默认进入 pending，未 promote 不出现在 RAG 检索结果。
2. 重复 fp_rule 候选被去重，冲突候选仅保留最优。
3. promote 后该规则可被误报匹配检索命中。
4. 超期未复核候选被自动 demote。

测试与验证：
`cd backend && pytest tests/test_services/test_memory_governance.py -v`。

降级策略：
治理服务不可用时 MemoryAgent 候选仍安全留存于 `memory_review`（pending），绝不自动污染检索库；去重与保留任务失败仅记告警；本 Issue 未完成不影响 P0/P1 主链路。

---

### ISSUE-082：Neo4j 图谱写入（可选增强）

优先级：
P2

目标：
为 GraphAgent 增加 Neo4j 双写：实体与关系同步写入 Neo4j，提供 Cypher 查询服务。Neo4j 不可用时零影响（PostgreSQL 派生图仍是事实来源）。

前置依赖：
ISSUE-050

输入上下文：
GraphOutput 与 graph_node、graph_edge 表；docker-compose 的 neo4j 服务（profile 标记 optional，默认不启动）；环境变量 `NEO4J_ENABLED`（默认 false）、`NEO4J_URI`、`NEO4J_USER`、`NEO4J_PASSWORD`。

文件范围：
1. `backend/app/core/neo4j_client.py`：`Neo4jClient`
2. `backend/app/services/graph_sync_service.py`：`GraphSyncService`
3. `infra/docker-compose.yml`（neo4j 服务加 profile）
4. `backend/tests/test_services/test_graph_sync.py`

统一命名：
1. Neo4j 节点标签与六类实体同名大写驼峰：`Account`、`Host`、`IP`、`Domain`、`Process`、`File`；关系类型为 8 种 relation_type 的大写形式（如 `LOGGED_IN_FROM`）
2. 节点属性：`node_id`、`event_id`、`entity_value` 加 properties 展开；约束：`node_id` 唯一
3. `GraphSyncService` 方法：`async sync_event_graph(event_id) -> SyncResult`、`async query_paths(event_id, start_value, end_value, max_depth=6) -> list`
4. `SyncResult` 字段：`nodes_synced`、`edges_synced`、`skipped`（NEO4J_ENABLED=false 时 true）

实现步骤：
1. 实现 Neo4jClient（neo4j 官方异步驱动、连接池、健康检查）。
2. 实现同步：MERGE 语义幂等写入节点与关系。
3. GraphAgent 输出后异步触发同步（NEO4J_ENABLED=false 直接 skipped）。
4. 实现 query_paths（Cypher 最短路径查询）。
5. 测试用 testcontainers 或 compose profile 启动 Neo4j；NEO4J_ENABLED=false 的零影响测试纳入常规套件，真实写入测试标记 `@pytest.mark.neo4j` 默认跳过。

验收标准：
1. NEO4J_ENABLED=false 时全部既有测试通过、无任何 Neo4j 连接尝试。
2. 启用后主场景图同步幂等（重复同步计数不变）。
3. query_paths 能返回 account 到外部 IP 的路径。

测试与验证：
`cd backend && pytest tests/test_services/test_graph_sync.py -v`（默认跳过 neo4j 标记）；启用验证：`docker compose --profile optional up -d neo4j && pytest -m neo4j -v`。

降级策略：
Neo4j 不可用时同步静默跳过并记录告警；查询回退 PostgreSQL 派生图（ISSUE-050 路径搜索）。

---

### ISSUE-083：Neo4j 攻击路径发现（可选增强）

优先级：
P2

目标：
基于 Neo4j 实现跨事件攻击路径发现：多事件实体关联查询、横向移动路径识别与可疑实体社区检测，结果可在前端关系图叠加展示。

前置依赖：
ISSUE-071、ISSUE-082

输入上下文：
Neo4j 中多事件图数据；`GET /api/v1/events/{event_id}/graph` 响应扩展字段 `cross_event_paths`（可空，本 Issue 填充）。

文件范围：
1. `backend/app/services/attack_path_service.py`：`AttackPathService`
2. `backend/app/api/v1/graph.py`（扩展 cross_event_paths）
3. `frontend/src/components/graph/CrossEventPathOverlay.tsx`
4. `backend/tests/test_services/test_attack_path.py`

统一命名：
1. 方法：`async find_cross_event_paths(event_id, max_depth=4) -> list[CrossEventPath]`、`async find_lateral_movement(entity_value) -> list`
2. `CrossEventPath` 字段：`path_id`、`related_event_ids`、`shared_entities`、`path_nodes`、`risk_hint`
3. 前端叠加层：跨事件路径用虚线边、共享实体节点加双环标识

实现步骤：
1. 实现跨事件查询：以当前事件实体为起点，查询其他 event_id 子图中的共享实体与连通路径。
2. 实现横向移动识别（同一账号或进程跨多主机的时间序路径）。
3. graph 端点在 NEO4J_ENABLED 且有数据时填充 cross_event_paths，否则空数组。
4. 前端叠加开关（默认关）渲染跨事件路径。
5. 测试标记 `@pytest.mark.neo4j`：构造两个共享 IP 的事件断言路径发现。

验收标准：
1. 两个共享外联 IP 的事件可互相发现关联路径。
2. Neo4j 未启用时 cross_event_paths 恒为空数组且前端开关隐藏。
3. 路径结果含 shared_entities 与来源事件 ID。

测试与验证：
`cd backend && pytest tests/test_services/test_attack_path.py -m neo4j -v`（需启用 Neo4j）。

降级策略：
功能整体不可用时前端不展示叠加开关，单事件图谱不受影响。

---

### ISSUE-084：OpenSearch 全文检索（可选增强）

优先级：
P2

目标：
引入 OpenSearch 承载原始日志与审计的全文检索：日志写入双路（PostgreSQL 加 OpenSearch）、检索 API 与前端搜索框。不可用时检索回退 PostgreSQL，零阻塞。

前置依赖：
ISSUE-023、ISSUE-063

输入上下文：
docker-compose 的 opensearch 服务（profile optional）；环境变量 `OPENSEARCH_ENABLED`（默认 false）、`OPENSEARCH_URL`；tool_call_log 与 event_audit_log 数据。

文件范围：
1. `backend/app/core/opensearch_client.py`：`OpenSearchClient`
2. `backend/app/services/search_service.py`：`SearchService`
3. `backend/app/api/v1/search.py`：`GET /api/v1/search`
4. `frontend/src/components/search/GlobalSearchBox.tsx`
5. `backend/tests/test_services/test_search_service.py`

统一命名：
1. 索引名固定：`shadowtrace-tool-calls`、`shadowtrace-audit-logs`、`shadowtrace-evidence`
2. `SearchService.search(query: str, index_scope: list[str] | None, page, page_size) -> SearchResult`；`SearchResult` 元素含 `index`、`doc_id`、`highlight`、`source_summary`、`event_id`
3. 检索端点查询参数：`q`、`scope`、`page`、`page_size`；OPENSEARCH_ENABLED=false 时走 PostgreSQL ILIKE 降级路径并在响应标注 `degraded=true`

实现步骤：
1. 实现客户端与索引初始化（mapping 含中文分词不强求，标准分词即可）。
2. 实现双写：审计与工具日志服务写库成功后异步投递 OpenSearch（失败仅告警）。
3. 实现检索服务双路径与高亮片段。
4. 实现前端顶栏全局搜索框（结果分组展示、点击跳转事件详情对应 Tab）。
5. 测试：降级路径常规套件覆盖；真实 OpenSearch 测试标记 `@pytest.mark.opensearch` 默认跳过。

验收标准：
1. OPENSEARCH_ENABLED=false 时搜索功能可用（PostgreSQL 路径）且全部既有测试通过。
2. 启用后搜索"block_ip"能命中工具调用记录并高亮。
3. OpenSearch 写入失败不影响审计落库。

测试与验证：
`cd backend && pytest tests/test_services/test_search_service.py -v`；启用验证：`docker compose --profile optional up -d opensearch && pytest -m opensearch -v`。

降级策略：
OpenSearch 不可用自动回退 PostgreSQL ILIKE 检索（功能保留、性能与高亮降级）。

---

### ISSUE-085：SOC 大屏（可选增强）

优先级：
P2

目标：
实现 SOC 总览大屏页：事件统计、严重度、Agent 活动与处置指标；“处置成功率”必须拆成动作执行成功率、效果验证率、XDR 写回确认率，禁止混成一个误导性数字。

前置依赖：
ISSUE-068、ISSUE-075

输入上下文：
`GET /api/v1/stats`（本 Issue 实现：返回事件分布、动作执行成功率、效果验证率、required 写回确认率与平均研判时长）；socket global 房间实时事件。

文件范围：
1. `backend/app/api/v1/stats.py`（stats 端点真实实现）
2. `frontend/src/pages/SocDashboardPage.tsx`（路由 `/dashboard`）
3. `frontend/src/components/dashboard/`：`StatCardGrid.tsx`、`SeverityPieChart.tsx`、`EventTrendChart.tsx`、`HighRiskTicker.tsx`
4. `backend/tests/test_api/test_stats.py`、`frontend/tests/pages/SocDashboardPage.test.tsx`

统一命名：
1. stats 响应字段：`total_events`、`by_status`、`by_severity`、`by_event_type`、`action_execution_success_rate`（SUCCESS/可判定动作）、`effect_verification_rate`（verified/需验证动作）、`writeback_confirmation_rate`（CONFIRMED/required 写回，not_required 不进分母）、`avg_investigation_seconds`、`events_last_24h`；三率的 numerator、denominator 与 null（分母为零）一并返回。
2. 大屏配色沿用既有状态与严重度颜色常量；深色主题 class 名 `soc-dark`

实现步骤：
1. 实现 stats 聚合查询（单 SQL 聚合为主，避免 N+1）。
2. 实现大屏布局（深色主题、全屏模式按钮、30 秒自动刷新加 socket 实时增量）。
3. 实现四个图表组件（ECharts 饼图与折线、滚动 ticker）。
4. 编写测试：分别构造动作成功但效果失败、效果成功但写回失败、全部成功三组数据，断言三率及各自分母，禁止用单一 action_success_rate 代替。

验收标准：
1. 演示数据摄取后大屏统计与库内数据一致。
2. 新事件创建后 ticker 与统计 30 秒内更新。
3. 该页面缺失或异常不影响其他路由。

测试与验证：
`cd backend && pytest tests/test_api/test_stats.py -v`；`cd frontend && pnpm test -- SocDashboardPage`。

降级策略：
无（本身即可选增强，任何故障不影响主链路）。

---

### ISSUE-086：全系统端到端测试套件

优先级：
P1

目标：
建立覆盖全部已交付能力的系统级测试套件：八类 EventType 各一条规则/主链用例、代表性高风险类型跑完整处置链，另含降级矩阵与并发压力冒烟，统一入口一条命令执行，作为交付前的总质量门禁。

前置依赖：
ISSUE-029、ISSUE-030、ISSUE-052、ISSUE-064、ISSUE-078、ISSUE-080

输入上下文：
全部集成测试标记（e2e_basic、e2e_response、orchestration、rag）；ISSUE-010 框架可为八类 EventType 各生成最小场景。

文件范围：
1. `backend/tests/system/test_full_system.py`
2. `backend/tests/system/test_degradation_matrix.py`
3. `backend/tests/system/test_concurrency_smoke.py`
4. `data/scenarios/`（在既有三场景外补齐 host_compromise、malicious_process、insider_privilege_abuse、lateral_movement、other_unclassified 最小场景包）
5. `Makefile`（新增 `make test-system`）

统一命名：
1. pytest 标记：`@pytest.mark.system`
2. 八类事件断言基线常量：`SCENARIO_EXPECTATIONS`（每类场景的预期 verdict、risk_score 区间、规则兜底与允许动作；other 只允许保守工单/通知）

实现步骤：
1. 补齐五个最小场景包（复用 ISSUE-010 框架，每个 10 至 20 条日志），并断言八类 EventType 均有 DEFAULT_PLANS 与 DEFAULT_RESPONSE_RULES。
2. 全链路用例：所有八类跑摄取、分诊、规则降级和报告；至少 data_exfiltration、host_compromise、lateral_movement 跑“审批、处置、写回、两阶段验证（含 EventDispositionService 激活终态写回）”完整链。MockXDR 场景断言写回，manual/file 场景明确不写回；live 仅在能力契约测试通过时启用。
3. 降级矩阵：逐项注入故障（LLM 失败、3 个数据源失败、Redis 短暂不可用、知识库为空、验证工具失败、预算耗尽触发报告并对未完成处置转人工、普通 Agent 输出护栏 block 在 enforce 下拦截而 warn_only 下仅告警、OutboundDispositionGuard 在任何模式始终拦截、动作振荡触发 ConvergenceGuard 强制收敛）断言状态与降级标注准确，不强求故障下伪成功。
4. 并发冒烟：10 个事件并发研判，断言全部终态、无租约冲突、无上下文串扰（事件间 EventContext 隔离）。
5. `make test-system` 串联全部标记套件并输出汇总。

验收标准：
1. 八类事件规则/主链用例全部通过，三类代表性高风险完整处置链通过。
2. 降级矩阵每项故障下主链路均完成且有对应降级标注。
3. 10 并发事件全部正确终态，无交叉污染。
4. `make test-system` 15 分钟内完成。

测试与验证：
`make test-system`（等价 `cd backend && pytest tests/system/ -m system -v`）。

降级策略：
无

---

### ISSUE-087：回归测试框架（金线轨迹快照与基线 diff 门禁）

优先级：
P1

目标：
建立确定性回归测试框架：把关键场景的研判结果与决策轨迹固化为金线快照，后续运行与基线做结构化 diff，关键指标漂移即失败。完成后系统演进有防回退的质量门禁。

前置依赖：
ISSUE-039、ISSUE-065、ISSUE-066、ISSUE-086

输入上下文：
mock 模式确定性（LLM golden、`MOCK_DETERMINISTIC=1`）；ISSUE-086 系统场景；ISSUE-066 轨迹指标；ISSUE-065 质量分。

文件范围：
1. `backend/tests/regression/baseline/`：金线快照 JSON（按场景）
2. `backend/tests/regression/test_regression.py`、`backend/tests/regression/snapshot.py`：`SnapshotRecorder`、`SnapshotDiffer`
3. `Makefile`（新增 `make test-regression`、`make update-baseline`）

统一命名：
1. pytest 标记：`@pytest.mark.regression`
2. 快照固定字段增加 dispositions（operation、execution_owner、writeback_status，不含厂商易变 raw_result）；executed_actions 按 ToolCategory=response 统计，不锁死名称。
3. `SnapshotRecorder.record(event_id) -> dict`、`SnapshotDiffer.diff(baseline, current) -> list[Drift]`；`Drift` 字段：`field`、`baseline_value`、`current_value`、`severity`（block、warn 两值）
4. 容差规则：final_verdict 与 executed_actions 集合必须完全一致（不一致为 block）；risk_score 允许 ±5 漂移（超出为 block）；trajectory_metrics 与 quality_scores 漂移超 20% 为 warn
5. `make update-baseline` 显式刷新金线（仅人工确认后执行）

实现步骤：
1. 实现 `SnapshotRecorder`：研判结束后从事件、报告、轨迹、质量分组装快照。
2. 实现 `SnapshotDiffer`：按容差规则比对，产出 Drift 列表。
3. 为三个演示场景与八类 EventType 场景各固化金线快照存入 baseline。
4. 实现回归用例：对每个场景跑完整研判、记录快照、与基线 diff，存在 block 级 Drift 即失败。
5. 实现 `make update-baseline`（带确认提示），`make test-regression` 运行回归套件。
6. 金线缺失时提示先 `make update-baseline`。

验收标准：
1. 在未改动逻辑时 `make test-regression` 全绿（零 block Drift）。
2. 人为改变某 Agent 输出使 final_verdict 或动作集变化时回归失败并指出漂移字段。
3. risk_score 超 ±5 漂移触发 block，20% 内指标漂移仅 warn。
4. `make update-baseline` 可显式刷新金线。

测试与验证：
`make test-regression`（等价 `cd backend && pytest tests/regression/ -m regression -v`）。

降级策略：
金线缺失时回归用例跳过并提示生成基线，不阻塞其他测试；本框架为质量门禁，未完成不影响 P0/P1 功能交付。

---

### ISSUE-088：Docker Compose 一键部署包

优先级：
P0

目标：
交付低成本一键部署：默认拉起 backend、frontend、postgres、redis、mock-xdr；Celery worker、知识库重组件与 live Provider 均按 profile 启用。默认环境无需真实 XDR、推理机或安全 GPT。

前置依赖：
ISSUE-064、ISSUE-067

输入上下文：
infra/docker-compose.yml 既有服务定义；Makefile 既有命令；`.env.example` 环境变量清单（简介第 4.7 节）。

文件范围：
1. `infra/docker-compose.yml`（整理：核心服务默认、neo4j 与 opensearch 与 embedding 服务归 profile optional）
2. `backend/Dockerfile`、`frontend/Dockerfile`（多阶段构建）
3. `infra/.env.example`
4. `scripts/bootstrap.sh`：迁移、可选加载知识库、摄取演示数据、健康检查
5. `Makefile`（新增 `make up`、`make down`、`make bootstrap`）
6. `docs/deployment.md`

统一命名：
1. compose 服务名固定：`postgres`、`redis`、`mock-xdr`、`backend`、`frontend`；`worker`、`neo4j`、`opensearch` 为 optional profile。
2. 端口约定：backend 8000、frontend 3000、postgres 5432、redis 6379
3. `make up` 等价 `docker compose -f infra/docker-compose.yml up -d --build`（核心服务）；`make bootstrap` 执行 scripts/bootstrap.sh
4. 健康检查端点：backend 用 `/api/v1/health`，严格复用 ISSUE-001 的完整响应模型（含三个 Adapter/Provider 状态与 simulation_enabled），不另写简化 Schema。

实现步骤：
1. 编写两个生产化 Dockerfile（backend 用 uvicorn 多 worker；frontend 构建后 nginx 托管并反代 `/api` 与 socket 路径到 backend）。
2. 整理 compose：mock-xdr 同时启用读取与 disposition 写回端点。backend 默认 SOURCE_MODE=mock_xdr、DISPOSITION_MODE=mock_xdr、TOOL_MODE=mock、LLM_MODE=mock、SIMULATION_ENABLED=true、TASK_MODE=background；Mock receipt 全部标 simulated。两个 ALLOW_* 只控制 live，Mock 由非生产环境栅栏控制。live profile 必须设 SIMULATION_ENABLED=false、禁用所有 Mock Provider 并重新显式授权。
3. 实现 bootstrap.sh：等待服务健康、alembic upgrade head、摄取三个演示场景、输出访问地址；仅 `LOAD_KB=true` 时执行 make load-kb，P0 bootstrap 不依赖 P1 知识库。
4. 编写 .env.example（全部变量带注释与默认值，默认 LLM_MODE=mock）。
5. 编写 deployment.md（前置要求、命令、常见问题、可选组件启用方式）。

验收标准：
1. 普通开发机上 `make up && make bootstrap` 后可见三个演示事件，无需真实 XDR、GPU 推理机或外部 LLM。
2. health 按 ISSUE-001 契约返回 source_adapter、disposition_adapter、tool_provider 状态、模式与能力；Mock 环境全部 healthy 且 simulation_enabled=true。
3. 不启用 optional profile 时无任何重组件容器。
4. `make down && make up` 数据卷保留事件数据。

测试与验证：
手工验证完整 bootstrap 流程；CI 增加 compose 构建与健康检查冒烟 job（不跑全量数据加载）。

降级策略：
frontend 构建失败不影响 backend API 演示（可单独 `docker compose up backend`）；默认 mock 模式确保无外部 LLM 依赖也能完整运行。

---

### ISSUE-089：一键演示脚本

优先级：
P1

目标：
交付评委演示脚本：单条命令依次驱动"内鬼数据外泄全链路自动研判""误报识别快速结案""验证失败重规划"三幕演示，关键节点输出讲解性日志与前端跳转提示，全程确定性可重复。

前置依赖：
ISSUE-077、ISSUE-078、ISSUE-088

输入上下文：
三个演示场景包；MOCK_DETERMINISTIC=1 确定性模式；MockLLM golden 响应；前端各页面路由。

文件范围：
1. `scripts/demo.py`：演示主脚本
2. `scripts/demo_narration.py`：`NARRATION_SCRIPT`（分幕讲解文案常量）
3. `Makefile`（新增 `make demo`、`make demo-reset`）
4. `docs/demo-guide.md`

统一命名：
1. 命令：make demo、make demo ACT=1、make demo-reset；reset 同时清理 MockXDR 时钟、摄取水位、jobs、outbox、receipts、幂等键和 MockEnvironmentState，避免上一轮写回污染演示。
2. 三幕固定：第一幕断言动作效果与 Mock XDR 写回双确认；第二幕误报快速结案、零实体副作用但有一条最小事件处置写回；第三幕分别演示效果失败重规划和写回故障不重执行动作。
3. 输出格式：每步带时间戳与阶段标题，关键节点打印前端 URL（如 `http://localhost:3000/events/{event_id}#timeline`）
4. 脚本退出码：全部断言通过为 0，任何一步失败非 0 并打印失败上下文

实现步骤：
1. 实现脚本骨架：环境检查（健康端点）、demo-reset、逐幕执行。
2. 每幕实现：摄取场景、触发研判、轮询关键状态节点并打印讲解词、断言预期结果、打印对应前端页面链接。
3. 第三幕实现验证失败注入（mock_verify_override）与恢复。
4. 实现讲解文案（中文，强调亮点：多 Agent 协作、decision_trace、冲突处理、误报识别、重规划、故事线）。
5. 编写 demo-guide.md：演示流程、每幕看点、前端配合演示动线、应急预案（单幕重跑）。

验收标准：
1. 干净环境 `make bootstrap && make demo` 全三幕通过且退出码 0。
2. 连续执行两次 `make demo-reset && make demo` 结果一致（确定性）。
3. 全三幕含等待时间不超过 10 分钟。
4. 每幕输出含可点击的前端跳转链接。

测试与验证：
`make demo-reset && make demo`；CI 增加每日定时演示冒烟 job（可选）。

降级策略：
前端不可用时脚本仍完整执行后端断言（跳转链接照常打印）；单幕失败可用 ACT 参数单独重演。

---

### ISSUE-090：增强演示与评委追问支撑（可选）

优先级：
P2

目标：
在基础演示之上提供加分演示项：跨事件关联演示（依赖 Neo4j）、SOC 大屏演示动线、对话式追问演示与性能数据展示，并准备评委常见追问的现场操作路径。

前置依赖：
ISSUE-076、ISSUE-083、ISSUE-085、ISSUE-089

输入上下文：
可选增强组件（启用 optional profile）；demo.py 的分幕框架。

文件范围：
1. `scripts/demo_extended.py`
2. `docs/demo-extended-guide.md`
3. `data/scenarios/cross_event_demo/`（两个共享基础设施的关联场景包）

统一命名：
1. 命令：`make demo-extended`（要求 optional profile 已启动，未启动时打印缺失组件清单退出码 2）
2. 加幕固定：第四幕跨事件关联（两事件共享外联 IP，展示 cross_event_paths）、第五幕大屏总览加对话追问（向 Chatbot 提问三个预设问题并断言回答含引用）

实现步骤：
1. 编写关联场景包（两事件共享 C2 IP 45.153.12.88）。
2. 实现第四幕：双事件研判后断言关联路径并打印图谱页链接。
3. 实现第五幕：打开大屏动线说明加三个预设 QA 断言。
4. 编写追问支撑文档：常见追问（如何防幻觉、误报怎么处理、能否接真实设备、token 成本）对应的现场演示操作与代码位置。

验收标准：
1. optional 组件齐备时 `make demo-extended` 全部通过。
2. 组件缺失时明确提示且不破坏基础演示。
3. 三个预设 QA 在 mock 模式下回答确定且含有效引用。

测试与验证：
`docker compose --profile optional up -d && make demo-extended`。

降级策略：
任一增强组件缺失时跳过对应幕并提示，基础三幕演示不受影响。

---

### ISSUE-091：Kubernetes 部署清单（可选增强）

优先级：
P2

目标：
提供 K8s 部署能力：核心服务的 Deployment、Service、ConfigMap、Secret 模板与 Kustomize 叠加，支持在单节点 k3s 或 kind 上部署验证。不作为主交付路径。

前置依赖：
ISSUE-088

输入上下文：
Docker 镜像（ISSUE-088 的 Dockerfile）；环境变量清单；核心服务拓扑（backend、worker、frontend、postgres、redis）。

文件范围：
1. `infra/k8s/base/`：`namespace.yaml`、`backend-deployment.yaml`、`worker-deployment.yaml`、`frontend-deployment.yaml`、`postgres-statefulset.yaml`、`redis-deployment.yaml`、各 Service 与 ConfigMap、`kustomization.yaml`
2. `infra/k8s/overlays/local/`：本地单节点叠加（NodePort、低资源限额）
3. `docs/k8s-deployment.md`
4. `scripts/k8s_smoke.sh`：部署后健康冒烟

统一命名：
1. namespace 固定：`shadowtrace`；标签约定：`app.kubernetes.io/name=shadowtrace`、`app.kubernetes.io/component={backend|worker|frontend|postgres|redis}`
2. Secret 名：`shadowtrace-secrets`（DATABASE_URL、REDIS_URL、LLM_API_KEY）；ConfigMap 名：`shadowtrace-config`（非敏感变量）
3. 镜像 tag 约定：`shadowtrace-backend:{git short sha}`、`shadowtrace-frontend:{git short sha}`

实现步骤：
1. 编写 base 清单（探针用 `/api/v1/health`、资源 requests 与 limits、postgres 用 StatefulSet 加 PVC）。
2. 编写 local overlay（kind 或 k3s 可直接 `kubectl apply -k`）。
3. 实现迁移与初始化 Job（bootstrap 逻辑容器化为一次性 Job）。
4. 编写冒烟脚本（等待 Pod Ready、健康端点、创建一个事件研判到 CLOSED）。
5. 编写部署文档。

验收标准：
1. kind 集群上 `kubectl apply -k infra/k8s/overlays/local` 全部 Pod Ready。
2. 冒烟脚本通过（含一次完整 mock 研判）。
3. 清单通过 `kubectl apply --dry-run=server` 校验。

测试与验证：
`bash scripts/k8s_smoke.sh`（本地 kind 环境）；CI 不强制。

降级策略：
K8s 路径整体可选，Docker Compose（ISSUE-088）始终是主交付部署方式。

---

### ISSUE-092：可观测性（OpenTelemetry 指标与追踪，可选增强）

优先级：
P2

目标：
接入 OpenTelemetry，除研判指标外重点观测 disposition outbox 延迟、写回确认率、冲突、重试和 UNKNOWN 积压。

前置依赖：
ISSUE-064、ISSUE-088

输入上下文：
FastAPI 与 Celery 既有调用链；llm_call_log 与 tool_call_log 的统计口径；环境变量 `OTEL_ENABLED`（默认 false）、`OTEL_EXPORTER_OTLP_ENDPOINT`。

文件范围：
1. `backend/app/core/telemetry.py`：`setup_telemetry`、`get_tracer`、`get_meter`
2. `backend/app/core/metrics.py`：业务指标定义
3. `infra/observability/`：`docker-compose.observability.yml`（otel-collector、prometheus、grafana）、`grafana-dashboard.json`、`prometheus.yml`
4. `backend/tests/test_core/test_telemetry.py`

统一命名：
1. 指标增加 `shadowtrace_writeback_total{status,adapter}`、`shadowtrace_writeback_queue_age_seconds`、`shadowtrace_writeback_retry_total`、`shadowtrace_action_unknown_total`；严禁把 source_object_id、IP 等高基数字段作为 label。
2. Span 增加 `disposition.submit`、`disposition.query_status`、`disposition.readback`，关联内部 event/action/disposition ID；未声明状态查询/回读能力时不创建对应 Span，秘密与 raw payload 不进入 Span。
3. OTEL_ENABLED=false 时全部埋点为 no-op（零开销路径）

实现步骤：
1. 实现 telemetry 初始化（FastAPI 与 httpx 与 SQLAlchemy 自动埋点加手动业务 Span）。
2. 在 BaseAgent、ToolExecutor、LLMClient 注入 Span 与指标计数（统一从既有回调点接入，不散落埋点）。
3. Grafana 增加写回积压、确认率、冲突/UNKNOWN 告警面板。
4. 编写测试：OTEL_ENABLED=false 零副作用、启用时内存 exporter 断言 Span 层级（api 包含 agent 包含 tool）与指标计数。

验收标准：
1. OTEL_ENABLED=false 时全部既有测试通过且无性能回退。
2. 启用后一次完整研判产生贯通的 trace（API 到 Agent 到工具到 LLM 同一 trace_id）。
3. Grafana 看板四面板均有数据。

测试与验证：
`cd backend && pytest tests/test_core/test_telemetry.py -v`；手工验证：`docker compose -f infra/observability/docker-compose.observability.yml up -d` 后执行一次演示并查看 Grafana。

降级策略：
观测组件任何故障不影响业务链路（导出失败静默丢弃）；默认关闭，纯可选增强。
