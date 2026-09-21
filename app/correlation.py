"""事件关联引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

对已注入告警按 ``(device_id, alert_type)`` 分组，组内按告警时间排序后做
"会话式" 聚合：相邻两条告警时间差 ``<= gap_seconds`` 即归入同一个事件，
超过间隔则开启新事件。

确定性保证
----------
- 结果只依赖 **告警集合** 与 ``gap_seconds``，与注入先后顺序、抑制规则、
  live/replay 评估结果均无关；
- 组内排序键为 ``(ts, seq, id)``，因此乱序注入（晚注入的告警带有更早的
  ``ts``）重算后得到完全一致的分组；
- 本模块不读取也不修改任何评估决定，事件关联不可能改变 live/replay 结果。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Optional

# 级别权重：数字越大级别越高，用于求事件的最高级别
LEVEL_RANK = {"info": 0, "warning": 1, "critical": 2}

MAX_GAP_SECONDS = 366 * 24 * 3600

DEFAULT_GAP_SECONDS = 900


def normalize_gap(value: Any) -> int:
    """校验可配置的聚合间隔（非负整数秒），非法时抛 ValueError。"""
    try:
        gap = int(value)
    except (TypeError, ValueError):
        raise ValueError("gap_seconds 必须是非负整数")
    if gap < 0:
        raise ValueError("gap_seconds 不能为负数")
    if gap > MAX_GAP_SECONDS:
        raise ValueError(f"gap_seconds 不能超过 {MAX_GAP_SECONDS} 秒")
    return gap


def correlate_events(alerts: list[dict], gap_seconds: int) -> list[dict]:
    """把已注入告警聚合为事件。

    入参告警字典需要键：id / seq / device_id / alert_type / level / ts(datetime)。
    返回事件列表，按 (first_ts, device_id, alert_type, 首个成员 id) 升序，
    每个事件：device_id / alert_type / members(按时间线顺序) / first_ts /
    last_ts / alert_count / max_level / member_ids / member_seqs。
    """
    buckets: dict[tuple[str, str], list[dict]] = {}
    for alert in alerts:
        key = (alert.get("device_id", "") or "", alert.get("alert_type", "") or "")
        buckets.setdefault(key, []).append(alert)

    events: list[dict] = []
    for key in sorted(buckets):
        # 稳定排序：同一时刻按注入序号、id 决胜，乱序注入也能得到确定次序
        members = sorted(buckets[key], key=lambda a: (a["ts"], a["seq"], a["id"]))
        current: list[dict] = []
        for member in members:
            if current:
                gap = (member["ts"] - current[-1]["ts"]).total_seconds()
                if gap > gap_seconds:
                    events.append(_make_event(key, current))
                    current = []
            current.append(member)
        if current:
            events.append(_make_event(key, current))

    events.sort(key=lambda e: (
        e["first_ts"], e["device_id"], e["alert_type"], e["member_ids"][0]
    ))
    return events


def _make_event(key: tuple[str, str], members: list[dict]) -> dict:
    max_level = max(
        (m.get("level", "info") for m in members),
        key=lambda lvl: LEVEL_RANK.get(lvl, 0),
    )
    return {
        "device_id": key[0],
        "alert_type": key[1],
        "members": members,
        "first_ts": members[0]["ts"],
        "last_ts": members[-1]["ts"],
        "alert_count": len(members),
        "max_level": max_level,
        "member_ids": [m["id"] for m in members],
        "member_seqs": [m["seq"] for m in members],
    }


def event_signature(gap_seconds: int, device_id: str, alert_type: str,
                    member_ids: list[int]) -> str:
    """事件内容签名：间隔 + 分组键 + 按时间线排序的成员 id 列表。

    只要告警集合与聚合间隔不变，任意时刻重算签名都相同，用于对齐持久化行
    并保留确认状态。
    """
    raw = "\x1f".join([
        str(gap_seconds), device_id or "", alert_type or "",
        ",".join(str(i) for i in member_ids),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def parse_filter_ts(value: Optional[str], field: str) -> Optional[datetime]:
    """解析筛选条件中的 ISO 8601 时间（也接受仅日期），非法时抛 ValueError。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except ValueError:
        raise ValueError(f"{field} 需要 ISO 8601 时间，如 2026-09-21 或 2026-09-21T09:00")


# ---------------------------------------------------------------------------
# 事件演进：两个快照之间按成员交集建立确定性血缘
# ---------------------------------------------------------------------------

# 血缘关系取值：
#   added       新侧事件，与任何旧事件无成员交集（新增）
#   removed     旧侧事件，与任何新事件无成员交集（消失）
#   continued   一对一交集（延续；成员集合可能增减，也可能完全相同）
#   split       旧事件与多个新事件有交集（拆分）
#   merge       新事件与多个旧事件有交集（合并）
#   split_merge 多对多交集，拆分与合并同时出现在同一条边上
LINEAGE_RELATIONS = ("added", "removed", "continued", "split", "merge", "split_merge")


def _lineage_ts_key(value: Any) -> str:
    """把事件首时间归一化为可比较字符串：datetime 转 ISO 文本，其余原样转 str。"""
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    return str(value)


def build_event_lineage(old_items: list[dict], new_items: list[dict]) -> dict:
    """按成员（告警 id）交集在新旧两个快照的事件之间建立血缘。

    入参事件字典需要键：``item_id``（快照内稳定序号）、``member_ids``
    （成员告警 id 列表）、``first_ts``（ISO 字符串或 datetime）、
    ``acknowledged``（布尔）；其余键原样挂到输出边的 ``old`` / ``new`` 上。

    标记规则（纯集合运算，确定且无随机性）：

    - 与对侧任何事件都无交集的旧事件 → ``removed``（消失），新事件 → ``added``（新增）；
    - 旧事件与多个新事件有交集 → 每条交集边标记 ``split``（拆分）；
    - 新事件与多个旧事件有交集 → 每条交集边标记 ``merge``（合并）；
      多对多时同一条边两个标记同时出现（``split_merge``）；
    - 其余一对一交集 → ``continued``（延续）；
    - 成员集合完全相同但确认状态不同 → ``ack_changed=True``，单独提示；
    - ``is_change``：除"成员完全相同且确认状态一致的延续"外都算变化，
      供界面"仅看变化"使用。

    边按 **新事件首时间升序 → 旧事件 item_id 升序 → 新事件 item_id** 稳定排序；
    消失边（无新事件）统一排在最后并按旧事件 item_id 排序。
    """
    old_members = {o["item_id"]: set(o["member_ids"]) for o in old_items}
    new_members = {n["item_id"]: set(n["member_ids"]) for n in new_items}
    old_by_id = {o["item_id"]: o for o in old_items}
    new_by_id = {n["item_id"]: n for n in new_items}

    # 交集对（边）与每个事件在对侧的交集中度
    pairs: list[tuple[Any, Any]] = []
    old_deg: dict[Any, int] = {oid: 0 for oid in old_by_id}
    new_deg: dict[Any, int] = {nid: 0 for nid in new_by_id}
    for oid, oset in old_members.items():
        for nid, nset in new_members.items():
            if oset & nset:
                pairs.append((oid, nid))
                old_deg[oid] += 1
                new_deg[nid] += 1

    edges: list[dict] = []
    for oid, nid in pairs:
        o_item, n_item = old_by_id[oid], new_by_id[nid]
        o_set, n_set = old_members[oid], new_members[nid]
        overlap = o_set & n_set
        is_split = old_deg[oid] >= 2
        is_merge = new_deg[nid] >= 2
        if is_split and is_merge:
            relation = "split_merge"
        elif is_split:
            relation = "split"
        elif is_merge:
            relation = "merge"
        else:
            relation = "continued"

        members_identical = o_set == n_set
        ack_changed = (
            members_identical
            and bool(o_item.get("acknowledged")) != bool(n_item.get("acknowledged"))
        )
        is_change = not (relation == "continued" and members_identical and not ack_changed)
        edges.append(_lineage_edge(
            relation, o_item, n_item, overlap, o_set - n_set, n_set - o_set,
            is_split, is_merge, members_identical, ack_changed, is_change,
        ))

    for oid, o_item in old_by_id.items():
        if old_deg[oid] == 0:
            o_set = old_members[oid]
            edges.append(_lineage_edge(
                "removed", o_item, None, set(), o_set, set(),
                False, False, False, False, True,
            ))
    for nid, n_item in new_by_id.items():
        if new_deg[nid] == 0:
            n_set = new_members[nid]
            edges.append(_lineage_edge(
                "added", None, n_item, set(), set(), n_set,
                False, False, False, False, True,
            ))

    def sort_key(edge: dict) -> tuple:
        n, o = edge["new"], edge["old"]
        if n is None:
            # 消失边统一沉底，再按旧事件 item_id
            return (1, "", o["item_id"], 0)
        return (0, _lineage_ts_key(n["first_ts"]),
                o["item_id"] if o else 10**18, n["item_id"])

    edges.sort(key=sort_key)

    stats = {
        "total": len(edges),
        "added": sum(1 for e in edges if e["relation"] == "added"),
        "removed": sum(1 for e in edges if e["relation"] == "removed"),
        "continued": sum(1 for e in edges if e["relation"] == "continued"),
        "split": sum(1 for e in edges if e["is_split"]),
        "merge": sum(1 for e in edges if e["is_merge"]),
        "split_merge": sum(1 for e in edges if e["relation"] == "split_merge"),
        "ack_changed": sum(1 for e in edges if e["ack_changed"]),
        "changed": sum(1 for e in edges if e["is_change"]),
    }
    return {"edges": edges, "stats": stats}


def _lineage_edge(
    relation: str,
    old_item: Optional[dict],
    new_item: Optional[dict],
    overlap: set,
    old_only: set,
    new_only: set,
    is_split: bool,
    is_merge: bool,
    members_identical: bool,
    ack_changed: bool,
    is_change: bool,
) -> dict:
    """构造一条血缘边，并把成员 id 交集换算成对应的成员序号（按 id 升序）。"""
    seq_map: dict[int, Any] = {}
    for item in (old_item, new_item):
        if item is None:
            continue
        seq_map.update(dict(zip(item["member_ids"], item.get("member_seqs", []))))

    def ids_and_seqs(ids: set) -> tuple[list, list]:
        ordered = sorted(ids)
        return ordered, [seq_map.get(i) for i in ordered]

    overlap_ids, overlap_seqs = ids_and_seqs(overlap)
    old_only_ids, old_only_seqs = ids_and_seqs(old_only)
    new_only_ids, new_only_seqs = ids_and_seqs(new_only)
    return {
        "relation": relation,
        "is_split": is_split,
        "is_merge": is_merge,
        "members_identical": members_identical,
        "ack_changed": ack_changed,
        "is_change": is_change,
        "overlap_count": len(overlap_ids),
        "overlap_member_ids": overlap_ids,
        "overlap_member_seqs": overlap_seqs,
        "old_only_member_ids": old_only_ids,
        "old_only_member_seqs": old_only_seqs,
        "new_only_member_ids": new_only_ids,
        "new_only_member_seqs": new_only_seqs,
        "old": old_item,
        "new": new_item,
    }
