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
