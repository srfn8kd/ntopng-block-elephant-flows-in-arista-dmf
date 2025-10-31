#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elephant_guard.py
Daemon to:
  - tail ntopng elephant-flow log
  - add 1:1 (src,dst) rules to DMF policy
  - prune rules using a resilient, stateful heuristic

Resilient pruning:
  - Detects counter resets via last-reset-time or decreasing counters
  - Applies cooldown after reset and a hold after add
  - Prunes on either long inactivity or sustained below-threshold growth

Python: 3.9+
Requires: requests
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional, List, Set
from collections import deque

try:
    import requests
except Exception:
    print("ERROR: This script requires the 'requests' package. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

# --------------------------------------------------------------------
# Regex: parse ntopng Elephant Flow lines
# Example line:
# 2025-10-31T20:17:30Z ... [Elephant Flow] [1.1.1.1:42367 -> 1.0.0.1:443]  Elephant Flow
# --------------------------------------------------------------------
ELEPHANT_RE = re.compile(
    r'\[Elephant Flow\]\s+\['
    r'(?P<src>[^:\s\]]+)(?::(?P<src_port>\d+))?\s*->\s*'
    r'(?P<dst>[^:\s\]]+)(?::(?P<dst_port>\d+))?'
    r'\]',
    re.IGNORECASE
)

JSON_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# =========================
# Config & State
# =========================

class Config:
    def __init__(self, path: str):
        self.path = path
        self.data = self._load(path)
        # Required
        self.controller = self._req("controller")
        self.policy_name = self._req("policy_name")
        self.token = self._req("token")
        self.ntop_log = self._req("ntop_log")
        self.seq_min = int(self._req("seq_min"))
        self.seq_max = int(self._req("seq_max"))
        # Behavior
        self.window_seconds = int(self._get("window_seconds", 60))
        self.packet_threshold = int(self._get("packet_threshold", 10))
        self.poll_interval = float(self._get("poll_interval", 1.0))
        self.housekeep_interval = int(self._get("housekeep_interval", self.window_seconds))
        # Files / dirs
        self.state_file = self._get("state_file", "/var/lib/elephant-guard/state.json")
        self.run_dir = self._get("run_dir", "/run/elephant-guard")
        self.log_file = self._get("activity_log", "/var/log/elephant-guard/activity.log")
        # TLS
        self.verify_tls = str(self._get("verify_tls", "false")).lower() in ("1", "true", "yes", "on")
        # Batching / rate limiting
        self.batch_enabled = bool(self._get("batch_enabled", True))
        self.batch_flush_interval = float(self._get("batch_flush_interval", 0.5))
        self.max_rules_per_sec = int(self._get("max_rules_per_sec", 4))
        self.max_rules_per_batch = int(self._get("max_rules_per_batch", 20))
        # Pruning hysteresis
        self.reset_cooldown_sec = int(self._get("reset_cooldown_sec", 6))
        self.min_hold_after_add_sec = int(self._get("min_hold_after_add_sec", 10))
        self.prune_inactive_after = int(self._get("prune_inactive_after", 120))
        self.consecutive_slow_windows = int(self._get("consecutive_slow_windows", 2))

        if self.seq_min < 0 or self.seq_max < self.seq_min:
            raise ValueError("Invalid sequence range; ensure 0 <= seq_min <= seq_max")

    def _load(self, path: str) -> Dict:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Config is not valid JSON: {e}")

    def _req(self, key: str):
        if key not in self.data:
            raise KeyError(f"Missing required config key: {key}")
        return self.data[key]

    def _get(self, key: str, default=None):
        return self.data.get(key, default)


class State:
    """
    Persistent state:
      - seq_map:      { (src_ip, dst_ip) : sequence }
      - seq_used:     set(sequence)
      - pkt_state:    {
            sequence : {
                "pkt": int,
                "last_reset": str,
                "ts": float,                # last baseline update
                "added_ts": float,          # when rule was added/adopted
                "last_increase_ts": float,  # last time pkt increased
                "cooldown_until": float,    # skip-prune until
                "slow_windows": int         # consecutive windows below threshold
            }
        }
      - last_housekeep: epoch_seconds
    """
    def __init__(self, path: str):
        self.path = path
        self.seq_map: Dict[Tuple[str, str], int] = {}
        self.seq_used: Set[int] = set()
        self.pkt_state: Dict[int, Dict[str, float | int | str]] = {}
        self.last_housekeep: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "seq_map": {f"{k[0]}->{k[1]}": v for k, v in self.seq_map.items()},
            "seq_used": sorted(list(self.seq_used)),
            "pkt_state": self.pkt_state,
            "last_housekeep": self.last_housekeep,
            "saved_at": utcnow_iso(),
        }

    @staticmethod
    def from_dict(d: Dict) -> "State":
        s = State(path="")
        s.seq_map = {}
        for k, v in d.get("seq_map", {}).items():
            try:
                src, dst = k.split("->", 1)
                s.seq_map[(src, dst)] = int(v)
            except Exception:
                continue
        s.seq_used = set(int(x) for x in d.get("seq_used", []))
        def _ps(v):
            return {
                "pkt": int(v.get("pkt", v.get("packet_count", 0))),
                "ts": float(v.get("ts", 0)),
                "last_reset": v.get("last_reset", ""),
                "added_ts": float(v.get("added_ts", 0)),
                "last_increase_ts": float(v.get("last_increase_ts", 0)),
                "cooldown_until": float(v.get("cooldown_until", 0)),
                "slow_windows": int(v.get("slow_windows", 0)),
            }
        s.pkt_state = { int(k): _ps(v) for k, v in d.get("pkt_state", {}).items() }
        s.last_housekeep = float(d.get("last_housekeep", 0))
        return s

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def load_if_exists(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            st = State.from_dict(d)
            st.path = self.path
            self.seq_map = st.seq_map
            self.seq_used = st.seq_used
            self.pkt_state = st.pkt_state
            self.last_housekeep = st.last_housekeep


# =========================
# DMF REST Client
# =========================

class DMFClient:
    def __init__(self, cfg: Config):
        self.base = cfg.controller.rstrip("/")
        self.policy_name = cfg.policy_name
        self.s = requests.Session()
        self.s.headers.update(JSON_HEADERS)
        self.s.headers.update({"Authorization": f"Bearer {cfg.token}"})
        self.verify = cfg.verify_tls

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def _request(self, method: str, path: str, json_body: Optional[Dict] = None, timeout: int = 10) -> requests.Response:
        url = self._url(path)
        resp = self.s.request(method, url, json=json_body, timeout=timeout, verify=self.verify)
        if not (200 <= resp.status_code < 300):
            raise requests.HTTPError(f"{method} {url} => {resp.status_code} {resp.text}", response=resp)
        return resp

    # --- Policy rule CRUD ---

    def list_rules(self) -> List[Dict]:
        path = f'/api/v1/data/controller/applications/dmf/policy[name="{self.policy_name}"]/rule'
        r = self._request("GET", path)
        try:
            return r.json()
        except Exception:
            return []

    def put_rule(self, sequence: int, src_ip: str, dst_ip: str) -> None:
        path = f'/api/v1/data/controller/applications/dmf/policy[name="{self.policy_name}"]/rule[sequence={sequence}]'
        body = {
            "sequence": sequence,
            "ether-type": 2048,
            "src-ip": src_ip,
            "dst-ip": dst_ip,
        }
        self._request("PUT", path, json_body=body)

    def delete_rule(self, sequence: int) -> None:
        path = f'/api/v1/data/controller/applications/dmf/policy[name="{self.policy_name}"]/rule[sequence={sequence}]'
        self._request("DELETE", path)

    # --- Flow info (live counters) ---

    def get_flow_info(self) -> Dict[int, Dict[str, int | str]]:
        """
        Returns:
          seq -> { "packet_count": int, "byte_count": int, "last_reset": str }
        """
        path = f'/api/v1/data/controller/applications/dmf/policy[name="{self.policy_name}"]?select=flow-info'
        r = self._request("GET", path)
        j = r.json()
        seq_to_counts: Dict[int, Dict[str, int | str]] = {}

        if not isinstance(j, list):
            return seq_to_counts

        for policy_obj in j:
            fins = policy_obj.get("flow-info", [])
            for fin in fins:
                flows = fin.get("flow", [])
                for flow in flows:
                    stats = flow.get("stats", {}) or {}
                    pkt = int(stats.get("packet-count", 0))
                    byt = int(stats.get("byte-count", 0))
                    lrt = stats.get("last-reset-time") or ""  # ISO-8601 or empty

                    related = flow.get("related-user-configured-matches", []) or []
                    for rel in related:
                        if rel.get("policy-name") != self.policy_name:
                            continue
                        seqs = rel.get("policy-matches", []) or []
                        for seq in seqs:
                            try:
                                seq_i = int(seq)
                            except Exception:
                                continue
                            prev = seq_to_counts.get(seq_i, {"packet_count": 0, "byte_count": 0, "last_reset": ""})
                            prev_pkt = int(prev.get("packet_count", 0))
                            prev_byt = int(prev.get("byte_count", 0))
                            prev_lrt = prev.get("last_reset", "")

                            new_pkt = pkt if pkt > prev_pkt else prev_pkt
                            new_byt = byt if byt > prev_byt else prev_byt
                            new_lrt = lrt if (lrt and lrt > prev_lrt) else prev_lrt

                            seq_to_counts[seq_i] = {
                                "packet_count": new_pkt,
                                "byte_count": new_byt,
                                "last_reset": new_lrt,
                            }
        return seq_to_counts


# =========================
# Sequence Allocator
# =========================

class SequenceAllocator:
    def __init__(self, seq_min: int, seq_max: int, used: Set[int]):
        self.seq_min = seq_min
        self.seq_max = seq_max
        self.used = set(used)

    def reserve(self, seq: int) -> None:
        if seq < self.seq_min or seq > self.seq_max:
            raise ValueError(f"Sequence {seq} out of configured range [{self.seq_min},{self.seq_max}]")
        self.used.add(seq)

    def free(self, seq: int) -> None:
        self.used.discard(seq)

    def next_free(self) -> Optional[int]:
        for s in range(self.seq_min, self.seq_max + 1):
            if s not in self.used:
                return s
        return None


# =========================
# Logging helper
# =========================

def log_line(path: str, msg: str):
    """Append to configured log file; on failure, fall back to stderr so journald shows it."""
    ts = utcnow_iso()
    try:
        d = os.path.dirname(path) or "."
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{ts} {msg}\n")
    except Exception as e:
        sys.stderr.write(f"{ts} [log-fail] {path}: {e} :: {msg}\n")


# =========================
# File tail (no deps)
# =========================

def tail_follow(path: str, poll_interval: float):
    """Yield new lines as appended; handle rotation and non-existence gracefully."""
    f = None
    inode = None
    pos = 0

    while True:
        try:
            st = os.stat(path)
            if f is None or inode != st.st_ino:
                if f:
                    f.close()
                f = open(path, "r", encoding="utf-8", errors="ignore")
                inode = st.st_ino
                if pos == 0:
                    f.seek(0, os.SEEK_END)  # start tailing at EOF initially
                else:
                    f.seek(min(pos, st.st_size), os.SEEK_SET)

            line = f.readline()
            if line:
                pos = f.tell()
                yield line.rstrip("\n")
            else:
                time.sleep(poll_interval)
        except FileNotFoundError:
            time.sleep(poll_interval)
        except Exception as e:
            print(f"[tail] error: {e}", file=sys.stderr)
            time.sleep(poll_interval)


# =========================
# Core Daemon
# =========================

class ElephantGuard:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = State(cfg.state_file)
        self.dmf = DMFClient(cfg)
        self.alloc: Optional[SequenceAllocator] = None
        self.dirty_marker = os.path.join(cfg.run_dir, "state.DIRTY")
        self.running = True

        # Batching / rate-limiting
        self.pending_pairs = deque()       # deque[(src, dst)]
        self.pending_set: Set[Tuple[str, str]] = set()
        self.last_token_refill = time.time()
        self.tokens = float(self.cfg.max_rules_per_sec)  # start full
        self.last_flush = time.time()

        signal.signal(signal.SIGINT, self._signal_stop)
        signal.signal(signal.SIGTERM, self._signal_stop)

    # ---- lifecycle ----

    def start(self):
        os.makedirs(self.cfg.run_dir, exist_ok=True)
        with open(self.dirty_marker, "w") as f:
            f.write(utcnow_iso())

        self._warmup()

        last_housekeep = time.time()
        # Startup banner
        log_line(self.cfg.log_file, f"[startup] elephant_guard running; activity_log={self.cfg.log_file} "
                                    f"batch_enabled={self.cfg.batch_enabled} max_rules_per_sec={self.cfg.max_rules_per_sec}")

        for line in tail_follow(self.cfg.ntop_log, self.cfg.poll_interval):
            if not self.running:
                break

            now = time.time()
            if now - last_housekeep >= self.cfg.housekeep_interval:
                self.housekeep()
                last_housekeep = now

            m = ELEPHANT_RE.search(line)
            if m:
                src_ip = m.group('src')
                dst_ip = m.group('dst')
                if self.cfg.batch_enabled:
                    key = (src_ip, dst_ip)
                    if key not in self.state.seq_map and key not in self.pending_set:
                        self.pending_pairs.append(key)
                        self.pending_set.add(key)
                        if len(self.pending_pairs) % 50 == 0:
                            log_line(self.cfg.log_file, f"[batch] pending queue length={len(self.pending_pairs)}")
                else:
                    try:
                        self.process_new_elephant(src_ip, dst_ip)
                    except Exception as e:
                        log_line(self.cfg.log_file, f"[error] processing {src_ip}->{dst_ip}: {e}")

            if self.cfg.batch_enabled and (now - self.last_flush) >= self.cfg.batch_flush_interval:
                self._flush_batch()
                self.last_flush = now

        self._clean_shutdown()

    def _signal_stop(self, signum, frame):
        self.running = False

    # ---- warmup / shutdown ----

    def _warmup(self):
        prior_dirty = os.path.exists(self.dirty_marker)

        self.state.load_if_exists()
        self.alloc = SequenceAllocator(self.cfg.seq_min, self.cfg.seq_max, self.state.seq_used)

        if prior_dirty or len(self.state.seq_map) == 0:
            log_line(self.cfg.log_file, "[warmup] rebuilding state from controller (dirty or empty state)")
            self._rebuild_from_controller()
        else:
            log_line(self.cfg.log_file, "[warmup] loaded clean state from disk")

        self.housekeep(initial=True)

    def _clean_shutdown(self):
        try:
            self.state.save()
            if os.path.exists(self.dirty_marker):
                os.remove(self.dirty_marker)
            log_line(self.cfg.log_file, "[shutdown] clean stop; state saved")
            sys.exit(0)
        except Exception as e:
            log_line(self.cfg.log_file, f"[shutdown] error saving state: {e}")
            sys.exit(2)

    # ---- controller sync ----

    def _rebuild_from_controller(self):
        # 1) Discover configured rules
        try:
            rules = self.dmf.list_rules()
        except Exception as e:
            raise RuntimeError(f"Failed to list rules: {e}")

        self.state.seq_map.clear()
        self.state.seq_used.clear()
        now = time.time()
        for r in rules:
            try:
                seq = int(r.get("sequence"))
                src = r.get("src-ip")
                dst = r.get("dst-ip")
                if src and dst and (self.cfg.seq_min <= seq <= self.cfg.seq_max):
                    self.state.seq_map[(src, dst)] = seq
                    self.state.seq_used.add(seq)
                    # If we adopt existing rules, seed added_ts reasonably
                    ps = self.state.pkt_state.get(seq, {})
                    ps.setdefault("added_ts", now)
                    self.state.pkt_state[seq] = ps
            except Exception:
                continue

        # 2) Seed counters + last_reset
        try:
            counts = self.dmf.get_flow_info()
        except Exception as e:
            log_line(self.cfg.log_file, f"[warn] get_flow_info failed during warmup: {e}")
            counts = {}

        self.state.pkt_state = {**self.state.pkt_state}  # ensure dict exists
        for seq in self.state.seq_used:
            c = counts.get(seq, {})
            pkt = int(c.get("packet_count", 0))
            lrt = c.get("last_reset", "")
            prev = self.state.pkt_state.get(seq, {})
            self.state.pkt_state[seq] = {
                "pkt": pkt,
                "last_reset": lrt,
                "ts": now,
                "added_ts": float(prev.get("added_ts", now)),
                "last_increase_ts": float(prev.get("last_increase_ts", 0 if pkt == 0 else now)),
                "cooldown_until": float(prev.get("cooldown_until", now + self.cfg.reset_cooldown_sec)),
                "slow_windows": int(prev.get("slow_windows", 0)),
            }

        self.alloc = SequenceAllocator(self.cfg.seq_min, self.cfg.seq_max, self.state.seq_used)
        log_line(self.cfg.log_file, f"[warmup] controller rules: {len(self.state.seq_map)}; seq used: {len(self.state.seq_used)}")

    # ---- batching helpers ----

    def _refill_tokens(self):
        now = time.time()
        elapsed = max(0.0, now - self.last_token_refill)
        if self.cfg.max_rules_per_sec > 0:
            self.tokens = min(float(self.cfg.max_rules_per_sec),
                              self.tokens + elapsed * self.cfg.max_rules_per_sec)
        self.last_token_refill = now

    def _flush_batch(self):
        if not self.pending_pairs:
            return

        self._refill_tokens()
        allowance = int(self.tokens)
        if allowance <= 0:
            return

        to_take = min(allowance, self.cfg.max_rules_per_batch, len(self.pending_pairs))

        # Single prune pass for entire batch
        try:
            self.prune_once()
        except Exception as e:
            log_line(self.cfg.log_file, f"[warn] batch prune_once failed: {e}")

        added = 0
        while added < to_take and self.pending_pairs:
            src_ip, dst_ip = self.pending_pairs.popleft()
            self.pending_set.discard((src_ip, dst_ip))

            if (src_ip, dst_ip) in self.state.seq_map:
                continue

            try:
                self._process_new_elephant_no_prune(src_ip, dst_ip)
                added += 1
            except Exception as e:
                log_line(self.cfg.log_file, f"[error] batch add {src_ip}->{dst_ip}: {e}")

        self.tokens -= float(added)
        if added or to_take:
            qlen = len(self.pending_pairs)
            log_line(self.cfg.log_file, f"[batch] added={added} allowed={to_take} remaining_queue={qlen} tokens={self.tokens:.2f}")

    # ---- operations ----

    def process_new_elephant(self, src_ip: str, dst_ip: str):
        key = (src_ip, dst_ip)
        if key in self.state.seq_map:
            seq = self.state.seq_map[key]
            log_line(self.cfg.log_file, f"[dup] {src_ip}->{dst_ip} already in policy seq={seq}")
            return

        # prune before allocating
        self.prune_once()
        self._process_new_elephant_no_prune(src_ip, dst_ip)

    def _process_new_elephant_no_prune(self, src_ip: str, dst_ip: str):
        key = (src_ip, dst_ip)
        if key in self.state.seq_map:
            seq = self.state.seq_map[key]
            log_line(self.cfg.log_file, f"[dup] {src_ip}->{dst_ip} already in policy seq={seq}")
            return

        seq = self.alloc.next_free()
        if seq is None:
            raise RuntimeError(f"No free sequence in configured range [{self.cfg.seq_min},{self.cfg.seq_max}]")

        self.dmf.put_rule(seq, src_ip, dst_ip)

        self.alloc.reserve(seq)
        self.state.seq_map[key] = seq
        now = time.time()

        # Seed counters after add
        pkt = 0
        lrt = ""
        try:
            counts = self.dmf.get_flow_info()
            c = counts.get(seq, {})
            pkt = int(c.get("packet_count", 0))
            lrt = c.get("last_reset", "")
        except Exception:
            pass

        self.state.pkt_state[seq] = {
            "pkt": pkt,
            "last_reset": lrt,
            "ts": now,
            "added_ts": now,
            "last_increase_ts": now if pkt > 0 else 0.0,
            "cooldown_until": now + self.cfg.min_hold_after_add_sec,  # hold after add
            "slow_windows": 0,
        }
        log_line(self.cfg.log_file, f"[add] seq={seq} {src_ip}->{dst_ip}")
        self.state.save()

    def prune_once(self):
        """Reset-aware, hysteretic pruning."""
        try:
            counts = self.dmf.get_flow_info()
        except Exception as e:
            log_line(self.cfg.log_file, f"[warn] prune_once: get_flow_info failed: {e}")
            return

        now = time.time()
        to_remove: List[int] = []

        # Iterate over active rules
        for (src, dst), seq in list(self.state.seq_map.items()):
            if not (self.cfg.seq_min <= seq <= self.cfg.seq_max):
                continue

            new = counts.get(seq, {})
            new_pkt = int(new.get("packet_count", 0))
            new_lrt = new.get("last_reset", "")

            ps = self.state.pkt_state.get(seq, None)
            if ps is None:
                # Seed a conservative state if missing
                self.state.pkt_state[seq] = {
                    "pkt": new_pkt, "last_reset": new_lrt, "ts": now,
                    "added_ts": now, "last_increase_ts": now if new_pkt > 0 else 0.0,
                    "cooldown_until": now + self.cfg.reset_cooldown_sec, "slow_windows": 0
                }
                continue

            prev_pkt = int(ps.get("pkt", 0))
            prev_lrt = ps.get("last_reset", "")
            prev_ts = float(ps.get("ts", now))
            last_increase_ts = float(ps.get("last_increase_ts", 0))
            cooldown_until = float(ps.get("cooldown_until", 0))
            added_ts = float(ps.get("added_ts", now))
            slow_windows = int(ps.get("slow_windows", 0))

            elapsed = max(1, int(now - prev_ts))
            reset = (new_lrt and new_lrt != prev_lrt) or (new_pkt < prev_pkt)

            # On reset: re-baseline and start a cooldown window
            if reset:
                self.state.pkt_state[seq] = {
                    "pkt": new_pkt,
                    "last_reset": new_lrt,
                    "ts": now,
                    "added_ts": added_ts,
                    "last_increase_ts": last_increase_ts,  # keep last known increase time
                    "cooldown_until": now + self.cfg.reset_cooldown_sec,
                    "slow_windows": 0
                }
                # Do NOT evaluate pruning this cycle
                # log_line(self.cfg.log_file, f"[reset] seq={seq} cooldown until {int(now + self.cfg.reset_cooldown_sec)}")
                continue

            # Update last_increase_ts if we saw growth
            delta = max(0, new_pkt - prev_pkt)
            if delta > 0:
                last_increase_ts = now
                slow_windows = 0  # reset slow window streak

            # Periodically advance the baseline on full windows
            if elapsed >= self.cfg.window_seconds:
                if delta < self.cfg.packet_threshold:
                    slow_windows += 1
                else:
                    slow_windows = 0
                prev_ts = now  # re-baseline time
                prev_pkt = new_pkt  # re-baseline pkt

            # Persist updated state (before prune decision)
            self.state.pkt_state[seq] = {
                "pkt": new_pkt,
                "last_reset": new_lrt,
                "ts": prev_ts,
                "added_ts": added_ts,
                "last_increase_ts": last_increase_ts,
                "cooldown_until": cooldown_until,
                "slow_windows": slow_windows
            }

            # Respect holds/cooldowns
            if now < cooldown_until:
                continue
            if now - added_ts < self.cfg.min_hold_after_add_sec:
                continue

            # Prune if either condition met:
            # 1) No increase for prune_inactive_after seconds (true inactivity)
            # 2) Sustained trickle: below threshold for N consecutive full windows
            no_increase_for = now - (last_increase_ts or added_ts)
            if no_increase_for >= self.cfg.prune_inactive_after or slow_windows >= self.cfg.consecutive_slow_windows:
                to_remove.append(seq)

        for seq in to_remove:
            self._remove_seq(seq)

        if to_remove:
            self.state.save()
            log_line(self.cfg.log_file, f"[prune] removed {len(to_remove)} rule(s)")

    def _remove_seq(self, seq: int):
        pair = None
        for k, v in self.state.seq_map.items():
            if v == seq:
                pair = k
                break

        if not pair:
            self.alloc.free(seq)
            self.state.pkt_state.pop(seq, None)
            return

        src, dst = pair
        try:
            self.dmf.delete_rule(seq)
            log_line(self.cfg.log_file, f"[del] seq={seq} {src}->{dst}")
        except Exception as e:
            log_line(self.cfg.log_file, f"[warn] delete seq={seq} failed: {e}")
            return

        self.state.seq_map.pop(pair, None)
        self.alloc.free(seq)
        self.state.pkt_state.pop(seq, None)

    def housekeep(self, initial: bool = False):
        """Light alignment of baselines and maintenance; does not force pruning."""
        try:
            counts = self.dmf.get_flow_info()
        except Exception as e:
            log_line(self.cfg.log_file, f"[warn] housekeeping: get_flow_info failed: {e}")
            return

        now = time.time()
        for seq in list(self.state.seq_used):
            c = counts.get(seq, {})
            new_pkt = int(c.get("packet_count", 0))
            new_lrt = c.get("last_reset", "")
            ps = self.state.pkt_state.get(seq, None)

            if ps is None:
                self.state.pkt_state[seq] = {
                    "pkt": new_pkt,
                    "last_reset": new_lrt,
                    "ts": now,
                    "added_ts": now,
                    "last_increase_ts": now if new_pkt > 0 else 0.0,
                    "cooldown_until": now + self.cfg.reset_cooldown_sec,
                    "slow_windows": 0
                }
                continue

            # If baseline is very old, gently refresh timestamps
            if now - float(ps.get("ts", now)) > 2 * self.cfg.window_seconds:
                ps["ts"] = now

            # Keep last_reset and pkt current (no pruning here)
            ps["pkt"] = new_pkt
            ps["last_reset"] = new_lrt
            self.state.pkt_state[seq] = ps

        self.state.last_housekeep = now
        log_line(self.cfg.log_file, "[housekeep] " + ("initial alignment complete" if initial else "periodic alignment complete"))


# =========================
# CLI
# =========================

def main():
    ap = argparse.ArgumentParser(description="DMF Elephant Guard")
    ap.add_argument("-c", "--config", required=True, help="Path to JSON config")
    args = ap.parse_args()

    try:
        cfg = Config(args.config)
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        eg = ElephantGuard(cfg)
        eg.start()
    except SystemExit:
        raise
    except Exception as e:
        log_line(getattr(cfg, "log_file", "/var/log/elephant-guard/activity.log"), f"[fatal] {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()

