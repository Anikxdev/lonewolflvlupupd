# -*- coding: utf-8 -*-
"""
FreeFire Level Up Bot - Professional Web Dashboard & Real-Time EXP Tracker
Embedded Async Web Server (aiohttp)
"""

import asyncio
import json
import os
import time
from typing import Dict, List, Any, Optional
from aiohttp import web


# ==================== FREE FIRE LEVEL TABLE ====================
# Cumulative total EXP required to BE at each level.
LEVELS = {
    "1": 0, "2": 48, "3": 202, "4": 544, "5": 1012,
    "6": 1844, "7": 2792, "8": 3800, "9": 4870, "10": 6004,
    "11": 7192, "12": 8448, "13": 9776, "14": 11140, "15": 12566,
    "16": 14060, "17": 15610, "18": 17224, "19": 18902, "20": 20632,
    "21": 22424, "22": 24728, "23": 26192, "24": 28166, "25": 30200,
    "26": 32294, "27": 34448, "28": 37804, "29": 41174, "30": 44870,
    "31": 48852, "32": 53334, "33": 58566, "34": 64096, "35": 69994,
    "36": 76460, "37": 83108, "38": 91128, "39": 99322, "40": 108092,
    "41": 120144, "42": 133266, "43": 147472, "44": 162760, "45": 179126,
    "46": 196572, "47": 215368, "48": 235516, "49": 257010, "50": 279860,
    "51": 304056, "52": 348318, "53": 394982, "54": 444044, "55": 495508,
    "56": 549364, "57": 633756, "58": 721744, "59": 813336, "60": 908522,
    "61": 1041438, "62": 1180352, "63": 1325256, "64": 1476184, "65": 1634300,
    "66": 1840946, "67": 2056594, "68": 2281242, "69": 2514880, "70": 2757530,
    "71": 3059506, "72": 3372284, "73": 3699456, "74": 4041030, "75": 4397020,
    "76": 4829104, "77": 5282204, "78": 5756304, "79": 6251404, "80": 6767504,
    "81": 7381324, "82": 8043154, "83": 8752952, "84": 9510808, "85": 10316638,
    "86": 11277190, "87": 12360748, "88": 13360304, "89": 14482858, "90": 15659418,
    "91": 17026708, "92": 18453688, "93": 19941280, "94": 21488570, "95": 23095858,
    "96": 24763138, "97": 26490138, "98": 28277708, "99": 30124996, "100": 32032284,
}

MAX_LEVEL = 100


def exp_to_next(level: int, exp: int) -> dict:
    """
    Compute progress info for a level/exp pair.
    Assumes `exp` is cumulative total EXP across all levels.
    """
    try:
        level = int(level or 1)
    except Exception:
        level = 1
    level = max(1, min(MAX_LEVEL, level))

    try:
        exp = int(exp or 0)
    except Exception:
        exp = 0
    exp = max(0, exp)

    cur = LEVELS.get(str(level), 0)

    if level >= MAX_LEVEL:
        return {
            "level": level,
            "next_level": None,
            "cur_level_exp": cur,
            "next_exp": None,
            "exp_in_level": 0,
            "exp_span": 0,
            "remaining": 0,
            "progress_pct": 100.0,
            "is_max": True,
        }

    nxt = LEVELS.get(str(level + 1), cur + 1)
    span = max(nxt - cur, 1)

    if exp >= cur:
        inside = min(exp - cur, span)
        remaining = max(nxt - exp, 0)
    else:
        inside = min(exp, span)
        remaining = max(span - exp, 0)

    return {
        "level": level,
        "next_level": level + 1,
        "cur_level_exp": cur,
        "next_exp": nxt,
        "exp_in_level": inside,
        "exp_span": span,
        "remaining": remaining,
        "progress_pct": round(inside * 100.0 / span, 2),
        "is_max": False,
    }


# ==================== BOT STATE ====================

class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "uid": uid,
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str,
                         level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": exp,
                "current_exp": exp,
                "gained_exp": 0,
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S"),
            }
        else:
            acc = self.accounts[uid_str]
            if nickname:
                acc["nickname"] = nickname
            if region:
                acc["region"] = region
            if level:
                acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(
                    f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! "
                    f"Total Gained: +{acc['gained_exp']}",
                    "success", uid_str,
                )
            self.recalc_totals()

    def update_status(self, uid: str, status: str,
                      active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = time.strftime("%H:%M:%S")
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")
            self.log(
                f"Account {self.accounts[uid_str]['nickname']} finished "
                f"Match #{self.accounts[uid_str]['matches_played']}",
                "info", uid_str,
            )
        # Always recompute totals from the source of truth
        self.recalc_totals()

    def recalc_totals(self):
        """
        Recompute totals from the current account registry.
        Both EXP and matches are derived, so removing an account
        also removes its contribution from the sidebar counters.
        """
        self.total_gained_exp = sum(
            acc.get("gained_exp", 0) for acc in self.accounts.values()
        )
        self.total_matches = sum(
            acc.get("matches_played", 0) for acc in self.accounts.values()
        )

    def remove_account(self, uid: str) -> bool:
        """Delete an account and refresh derived totals."""
        uid_str = str(uid)
        if uid_str in self.accounts:
            del self.accounts[uid_str]
            self.recalc_totals()
            return True
        return False


bot_state = BotState()


# ==================== HTTP HANDLERS ====================

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "templates", "index.html"
)


async def handle_index(request: web.Request) -> web.Response:
    if os.path.exists(TEMPLATE_PATH):
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = (
            "<html><body style='background:#050505;color:#ff5a5a;"
            "font-family:monospace;padding:40px;text-align:center;'>"
            "<h1>Dashboard is initializing</h1>"
            "<p>Please wait a moment and refresh the page.</p>"
            "</body></html>"
        )
    return web.Response(text=content, content_type="text/html", charset="utf-8")


async def handle_get_stats(request: web.Request) -> web.Response:
    accounts_data = []
    for acc in bot_state.accounts.values():
        enriched = dict(acc)
        prog = exp_to_next(acc.get("level", 1), acc.get("current_exp", 0))
        enriched["exp_next"]      = prog["next_exp"]
        enriched["exp_remaining"] = prog["remaining"]
        enriched["exp_progress"]  = prog["progress_pct"]
        enriched["exp_in_level"]  = prog["exp_in_level"]
        enriched["exp_span"]      = prog["exp_span"]
        enriched["next_level"]    = prog["next_level"]
        enriched["is_max_level"]  = prog["is_max"]
        accounts_data.append(enriched)

    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)

    # Make sure totals are fresh before responding
    bot_state.recalc_totals()

    return web.json_response({
        "total_accounts":   len(bot_state.accounts),
        "total_matches":    bot_state.total_matches,
        "total_gained_exp": bot_state.total_gained_exp,
        "accounts":         accounts_data,
        "logs":             bot_state.logs[-60:],
        "uptime":           int(time.time() - bot_state.start_time),
    })


async def handle_add_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        accounts_file = "accounts.json"
        existing = []
        if os.path.exists(accounts_file):
            try:
                with open(accounts_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return web.json_response(
                    {"status": "error", "error": "UID and Password are required"}
                )
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            existing.append({"uid": uid, "password": pwd})
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return web.json_response(
                    {"status": "error", "error": "Token is required"}
                )
            existing = [acc for acc in existing if acc.get("token") != token]
            existing.append({"token": token})
        else:
            return web.json_response(
                {"status": "error", "error": "Invalid payload"}
            )

        with open(accounts_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        bot_state.log(f"New account added: {data.get('uid') or 'Token'}", "success")

        if "on_account_added" in bot_state.refresh_callbacks:
            asyncio.create_task(
                bot_state.refresh_callbacks["on_account_added"](data)
            )

        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_delete_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid") or "").strip()
        if not uid:
            return web.json_response(
                {"status": "error", "error": "UID is required"}, status=400
            )

        credentials  = bot_state.account_credentials.get(uid, {})
        auth_uid     = str(credentials.get("auth_uid") or "").strip()
        auth_token   = str(credentials.get("auth_token") or "").strip()
        accounts_file = "accounts.json"

        # Remove from accounts.json (matching uid, auth_uid or token)
        if os.path.exists(accounts_file):
            with open(accounts_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
            existing = [
                acc for acc in existing
                if str(acc.get("uid") or "").strip() not in {uid, auth_uid}
                and str(acc.get("token") or "").strip() != auth_token
            ]
            with open(accounts_file, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)

        # Remove from in-memory registry + recompute totals
        removed = bot_state.remove_account(uid)
        if auth_uid and auth_uid != uid:
            bot_state.remove_account(auth_uid)

        # Cancel the worker task(s)
        worker_keys = {uid, auth_uid}
        if auth_token:
            worker_keys.add(auth_token[:10])
        workers = {
            bot_state.account_workers.pop(key)
            for key in worker_keys if key in bot_state.account_workers
        }
        for worker in workers:
            if not worker.done():
                worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        # Clean credentials cache
        for key, value in list(bot_state.account_credentials.items()):
            if key == uid or value is credentials:
                bot_state.account_credentials.pop(key, None)

        bot_state.log(
            f"Account {uid} removed from rotation and its match stopped.",
            "warning", uid,
        )

        return web.json_response({
            "status": "ok",
            "removed": removed,
            "total_accounts": len(bot_state.accounts),
            "total_matches": bot_state.total_matches,
            "total_gained_exp": bot_state.total_gained_exp,
        })
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_refresh_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if "on_refresh_account" in bot_state.refresh_callbacks:
            asyncio.create_task(
                bot_state.refresh_callbacks["on_refresh_account"](uid)
            )
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def start_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    # -------- Client-facing banner --------
    print()
    print("\033[96m╔══════════════════════════════════════════════════════════╗\033[0m")
    print("\033[96m║\033[0m  \033[92m✓  DASHBOARD IS LIVE\033[0m                                    \033[96m║\033[0m")
    print("\033[96m║\033[0m                                                          \033[96m║\033[0m")
    pad = " " * (28 - len(str(port)))
    print(f"\033[96m║\033[0m  \033[97mAddress :\033[0m  \033[93mhttp://localhost:{port}\033[0m{pad}\033[96m║\033[0m")
    print("\033[96m║\033[0m                                                          \033[96m║\033[0m")
    print("\033[96m║\033[0m  \033[90mOpen this address in your browser to manage accounts.\033[0m  \033[96m║\033[0m")
    print("\033[96m╚══════════════════════════════════════════════════════════╝\033[0m")
    print()