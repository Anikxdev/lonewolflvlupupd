# -*- coding: utf-8 -*-
"""
FreeFire Level Up Bot - Professional Web Dashboard & Real-Time EXP Tracker
Embedded Async Web Server (aiohttp)
"""

import asyncio
import base64
from contextlib import contextmanager
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from typing import Dict, Generator, List, Any, Optional
from zoneinfo import ZoneInfo
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import ec
from pywebpush import WebPushException, webpush

ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")
AUTH_DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_auth.sqlite3")
LOGIN_KEY_ENV = "DASHBOARD_LOGIN_KEY"
SESSION_COOKIE = "dashboard_session"
SESSION_TTL = 30 * 24 * 60 * 60
EXP_NOTIFICATION_INTERVAL = 50_000
BD_TIMEZONE = ZoneInfo("Asia/Dhaka")
LOG_DEDUPE_SECONDS = 30


def bd_time() -> str:
    return datetime.now(BD_TIMEZONE).strftime("%H:%M:%S")


def _load_accounts_file() -> List[Dict[str, Any]]:
    if not os.path.exists(ACCOUNTS_FILE):
        return []
    with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        accounts = json.load(f)
    if not isinstance(accounts, list) or any(not isinstance(acc, dict) for acc in accounts):
        raise ValueError("accounts.json must contain a list of account objects")
    return accounts


def _save_accounts_file(accounts: List[Dict[str, Any]]) -> None:
    temp_file = ACCOUNTS_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2)
    os.replace(temp_file, ACCOUNTS_FILE)


@contextmanager
def _database() -> Generator[sqlite3.Connection, None, None]:
    connection = sqlite3.connect(AUTH_DATABASE)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def initialize_dashboard_storage() -> None:
    with _database() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS auth_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS auth_attempts (client_ip TEXT PRIMARY KEY, failures INTEGER NOT NULL, blocked_until REAL NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, subscription_json TEXT NOT NULL)"
        )
        has_login_key = connection.execute(
            "SELECT 1 FROM auth_settings WHERE name = 'login_salt'"
        ).fetchone()
        if not has_login_key:
            login_key = os.environ.get(LOGIN_KEY_ENV)
            if login_key is None:
                login_key = getpass.getpass(
                    f"Set the dashboard login key (enter {LOGIN_KEY_ENV} to configure without a prompt): "
                )
            if not login_key:
                raise RuntimeError("A non-empty dashboard login key is required")
            salt = secrets.token_bytes(16)
            key_hash = hashlib.pbkdf2_hmac("sha256", login_key.encode("utf-8"), salt, 310_000)
            connection.executemany(
                "INSERT INTO auth_settings (name, value) VALUES (?, ?)",
                [
                    ("login_salt", _base64url(salt)),
                    ("login_hash", _base64url(key_hash)),
                ],
            )

        vapid_private = connection.execute(
            "SELECT value FROM auth_settings WHERE name = 'vapid_private'"
        ).fetchone()
        if not vapid_private:
            private_key = ec.generate_private_key(ec.SECP256R1())
            private_value = private_key.private_numbers().private_value.to_bytes(32, "big")
            public_numbers = private_key.public_key().public_numbers()
            public_value = (
                b"\x04"
                + public_numbers.x.to_bytes(32, "big")
                + public_numbers.y.to_bytes(32, "big")
            )
            connection.executemany(
                "INSERT INTO auth_settings (name, value) VALUES (?, ?)",
                [
                    ("vapid_private", _base64url(private_value)),
                    ("vapid_public", _base64url(public_value)),
                ],
            )


def _verify_login_key(candidate: str) -> bool:
    with _database() as connection:
        salt_row = connection.execute(
            "SELECT value FROM auth_settings WHERE name = 'login_salt'"
        ).fetchone()
        hash_row = connection.execute(
            "SELECT value FROM auth_settings WHERE name = 'login_hash'"
        ).fetchone()
    if not salt_row or not hash_row:
        return False
    salt = base64.urlsafe_b64decode(salt_row["value"] + "=" * (-len(salt_row["value"]) % 4))
    expected = base64.urlsafe_b64decode(hash_row["value"] + "=" * (-len(hash_row["value"]) % 4))
    actual = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, 310_000)
    return hmac.compare_digest(actual, expected)


def _session_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_authenticated(request: web.Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    with _database() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (time.time(),))
        return connection.execute(
            "SELECT 1 FROM auth_sessions WHERE token_hash = ? AND expires_at > ?",
            (_session_hash(token), time.time()),
        ).fetchone() is not None


@web.middleware
async def dashboard_auth_middleware(request: web.Request, handler):
    public_paths = {"/login", "/api/auth/login", "/api/auth/status", "/service-worker.js"}
    authenticated = _is_authenticated(request)
    request["authenticated"] = authenticated
    if request.path in public_paths:
        return await handler(request)
    if authenticated:
        return await handler(request)
    if request.method == "GET" and request.path == "/":
        return await handler(request)
    if request.path.startswith("/api/"):
        return web.json_response(
            {"status": "error", "error": "Login required"},
            status=401,
        )
    raise web.HTTPFound("/login")


async def handle_login_page(request: web.Request) -> web.Response:
    if request.get("authenticated"):
        raise web.HTTPFound("/")
    login_path = os.path.join(os.path.dirname(TEMPLATE_PATH), "login.html")
    return web.FileResponse(login_path)


async def handle_auth_status(request: web.Request) -> web.Response:
    return web.json_response({"authenticated": bool(request.get("authenticated"))})


async def handle_auth_login(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        candidate = data.get("key") if isinstance(data, dict) else None
        client_ip = request.remote or "unknown"
        now = time.time()
        with _database() as connection:
            attempt = connection.execute(
                "SELECT failures, blocked_until FROM auth_attempts WHERE client_ip = ?",
                (client_ip,),
            ).fetchone()
        if attempt and attempt["blocked_until"] > now:
            return web.json_response(
                {"status": "error", "error": "Too many attempts. Try again in a minute."},
                status=429,
            )
        valid_key = (
            isinstance(candidate, str)
            and 0 < len(candidate) <= 512
            and _verify_login_key(candidate)
        )
        if not valid_key:
            failures = attempt["failures"] + 1 if attempt else 1
            with _database() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO auth_attempts (client_ip, failures, blocked_until) VALUES (?, ?, ?)",
                    (client_ip, failures, now + 60 if failures >= 5 else 0),
                )
            return web.json_response(
                {"status": "error", "error": "Invalid login key"},
                status=401,
            )
        with _database() as connection:
            connection.execute(
                "DELETE FROM auth_attempts WHERE client_ip = ?",
                (client_ip,),
            )
        session_token = secrets.token_urlsafe(32)
        expires_at = time.time() + SESSION_TTL
        with _database() as connection:
            connection.execute(
                "INSERT INTO auth_sessions (token_hash, expires_at) VALUES (?, ?)",
                (_session_hash(session_token), expires_at),
            )
        response = web.json_response({"status": "ok"})
        response.set_cookie(
            SESSION_COOKIE,
            session_token,
            max_age=SESSION_TTL,
            httponly=True,
            secure=request.secure or request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() == "https",
            samesite="Strict",
            path="/",
        )
        return response
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=500)


async def handle_auth_logout(request: web.Request) -> web.Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with _database() as connection:
            connection.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?",
                (_session_hash(token),),
            )
    response = web.json_response({"status": "ok"})
    response.del_cookie(SESSION_COOKIE, path="/")
    return response


async def handle_push_public_key(request: web.Request) -> web.Response:
    with _database() as connection:
        row = connection.execute(
            "SELECT value FROM auth_settings WHERE name = 'vapid_public'"
        ).fetchone()
    if not row:
        return web.json_response(
            {"status": "error", "error": "Push notification keys are unavailable"},
            status=503,
        )
    return web.json_response({"publicKey": row["value"]})


async def handle_push_subscribe(request: web.Request) -> web.Response:
    try:
        subscription = await request.json()
        endpoint = subscription.get("endpoint")
        keys = subscription.get("keys")
        if not isinstance(endpoint, str) or not endpoint.startswith("https://") or not isinstance(keys, dict):
            return web.json_response(
                {"status": "error", "error": "Invalid push subscription"},
                status=400,
            )
        with _database() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO push_subscriptions (endpoint, subscription_json) VALUES (?, ?)",
                (endpoint, json.dumps(subscription)),
            )
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=400)


async def handle_service_worker(request: web.Request) -> web.Response:
    worker_path = os.path.join(os.path.dirname(TEMPLATE_PATH), "service-worker.js")
    return web.FileResponse(
        worker_path,
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )


async def send_push_notification(title: str, body: str, tag: str) -> None:
    with _database() as connection:
        private_row = connection.execute(
            "SELECT value FROM auth_settings WHERE name = 'vapid_private'"
        ).fetchone()
        subscriptions = connection.execute(
            "SELECT endpoint, subscription_json FROM push_subscriptions"
        ).fetchall()
    if not private_row or not subscriptions:
        return

    payload = json.dumps({"title": title, "body": body, "tag": tag, "url": "/"})
    vapid_private = private_row["value"]
    for row in subscriptions:
        subscription = json.loads(row["subscription_json"])
        try:
            await asyncio.to_thread(
                webpush,
                subscription_info=subscription,
                data=payload,
                vapid_private_key=vapid_private,
                vapid_claims={"sub": "mailto:admin@example.com"},
            )
        except WebPushException as e:
            status_code = getattr(getattr(e, "response", None), "status_code", None)
            if status_code in {404, 410}:
                with _database() as connection:
                    connection.execute(
                        "DELETE FROM push_subscriptions WHERE endpoint = ?",
                        (row["endpoint"],),
                    )
            else:
                bot_state.log(f"Push notification failed: {e}", "error")
        except Exception as e:
            bot_state.log(f"Push notification failed: {e}", "error")


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
        self.account_operation_lock = asyncio.Lock()
        self.exp_notification_callback = None
        self._recent_log_entries: Dict[tuple, float] = {}

    @staticmethod
    def _important_log(message: str) -> bool:
        text = message.lower()
        return any(marker in text for marker in (
            "exp milestone",
            "new account added",
            "imported ",
            "web dashboard live",
            "all sessions cleanly closed",
            "shutting down all accounts",
            "cannot restart account",
            "no accounts found",
        ))

    @staticmethod
    def _log_dedupe_key(message: str) -> str:
        normalized = re.sub(r"\b\d+(?:\.\d+){3}(?::\d+)?\b", "<endpoint>", message)
        normalized = re.sub(r"\b\d+\b", "#", normalized)
        return normalized[:180]

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        if level in {"info", "success"} and not self._important_log(message):
            return
        now = time.monotonic()
        key = (level, uid, self._log_dedupe_key(message))
        previous = self._recent_log_entries.get(key)
        if previous is not None and now - previous < LOG_DEDUPE_SECONDS:
            return
        self._recent_log_entries[key] = now
        if len(self._recent_log_entries) > 1000:
            cutoff = now - LOG_DEDUPE_SECONDS
            self._recent_log_entries = {
                entry_key: timestamp
                for entry_key, timestamp in self._recent_log_entries.items()
                if timestamp >= cutoff
            }
        entry = {
            "time": bd_time(),
            "level": level,
            "message": message,
            "uid": uid,
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str,
                         level: int, exp: int, likes: int = 0,
                         added_at: Optional[float] = None):
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
                "last_updated": bd_time(),
                "added_at": added_at or time.time(),
                "notified_exp_milestone": 0,
            }
        else:
            acc = self.accounts[uid_str]
            previous_gained = acc.get("gained_exp", 0)
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
            acc["last_updated"] = bd_time()
            if added_at:
                acc["added_at"] = added_at
            self._notify_exp_milestones(uid_str, acc, previous_gained, acc["gained_exp"])
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            previous_gained = acc["gained_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = bd_time()
            self._notify_exp_milestones(uid_str, acc, previous_gained, acc["gained_exp"])
            diff = current_exp - old_exp
            if diff > 0:
                self.log(
                    f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! "
                    f"Total Gained: +{acc['gained_exp']}",
                    "success", uid_str,
                )
            self.recalc_totals()

    def _notify_exp_milestones(self, uid: str, account: Dict[str, Any],
                               previous_gained: int, current_gained: int):
        last_notified = account.get("notified_exp_milestone", 0)
        first_milestone = max(previous_gained // EXP_NOTIFICATION_INTERVAL, last_notified) + 1
        last_milestone = current_gained // EXP_NOTIFICATION_INTERVAL
        account["notified_exp_milestone"] = max(last_notified, last_milestone)
        if not self.exp_notification_callback or last_milestone < first_milestone:
            return
        for milestone in range(first_milestone, last_milestone + 1):
            self.log(
                f"EXP milestone: {account['nickname']} reached +{milestone * EXP_NOTIFICATION_INTERVAL:,} EXP",
                "success",
                uid,
            )
            try:
                asyncio.get_running_loop().create_task(
                    self.exp_notification_callback(
                        uid,
                        account["nickname"],
                        milestone * EXP_NOTIFICATION_INTERVAL,
                    )
                )
            except RuntimeError:
                self.log("Cannot queue EXP notification without an active event loop", "error", uid)

    def update_status(self, uid: str, status: str,
                      active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = bd_time()

    def increment_match(self, uid: str):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = bd_time()
            self.accounts[uid_str]["last_updated"] = bd_time()
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
    if not request.get("authenticated"):
        return await handle_login_page(request)
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
        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return web.json_response(
                    {"status": "error", "error": "UID and Password are required"}
                )
            account = {"uid": uid, "password": pwd, "added_at": time.time()}
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return web.json_response(
                    {"status": "error", "error": "Token is required"}
                )
            account = {"token": token, "added_at": time.time()}
        else:
            return web.json_response(
                {"status": "error", "error": "Invalid payload"}
            )

        async with bot_state.account_operation_lock:
            existing = _load_accounts_file()
            if "uid" in account:
                existing = [acc for acc in existing if str(acc.get("uid", "")).strip() != account["uid"]]
            else:
                existing = [acc for acc in existing if acc.get("token") != account["token"]]
            existing.append(account)
            _save_accounts_file(existing)

            bot_state.log(f"New account added: {account.get('uid') or 'Token'}", "success")

            callback = bot_state.refresh_callbacks.get("on_account_added")
            if callback:
                await callback(account)

        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_import_accounts(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        raw_accounts = data.get("accounts") if isinstance(data, dict) else None
        if not isinstance(raw_accounts, list) or not raw_accounts:
            return web.json_response(
                {"status": "error", "error": "JSON must contain a non-empty list of UID/password objects"},
                status=400,
            )

        imported: Dict[str, Dict[str, str]] = {}
        for item in raw_accounts:
            if not isinstance(item, dict):
                return web.json_response(
                    {"status": "error", "error": "Each JSON entry must be an object"},
                    status=400,
                )
            if "uid" in item and "password" in item:
                uid, password = item["uid"], item["password"]
            elif len(item) == 1:
                uid, password = next(iter(item.items()))
            else:
                return web.json_response(
                    {"status": "error", "error": 'Each entry must be {"UID": "password"} or {"uid": "UID", "password": "password"}'},
                    status=400,
                )
            uid = str(uid).strip()
            password = str(password).strip()
            if not uid or not password:
                return web.json_response(
                    {"status": "error", "error": "UID and password values cannot be empty"},
                    status=400,
                )
            imported[uid] = {"uid": uid, "password": password, "added_at": time.time()}

        async with bot_state.account_operation_lock:
            existing = _load_accounts_file()
            imported_uids = set(imported)
            existing = [
                acc for acc in existing
                if str(acc.get("uid", "")).strip() not in imported_uids
            ]
            existing.extend(imported.values())
            _save_accounts_file(existing)

            callback = bot_state.refresh_callbacks.get("on_account_added")
            if callback:
                imported_accounts = list(imported.values())
                for index, account in enumerate(imported_accounts):
                    await callback(account)
                    if index < len(imported_accounts) - 1:
                        await asyncio.sleep(0.5)

        bot_state.log(f"Imported {len(imported)} account(s) from JSON", "success")
        return web.json_response({"status": "ok", "imported": len(imported)})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=500)


async def handle_delete_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid") or "").strip()
        if not uid:
            return web.json_response(
                {"status": "error", "error": "UID is required"}, status=400
            )

        async with bot_state.account_operation_lock:
            credentials = bot_state.account_credentials.get(uid)
            if credentials is None:
                credentials = next(
                    (value for value in bot_state.account_credentials.values()
                     if str(value.get("account_id", "")) == uid),
                    {},
                )
            auth_uid = str(credentials.get("auth_uid") or "").strip()
            auth_token = str(credentials.get("auth_token") or credentials.get("access_token") or "").strip()

            existing = _load_accounts_file()
            existing = [
                acc for acc in existing
                if str(acc.get("uid") or "").strip() not in {uid, auth_uid}
                and (not auth_token or str(acc.get("token") or "").strip() != auth_token)
            ]
            _save_accounts_file(existing)

            worker_keys = {
                uid, auth_uid, f"guest:{uid}", f"guest:{auth_uid}",
                auth_token[:10] if auth_token else "",
                f"token:{auth_token}" if auth_token else "",
            }
            workers = {
                bot_state.account_workers.pop(key)
                for key in worker_keys if key and key in bot_state.account_workers
            }
            for worker in workers:
                if not worker.done():
                    worker.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)

            removed = bot_state.remove_account(uid)
            if auth_uid and auth_uid != uid:
                removed = bot_state.remove_account(auth_uid) or removed

            for key, value in list(bot_state.account_credentials.items()):
                if key in {uid, auth_uid} or value is credentials:
                    bot_state.account_credentials.pop(key, None)

            callback = bot_state.refresh_callbacks.get("on_account_removed")
            if callback:
                await callback(uid, credentials)

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


async def handle_restart_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid") or "").strip()
        if not uid:
            return web.json_response(
                {"status": "error", "error": "Account ID is required"}, status=400
            )

        callback = bot_state.refresh_callbacks.get("on_restart_account")
        if callback is None:
            return web.json_response(
                {"status": "error", "error": "Account restart is unavailable"}, status=503
            )

        async with bot_state.account_operation_lock:
            restarted = await callback(uid)
        if not restarted:
            return web.json_response(
                {"status": "error", "error": f"Account {uid} was not found or could not be restarted"},
                status=404,
            )
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=500)


async def start_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    initialize_dashboard_storage()
    app = web.Application(middlewares=[dashboard_auth_middleware])
    app.router.add_get("/", handle_index)
    app.router.add_get("/login", handle_login_page)
    app.router.add_get("/service-worker.js", handle_service_worker)
    app.router.add_get("/api/auth/status", handle_auth_status)
    app.router.add_post("/api/auth/login", handle_auth_login)
    app.router.add_post("/api/auth/logout", handle_auth_logout)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_get("/api/push/public-key", handle_push_public_key)
    app.router.add_post("/api/push/subscribe", handle_push_subscribe)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/import", handle_import_accounts)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)
    app.router.add_post("/api/account/restart", handle_restart_account)

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