from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import requests
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import telebot
from dotenv import load_dotenv
from telebot import types


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bot.db"
PLUGINS_JSON = Path(os.getenv("PLUGINS_JSON", BASE_DIR / "plugins.json"))
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CAPTCHA_TTL_SECONDS = int(os.getenv("CAPTCHA_TTL_SECONDS", "120"))
VERIFICATION_TTL_HOURS = int(os.getenv("VERIFICATION_TTL_HOURS", "24"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "10"))
RATE_LIMIT_MAX_ACTIONS = int(os.getenv("RATE_LIMIT_MAX_ACTIONS", "8"))
RELEASES_DIR = Path(os.getenv("RELEASES_DIR", BASE_DIR / "releases"))
ADMIN_IDS = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN не найден. Добавьте его в .env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")
db_lock = threading.Lock()
rate_limit_store: dict[int, list[float]] = {}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,47}$")
OPTIONAL_SKIP_VALUES = {"-", "—", "skip", "пропустить", "нет"}
DEFAULT_PLATFORM = "Windows"


@dataclass
class Plugin:
    slug: str
    title: str
    version: str = ""
    description: str = ""
    delivery: str = "file"  # file | link
    file_path: str = ""
    external_url: str = ""
    sha256: str = ""
    platform: str = DEFAULT_PLATFORM
    note: str = ""
    telegram_file_id: str = ""
    original_filename: str = ""
    file_size: int = 0


# ---------- Helpers ----------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def user_label(user: types.User) -> str:
    if user.username:
        return f"@{user.username}"
    return user.first_name or str(user.id)


def now_ts() -> float:
    return time.time()


def hit_rate_limit(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return False
    current = now_ts()
    window_start = current - RATE_LIMIT_WINDOW_SECONDS
    history = rate_limit_store.get(user_id, [])
    history = [x for x in history if x >= window_start]
    history.append(current)
    rate_limit_store[user_id] = history
    return len(history) > RATE_LIMIT_MAX_ACTIONS


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def ensure_release_dir() -> None:
    RELEASES_DIR.mkdir(parents=True, exist_ok=True)


def resolve_plugin_file_path(file_path: str) -> Path:
    path = Path(file_path)
    if not path.is_absolute():
        path = (BASE_DIR / path).resolve()
    return path


def relative_to_base(path: Path) -> str:
    try:
        return f"./{path.resolve().relative_to(BASE_DIR.resolve()).as_posix()}"
    except ValueError:
        return str(path.resolve())


def clean_optional_text(value: str) -> str:
    value = value.strip()
    if value.lower() in OPTIONAL_SKIP_VALUES:
        return ""
    return value


def is_valid_slug(value: str) -> bool:
    return bool(SLUG_RE.fullmatch(value.strip().lower()))


def short_plugin_title(plugin: Plugin) -> str:
    title = plugin.title
    if plugin.version:
        title = f"{title} · {plugin.version}"
    return title[:60]


def can_download_via_getfile(file_size: int | None) -> bool:
    return bool(file_size and file_size <= 20 * 1024 * 1024)


def safe_send_document(chat_id: int, document: Any, caption: str, visible_file_name: str | None = None):
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            kwargs = {"caption": caption}
            if visible_file_name:
                kwargs["visible_file_name"] = visible_file_name
            return bot.send_document(chat_id, document, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            logger.warning("Сбой отправки документа, попытка %s/2: %s", attempt + 1, exc)
            time.sleep(2 + attempt)
    if last_exc:
        raise last_exc
    raise RuntimeError("Не удалось отправить документ")


# ---------- Database ----------

def with_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db_lock:
        conn = with_db()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                is_verified INTEGER DEFAULT 0,
                verified_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS captcha_challenges (
                user_id INTEGER PRIMARY KEY,
                answer TEXT NOT NULL,
                plugin_slug TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS download_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plugin_slug TEXT NOT NULL,
                delivery_method TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS plugin_file_cache (
                plugin_slug TEXT PRIMARY KEY,
                telegram_file_id TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                user_id INTEGER PRIMARY KEY,
                action TEXT NOT NULL,
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS release_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plugin_slug TEXT NOT NULL,
                plugin_version TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                UNIQUE(user_id, plugin_slug, plugin_version)
            )
            """
        )
        conn.commit()
        conn.close()


def upsert_user(user: types.User) -> None:
    current = iso(utcnow())
    with db_lock:
        conn = with_db()
        conn.execute(
            """
            INSERT INTO users (user_id, username, first_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                updated_at = excluded.updated_at
            """,
            (user.id, user.username, user.first_name, current, current),
        )
        conn.commit()
        conn.close()


def is_verified(user_id: int) -> bool:
    with db_lock:
        conn = with_db()
        row = conn.execute(
            "SELECT is_verified, verified_until FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
    if not row:
        return False
    if int(row["is_verified"] or 0) != 1:
        return False
    verified_until = parse_dt(row["verified_until"])
    return bool(verified_until and verified_until > utcnow())


def set_verified(user_id: int) -> None:
    until = utcnow() + timedelta(hours=VERIFICATION_TTL_HOURS)
    with db_lock:
        conn = with_db()
        conn.execute(
            """
            UPDATE users
            SET is_verified = 1,
                verified_until = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (iso(until), iso(utcnow()), user_id),
        )
        conn.commit()
        conn.close()


def create_challenge(user_id: int, plugin_slug: str, answer: str) -> None:
    expires = utcnow() + timedelta(seconds=CAPTCHA_TTL_SECONDS)
    with db_lock:
        conn = with_db()
        conn.execute(
            """
            INSERT INTO captcha_challenges (user_id, answer, plugin_slug, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                answer = excluded.answer,
                plugin_slug = excluded.plugin_slug,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at
            """,
            (user_id, answer, plugin_slug, iso(expires), iso(utcnow())),
        )
        conn.commit()
        conn.close()


def get_challenge(user_id: int) -> sqlite3.Row | None:
    with db_lock:
        conn = with_db()
        row = conn.execute(
            "SELECT * FROM captcha_challenges WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
    return row


def clear_challenge(user_id: int) -> None:
    with db_lock:
        conn = with_db()
        conn.execute("DELETE FROM captcha_challenges WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()


def log_download(user_id: int, plugin_slug: str, delivery_method: str) -> None:
    with db_lock:
        conn = with_db()
        conn.execute(
            "INSERT INTO download_logs (user_id, plugin_slug, delivery_method, created_at) VALUES (?, ?, ?, ?)",
            (user_id, plugin_slug, delivery_method, iso(utcnow())),
        )
        conn.commit()
        conn.close()


def get_plugin_downloaders(plugin_slug: str) -> list[int]:
    with db_lock:
        conn = with_db()
        rows = conn.execute(
            "SELECT DISTINCT user_id FROM download_logs WHERE plugin_slug = ? ORDER BY user_id ASC",
            (plugin_slug,),
        ).fetchall()
        conn.close()
    return [int(row["user_id"]) for row in rows]


def get_plugin_downloaders_count(plugin_slug: str) -> int:
    with db_lock:
        conn = with_db()
        row = conn.execute(
            "SELECT COUNT(DISTINCT user_id) AS c FROM download_logs WHERE plugin_slug = ?",
            (plugin_slug,),
        ).fetchone()
        conn.close()
    return int(row["c"] if row else 0)


def was_notified(user_id: int, plugin_slug: str, plugin_version: str) -> bool:
    with db_lock:
        conn = with_db()
        row = conn.execute(
            "SELECT 1 FROM release_notifications WHERE user_id = ? AND plugin_slug = ? AND plugin_version = ?",
            (user_id, plugin_slug, plugin_version),
        ).fetchone()
        conn.close()
    return bool(row)


def mark_notified(user_id: int, plugin_slug: str, plugin_version: str) -> None:
    with db_lock:
        conn = with_db()
        conn.execute(
            """
            INSERT OR IGNORE INTO release_notifications (user_id, plugin_slug, plugin_version, sent_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, plugin_slug, plugin_version, iso(utcnow())),
        )
        conn.commit()
        conn.close()


def get_cached_file_id(plugin_slug: str) -> str | None:
    with db_lock:
        conn = with_db()
        row = conn.execute(
            "SELECT telegram_file_id FROM plugin_file_cache WHERE plugin_slug = ?",
            (plugin_slug,),
        ).fetchone()
        conn.close()
    return row["telegram_file_id"] if row else None


def set_cached_file_id(plugin_slug: str, telegram_file_id: str) -> None:
    if not telegram_file_id:
        return
    with db_lock:
        conn = with_db()
        conn.execute(
            """
            INSERT INTO plugin_file_cache (plugin_slug, telegram_file_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(plugin_slug) DO UPDATE SET
                telegram_file_id = excluded.telegram_file_id,
                updated_at = excluded.updated_at
            """,
            (plugin_slug, telegram_file_id, iso(utcnow())),
        )
        conn.commit()
        conn.close()


def clear_cached_file_id(plugin_slug: str) -> None:
    with db_lock:
        conn = with_db()
        conn.execute("DELETE FROM plugin_file_cache WHERE plugin_slug = ?", (plugin_slug,))
        conn.commit()
        conn.close()


def get_admin_session(user_id: int) -> sqlite3.Row | None:
    with db_lock:
        conn = with_db()
        row = conn.execute(
            "SELECT * FROM admin_sessions WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
    return row


def set_admin_session(user_id: int, action: str, state: str, payload: dict[str, Any]) -> None:
    with db_lock:
        conn = with_db()
        conn.execute(
            """
            INSERT INTO admin_sessions (user_id, action, state, payload_json, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                action = excluded.action,
                state = excluded.state,
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at
            """,
            (user_id, action, state, json.dumps(payload, ensure_ascii=False), iso(utcnow())),
        )
        conn.commit()
        conn.close()


def clear_admin_session(user_id: int) -> None:
    with db_lock:
        conn = with_db()
        conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()


def parse_admin_payload(row: sqlite3.Row | None) -> dict[str, Any]:
    if not row:
        return {}
    try:
        return json.loads(row["payload_json"] or "{}")
    except json.JSONDecodeError:
        return {}


def get_stats_text() -> str:
    with db_lock:
        conn = with_db()
        users_total = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        users_verified = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE is_verified = 1 AND verified_until > ?",
            (iso(utcnow()),),
        ).fetchone()["c"]
        downloads_total = conn.execute("SELECT COUNT(*) AS c FROM download_logs").fetchone()["c"]
        notifications_total = conn.execute("SELECT COUNT(*) AS c FROM release_notifications").fetchone()["c"]
        top_rows = conn.execute(
            """
            SELECT plugin_slug, COUNT(*) AS c
            FROM download_logs
            GROUP BY plugin_slug
            ORDER BY c DESC, plugin_slug ASC
            LIMIT 5
            """
        ).fetchall()
        conn.close()

    lines = [
        "<b>Статистика</b>",
        f"Пользователей: {users_total}",
        f"Подтверждённых: {users_verified}",
        f"Выдач: {downloads_total}",
        f"Уведомлений о релизах: {notifications_total}",
    ]
    if top_rows:
        lines.append("")
        lines.append("<b>Топ плагинов:</b>")
        for row in top_rows:
            lines.append(f"• {escape_html(row['plugin_slug'])}: {row['c']}")
    return "\n".join(lines)


# ---------- Plugins ----------

def load_plugins() -> dict[str, Plugin]:
    if not PLUGINS_JSON.exists():
        logger.warning("Файл %s не найден", PLUGINS_JSON)
        return {}

    raw = json.loads(PLUGINS_JSON.read_text(encoding="utf-8"))
    result: dict[str, Plugin] = {}
    for item in raw:
        defaults = {
            "version": "",
            "description": "",
            "delivery": "file",
            "file_path": "",
            "external_url": "",
            "sha256": "",
            "platform": DEFAULT_PLATFORM,
            "note": "",
            "telegram_file_id": "",
            "original_filename": "",
            "file_size": 0,
        }
        defaults.update(item)
        plugin = Plugin(**defaults)
        result[plugin.slug] = plugin
    return result


def save_plugins(plugins: dict[str, Plugin]) -> None:
    PLUGINS_JSON.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(plugin) for plugin in sorted(plugins.values(), key=lambda x: x.slug)]
    PLUGINS_JSON.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def get_plugin(slug: str) -> Plugin | None:
    return load_plugins().get(slug)


def add_or_update_plugin(plugin: Plugin, clear_cache: bool = True) -> None:
    plugins = load_plugins()
    plugins[plugin.slug] = plugin
    save_plugins(plugins)
    if clear_cache:
        clear_cached_file_id(plugin.slug)
    if plugin.telegram_file_id:
        set_cached_file_id(plugin.slug, plugin.telegram_file_id)


def remove_plugin(slug: str) -> Plugin | None:
    plugins = load_plugins()
    plugin = plugins.pop(slug, None)
    if not plugin:
        return None
    save_plugins(plugins)
    clear_cached_file_id(slug)
    try_remove_plugin_file(plugin)
    return plugin


def try_remove_plugin_file(plugin: Plugin) -> None:
    if plugin.delivery != "file" or not plugin.file_path:
        return
    file_path = resolve_plugin_file_path(plugin.file_path)
    if not file_path.exists():
        return
    try:
        releases_root = RELEASES_DIR.resolve()
        resolved = file_path.resolve()
        if releases_root in resolved.parents:
            resolved.unlink(missing_ok=True)
            parent = resolved.parent
            while parent != releases_root and parent.exists():
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent
    except Exception:
        logger.exception("Не удалось удалить файл плагина %s", plugin.slug)


def plugin_caption(plugin: Plugin, checksum: str | None = None) -> str:
    lines = [f"<b>{escape_html(plugin.title)}</b>"]
    if plugin.version:
        lines.append(f"Версия: {escape_html(plugin.version)}")
    if plugin.note:
        lines.append(f"Состав: {escape_html(plugin.note)}")
    if plugin.description:
        lines.append("")
        lines.append(escape_html(plugin.description))
    if checksum:
        lines.append("")
        lines.append(f"SHA-256: <code>{checksum}</code>")
    return "\n".join(lines)


def plugin_admin_text(plugin: Plugin) -> str:
    lines = [
        f"<b>{escape_html(plugin.title)}</b>",
        f"Slug: <code>{escape_html(plugin.slug)}</code>",
        f"Версия: {escape_html(plugin.version or '—')}",
        f"Тип выдачи: {escape_html(plugin.delivery)}",
        f"Скачавших пользователей: {get_plugin_downloaders_count(plugin.slug)}",
    ]
    if plugin.original_filename:
        lines.append(f"Файл: <code>{escape_html(plugin.original_filename)}</code>")
    elif plugin.file_path:
        lines.append(f"Файл: <code>{escape_html(Path(plugin.file_path).name)}</code>")
    if plugin.external_url:
        lines.append(f"Ссылка: {escape_html(plugin.external_url)}")
    if plugin.note:
        lines.append(f"Состав: {escape_html(plugin.note)}")
    return "\n".join(lines)


def build_plugins_keyboard() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    plugins = list(load_plugins().values())
    for plugin in plugins:
        title = plugin.title
        if plugin.version:
            title = f"{plugin.title} · {plugin.version}"
        kb.add(types.InlineKeyboardButton(title[:60], callback_data=f"pl:{plugin.slug}"))
    return kb


def build_notify_plugin_keyboard(plugin_slug: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("Получить установщик", callback_data=f"pl:{plugin_slug}"))
    return kb


def build_admin_keyboard() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("Добавить плагин", callback_data="ad:add"))
    kb.add(types.InlineKeyboardButton("Обновить плагин", callback_data="ad:update"))
    kb.add(types.InlineKeyboardButton("Удалить плагин", callback_data="ad:delete"))
    kb.add(types.InlineKeyboardButton("Список плагинов", callback_data="ad:list"))
    kb.add(types.InlineKeyboardButton("Статистика", callback_data="ad:stats"))
    return kb


def build_admin_plugins_list_keyboard(action_prefix: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    plugins = list(load_plugins().values())
    for plugin in plugins:
        kb.add(types.InlineKeyboardButton(short_plugin_title(plugin), callback_data=f"{action_prefix}:{plugin.slug}"))
    kb.add(types.InlineKeyboardButton("Назад", callback_data="ad:back"))
    return kb


def build_update_actions_keyboard(slug: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("Сменить версию", callback_data=f"ad:editversion:{slug}"))
    kb.add(types.InlineKeyboardButton("Заменить установщик", callback_data=f"ad:editinstaller:{slug}"))
    kb.add(types.InlineKeyboardButton("Уведомить скачавших", callback_data=f"ad:notify:{slug}"))
    kb.add(types.InlineKeyboardButton("Назад", callback_data="ad:update"))
    return kb


def build_post_update_keyboard(slug: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("Уведомить скачавших", callback_data=f"ad:notify:{slug}"))
    kb.add(types.InlineKeyboardButton("К панели", callback_data="ad:back"))
    return kb


def admin_plugins_text() -> str:
    plugins = list(load_plugins().values())
    if not plugins:
        return "<b>Витрина пуста.</b>"

    lines = ["<b>Плагины на витрине</b>"]
    for plugin in plugins:
        line = f"• <code>{escape_html(plugin.slug)}</code> — {escape_html(plugin.title)}"
        meta = []
        if plugin.version:
            meta.append(plugin.version)
        if meta:
            line += f" ({escape_html(' / '.join(meta))})"
        lines.append(line)
    return "\n".join(lines)


def notify_downloaders(plugin: Plugin) -> tuple[int, int, int]:
    version_key = plugin.version or "unversioned"
    user_ids = get_plugin_downloaders(plugin.slug)
    if not user_ids:
        return 0, 0, 0

    sent = 0
    skipped = 0
    failed = 0
    text = (
        f"<b>Новая версия: {escape_html(plugin.title)}</b>\n"
        f"Доступен новый релиз: <b>{escape_html(plugin.version or 'обновление')}</b>.\n"
        "Нажмите кнопку ниже, чтобы получить установщик."
    )
    kb = build_notify_plugin_keyboard(plugin.slug)

    for user_id in user_ids:
        if was_notified(user_id, plugin.slug, version_key):
            skipped += 1
            continue
        try:
            bot.send_message(user_id, text, reply_markup=kb)
            mark_notified(user_id, plugin.slug, version_key)
            sent += 1
            time.sleep(0.05)
        except Exception:
            failed += 1
            logger.exception("Не удалось уведомить user_id=%s по плагину %s", user_id, plugin.slug)
    return sent, skipped, failed


# ---------- CAPTCHA ----------

def create_captcha_keyboard(answer: str) -> types.InlineKeyboardMarkup:
    candidates = {answer}
    while len(candidates) < 6:
        candidates.add(str(random.randint(10, 99)))
    values = list(candidates)
    random.shuffle(values)

    kb = types.InlineKeyboardMarkup(row_width=3)
    buttons = [types.InlineKeyboardButton(v, callback_data=f"cv:{v}") for v in values]
    kb.add(*buttons)
    kb.add(types.InlineKeyboardButton("Обновить проверку", callback_data="cv:refresh"))
    return kb


def start_captcha(chat_id: int, user_id: int, plugin_slug: str) -> None:
    answer = str(random.randint(10, 99))
    create_challenge(user_id, plugin_slug, answer)
    text = (
        "<b>Проверка на человека</b>\n"
        "Нажмите на число ниже.\n"
        f"Нужно выбрать: <b>{answer}</b>\n\n"
        f"Проверка действует {CAPTCHA_TTL_SECONDS} сек."
    )
    bot.send_message(chat_id, text, reply_markup=create_captcha_keyboard(answer))


# ---------- Delivery ----------

def send_plugin(chat_id: int, user_id: int, plugin: Plugin) -> None:
    if plugin.delivery == "link":
        text = plugin_caption(plugin, plugin.sha256 or None)
        text += f"\n\nСсылка на скачивание:\n{escape_html(plugin.external_url)}"
        bot.send_message(chat_id, text, disable_web_page_preview=True)
        log_download(user_id, plugin.slug, "link")
        return

    checksum = plugin.sha256.strip() or None
    caption = plugin_caption(plugin, checksum)

    cached_file_id = plugin.telegram_file_id or get_cached_file_id(plugin.slug)
    if cached_file_id:
        sent = safe_send_document(chat_id, cached_file_id, caption)
        if sent.document and sent.document.file_id:
            set_cached_file_id(plugin.slug, sent.document.file_id)
        log_download(user_id, plugin.slug, "telegram_cached")
        return

    file_path = resolve_plugin_file_path(plugin.file_path) if plugin.file_path else None
    if file_path and file_path.exists():
        file_size = file_path.stat().st_size
        max_bot_size = 50 * 1024 * 1024
        if file_size > max_bot_size:
            bot.send_message(
                chat_id,
                "Установщик слишком большой для прямой отправки ботом. Для такого файла лучше использовать внешнюю ссылку.",
            )
            return

        effective_checksum = checksum or sha256_of_file(file_path)
        caption = plugin_caption(plugin, effective_checksum)
        with file_path.open("rb") as f:
            sent = safe_send_document(chat_id, f, caption, visible_file_name=file_path.name)
        if sent.document and sent.document.file_id:
            set_cached_file_id(plugin.slug, sent.document.file_id)
        log_download(user_id, plugin.slug, "telegram_upload")
        return

    bot.send_message(
        chat_id,
        "Файл пока недоступен на сервере. Загрузите установщик через /admin заново или переключите выдачу на внешнюю ссылку.",
    )


# ---------- Admin flows ----------

def open_admin_panel(chat_id: int) -> None:
    plugins_count = len(load_plugins())
    text = (
        "<b>Панель администратора</b>\n"
        f"Плагинов на витрине: {plugins_count}\n\n"
        "Через эту панель можно добавить плагин, обновить версию, заменить установщик и уведомить тех, кто уже скачивал прошлый релиз."
    )
    bot.send_message(chat_id, text, reply_markup=build_admin_keyboard())


def start_add_plugin_flow(chat_id: int, user_id: int) -> None:
    clear_admin_session(user_id)
    set_admin_session(user_id, "add_plugin", "slug", {})
    bot.send_message(
        chat_id,
        "Отправьте slug нового плагина. Допустимы только латиница, цифры, дефис, подчёркивание и точка. Пример: <code>octavion</code>",
    )


def start_edit_version_flow(chat_id: int, user_id: int, slug: str) -> None:
    plugin = get_plugin(slug)
    if not plugin:
        bot.send_message(chat_id, "Плагин не найден.")
        return
    clear_admin_session(user_id)
    set_admin_session(user_id, "edit_version", "await_version", {"slug": slug})
    bot.send_message(
        chat_id,
        (
            f"Текущая версия плагина <b>{escape_html(plugin.title)}</b>: <code>{escape_html(plugin.version or '—')}</code>\n"
            "Отправьте новую версию. Пример: <code>0.2.0</code>"
        ),
    )


def start_replace_installer_flow(chat_id: int, user_id: int, slug: str) -> None:
    plugin = get_plugin(slug)
    if not plugin:
        bot.send_message(chat_id, "Плагин не найден.")
        return
    clear_admin_session(user_id)
    set_admin_session(user_id, "replace_installer", "await_version", {"slug": slug})
    bot.send_message(
        chat_id,
        (
            f"Вы обновляете установщик для <b>{escape_html(plugin.title)}</b>.\n"
            f"Текущая версия: <code>{escape_html(plugin.version or '—')}</code>\n"
            "Отправьте новую версию или <code>-</code>, если версию менять не нужно."
        ),
    )


def process_admin_text(message: types.Message, session: sqlite3.Row) -> None:
    action = session["action"]
    state = session["state"]
    payload = parse_admin_payload(session)
    text = (message.text or "").strip()

    if action == "add_plugin":
        if state == "slug":
            slug = text.lower()
            if not is_valid_slug(slug):
                bot.reply_to(message, "Неверный slug. Пример корректного значения: <code>octavion</code>")
                return
            if get_plugin(slug):
                bot.reply_to(message, "Плагин с таким slug уже существует. Возьмите другой slug или сначала удалите старый.")
                return
            payload["slug"] = slug
            set_admin_session(message.from_user.id, action, "title", payload)
            bot.send_message(message.chat.id, "Теперь отправьте название плагина. Пример: <code>Octavion</code>")
            return

        if state == "title":
            if not text:
                bot.reply_to(message, "Название не должно быть пустым.")
                return
            payload["title"] = text
            set_admin_session(message.from_user.id, action, "version", payload)
            bot.send_message(message.chat.id, "Отправьте версию плагина или <code>-</code>, если пока не нужно.")
            return

        if state == "version":
            payload["version"] = clean_optional_text(text)
            set_admin_session(message.from_user.id, action, "description", payload)
            bot.send_message(message.chat.id, "Отправьте краткое описание плагина. Можно <code>-</code> для пропуска.")
            return

        if state == "description":
            payload["description"] = clean_optional_text(text)
            set_admin_session(message.from_user.id, action, "note", payload)
            bot.send_message(message.chat.id, "Отправьте примечание к сборке, например <code>VST3 + Standalone</code>. Можно <code>-</code> для пропуска.")
            return

        if state == "note":
            payload["note"] = clean_optional_text(text)
            set_admin_session(message.from_user.id, action, "delivery", payload)
            kb = types.InlineKeyboardMarkup(row_width=2)
            kb.add(
                types.InlineKeyboardButton("Загрузить файл", callback_data="ad:adddelivery:file"),
                types.InlineKeyboardButton("Указать ссылку", callback_data="ad:adddelivery:link"),
            )
            bot.send_message(message.chat.id, "Как будет выдаваться плагин?", reply_markup=kb)
            return

        if state == "link_url":
            if not (text.startswith("http://") or text.startswith("https://")):
                bot.reply_to(message, "Ссылка должна начинаться с http:// или https://")
                return
            plugin = Plugin(
                slug=payload["slug"],
                title=payload["title"],
                version=payload.get("version", ""),
                description=payload.get("description", ""),
                delivery="link",
                external_url=text,
                platform=DEFAULT_PLATFORM,
                note=payload.get("note", ""),
            )
            add_or_update_plugin(plugin)
            clear_admin_session(message.from_user.id)
            bot.send_message(
                message.chat.id,
                f"Плагин <b>{escape_html(plugin.title)}</b> добавлен на витрину как внешняя ссылка.\nSlug: <code>{escape_html(plugin.slug)}</code>",
                reply_markup=build_admin_keyboard(),
            )
            return

    if action == "edit_version" and state == "await_version":
        plugin = get_plugin(payload.get("slug", ""))
        if not plugin:
            clear_admin_session(message.from_user.id)
            bot.reply_to(message, "Плагин не найден.")
            return
        new_version = text.strip()
        if not new_version or new_version.lower() in OPTIONAL_SKIP_VALUES:
            bot.reply_to(message, "Версия не должна быть пустой. Отправьте конкретное значение, например <code>0.2.0</code>.")
            return
        plugin.version = new_version
        add_or_update_plugin(plugin, clear_cache=False)
        clear_admin_session(message.from_user.id)
        bot.send_message(
            message.chat.id,
            (
                f"Версия для <b>{escape_html(plugin.title)}</b> обновлена.\n"
                f"Новая версия: <code>{escape_html(plugin.version)}</code>"
            ),
            reply_markup=build_post_update_keyboard(plugin.slug),
        )
        return

    if action == "replace_installer":
        plugin = get_plugin(payload.get("slug", ""))
        if not plugin:
            clear_admin_session(message.from_user.id)
            bot.reply_to(message, "Плагин не найден.")
            return

        if state == "await_version":
            new_version = clean_optional_text(text)
            payload["new_version"] = new_version
            set_admin_session(message.from_user.id, action, "delivery", payload)
            kb = types.InlineKeyboardMarkup(row_width=2)
            kb.add(
                types.InlineKeyboardButton("Загрузить файл", callback_data="ad:replacedelivery:file"),
                types.InlineKeyboardButton("Указать ссылку", callback_data="ad:replacedelivery:link"),
            )
            bot.send_message(message.chat.id, "Как будет выдаваться новая сборка?", reply_markup=kb)
            return

        if state == "link_url":
            if not (text.startswith("http://") or text.startswith("https://")):
                bot.reply_to(message, "Ссылка должна начинаться с http:// или https://")
                return
            old_plugin = get_plugin(payload["slug"])
            if not old_plugin:
                clear_admin_session(message.from_user.id)
                bot.reply_to(message, "Плагин не найден.")
                return
            old_file_plugin = Plugin(**asdict(old_plugin))
            old_plugin.delivery = "link"
            old_plugin.external_url = text
            old_plugin.file_path = ""
            old_plugin.sha256 = ""
            old_plugin.telegram_file_id = ""
            old_plugin.original_filename = ""
            old_plugin.file_size = 0
            if payload.get("new_version"):
                old_plugin.version = payload["new_version"]
            add_or_update_plugin(old_plugin)
            clear_admin_session(message.from_user.id)
            try_remove_plugin_file(old_file_plugin)
            bot.send_message(
                message.chat.id,
                (
                    f"Установщик для <b>{escape_html(old_plugin.title)}</b> обновлён.\n"
                    f"Текущая версия: <code>{escape_html(old_plugin.version or '—')}</code>"
                ),
                reply_markup=build_post_update_keyboard(old_plugin.slug),
            )
            return


def store_uploaded_document(message: types.Message, session: sqlite3.Row) -> None:
    action = session["action"]
    state = session["state"]
    payload = parse_admin_payload(session)
    document = message.document
    if not document:
        return

    if action not in {"add_plugin", "replace_installer"} or state != "file_upload":
        return

    ensure_release_dir()
    slug = payload["slug"]
    safe_filename = Path(document.file_name or f"{slug}.bin").name

    file_path_value = ""
    checksum = ""
    file_size = int(document.file_size or 0)
    telegram_file_id = document.file_id or ""

    if can_download_via_getfile(file_size):
        plugin_dir = RELEASES_DIR / slug
        plugin_dir.mkdir(parents=True, exist_ok=True)
        target_path = plugin_dir / safe_filename
        if target_path.exists():
            target_path.unlink()
        file_info = bot.get_file(document.file_id)
        downloaded = bot.download_file(file_info.file_path)
        target_path.write_bytes(downloaded)
        checksum = sha256_of_file(target_path)
        file_path_value = relative_to_base(target_path)
    else:
        logger.info("Файл %s слишком большой для download_file через Bot API, сохраняю только Telegram file_id", safe_filename)

    if action == "add_plugin":
        plugin = Plugin(
            slug=slug,
            title=payload["title"],
            version=payload.get("version", ""),
            description=payload.get("description", ""),
            delivery="file",
            file_path=file_path_value,
            sha256=checksum,
            platform=DEFAULT_PLATFORM,
            note=payload.get("note", ""),
            telegram_file_id=telegram_file_id,
            original_filename=safe_filename,
            file_size=file_size,
        )
        add_or_update_plugin(plugin)
        clear_admin_session(message.from_user.id)
        extra = f"\nSHA-256: <code>{checksum}</code>" if checksum else ""
        bot.send_message(
            message.chat.id,
            (
                f"Плагин <b>{escape_html(plugin.title)}</b> добавлен на витрину.\n"
                f"Slug: <code>{escape_html(plugin.slug)}</code>\n"
                f"Файл: <code>{escape_html(safe_filename)}</code>{extra}"
            ),
            reply_markup=build_admin_keyboard(),
        )
        return

    old_plugin = get_plugin(slug)
    if not old_plugin:
        clear_admin_session(message.from_user.id)
        bot.send_message(message.chat.id, "Плагин не найден.")
        return
    old_file_plugin = Plugin(**asdict(old_plugin))
    old_plugin.delivery = "file"
    old_plugin.external_url = ""
    old_plugin.file_path = file_path_value
    old_plugin.sha256 = checksum
    old_plugin.telegram_file_id = telegram_file_id
    old_plugin.original_filename = safe_filename
    old_plugin.file_size = file_size
    if payload.get("new_version"):
        old_plugin.version = payload["new_version"]
    add_or_update_plugin(old_plugin)
    clear_admin_session(message.from_user.id)
    if old_file_plugin.file_path and old_file_plugin.file_path != old_plugin.file_path:
        try_remove_plugin_file(old_file_plugin)
    extra = f"\nSHA-256: <code>{checksum}</code>" if checksum else ""
    bot.send_message(
        message.chat.id,
        (
            f"Установщик для <b>{escape_html(old_plugin.title)}</b> обновлён.\n"
            f"Версия: <code>{escape_html(old_plugin.version or '—')}</code>\n"
            f"Файл: <code>{escape_html(safe_filename)}</code>{extra}"
        ),
        reply_markup=build_post_update_keyboard(old_plugin.slug),
    )


# ---------- Command / Callback handlers ----------

def ensure_private(message: types.Message) -> bool:
    if message.chat.type != "private":
        bot.reply_to(message, "Этот бот работает только в личных сообщениях.")
        return False
    return True


@bot.message_handler(commands=["start", "help", "plugins"])
def cmd_start(message: types.Message) -> None:
    if not ensure_private(message):
        return
    if message.from_user and message.from_user.is_bot:
        return
    if hit_rate_limit(message.from_user.id):
        bot.reply_to(message, "Слишком много запросов. Подождите несколько секунд.")
        return

    upsert_user(message.from_user)
    plugins = load_plugins()
    if not plugins:
        bot.reply_to(message, "Список плагинов пуст. Сначала добавьте плагины через /admin или заполните plugins.json.")
        return

    text = (
        "<b>VST Plugins от Rootnot Audio.</b>\n"
        "Выдача установщиков для Windows."
    )
    bot.send_message(message.chat.id, text, reply_markup=build_plugins_keyboard())


@bot.message_handler(commands=["admin"])
def cmd_admin(message: types.Message) -> None:
    if not ensure_private(message):
        return
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "Недостаточно прав.")
        return
    upsert_user(message.from_user)
    open_admin_panel(message.chat.id)


@bot.message_handler(commands=["cancel"])
def cmd_cancel(message: types.Message) -> None:
    if not ensure_private(message):
        return
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "Недостаточно прав.")
        return
    clear_admin_session(message.from_user.id)
    bot.reply_to(message, "Текущее действие отменено.")
    open_admin_panel(message.chat.id)


@bot.message_handler(commands=["stats"])
def cmd_stats(message: types.Message) -> None:
    if not ensure_private(message):
        return
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "Недостаточно прав.")
        return
    upsert_user(message.from_user)
    bot.send_message(message.chat.id, get_stats_text())


@bot.message_handler(content_types=["document"])
def on_document(message: types.Message) -> None:
    if not ensure_private(message):
        return
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "Загрузка файлов доступна только администратору.")
        return

    upsert_user(message.from_user)
    session = get_admin_session(message.from_user.id)
    if not session:
        bot.reply_to(message, "Сейчас загрузка не ожидается. Используйте /admin и начните добавление или обновление плагина.")
        return

    try:
        store_uploaded_document(message, session)
    except Exception:
        logger.exception("Ошибка при загрузке установщика")
        bot.reply_to(message, "Не удалось обработать файл. Проверьте, что бот получает документ целиком, и попробуйте ещё раз.")


@bot.message_handler(func=lambda m: bool(m.text) and not m.text.startswith("/"), content_types=["text"])
def on_text(message: types.Message) -> None:
    if not ensure_private(message):
        return
    if message.from_user.is_bot:
        return
    upsert_user(message.from_user)

    session = get_admin_session(message.from_user.id)
    if session and is_admin(message.from_user.id):
        process_admin_text(message, session)
        return


@bot.callback_query_handler(func=lambda call: True)
def on_callback(call: types.CallbackQuery) -> None:
    if call.from_user.is_bot:
        bot.answer_callback_query(call.id)
        return
    upsert_user(call.from_user)

    if hit_rate_limit(call.from_user.id):
        bot.answer_callback_query(call.id, "Слишком много действий. Подождите несколько секунд.")
        return

    data = call.data or ""

    if data.startswith("ad:"):
        if not is_admin(call.from_user.id):
            bot.answer_callback_query(call.id, "Недостаточно прав")
            return

        if data == "ad:add":
            bot.answer_callback_query(call.id, "Добавление плагина")
            start_add_plugin_flow(call.message.chat.id, call.from_user.id)
            return

        if data == "ad:update":
            bot.answer_callback_query(call.id, "Выберите плагин")
            plugins = load_plugins()
            if not plugins:
                bot.send_message(call.message.chat.id, "Обновлять пока нечего. Витрина пуста.", reply_markup=build_admin_keyboard())
                return
            bot.send_message(
                call.message.chat.id,
                "Выберите плагин для обновления.",
                reply_markup=build_admin_plugins_list_keyboard("ad:editpick"),
            )
            return

        if data == "ad:delete":
            bot.answer_callback_query(call.id, "Выберите плагин")
            plugins = load_plugins()
            if not plugins:
                bot.send_message(call.message.chat.id, "Удалять пока нечего. Витрина пуста.", reply_markup=build_admin_keyboard())
                return
            bot.send_message(
                call.message.chat.id,
                "Выберите плагин для удаления с витрины.",
                reply_markup=build_admin_plugins_list_keyboard("ad:delpick"),
            )
            return

        if data == "ad:list":
            bot.answer_callback_query(call.id, "Список плагинов")
            bot.send_message(call.message.chat.id, admin_plugins_text(), reply_markup=build_admin_keyboard())
            return

        if data == "ad:stats":
            bot.answer_callback_query(call.id, "Статистика")
            bot.send_message(call.message.chat.id, get_stats_text(), reply_markup=build_admin_keyboard())
            return

        if data == "ad:back":
            bot.answer_callback_query(call.id)
            open_admin_panel(call.message.chat.id)
            return

        if data.startswith("ad:editpick:"):
            slug = data.split(":", 2)[2]
            plugin = get_plugin(slug)
            if not plugin:
                bot.answer_callback_query(call.id, "Плагин не найден")
                return
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                plugin_admin_text(plugin),
                reply_markup=build_update_actions_keyboard(slug),
            )
            return

        if data.startswith("ad:editversion:"):
            slug = data.split(":", 2)[2]
            bot.answer_callback_query(call.id, "Обновление версии")
            start_edit_version_flow(call.message.chat.id, call.from_user.id, slug)
            return

        if data.startswith("ad:editinstaller:"):
            slug = data.split(":", 2)[2]
            bot.answer_callback_query(call.id, "Замена установщика")
            start_replace_installer_flow(call.message.chat.id, call.from_user.id, slug)
            return

        if data.startswith("ad:notify:"):
            slug = data.split(":", 2)[2]
            plugin = get_plugin(slug)
            if not plugin:
                bot.answer_callback_query(call.id, "Плагин не найден")
                return
            bot.answer_callback_query(call.id, "Рассылаю уведомления")
            sent, skipped, failed = notify_downloaders(plugin)
            bot.send_message(
                call.message.chat.id,
                (
                    f"<b>Рассылка завершена</b>\n"
                    f"Плагин: {escape_html(plugin.title)}\n"
                    f"Версия: <code>{escape_html(plugin.version or '—')}</code>\n"
                    f"Отправлено: {sent}\n"
                    f"Уже были уведомлены об этой версии: {skipped}\n"
                    f"Не доставлено: {failed}"
                ),
                reply_markup=build_update_actions_keyboard(slug),
            )
            return

        if data.startswith("ad:adddelivery:"):
            mode = data.split(":", 2)[2]
            session = get_admin_session(call.from_user.id)
            if not session or session["action"] != "add_plugin" or session["state"] != "delivery":
                bot.answer_callback_query(call.id, "Сессия устарела")
                return

            payload = parse_admin_payload(session)
            if mode == "file":
                set_admin_session(call.from_user.id, "add_plugin", "file_upload", payload)
                bot.answer_callback_query(call.id, "Жду файл")
                bot.send_message(
                    call.message.chat.id,
                    "Отправьте установщик как документ. Бот сохранит Telegram file_id и, если файл до 20 МБ, дополнительно сделает локальную копию в <code>releases</code>.",
                )
                return

            if mode == "link":
                set_admin_session(call.from_user.id, "add_plugin", "link_url", payload)
                bot.answer_callback_query(call.id, "Жду ссылку")
                bot.send_message(call.message.chat.id, "Отправьте прямую ссылку на скачивание.")
                return

        if data.startswith("ad:replacedelivery:"):
            mode = data.split(":", 2)[2]
            session = get_admin_session(call.from_user.id)
            if not session or session["action"] != "replace_installer" or session["state"] != "delivery":
                bot.answer_callback_query(call.id, "Сессия устарела")
                return
            payload = parse_admin_payload(session)
            if mode == "file":
                set_admin_session(call.from_user.id, "replace_installer", "file_upload", payload)
                bot.answer_callback_query(call.id, "Жду файл")
                bot.send_message(
                    call.message.chat.id,
                    "Отправьте новый установщик как документ. Версия обновится, если вы указали её на предыдущем шаге.",
                )
                return
            if mode == "link":
                set_admin_session(call.from_user.id, "replace_installer", "link_url", payload)
                bot.answer_callback_query(call.id, "Жду ссылку")
                bot.send_message(call.message.chat.id, "Отправьте прямую ссылку на новую сборку.")
                return

        if data.startswith("ad:delpick:"):
            slug = data.split(":", 2)[2]
            plugin = get_plugin(slug)
            if not plugin:
                bot.answer_callback_query(call.id, "Плагин не найден")
                return
            kb = types.InlineKeyboardMarkup(row_width=2)
            kb.add(
                types.InlineKeyboardButton("Да, удалить", callback_data=f"ad:delconfirm:{slug}"),
                types.InlineKeyboardButton("Нет", callback_data="ad:back"),
            )
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                f"Удалить <b>{escape_html(plugin.title)}</b> с витрины?",
                reply_markup=kb,
            )
            return

        if data.startswith("ad:delconfirm:"):
            slug = data.split(":", 2)[2]
            plugin = remove_plugin(slug)
            if not plugin:
                bot.answer_callback_query(call.id, "Плагин уже удалён")
                return
            clear_admin_session(call.from_user.id)
            bot.answer_callback_query(call.id, "Удалено")
            bot.send_message(
                call.message.chat.id,
                f"Плагин <b>{escape_html(plugin.title)}</b> удалён с витрины.",
                reply_markup=build_admin_keyboard(),
            )
            return

    if data.startswith("pl:"):
        plugin_slug = data.split(":", 1)[1]
        plugin = get_plugin(plugin_slug)
        if not plugin:
            bot.answer_callback_query(call.id, "Плагин не найден")
            return

        if not is_verified(call.from_user.id):
            bot.answer_callback_query(call.id, "Нужна проверка")
            start_captcha(call.message.chat.id, call.from_user.id, plugin_slug)
            return

        bot.answer_callback_query(call.id, "Готово")
        send_plugin(call.message.chat.id, call.from_user.id, plugin)
        return

    if data.startswith("cv:"):
        choice = data.split(":", 1)[1]
        challenge = get_challenge(call.from_user.id)
        if not challenge:
            bot.answer_callback_query(call.id, "Проверка устарела")
            return

        expires_at = parse_dt(challenge["expires_at"])
        if not expires_at or expires_at <= utcnow():
            clear_challenge(call.from_user.id)
            bot.answer_callback_query(call.id, "Проверка истекла")
            bot.send_message(call.message.chat.id, "Проверка истекла. Выберите плагин ещё раз.")
            return

        if choice == "refresh":
            clear_challenge(call.from_user.id)
            start_captcha(call.message.chat.id, call.from_user.id, challenge["plugin_slug"])
            bot.answer_callback_query(call.id, "Проверка обновлена")
            return

        if choice != challenge["answer"]:
            clear_challenge(call.from_user.id)
            bot.answer_callback_query(call.id, "Неверный ответ")
            bot.send_message(call.message.chat.id, "Проверка не пройдена. Выберите плагин ещё раз.")
            return

        clear_challenge(call.from_user.id)
        set_verified(call.from_user.id)
        bot.answer_callback_query(call.id, "Проверка пройдена")
        bot.send_message(
            call.message.chat.id,
            f"Проверка пройдена. Доступ выдан на {VERIFICATION_TTL_HOURS} ч.",
        )
        plugin = get_plugin(challenge["plugin_slug"])
        if not plugin:
            bot.send_message(call.message.chat.id, "Плагин не найден. Возможно, список был изменён.")
            return
        send_plugin(call.message.chat.id, call.from_user.id, plugin)
        return

    bot.answer_callback_query(call.id)



def main() -> None:
    ensure_release_dir()
    init_db()
    logger.info("Бот запущен. Плагины: %s", list(load_plugins().keys()))
    bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)


if __name__ == "__main__":
    main()
