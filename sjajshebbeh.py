# -*- coding: utf-8 -*-

“””
Voucher Bot - Combined & Fixed

- vouch_type (TRADE / BUY / SELL)
- verified field + VerifyVouchView
- /vouchbuy, /vouchsell, /vouchtrade commands
- Full 3-step wizard flow
- All admin commands, config, leaderboard, stats, export, softlock, shutdown
  “””

import asyncio
import logging
import signal
import json
import os
import discord
import pyotp
import sys
import aiosqlite
from io import BytesIO
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# ENV / SECRETS

load_dotenv()

TOKEN = os.getenv(“DISCORD_TOKEN”, “”).strip()
TOTP_SECRET = os.getenv(“TOTP_SECRET”, “”).strip()

if not TOKEN:
raise RuntimeError(
“DISCORD_TOKEN is not set. Export it in ~/.bashrc or add it to .env.”
)
if not TOTP_SECRET:
print(“WARNING: TOTP_SECRET is not set. /shutdown will not work.”)

# INTENTS & BOT

intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix=”!”, intents=intents)

# CONSTANTS / DEFAULTS

OWNER_ID = 906781117632368730
STATUS_CHANNEL_ID = 1461148246863773698
DB_FILE = “vouches.db”
PAGE_SIZE = 5

MIN_ACCOUNT_AGE_DAYS = 7
MIN_SERVER_JOIN_HOURS = 6

PROTECTED_ROLE_IDS = [
1460784670487871589,
1460060689325490216,
1460056861750595654,
1460054414294253730,
]

TRUSTED_ROLE_ID = 1461128340466307313
RESTRICTED_ROLE_ID = 1466232113945640960
TRUSTED_MIN_VOUCHES = 25
TRUSTED_MIN_AVG = 4.7
RESTRICTED_MIN_VOUCHES = 5
RESTRICTED_MAX_AVG = 2.5

DEFAULT_CONFIG = {
“OWNER_ID”: OWNER_ID,
“STATUS_CHANNEL_ID”: STATUS_CHANNEL_ID,
“TRUSTED_ROLE_ID”: TRUSTED_ROLE_ID,
“RESTRICTED_ROLE_ID”: RESTRICTED_ROLE_ID,
“TRUSTED_MIN_VOUCHES”: TRUSTED_MIN_VOUCHES,
“TRUSTED_MIN_AVG”: TRUSTED_MIN_AVG,
“RESTRICTED_MIN_VOUCHES”: RESTRICTED_MIN_VOUCHES,
“RESTRICTED_MAX_AVG”: RESTRICTED_MAX_AVG,
“PROTECTED_ROLE_IDS”: PROTECTED_ROLE_IDS,
}

# LOGGING

logging.basicConfig(
level=logging.INFO,
format=”%(asctime)s | %(levelname)s | %(name)s | %(message)s”,
)
log = logging.getLogger(“voucher”)

# EMOJI CONSTANTS (unicode escapes only - no literal emoji)

STAR = “\u2B50”
CROSS = “\u274C”
CHECK = “\u2705”
LOCK = “\U0001F510”
WARN = “\u26A0”
TROPHY = “\U0001F3C6”
PING_EMOJI = “\U0001F3D3”

# SQLITE HELPERS

_db_lock = asyncio.Lock()

async def db_connect(path: str) -> aiosqlite.Connection:
db = await aiosqlite.connect(path)
await db.execute(“PRAGMA journal_mode=WAL;”)
await db.execute(“PRAGMA synchronous=NORMAL;”)
await db.execute(“PRAGMA busy_timeout=5000;”)
await db.execute(“PRAGMA foreign_keys=ON;”)
return db

@asynccontextmanager
async def db_open(path: str):
db = await db_connect(path)
try:
yield db
finally:
await db.close()

# DB INIT

async def init_db():
“”“Create tables with all columns. Safe to run on existing DBs.”””
async with _db_lock, db_open(DB_FILE) as db:
await db.execute(”””
CREATE TABLE IF NOT EXISTS vouches (
id                INTEGER PRIMARY KEY AUTOINCREMENT,
guild_id          INTEGER NOT NULL,
vouched_user_id   INTEGER NOT NULL,
voucher_user_id   INTEGER NOT NULL,
trader_user_id    INTEGER NOT NULL,
middleman_user_id INTEGER,
rating            INTEGER NOT NULL,
traded_item       TEXT    NOT NULL,
created_at        TEXT    NOT NULL,
suspicious        INTEGER NOT NULL DEFAULT 0,
vouch_type        TEXT    NOT NULL DEFAULT ‘TRADE’,
verified          INTEGER NOT NULL DEFAULT 0
)
“””)

```
    # Idempotent column additions for existing DBs
    for col, definition in [
        ("vouch_type", "TEXT NOT NULL DEFAULT 'TRADE'"),
        ("verified", "INTEGER NOT NULL DEFAULT 0"),
    ]:
        try:
            await db.execute(
                f"ALTER TABLE vouches ADD COLUMN {col} {definition}"
            )
        except Exception:
            pass  # column already exists

    await db.execute("""
        CREATE TABLE IF NOT EXISTS guild_config (
            guild_id INTEGER NOT NULL,
            key      TEXT    NOT NULL,
            value    TEXT    NOT NULL,
            PRIMARY KEY (guild_id, key)
        )
    """)

    await db.commit()
log.info("Database initialised.")
```

# GUILD CONFIG

async def cfg_get(guild_id: int, key: str):
“”“Return per-guild config value, falling back to DEFAULT_CONFIG.”””
async with _db_lock, db_open(DB_FILE) as db:
cur = await db.execute(
“SELECT value FROM guild_config WHERE guild_id=? AND key=?”,
(guild_id, key),
)
row = await cur.fetchone()

```
if row is None:
    return DEFAULT_CONFIG.get(key)
try:
    return json.loads(row[0])
except Exception:
    return row[0]
```

async def cfg_set(guild_id: int, key: str, value):
“”“Persist a per-guild config value (stored as JSON).”””
raw = json.dumps(value)
async with _db_lock, db_open(DB_FILE) as db:
await db.execute(
“INSERT INTO guild_config (guild_id, key, value) VALUES (?, ?, ?) “
“ON CONFLICT(guild_id, key) DO UPDATE SET value=excluded.value”,
(guild_id, key, raw),
)
await db.commit()

# FORMATTING HELPERS

def _fmt_role(role_id) -> str:
if not role_id or int(role_id) == 0:
return “0 (disabled)”
return f”<@&{int(role_id)}> (`{int(role_id)}`)”

def _fmt_channel(channel_id) -> str:
if not channel_id or int(channel_id) == 0:
return “0 (not set)”
return f”<#{int(channel_id)}> (`{int(channel_id)}`)”

def _fmt_role_id(rid) -> str:
if not rid or rid == 0:
return “Disabled”
return f”<@&{rid}> (`{rid}`)”

def _fmt_chan_id(cid) -> str:
if not cid or cid == 0:
return “Not set”
return f”<#{cid}> (`{cid}`)”

def utc_now_str() -> str:
return datetime.now(timezone.utc).strftime(”%Y-%m-%d %H:%M:%S UTC”)

# SOFTLOCK STATE

_softlock_previous: dict = {}

# VOUCH QUERIES

async def fetch_vouches_page(guild_id: int, vouched_user_id: int, page: int):
“”“Returns (rows, total_count). page is 0-based.”””
offset = page * PAGE_SIZE
async with _db_lock, db_open(DB_FILE) as db:
cur_total = await db.execute(
“SELECT COUNT(*) FROM vouches WHERE guild_id=? AND vouched_user_id=?”,
(guild_id, vouched_user_id),
)
total = (await cur_total.fetchone())[0]

```
    cur = await db.execute(
        """
        SELECT id, voucher_user_id, trader_user_id, middleman_user_id,
               rating, traded_item, created_at, suspicious,
               vouch_type, verified
        FROM vouches
        WHERE guild_id=? AND vouched_user_id=?
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (guild_id, vouched_user_id, PAGE_SIZE, offset),
    )
    rows = await cur.fetchall()
return rows, total
```

async def get_user_trust_stats(guild_id: int, user_id: int) -> dict:
async with _db_lock, db_open(DB_FILE) as db:
cur = await db.execute(
“SELECT COUNT(*), AVG(rating), SUM(suspicious) FROM vouches “
“WHERE guild_id=? AND vouched_user_id=?”,
(guild_id, user_id),
)
total, avg, suspicious_sum = await cur.fetchone()

```
    cur2 = await db.execute(
        "SELECT COUNT(*), AVG(rating) FROM vouches "
        "WHERE guild_id=? AND vouched_user_id=? AND middleman_user_id IS NOT NULL",
        (guild_id, user_id),
    )
    mm_count, mm_avg = await cur2.fetchone()

return {
    "total": int(total or 0),
    "avg": float(avg) if avg is not None else None,
    "suspicious": int(suspicious_sum or 0),
    "middleman_count": int(mm_count or 0),
    "middleman_avg": float(mm_avg) if mm_avg is not None else None,
}
```

async def detect_suspicious_vouch(
guild_id: int, vouched_user_id: int, voucher_user_id: int
) -> int:
“”“Return 1 if the vouch looks suspicious, else 0.”””
async with _db_lock, db_open(DB_FILE) as db:
cur = await db.execute(
“””
SELECT COUNT(*) FROM vouches
WHERE guild_id=? AND vouched_user_id=? AND voucher_user_id=?
AND datetime(replace(created_at,’ UTC’,’’)) >= datetime(‘now’,’-7 days’)
“””,
(guild_id, vouched_user_id, voucher_user_id),
)
recent_same = (await cur.fetchone())[0] or 0

```
    cur2 = await db.execute(
        """
        SELECT COUNT(*) FROM vouches
        WHERE guild_id=? AND vouched_user_id=? AND voucher_user_id=?
          AND datetime(replace(created_at,' UTC','')) >= datetime('now','-14 days')
        """,
        (guild_id, voucher_user_id, vouched_user_id),
    )
    mutual = (await cur2.fetchone())[0] or 0

return 1 if (recent_same >= 1 or mutual >= 1) else 0
```

# TRUST GATE

async def apply_trust_gate(guild: discord.Guild, member: discord.Member):
“”“Auto-assign Trusted / Restricted roles based on vouch stats.”””
if guild is None:
return

```
trusted_role_id = await cfg_get(guild.id, "TRUSTED_ROLE_ID")
restricted_role_id = await cfg_get(guild.id, "RESTRICTED_ROLE_ID")

if (not trusted_role_id or int(trusted_role_id) == 0) and (
    not restricted_role_id or int(restricted_role_id) == 0
):
    return

me = guild.me
if me is None or not me.guild_permissions.manage_roles:
    return

trusted_min_vouches = await cfg_get(guild.id, "TRUSTED_MIN_VOUCHES")
trusted_min_avg = await cfg_get(guild.id, "TRUSTED_MIN_AVG")
restricted_min_vouches = await cfg_get(guild.id, "RESTRICTED_MIN_VOUCHES")
restricted_max_avg = await cfg_get(guild.id, "RESTRICTED_MAX_AVG")

trusted_role = (
    guild.get_role(int(trusted_role_id))
    if trusted_role_id and int(trusted_role_id) != 0
    else None
)
restricted_role = (
    guild.get_role(int(restricted_role_id))
    if restricted_role_id and int(restricted_role_id) != 0
    else None
)

def can_manage(role):
    return role is not None and me.top_role > role

stats = await get_user_trust_stats(guild.id, member.id)
total = stats["total"]
avg = stats["avg"]
if avg is None:
    return

should_trust = total >= int(trusted_min_vouches or 0) and avg >= float(
    trusted_min_avg or 0
)
should_restrict = total >= int(
    restricted_min_vouches or 0
) and avg <= float(restricted_max_avg or 0)

try:
    if restricted_role and can_manage(restricted_role):
        if should_restrict and restricted_role not in member.roles:
            await member.add_roles(
                restricted_role,
                reason="Trust gate: restricted (low avg rating)",
            )
        elif not should_restrict and restricted_role in member.roles:
            await member.remove_roles(
                restricted_role, reason="Trust gate: remove restricted"
            )

    if trusted_role and can_manage(trusted_role):
        if should_trust and trusted_role not in member.roles:
            await member.add_roles(
                trusted_role,
                reason="Trust gate: trusted (high avg rating)",
            )
        elif not should_trust and trusted_role in member.roles:
            await member.remove_roles(
                trusted_role, reason="Trust gate: remove trusted"
            )
except Exception:
    pass
```

# EMBED BUILDER

def build_vouches_embed(
user: discord.Member, rows, total: int, page: int
) -> discord.Embed:
total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
embed = discord.Embed(
title=f”Vouches for {user}”,
description=f”Total vouches: **{total}**”,
color=discord.Color.blurple(),
)
embed.set_footer(
text=f”Page {page + 1}/{total_pages} - Showing {PAGE_SIZE} per page”
)

```
if not rows:
    embed.add_field(
        name="No vouches", value="No results on this page.", inline=False
    )
    return embed

start_index = page * PAGE_SIZE
for i, row in enumerate(rows, start=1):
    vid, voucher_id, trader_id, middleman_id, rating, traded_item, created_at, suspicious = row[:8]
    vtype = row[8] if len(row) > 8 else "TRADE"
    verified = row[9] if len(row) > 9 else 0

    stars = STAR * int(rating)
    flag = f" {WARN}" if suspicious else ""
    verified_text = f"{CHECK} Verified" if verified else "\u23F3 Pending"

    mm_text = f"<@{middleman_id}>" if middleman_id else "None"
    value = (
        f"**Type:** {vtype}\n"
        f"**From:** <@{voucher_id}>\n"
        f"**Trader:** <@{trader_id}>\n"
        f"**Middleman:** {mm_text}\n"
        f"**Rating:** {stars}{flag}\n"
        f"**Item:** {traded_item}\n"
        f"**Date:** {created_at}\n"
        f"**Status:** {verified_text}\n"
        f"**ID:** `{vid}`"
    )
    embed.add_field(
        name=f"Vouch #{start_index + i}", value=value[:1024], inline=False
    )

return embed
```

# PAGINATOR VIEW

class VouchesPaginator(discord.ui.View):
def **init**(
self,
*,
requester_id: int,
guild_id: int,
target_member: discord.Member,
):
super().**init**(timeout=180)
self.requester_id = requester_id
self.guild_id = guild_id
self.target_member = target_member
self.page = 0
self.total = 0

```
async def interaction_check(self, interaction: discord.Interaction) -> bool:
    if interaction.user.id != self.requester_id:
        await interaction.response.send_message(
            f"{CROSS} Only the person who ran this command can use these buttons.",
            ephemeral=True,
        )
        return False
    return True

def _set_button_state(self):
    total_pages = max(1, (self.total + PAGE_SIZE - 1) // PAGE_SIZE)
    self.prev_btn.disabled = self.page <= 0
    self.next_btn.disabled = self.page >= total_pages - 1

async def refresh(self, interaction: discord.Interaction):
    rows, total = await fetch_vouches_page(
        self.guild_id, self.target_member.id, self.page
    )
    self.total = total
    self._set_button_state()
    embed = build_vouches_embed(self.target_member, rows, self.total, self.page)
    await interaction.response.edit_message(
        embed=embed,
        view=self,
        allowed_mentions=discord.AllowedMentions(users=True),
    )

@discord.ui.button(label="Prev", style=discord.ButtonStyle.secondary)
async def prev_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    if self.page > 0:
        self.page -= 1
    await self.refresh(interaction)

@discord.ui.button(label="Next", style=discord.ButtonStyle.primary)
async def next_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    total_pages = max(1, (self.total + PAGE_SIZE - 1) // PAGE_SIZE)
    if self.page < total_pages - 1:
        self.page += 1
    await self.refresh(interaction)

async def on_timeout(self):
    for child in self.children:
        if isinstance(child, discord.ui.Button):
            child.disabled = True
```

# VOUCH VERIFICATION VIEW

class VerifyVouchView(discord.ui.View):
“”“Sent to the vouched user so they can confirm or deny the trade.”””

```
def __init__(self, vouch_id: int, vouched_user_id: int):
    super().__init__(timeout=86400)  # 24 hours
    self.vouch_id = vouch_id
    self.vouched_user_id = vouched_user_id

async def interaction_check(self, interaction: discord.Interaction) -> bool:
    if interaction.user.id != self.vouched_user_id:
        await interaction.response.send_message(
            f"{CROSS} Only the vouched user can confirm or deny this vouch.",
            ephemeral=True,
        )
        return False
    return True

@discord.ui.button(label="Confirm Trade", style=discord.ButtonStyle.success)
async def confirm(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    async with _db_lock, db_open(DB_FILE) as db:
        await db.execute(
            "UPDATE vouches SET verified=1 WHERE id=?", (self.vouch_id,)
        )
        await db.commit()
    for child in self.children:
        child.disabled = True
    await interaction.response.edit_message(
        content=f"{CHECK} Vouch confirmed!", view=self
    )

@discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
async def deny(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    async with _db_lock, db_open(DB_FILE) as db:
        await db.execute(
            "DELETE FROM vouches WHERE id=?", (self.vouch_id,)
        )
        await db.commit()
    for child in self.children:
        child.disabled = True
    await interaction.response.edit_message(
        content=f"{CROSS} Vouch denied and removed.", view=self
    )

async def on_timeout(self):
    for child in self.children:
        child.disabled = True
```

# 3-STEP VOUCH FLOW

class StepBaseView(discord.ui.View):
“”“Locks interactions to the person who started the vouch command.”””

```
def __init__(self, requester_id: int):
    super().__init__(timeout=180)
    self.requester_id = requester_id

async def interaction_check(self, interaction: discord.Interaction) -> bool:
    if interaction.user.id != self.requester_id:
        await interaction.response.send_message(
            f"{CROSS} Only the person who started this vouch can use these menus.",
            ephemeral=True,
        )
        return False
    return True
```

class TraderSelectStep(StepBaseView):
def **init**(self, requester_id: int, vouch_type: str = “TRADE”):
super().**init**(requester_id)
self.vouch_type = vouch_type

```
    self.trader_select = discord.ui.UserSelect(
        placeholder="Step 1/3: Select the Trader",
        min_values=1,
        max_values=1,
    )
    self.trader_select.callback = self.on_trader_selected
    self.add_item(self.trader_select)

async def on_trader_selected(self, interaction: discord.Interaction):
    trader = self.trader_select.values[0]
    await interaction.response.edit_message(
        content=(
            f"{CHECK} **Trader selected:** {trader.mention}\n\n"
            "Step 2/3: Select a **Middleman** (optional) or press **Skip**."
        ),
        view=MiddlemanSelectStep(
            requester_id=self.requester_id,
            trader=trader,
            vouch_type=self.vouch_type,
        ),
        allowed_mentions=discord.AllowedMentions(users=True),
    )
```

class MiddlemanSelectStep(StepBaseView):
def **init**(
self,
requester_id: int,
trader: discord.Member,
vouch_type: str = “TRADE”,
):
super().**init**(requester_id)
self.trader = trader
self.vouch_type = vouch_type

```
    self.middleman_select = discord.ui.UserSelect(
        placeholder="Step 2/3: Select Middleman (optional)",
        min_values=0,
        max_values=1,
    )
    self.middleman_select.callback = self.on_middleman_selected
    self.add_item(self.middleman_select)

async def on_middleman_selected(self, interaction: discord.Interaction):
    middleman = (
        self.middleman_select.values[0]
        if self.middleman_select.values
        else None
    )
    await self._go_next(interaction, middleman)

@discord.ui.button(label="Skip", style=discord.ButtonStyle.secondary)
async def skip_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    await self._go_next(interaction, None)

async def _go_next(self, interaction: discord.Interaction, middleman):
    mid_text = middleman.mention if middleman else "None"
    await interaction.response.edit_message(
        content=(
            f"{CHECK} **Trader:** {self.trader.mention}\n"
            f"{CHECK} **Middleman:** {mid_text}\n\n"
            "Step 3/3: Select who you are **vouching for**."
        ),
        view=VouchForSelectStep(
            requester_id=self.requester_id,
            trader=self.trader,
            middleman=middleman,
            vouch_type=self.vouch_type,
        ),
        allowed_mentions=discord.AllowedMentions(users=True),
    )
```

class VouchForSelectStep(StepBaseView):
def **init**(
self,
requester_id: int,
trader: discord.Member,
middleman,
vouch_type: str = “TRADE”,
):
super().**init**(requester_id)
self.trader = trader
self.middleman = middleman
self.vouch_type = vouch_type

```
    self.vouchfor_select = discord.ui.UserSelect(
        placeholder="Step 3/3: Select who this vouch is for",
        min_values=1,
        max_values=1,
    )
    self.vouchfor_select.callback = self.on_vouchfor_selected
    self.add_item(self.vouchfor_select)

async def on_vouchfor_selected(self, interaction: discord.Interaction):
    vouched_user = self.vouchfor_select.values[0]
    await interaction.response.send_modal(
        VouchModal(
            vouch_type=self.vouch_type,
            trader=self.trader,
            middleman=self.middleman,
            vouched_user=vouched_user,
        )
    )
```

# VOUCH MODAL

class VouchModal(discord.ui.Modal):
rating = discord.ui.TextInput(
label=“Rating (1-5)”,
placeholder=“Example: 5”,
max_length=1,
required=True,
)
traded_item = discord.ui.TextInput(
label=“What did you trade to them?”,
placeholder=“Describe the item(s)”,
required=True,
)

```
def __init__(
    self,
    vouch_type: str,
    trader: discord.Member,
    middleman,
    vouched_user: discord.Member,
):
    super().__init__(title=f"{vouch_type.title()} Vouch")
    self.vouch_type = vouch_type
    self.trader = trader
    self.middleman = middleman
    self.vouched_user = vouched_user

async def on_submit(self, interaction: discord.Interaction):
    try:
        stars = int(self.rating.value)
        if not 1 <= stars <= 5:
            raise ValueError
    except ValueError:
        return await interaction.response.send_message(
            f"{CROSS} Rating must be a number between **1 and 5**.",
            ephemeral=True,
        )

    if interaction.guild is None:
        return await interaction.response.send_message(
            f"{CROSS} This command can only be used in a server.",
            ephemeral=True,
        )

    now_utc = datetime.now(timezone.utc)
    if interaction.user.created_at:
        acct_age_days = (now_utc - interaction.user.created_at).days
        if acct_age_days < MIN_ACCOUNT_AGE_DAYS:
            return await interaction.response.send_message(
                f"{CROSS} Your account must be at least **{MIN_ACCOUNT_AGE_DAYS} days** old to submit vouches.",
                ephemeral=True,
            )

    if interaction.user.joined_at:
        join_hours = (
            now_utc - interaction.user.joined_at
        ).total_seconds() / 3600.0
        if join_hours < MIN_SERVER_JOIN_HOURS:
            return await interaction.response.send_message(
                f"{CROSS} You must be in this server for at least **{MIN_SERVER_JOIN_HOURS} hours** to submit vouches.",
                ephemeral=True,
            )

    suspicious = await detect_suspicious_vouch(
        interaction.guild_id, self.vouched_user.id, interaction.user.id
    )

    created_at = utc_now_str()
    async with _db_lock, db_open(DB_FILE) as db:
        cursor = await db.execute(
            """
            INSERT INTO vouches (
                guild_id, vouched_user_id, voucher_user_id,
                trader_user_id, middleman_user_id,
                rating, traded_item, created_at, suspicious,
                vouch_type, verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                interaction.guild_id,
                self.vouched_user.id,
                interaction.user.id,
                self.trader.id,
                self.middleman.id if self.middleman else None,
                stars,
                self.traded_item.value,
                created_at,
                suspicious,
                self.vouch_type,
                0,
            ),
        )
        await db.commit()
        vouch_id = cursor.lastrowid

    embed = discord.Embed(
        title=f"{STAR} {self.vouch_type} Vouch",
        color=discord.Color.purple(),
    )
    embed.add_field(
        name="Rating",
        value=(STAR * stars) + (f" {WARN}" if suspicious else ""),
        inline=False,
    )
    embed.add_field(name="Trader", value=self.trader.mention, inline=False)
    embed.add_field(
        name="Middleman",
        value=self.middleman.mention if self.middleman else "None",
        inline=False,
    )
    embed.add_field(name="Item", value=self.traded_item.value, inline=False)
    embed.add_field(
        name="Vouch For", value=self.vouched_user.mention, inline=False
    )
    embed.add_field(
        name="Status", value="\u23F3 Pending verification", inline=False
    )
    embed.set_footer(
        text=f"Submitted by {interaction.user}  |  ID: {vouch_id}",
        icon_url=interaction.user.display_avatar.url,
    )

    await interaction.response.send_message(
        embed=embed,
        allowed_mentions=discord.AllowedMentions(users=True),
    )

    # DM the vouched user for verification
    try:
        dm_embed = discord.Embed(
            title=f"{STAR} You received a new vouch - please verify!",
            description=f"Server: **{interaction.guild.name}**",
            color=discord.Color.green(),
        )
        dm_embed.add_field(
            name="From", value=interaction.user.mention, inline=False
        )
        dm_embed.add_field(
            name="Type", value=self.vouch_type, inline=True
        )
        dm_embed.add_field(
            name="Rating", value=STAR * stars, inline=True
        )
        dm_embed.add_field(
            name="Trader", value=self.trader.mention, inline=False
        )
        dm_embed.add_field(
            name="Middleman",
            value=self.middleman.mention if self.middleman else "None",
            inline=False,
        )
        dm_embed.add_field(
            name="Item", value=self.traded_item.value, inline=False
        )
        if suspicious:
            dm_embed.add_field(
                name="Notice",
                value=f"{WARN} This vouch was auto-flagged as suspicious.",
                inline=False,
            )
        dm_embed.set_footer(
            text="Press Confirm to verify, or Deny to remove this vouch."
        )

        await self.vouched_user.send(
            embed=dm_embed,
            view=VerifyVouchView(
                vouch_id=vouch_id,
                vouched_user_id=self.vouched_user.id,
            ),
            allowed_mentions=discord.AllowedMentions(users=True),
        )
    except Exception:
        pass  # DMs may be disabled

    await apply_trust_gate(interaction.guild, self.vouched_user)
```

# SETUP WIZARD

class SetupWizardState:
def **init**(self):
self.owner_id = None
self.status_channel_id = None
self.trusted_role_id = None
self.restricted_role_id = None
self.protected_role_ids = []
self.trusted_min_vouches = None
self.trusted_min_avg = None
self.restricted_min_vouches = None
self.restricted_max_avg = None

def _wizard_admin_only(interaction: discord.Interaction) -> bool:
return (
interaction.guild is not None
and interaction.user.guild_permissions.administrator
)

async def _wizard_embed(
guild: discord.Guild, state: SetupWizardState
) -> discord.Embed:
embed = discord.Embed(
title=“Voucher Bot Setup Wizard”,
description=“Use the menus/buttons below to configure the bot.\nWhen finished, press **Save**.”,
color=discord.Color.blurple(),
)
embed.add_field(
name=“Owner ID”, value=f”`{state.owner_id or 0}`”, inline=False
)
embed.add_field(
name=“Status Channel”,
value=_fmt_chan_id(state.status_channel_id),
inline=False,
)
embed.add_field(
name=“Trusted Role”,
value=_fmt_role_id(state.trusted_role_id),
inline=True,
)
embed.add_field(
name=“Restricted Role”,
value=_fmt_role_id(state.restricted_role_id),
inline=True,
)

```
prot = (
    "\n".join([f"<@&{rid}> (`{rid}`)" for rid in state.protected_role_ids])
    if state.protected_role_ids
    else "None"
)
embed.add_field(
    name="Protected Roles (Immunity)", value=prot[:1024], inline=False
)

tv = state.trusted_min_vouches
ta = state.trusted_min_avg
rv = state.restricted_min_vouches
ra = state.restricted_max_avg
embed.add_field(
    name="Thresholds",
    value=(
        f"Trusted: **{tv if tv is not None else '-'}** vouches, "
        f"avg **{ta if ta is not None else '-'}**+\n"
        f"Restricted: **{rv if rv is not None else '-'}** vouches, "
        f"avg **{ra if ra is not None else '-'}** or lower"
    ),
    inline=False,
)
embed.set_footer(text="Tip: You can re-run /setupwizard anytime.")
return embed
```

class ThresholdsModal(discord.ui.Modal, title=“Set Trust Thresholds”):
trusted_min_vouches = discord.ui.TextInput(
label=“Trusted min vouches”, placeholder=“25”, required=True, max_length=6
)
trusted_min_avg = discord.ui.TextInput(
label=“Trusted min avg (0-5)”, placeholder=“4.7”, required=True, max_length=6
)
restricted_min_vouches = discord.ui.TextInput(
label=“Restricted min vouches”, placeholder=“5”, required=True, max_length=6
)
restricted_max_avg = discord.ui.TextInput(
label=“Restricted max avg (0-5)”, placeholder=“2.5”, required=True, max_length=6
)

```
def __init__(self, view):
    super().__init__()
    self.view_ref = view

async def on_submit(self, interaction: discord.Interaction):
    try:
        tv = int(str(self.trusted_min_vouches.value).strip())
        ta = float(str(self.trusted_min_avg.value).strip())
        rv = int(str(self.restricted_min_vouches.value).strip())
        ra = float(str(self.restricted_max_avg.value).strip())
    except ValueError:
        return await interaction.response.send_message(
            f"{CROSS} Use numbers only.", ephemeral=True
        )

    if tv < 0 or rv < 0:
        return await interaction.response.send_message(
            f"{CROSS} Vouch counts can't be negative.", ephemeral=True
        )
    if not (0.0 <= ta <= 5.0) or not (0.0 <= ra <= 5.0):
        return await interaction.response.send_message(
            f"{CROSS} Averages must be between 0 and 5.", ephemeral=True
        )

    st = self.view_ref.state
    st.trusted_min_vouches = tv
    st.trusted_min_avg = ta
    st.restricted_min_vouches = rv
    st.restricted_max_avg = ra

    embed = await _wizard_embed(interaction.guild, st)
    await interaction.response.edit_message(embed=embed, view=self.view_ref)
```

class SetupWizardView(discord.ui.View):
def **init**(
self,
requester_id: int,
guild: discord.Guild,
state: SetupWizardState,
):
super().**init**(timeout=300)
self.requester_id = requester_id
self.guild = guild
self.state = state

```
    self.channel_select = discord.ui.ChannelSelect(
        placeholder="Pick Status Channel",
        min_values=0,
        max_values=1,
        channel_types=[discord.ChannelType.text],
    )
    self.channel_select.callback = self._on_channel_selected
    self.add_item(self.channel_select)

    self.trusted_role_select = discord.ui.RoleSelect(
        placeholder="Pick Trusted Role (optional)",
        min_values=0,
        max_values=1,
    )
    self.trusted_role_select.callback = self._on_trusted_selected
    self.add_item(self.trusted_role_select)

    self.restricted_role_select = discord.ui.RoleSelect(
        placeholder="Pick Restricted Role (optional)",
        min_values=0,
        max_values=1,
    )
    self.restricted_role_select.callback = self._on_restricted_selected
    self.add_item(self.restricted_role_select)

    self.protected_roles_select = discord.ui.RoleSelect(
        placeholder="Pick Protected Roles (staff immunity) - multi-select",
        min_values=0,
        max_values=10,
    )
    self.protected_roles_select.callback = self._on_protected_selected
    self.add_item(self.protected_roles_select)

async def interaction_check(self, interaction: discord.Interaction) -> bool:
    if interaction.user.id != self.requester_id:
        await interaction.response.send_message(
            f"{CROSS} Only the admin who started setup can use this.",
            ephemeral=True,
        )
        return False
    return True

async def _refresh(self, interaction: discord.Interaction):
    embed = await _wizard_embed(interaction.guild, self.state)
    await interaction.response.edit_message(embed=embed, view=self)

async def _on_channel_selected(self, interaction: discord.Interaction):
    self.state.status_channel_id = (
        self.channel_select.values[0].id
        if self.channel_select.values
        else 0
    )
    await self._refresh(interaction)

async def _on_trusted_selected(self, interaction: discord.Interaction):
    self.state.trusted_role_id = (
        self.trusted_role_select.values[0].id
        if self.trusted_role_select.values
        else 0
    )
    await self._refresh(interaction)

async def _on_restricted_selected(self, interaction: discord.Interaction):
    self.state.restricted_role_id = (
        self.restricted_role_select.values[0].id
        if self.restricted_role_select.values
        else 0
    )
    await self._refresh(interaction)

async def _on_protected_selected(self, interaction: discord.Interaction):
    self.state.protected_role_ids = (
        [r.id for r in self.protected_roles_select.values]
        if self.protected_roles_select.values
        else []
    )
    await self._refresh(interaction)

@discord.ui.button(label="Set Thresholds", style=discord.ButtonStyle.primary)
async def set_thresholds_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    await interaction.response.send_modal(ThresholdsModal(self))

@discord.ui.button(label="Use Me as Owner", style=discord.ButtonStyle.secondary)
async def set_owner_me_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    self.state.owner_id = interaction.user.id
    await self._refresh(interaction)

@discord.ui.button(label="Save", style=discord.ButtonStyle.success)
async def save_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    if interaction.guild is None:
        return await interaction.response.send_message(
            f"{CROSS} Server only.", ephemeral=True
        )

    gid = interaction.guild_id

    if self.state.owner_id is None:
        self.state.owner_id = (
            await cfg_get(gid, "OWNER_ID") or interaction.user.id
        )
    if self.state.status_channel_id is None:
        self.state.status_channel_id = (
            await cfg_get(gid, "STATUS_CHANNEL_ID") or 0
        )
    if self.state.trusted_role_id is None:
        self.state.trusted_role_id = (
            await cfg_get(gid, "TRUSTED_ROLE_ID") or 0
        )
    if self.state.restricted_role_id is None:
        self.state.restricted_role_id = (
            await cfg_get(gid, "RESTRICTED_ROLE_ID") or 0
        )
    if self.state.trusted_min_vouches is None:
        self.state.trusted_min_vouches = await cfg_get(
            gid, "TRUSTED_MIN_VOUCHES"
        )
    if self.state.trusted_min_avg is None:
        self.state.trusted_min_avg = await cfg_get(gid, "TRUSTED_MIN_AVG")
    if self.state.restricted_min_vouches is None:
        self.state.restricted_min_vouches = await cfg_get(
            gid, "RESTRICTED_MIN_VOUCHES"
        )
    if self.state.restricted_max_avg is None:
        self.state.restricted_max_avg = await cfg_get(
            gid, "RESTRICTED_MAX_AVG"
        )
    if not self.state.protected_role_ids:
        self.state.protected_role_ids = (
            await cfg_get(gid, "PROTECTED_ROLE_IDS") or []
        )

    await cfg_set(gid, "OWNER_ID", int(self.state.owner_id))
    await cfg_set(
        gid, "STATUS_CHANNEL_ID", int(self.state.status_channel_id or 0)
    )
    await cfg_set(
        gid, "TRUSTED_ROLE_ID", int(self.state.trusted_role_id or 0)
    )
    await cfg_set(
        gid, "RESTRICTED_ROLE_ID", int(self.state.restricted_role_id or 0)
    )
    await cfg_set(gid, "PROTECTED_ROLE_IDS", self.state.protected_role_ids)
    await cfg_set(
        gid,
        "TRUSTED_MIN_VOUCHES",
        int(self.state.trusted_min_vouches or 0),
    )
    await cfg_set(
        gid,
        "TRUSTED_MIN_AVG",
        float(self.state.trusted_min_avg or 0.0),
    )
    await cfg_set(
        gid,
        "RESTRICTED_MIN_VOUCHES",
        int(self.state.restricted_min_vouches or 0),
    )
    await cfg_set(
        gid,
        "RESTRICTED_MAX_AVG",
        float(self.state.restricted_max_avg or 0.0),
    )

    for child in self.children:
        if hasattr(child, "disabled"):
            child.disabled = True

    embed = await _wizard_embed(interaction.guild, self.state)
    embed.description = (
        f"{CHECK} Saved! Run `/setup` to view or `/setupwizard` to change again."
    )
    await interaction.response.edit_message(embed=embed, view=self)

@discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger)
async def cancel_btn(
    self, interaction: discord.Interaction, button: discord.ui.Button
):
    for child in self.children:
        if hasattr(child, "disabled"):
            child.disabled = True
    await interaction.response.edit_message(
        content=f"{WARN} Setup cancelled.", view=self
    )

async def on_timeout(self):
    for child in self.children:
        if hasattr(child, "disabled"):
            child.disabled = True
```

@bot.tree.command(
name=“setupwizard”, description=“Interactive setup wizard (Admin only).”
)
async def setupwizard(interaction: discord.Interaction):
if not _wizard_admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
gid = interaction.guild_id
st = SetupWizardState()
st.owner_id = await cfg_get(gid, "OWNER_ID") or interaction.user.id
st.status_channel_id = await cfg_get(gid, "STATUS_CHANNEL_ID") or 0
st.trusted_role_id = await cfg_get(gid, "TRUSTED_ROLE_ID") or 0
st.restricted_role_id = await cfg_get(gid, "RESTRICTED_ROLE_ID") or 0
st.protected_role_ids = await cfg_get(gid, "PROTECTED_ROLE_IDS") or []
st.trusted_min_vouches = await cfg_get(gid, "TRUSTED_MIN_VOUCHES")
st.trusted_min_avg = await cfg_get(gid, "TRUSTED_MIN_AVG")
st.restricted_min_vouches = await cfg_get(gid, "RESTRICTED_MIN_VOUCHES")
st.restricted_max_avg = await cfg_get(gid, "RESTRICTED_MAX_AVG")

view = SetupWizardView(
    requester_id=interaction.user.id,
    guild=interaction.guild,
    state=st,
)
embed = await _wizard_embed(interaction.guild, st)
await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
```

# EVENTS

_sent_online = False

@bot.event
async def on_ready():
global _sent_online

```
await bot.change_presence(
    status=discord.Status.online,
    activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="Vouchers and Servers, .gg/QHS9q6mFfE join for Help!",
    ),
)

try:
    await init_db()
except Exception as e:
    log.error("DB init error: %s", e)

if not _sent_online:
    _sent_online = True
    for g in bot.guilds:
        try:
            status_id = await cfg_get(g.id, "STATUS_CHANNEL_ID")
            if not status_id:
                continue
            channel = bot.get_channel(int(status_id))
            if channel:
                await channel.send("**AMP VOUCHER BOT CURRENTLY ONLINE** " + CHECK)
        except Exception:
            pass

try:
    await bot.tree.sync()
except Exception as e:
    log.error("Slash sync error: %s", e)

log.info("Logged in as %s", bot.user)
```

@bot.tree.error
async def on_app_command_error(
interaction: discord.Interaction, error: app_commands.AppCommandError
):
log.exception(“App command error: %s”, error)
msg = f”{CROSS} Something went wrong running that command.”
try:
if interaction.response.is_done():
await interaction.followup.send(msg, ephemeral=True)
else:
await interaction.response.send_message(msg, ephemeral=True)
except Exception:
pass

@bot.event
async def on_error(event, *args, **kwargs):
log.exception(“Unhandled event error: %s”, event)

# SLASH COMMANDS - VOUCH ENTRY POINTS

@bot.tree.command(name=“vouch”, description=“Create a TRADE vouch (3-step wizard)”)
async def vouch(interaction: discord.Interaction):
await interaction.response.send_message(
“Step 1/3: Select the **Trader**.”,
view=TraderSelectStep(requester_id=interaction.user.id, vouch_type=“TRADE”),
ephemeral=True,
)

@bot.tree.command(
name=“vouchbuy”, description=“Create a BUY vouch (you bought from someone)”
)
async def vouchbuy(interaction: discord.Interaction):
await interaction.response.send_message(
“Step 1/3: Select the **Trader** (seller).”,
view=TraderSelectStep(requester_id=interaction.user.id, vouch_type=“BUY”),
ephemeral=True,
)

@bot.tree.command(
name=“vouchsell”, description=“Create a SELL vouch (you sold to someone)”
)
async def vouchsell(interaction: discord.Interaction):
await interaction.response.send_message(
“Step 1/3: Select the **Trader** (buyer).”,
view=TraderSelectStep(requester_id=interaction.user.id, vouch_type=“SELL”),
ephemeral=True,
)

@bot.tree.command(
name=“vouchtrade”, description=“Create a TRADE vouch (item-for-item swap)”
)
async def vouchtrade(interaction: discord.Interaction):
await interaction.response.send_message(
“Step 1/3: Select the **Trader**.”,
view=TraderSelectStep(requester_id=interaction.user.id, vouch_type=“TRADE”),
ephemeral=True,
)

# SLASH COMMANDS - LOOKUP

@bot.tree.command(name=“ping”, description=“Check bot latency”)
async def ping(interaction: discord.Interaction):
await interaction.response.send_message(
f”{PING_EMOJI} Pong! **{round(bot.latency * 1000)} ms**”, ephemeral=True
)

@bot.tree.command(name=“vouches”, description=“Pull up all saved vouches for a user”)
@app_commands.describe(user=“User to look up”)
async def vouches(interaction: discord.Interaction, user: discord.Member):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} This command can only be used in a server.”, ephemeral=True
)

```
rows, total = await fetch_vouches_page(interaction.guild_id, user.id, 0)

if total == 0:
    return await interaction.response.send_message(
        f"No vouches found for {user.mention}.", ephemeral=True
    )

view = VouchesPaginator(
    requester_id=interaction.user.id,
    guild_id=interaction.guild_id,
    target_member=user,
)
view.total = total
view._set_button_state()

embed = build_vouches_embed(user, rows, total, 0)
await interaction.response.send_message(
    embed=embed,
    view=view,
    ephemeral=True,
    allowed_mentions=discord.AllowedMentions(users=True),
)
```

@bot.tree.command(name=“trust”, description=“Show vouch trust stats for a user”)
@app_commands.describe(user=“User to check”)
async def trust(interaction: discord.Interaction, user: discord.Member):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)

```
stats = await get_user_trust_stats(interaction.guild_id, user.id)
total = stats["total"]
avg = stats["avg"]
suspicious = stats["suspicious"]
mm_count = stats["middleman_count"]
mm_avg = stats["middleman_avg"]

trusted_min_vouches = await cfg_get(interaction.guild_id, "TRUSTED_MIN_VOUCHES") or 25
trusted_min_avg_val = await cfg_get(interaction.guild_id, "TRUSTED_MIN_AVG") or 4.5

badges = []
if total >= int(trusted_min_vouches) and (avg or 0) >= float(trusted_min_avg_val):
    badges.append(f"{TROPHY} Trusted Trader")
if suspicious >= 3:
    badges.append(f"{WARN} Suspicious Activity")
if mm_count >= 10 and (mm_avg or 0) >= 4.5:
    badges.append(f"{CHECK} Reliable Middleman")

embed = discord.Embed(title=f"Trust Report: {user}", color=discord.Color.gold())
embed.add_field(name="Total vouches", value=str(total), inline=True)
embed.add_field(
    name="Average rating",
    value=(f"{avg:.2f}/5" if avg is not None else "N/A"),
    inline=True,
)
embed.add_field(name="Suspicious flags", value=str(suspicious), inline=True)
embed.add_field(name="MM vouches", value=str(mm_count), inline=True)
embed.add_field(
    name="MM avg",
    value=(f"{mm_avg:.2f}/5" if mm_avg is not None else "N/A"),
    inline=True,
)
embed.add_field(
    name="Badges",
    value=("\n".join(badges) if badges else "None"),
    inline=False,
)

await interaction.response.send_message(embed=embed, ephemeral=True)
```

@bot.tree.command(name=“stats”, description=“Show server-wide vouch stats”)
async def stats(interaction: discord.Interaction):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)

```
async with _db_lock, db_open(DB_FILE) as db:
    cur = await db.execute(
        "SELECT COUNT(*), AVG(rating), SUM(suspicious) FROM vouches WHERE guild_id=?",
        (interaction.guild_id,),
    )
    total, avg, suspicious_sum = await cur.fetchone()

    cur2 = await db.execute(
        """
        SELECT middleman_user_id, COUNT(*), AVG(rating)
        FROM vouches
        WHERE guild_id=? AND middleman_user_id IS NOT NULL
        GROUP BY middleman_user_id
        ORDER BY COUNT(*) DESC
        LIMIT 5
        """,
        (interaction.guild_id,),
    )
    top_middlemen = await cur2.fetchall()

embed = discord.Embed(title="Server Vouch Stats", color=discord.Color.teal())
embed.add_field(name="Total vouches", value=str(total or 0), inline=True)
embed.add_field(
    name="Average rating",
    value=(f"{avg:.2f}/5" if avg is not None else "N/A"),
    inline=True,
)
embed.add_field(
    name="Suspicious flags", value=str(suspicious_sum or 0), inline=True
)

if top_middlemen:
    lines = [
        f"<@{mm_id}> - **{cnt}** vouches - avg **{(mm_avg or 0):.2f}/5**"
        for mm_id, cnt, mm_avg in top_middlemen
    ]
    embed.add_field(name="Top Middlemen", value="\n".join(lines), inline=False)
else:
    embed.add_field(
        name="Top Middlemen", value="No middleman data yet.", inline=False
    )

await interaction.response.send_message(embed=embed, ephemeral=True)
```

@bot.tree.command(
name=“leaderboard”,
description=“Top traders by vouch count (and avg rating)”,
)
async def leaderboard(interaction: discord.Interaction):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)

```
async with _db_lock, db_open(DB_FILE) as db:
    cur = await db.execute(
        """
        SELECT vouched_user_id, COUNT(*) AS c, AVG(rating) AS a
        FROM vouches
        WHERE guild_id=?
        GROUP BY vouched_user_id
        ORDER BY c DESC, a DESC
        LIMIT 10
        """,
        (interaction.guild_id,),
    )
    rows = await cur.fetchall()

if not rows:
    return await interaction.response.send_message(
        "No vouches yet.", ephemeral=True
    )

embed = discord.Embed(
    title=f"{TROPHY} Vouch Leaderboard", color=discord.Color.gold()
)
lines = [
    f"**#{idx}** <@{uid}> - **{count}** vouches - avg **{(avg or 0):.2f}/5**"
    for idx, (uid, count, avg) in enumerate(rows, start=1)
]
embed.description = "\n".join(lines)
await interaction.response.send_message(
    embed=embed,
    ephemeral=True,
    allowed_mentions=discord.AllowedMentions(users=True),
)
```

# ADMIN COMMANDS

@bot.tree.command(
name=“exportvouches”,
description=“Export vouches for a user as CSV (Admin only)”,
)
@app_commands.describe(user=“User to export vouches for”)
async def exportvouches(interaction: discord.Interaction, user: discord.Member):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)
if not interaction.user.guild_permissions.administrator:
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
async with _db_lock, db_open(DB_FILE) as db:
    cur = await db.execute(
        """
        SELECT id, voucher_user_id, trader_user_id, middleman_user_id,
               rating, traded_item, created_at, suspicious, vouch_type, verified
        FROM vouches
        WHERE guild_id=? AND vouched_user_id=?
        ORDER BY id DESC
        """,
        (interaction.guild_id, user.id),
    )
    rows = await cur.fetchall()

if not rows:
    return await interaction.response.send_message(
        f"No vouches found for {user.mention}.", ephemeral=True
    )

header = "id,vouched_user_id,voucher_user_id,trader_user_id,middleman_user_id,rating,traded_item,created_at,suspicious,vouch_type,verified"
csv_lines = [header]
for r in rows:
    vid, voucher_id, trader_id, mm_id, rating, item, created_at, suspicious = r[:8]
    vtype = r[8] if len(r) > 8 else "TRADE"
    verified = r[9] if len(r) > 9 else 0
    item_safe = str(item).replace('"', '""')
    csv_lines.append(
        f'{vid},{user.id},{voucher_id},{trader_id},{mm_id or ""},{rating},'
        f'"{item_safe}","{created_at}",{suspicious},{vtype},{verified}'
    )

data = "\n".join(csv_lines).encode("utf-8")
file = discord.File(fp=BytesIO(data), filename=f"vouches_{user.id}.csv")

await interaction.response.send_message(
    content=f"{CHECK} Export for {user.mention}:", file=file, ephemeral=True
)
```

@bot.tree.command(
name=“maxmute”,
description=“Timeout a user for the maximum duration (Admin only).”,
)
@app_commands.describe(user=“User to max mute”, reason=“Reason for max mute”)
async def maxmute(
interaction: discord.Interaction,
user: discord.Member,
reason: str = “No reason provided”,
):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)
if not interaction.user.guild_permissions.administrator:
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
protected_ids = await cfg_get(interaction.guild_id, "PROTECTED_ROLE_IDS") or []
if any(role.id in protected_ids for role in user.roles):
    return await interaction.response.send_message(
        f"{CROSS} That user is protected (staff immunity).", ephemeral=True
    )

me = interaction.guild.me
if me is None or not me.guild_permissions.moderate_members:
    return await interaction.response.send_message(
        f"{CROSS} I need the **Moderate Members** permission to timeout users.",
        ephemeral=True,
    )

if user.id == interaction.user.id:
    return await interaction.response.send_message(
        f"{CROSS} You can't maxmute yourself.", ephemeral=True
    )
if user.guild_permissions.administrator:
    return await interaction.response.send_message(
        f"{CROSS} I won't maxmute an Administrator.", ephemeral=True
    )
if me and user.top_role >= me.top_role:
    return await interaction.response.send_message(
        f"{CROSS} I can't maxmute that user (role hierarchy).", ephemeral=True
    )

try:
    await user.timeout(
        timedelta(days=28),
        reason=f"{reason} | Muted by {interaction.user} ({interaction.user.id})",
    )
except discord.Forbidden:
    return await interaction.response.send_message(
        f"{CROSS} I don't have permission to timeout that user.", ephemeral=True
    )
except Exception as e:
    return await interaction.response.send_message(
        f"{CROSS} Failed to maxmute: `{e}`", ephemeral=True
    )

embed = discord.Embed(
    title=f"{LOCK} Max Muted",
    description=f"{user.mention} has been timed out for **28 days**.",
    color=discord.Color.orange(),
)
embed.add_field(name="Reason", value=reason, inline=False)
embed.set_footer(text=f"Action by {interaction.user}")
await interaction.response.send_message(
    embed=embed, allowed_mentions=discord.AllowedMentions(users=True)
)
```

@bot.tree.command(
name=“unmute”, description=“Remove a timeout from a user (Admin only).”
)
@app_commands.describe(user=“User to unmute”, reason=“Reason for unmute”)
async def unmute(
interaction: discord.Interaction,
user: discord.Member,
reason: str = “No reason provided”,
):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)
if not interaction.user.guild_permissions.administrator:
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
me = interaction.guild.me
if me is None or not me.guild_permissions.moderate_members:
    return await interaction.response.send_message(
        f"{CROSS} I need the **Moderate Members** permission to unmute users.",
        ephemeral=True,
    )

if user.communication_disabled_until is None:
    return await interaction.response.send_message(
        f"{CROSS} {user.mention} is not muted.", ephemeral=True
    )
if me and user.top_role >= me.top_role:
    return await interaction.response.send_message(
        f"{CROSS} I can't unmute that user (role hierarchy).", ephemeral=True
    )

try:
    await user.timeout(
        None,
        reason=f"{reason} | Unmuted by {interaction.user} ({interaction.user.id})",
    )
except discord.Forbidden:
    return await interaction.response.send_message(
        f"{CROSS} I don't have permission to unmute that user.", ephemeral=True
    )
except Exception as e:
    return await interaction.response.send_message(
        f"{CROSS} Failed to unmute: `{e}`", ephemeral=True
    )

embed = discord.Embed(
    title=f"{CHECK} User Unmuted",
    description=f"{user.mention} has been unmuted.",
    color=discord.Color.green(),
)
embed.add_field(name="Reason", value=reason, inline=False)
embed.set_footer(text=f"Action by {interaction.user}")
await interaction.response.send_message(
    embed=embed, allowed_mentions=discord.AllowedMentions(users=True)
)
```

@bot.tree.command(
name=“softlock”,
description=“Soft-lock the current channel (block @everyone from sending). Admin only.”,
)
async def softlock(interaction: discord.Interaction):
if interaction.guild is None or not isinstance(
interaction.channel, discord.TextChannel
):
return await interaction.response.send_message(
f”{CROSS} Use this in a server text channel.”, ephemeral=True
)
if not interaction.user.guild_permissions.administrator:
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
channel = interaction.channel
everyone = interaction.guild.default_role
prev = channel.overwrites_for(everyone)
_softlock_previous[channel.id] = prev

new_ow = discord.PermissionOverwrite.from_pair(
    channel.permissions_for(everyone), discord.Permissions.none()
)
new_ow.send_messages = False
new_ow.add_reactions = False
new_ow.create_public_threads = False
new_ow.create_private_threads = False

try:
    await channel.set_permissions(everyone, overwrite=new_ow, reason="Softlock")
except discord.Forbidden:
    return await interaction.response.send_message(
        f"{CROSS} I need permission to manage channel overwrites.", ephemeral=True
    )

await interaction.response.send_message(f"{LOCK} Soft-locked {channel.mention}.")
```

@bot.tree.command(
name=“softunlock”,
description=“Remove soft-lock and restore previous @everyone permissions. Admin only.”,
)
async def softunlock(interaction: discord.Interaction):
if interaction.guild is None or not isinstance(
interaction.channel, discord.TextChannel
):
return await interaction.response.send_message(
f”{CROSS} Use this in a server text channel.”, ephemeral=True
)
if not interaction.user.guild_permissions.administrator:
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
channel = interaction.channel
everyone = interaction.guild.default_role
prev = _softlock_previous.get(channel.id)

if prev is None:
    return await interaction.response.send_message(
        f"{CROSS} No saved softlock state for this channel.", ephemeral=True
    )

try:
    await channel.set_permissions(everyone, overwrite=prev, reason="Softunlock")
except discord.Forbidden:
    return await interaction.response.send_message(
        f"{CROSS} I need permission to manage channel overwrites.", ephemeral=True
    )

_softlock_previous.pop(channel.id, None)
await interaction.response.send_message(
    f"{CHECK} Soft-unlocked {channel.mention}."
)
```

# CONFIG COMMANDS

def _admin_only(interaction: discord.Interaction) -> bool:
return (
interaction.guild is not None
and interaction.user.guild_permissions.administrator
)

@bot.tree.command(
name=“setup”, description=“Show current setup/config values for this server.”
)
async def setup(interaction: discord.Interaction):
if interaction.guild is None:
return await interaction.response.send_message(
f”{CROSS} Server only.”, ephemeral=True
)
if not interaction.user.guild_permissions.administrator:
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)

```
gid = interaction.guild_id

owner_id = await cfg_get(gid, "OWNER_ID")
status_channel_id = await cfg_get(gid, "STATUS_CHANNEL_ID")
trusted_role_id = await cfg_get(gid, "TRUSTED_ROLE_ID")
restricted_role_id = await cfg_get(gid, "RESTRICTED_ROLE_ID")
protected_ids = await cfg_get(gid, "PROTECTED_ROLE_IDS") or []
trusted_min_v = await cfg_get(gid, "TRUSTED_MIN_VOUCHES")
trusted_min_avg = await cfg_get(gid, "TRUSTED_MIN_AVG")
restricted_min_v = await cfg_get(gid, "RESTRICTED_MIN_VOUCHES")
restricted_max_avg = await cfg_get(gid, "RESTRICTED_MAX_AVG")

protected_lines = (
    [f"<@&{rid}> (`{rid}`)" for rid in protected_ids]
    if protected_ids
    else ["None"]
)

embed = discord.Embed(
    title="Voucher Bot Setup",
    description="Use `/config` to change these values.",
    color=discord.Color.blurple(),
)
embed.add_field(name="Owner ID", value=f"`{owner_id}`", inline=False)
embed.add_field(
    name="Status Channel",
    value=_fmt_channel(int(status_channel_id) if status_channel_id else 0),
    inline=False,
)
embed.add_field(
    name="Trusted Role",
    value=_fmt_role(int(trusted_role_id) if trusted_role_id else 0),
    inline=False,
)
embed.add_field(
    name="Restricted Role",
    value=_fmt_role(int(restricted_role_id) if restricted_role_id else 0),
    inline=False,
)
embed.add_field(
    name="Protected Roles",
    value="\n".join(protected_lines)[:1024],
    inline=False,
)
embed.add_field(
    name="Thresholds",
    value=(
        f"Trusted: **{trusted_min_v}** vouches, avg **{trusted_min_avg}**+\n"
        f"Restricted: **{restricted_min_v}** vouches, avg **{restricted_max_avg}** or lower"
    ),
    inline=False,
)
await interaction.response.send_message(embed=embed, ephemeral=True)
```

config_group = app_commands.Group(
name=“config”, description=“Change Voucher Bot settings (Admin only).”
)
bot.tree.add_command(config_group)

@config_group.command(name=“show”, description=“Show current config (same as /setup).”)
async def config_show(interaction: discord.Interaction):
await setup(interaction)

@config_group.command(
name=“reset_defaults”, description=“Reset this server back to file defaults.”
)
async def reset_defaults(interaction: discord.Interaction):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
async with _db_lock, db_open(DB_FILE) as db:
await db.execute(
“DELETE FROM guild_config WHERE guild_id=?”, (interaction.guild_id,)
)
await db.commit()
await interaction.response.send_message(
f”{CHECK} Reset complete. Run `/setup` to confirm.”, ephemeral=True
)

@config_group.command(
name=“set_owner”,
description=“Set the owner ID used for /shutdown authorization.”,
)
@app_commands.describe(owner_id=“Numeric Discord user ID”)
async def set_owner(interaction: discord.Interaction, owner_id: str):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
try:
oid = int(owner_id)
except ValueError:
return await interaction.response.send_message(
f”{CROSS} Must be a number.”, ephemeral=True
)
await cfg_set(interaction.guild_id, “OWNER_ID”, oid)
await interaction.response.send_message(
f”{CHECK} Owner ID set to `{oid}`.”, ephemeral=True
)

@config_group.command(
name=“set_status_channel”,
description=“Set the status channel for online/offline notices.”,
)
@app_commands.describe(channel=“Pick a channel”)
async def set_status_channel(
interaction: discord.Interaction, channel: discord.TextChannel
):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
await cfg_set(interaction.guild_id, “STATUS_CHANNEL_ID”, channel.id)
await interaction.response.send_message(
f”{CHECK} Status channel set to {channel.mention}.”, ephemeral=True
)

@config_group.command(name=“set_trusted_role”, description=“Set the Trusted role.”)
@app_commands.describe(role=“Pick a role”)
async def set_trusted_role(interaction: discord.Interaction, role: discord.Role):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
await cfg_set(interaction.guild_id, “TRUSTED_ROLE_ID”, role.id)
await interaction.response.send_message(
f”{CHECK} Trusted role set to {role.mention}.”, ephemeral=True
)

@config_group.command(
name=“disable_trusted_role”,
description=“Disable Trusted auto-role assignment.”,
)
async def disable_trusted_role(interaction: discord.Interaction):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
await cfg_set(interaction.guild_id, “TRUSTED_ROLE_ID”, 0)
await interaction.response.send_message(
f”{CHECK} Trusted role disabled.”, ephemeral=True
)

@config_group.command(
name=“set_restricted_role”, description=“Set the Restricted role.”
)
@app_commands.describe(role=“Pick a role”)
async def set_restricted_role(interaction: discord.Interaction, role: discord.Role):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
await cfg_set(interaction.guild_id, “RESTRICTED_ROLE_ID”, role.id)
await interaction.response.send_message(
f”{CHECK} Restricted role set to {role.mention}.”, ephemeral=True
)

@config_group.command(
name=“disable_restricted_role”,
description=“Disable Restricted auto-role assignment.”,
)
async def disable_restricted_role(interaction: discord.Interaction):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
await cfg_set(interaction.guild_id, “RESTRICTED_ROLE_ID”, 0)
await interaction.response.send_message(
f”{CHECK} Restricted role disabled.”, ephemeral=True
)

@config_group.command(
name=“add_protected_role”,
description=“Add a role to staff immunity (protected).”,
)
@app_commands.describe(role=“Role to protect”)
async def add_protected_role(interaction: discord.Interaction, role: discord.Role):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
ids = await cfg_get(interaction.guild_id, “PROTECTED_ROLE_IDS”) or []
if role.id not in ids:
ids.append(role.id)
await cfg_set(interaction.guild_id, “PROTECTED_ROLE_IDS”, ids)
await interaction.response.send_message(
f”{CHECK} Added protected role: {role.mention}”, ephemeral=True
)

@config_group.command(
name=“remove_protected_role”,
description=“Remove a role from staff immunity.”,
)
@app_commands.describe(role=“Role to unprotect”)
async def remove_protected_role(interaction: discord.Interaction, role: discord.Role):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
ids = await cfg_get(interaction.guild_id, “PROTECTED_ROLE_IDS”) or []
if role.id in ids:
ids.remove(role.id)
await cfg_set(interaction.guild_id, “PROTECTED_ROLE_IDS”, ids)
await interaction.response.send_message(
f”{CHECK} Removed protected role: {role.mention}”, ephemeral=True
)

@config_group.command(
name=“set_thresholds”, description=“Set trust gate thresholds.”
)
@app_commands.describe(
trusted_min_vouches=“Trusted min vouches”,
trusted_min_avg=“Trusted min average rating”,
restricted_min_vouches=“Restricted min vouches”,
restricted_max_avg=“Restricted max average rating (triggers restricted if at or below)”,
)
async def set_thresholds(
interaction: discord.Interaction,
trusted_min_vouches: int,
trusted_min_avg: float,
restricted_min_vouches: int,
restricted_max_avg: float,
):
if not _admin_only(interaction):
return await interaction.response.send_message(
f”{CROSS} Admin only.”, ephemeral=True
)
if trusted_min_vouches < 0 or restricted_min_vouches < 0:
return await interaction.response.send_message(
f”{CROSS} Vouch counts can’t be negative.”, ephemeral=True
)
if not (0.0 <= trusted_min_avg <= 5.0) or not (0.0 <= restricted_max_avg <= 5.0):
return await interaction.response.send_message(
f”{CROSS} Averages must be between 0 and 5.”, ephemeral=True
)

```
gid = interaction.guild_id
await cfg_set(gid, "TRUSTED_MIN_VOUCHES", trusted_min_vouches)
await cfg_set(gid, "TRUSTED_MIN_AVG", trusted_min_avg)
await cfg_set(gid, "RESTRICTED_MIN_VOUCHES", restricted_min_vouches)
await cfg_set(gid, "RESTRICTED_MAX_AVG", restricted_max_avg)
await interaction.response.send_message(
    f"{CHECK} Thresholds updated. Run `/setup` to view.", ephemeral=True
)
```

# SHUTDOWN

@bot.tree.command(name=“shutdown”, description=“Shut down the bot (owner only)”)
@app_commands.describe(code=“Google Authenticator TOTP code”)
async def shutdown(interaction: discord.Interaction, code: str):
owner_id = (
await cfg_get(interaction.guild_id, “OWNER_ID”)
if interaction.guild_id
else OWNER_ID
)
if interaction.user.id != int(owner_id or OWNER_ID):
return await interaction.response.send_message(
f”{CROSS} You are not authorized.”, ephemeral=True
)

```
if not TOTP_SECRET:
    return await interaction.response.send_message(
        f"{CROSS} TOTP_SECRET is not configured on this bot.", ephemeral=True
    )

totp = pyotp.TOTP(TOTP_SECRET)
if not totp.verify(code):
    return await interaction.response.send_message(
        f"{CROSS} Invalid Google Authenticator code.", ephemeral=True
    )

await interaction.response.send_message(f"{LOCK} Verified. Shutting down...")

for g in bot.guilds:
    try:
        status_id = await cfg_get(g.id, "STATUS_CHANNEL_ID")
        if not status_id:
            continue
        ch = bot.get_channel(int(status_id))
        if ch:
            await ch.send(
                "**AMP VOUCHER BOT CURRENTLY OFFLINE AND UNDER MAINTENANCE**"
            )
    except Exception:
        pass

log.info("Shutdown requested by %s", interaction.user)
await bot.close()
sys.exit(0)
```

# SIGNAL HANDLERS

def _install_signal_handlers():
try:
loop = asyncio.get_event_loop()
except RuntimeError:
return

```
async def _graceful_close():
    log.info("Graceful shutdown requested via signal")
    for g in bot.guilds:
        try:
            status_id = await cfg_get(g.id, "STATUS_CHANNEL_ID")
            if not status_id:
                continue
            channel = bot.get_channel(int(status_id))
            if channel:
                await channel.send(
                    "**AMP VOUCHER BOT CURRENTLY OFFLINE (Host restart/stop)**"
                )
        except Exception:
            pass
    try:
        await bot.close()
    except Exception:
        pass

def _handler():
    asyncio.create_task(_graceful_close())

for sig in (signal.SIGINT, signal.SIGTERM):
    try:
        loop.add_signal_handler(sig, _handler)
    except NotImplementedError:
        pass  # Windows
```

_install_signal_handlers()

# ENTRY POINT

bot.run(TOKEN)