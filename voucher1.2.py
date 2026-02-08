# -*- coding: utf-8 -*-

import logging
import signal
import os
import discord
import pyotp
import sys
import aiosqlite
from io import BytesIO
from datetime import datetime, timedelta, timezone
from discord import app_commands
from discord.ext import commands

from dotenv import load_dotenv

# Load .env if present (optional). On Oracle you can still use ~/.bashrc env vars.
load_dotenv()

# Read secrets from environment variables
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
TOTP_SECRET = os.getenv("TOTP_SECRET", "").strip()

if not TOKEN:
    raise RuntimeError(
        "DISCORD_TOKEN is not set. Set it in ~/.bashrc (export DISCORD_TOKEN=...) "
        "or create a .env file with DISCORD_TOKEN=..."
    )

if not TOTP_SECRET:
    print("WARNING: TOTP_SECRET is not set. /shutdown will not work until you set it.")
    
# ---------- INTENTS ----------
intents = discord.Intents.default()
intents.members = True  # needed for joined_at + role actions reliability
bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- CONFIG ----------
OWNER_ID = 906781117632368730
STATUS_CHANNEL_ID = 1461148246863773698

DB_FILE = vouches.db

# ---------- LOGGING ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("voucher")

# ---------- SQLITE HARDENING (NO LOGIC CHANGES) ----------
_db_lock = asyncio.Lock()

async def db_connect(path: str):
    """
    Returns an aiosqlite connection with production-safe pragmas.
    Keeps same schema/queries/behavior—just makes SQLite more reliable under load.
    """
    db = await aiosqlite.connect(path)
    # WAL helps concurrency; busy_timeout reduces "database is locked"
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA synchronous=NORMAL;")
    await db.execute("PRAGMA busy_timeout=5000;")
    await db.execute("PRAGMA foreign_keys=ON;")
    return db

PAGE_SIZE = 5  # vouches per page

# Account age / join age requirements for submitting a vouch
MIN_ACCOUNT_AGE_DAYS = 7
MIN_SERVER_JOIN_HOURS = 6

# Protected roles (staff immunity). Put role IDs here.
PROTECTED_ROLE_IDS = [
    1460784670487871589, 1460060689325490216, 1460056861750595654, 1460054414294253730
    # 123456789012345678,
]

# Trust Gate role IDs (optional, but recommended)
TRUSTED_ROLE_ID = 1461128340466307313      # set to your "Trusted" role ID (0 disables)
RESTRICTED_ROLE_ID = 1466232113945640960   # set to your "Restricted" role ID (0 disables)

# Trust gate thresholds
TRUSTED_MIN_VOUCHES = 25
TRUSTED_MIN_AVG = 4.7
RESTRICTED_MIN_VOUCHES = 5
RESTRICTED_MAX_AVG = 2.5

# ---------- SAFE EMOJI CONSTANTS ----------
STAR = "\u2B50"          # ⭐
CROSS = "\u274C"         # ❌
CHECK = "\u2705"         # ✅
LOCK = "\U0001F510"      # 🔐
WARN = "\u26A0"          # ⚠️
TROPHY = "\U0001F3C6"    # 🏆

# ---------- SOFTLOCK STATE ----------
_softlock_previous = {}  # channel_id -> previous overwrite for @everyone


# ---------- DB ----------
async def init_db():
    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vouches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                vouched_user_id INTEGER NOT NULL,
                voucher_user_id INTEGER NOT NULL,
                trader_user_id INTEGER NOT NULL,
                middleman_user_id INTEGER,
                rating INTEGER NOT NULL,
                traded_item TEXT NOT NULL,
                created_at TEXT NOT NULL,
                suspicious INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.commit()


def utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


async def fetch_vouches_page(guild_id: int, vouched_user_id: int, page: int):
    """Returns (rows, total_count). page is 0-based."""
    offset = page * PAGE_SIZE
    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        cur_total = await db.execute("""
            SELECT COUNT(*)
            FROM vouches
            WHERE guild_id = ? AND vouched_user_id = ?
        """, (guild_id, vouched_user_id))
        total = (await cur_total.fetchone())[0]

        cur = await db.execute("""
            SELECT id, voucher_user_id, trader_user_id, middleman_user_id, rating, traded_item, created_at, suspicious
            FROM vouches
            WHERE guild_id = ? AND vouched_user_id = ?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (guild_id, vouched_user_id, PAGE_SIZE, offset))
        rows = await cur.fetchall()

    return rows, total


async def get_user_trust_stats(guild_id: int, user_id: int):
    """Returns dict of trust stats for a vouched user."""
    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        cur = await db.execute("""
            SELECT COUNT(*), AVG(rating), SUM(suspicious)
            FROM vouches
            WHERE guild_id = ? AND vouched_user_id = ?
        """, (guild_id, user_id))
        total, avg, suspicious_sum = await cur.fetchone()

        cur2 = await db.execute("""
            SELECT COUNT(*), AVG(rating)
            FROM vouches
            WHERE guild_id = ? AND vouched_user_id = ? AND middleman_user_id IS NOT NULL
        """, (guild_id, user_id))
        mm_count, mm_avg = await cur2.fetchone()

    return {
        "total": int(total or 0),
        "avg": float(avg) if avg is not None else None,
        "suspicious": int(suspicious_sum or 0),
        "middleman_count": int(mm_count or 0),
        "middleman_avg": float(mm_avg) if mm_avg is not None else None,
    }


async def detect_suspicious_vouch(guild_id: int, vouched_user_id: int, voucher_user_id: int) -> int:
    """
    Simple-but-effective suspicious detection:
    - Same voucher vouching same target multiple times recently
    - Mutual vouching loop recently
    Returns 1 if suspicious else 0.
    """
    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        # same voucher -> same target within last 7 days
        cur = await db.execute("""
            SELECT COUNT(*)
            FROM vouches
            WHERE guild_id = ? AND vouched_user_id = ? AND voucher_user_id = ?
              AND datetime(replace(created_at,' UTC','')) >= datetime('now','-7 days')
        """, (guild_id, vouched_user_id, voucher_user_id))
        recent_same = (await cur.fetchone())[0] or 0

        # mutual loop in last 14 days: A vouched B and B vouched A
        cur2 = await db.execute("""
            SELECT COUNT(*)
            FROM vouches
            WHERE guild_id = ?
              AND vouched_user_id = ?
              AND voucher_user_id = ?
              AND datetime(replace(created_at,' UTC','')) >= datetime('now','-14 days')
        """, (guild_id, voucher_user_id, vouched_user_id))
        mutual = (await cur2.fetchone())[0] or 0

    if recent_same >= 1:
        return 1
    if mutual >= 1:
        return 1
    return 0


async def apply_trust_gate(guild: discord.Guild, member: discord.Member):
    """Auto-assign Trusted/Restricted roles based on vouch stats. Safe + permission-checked."""
    if guild is None:
        return

    if TRUSTED_ROLE_ID == 0 and RESTRICTED_ROLE_ID == 0:
        return

    me = guild.me
    if me is None or not me.guild_permissions.manage_roles:
        return

    # role objects
    trusted_role = guild.get_role(TRUSTED_ROLE_ID) if TRUSTED_ROLE_ID else None
    restricted_role = guild.get_role(RESTRICTED_ROLE_ID) if RESTRICTED_ROLE_ID else None

    # bot role hierarchy safety
    def can_manage(role: discord.Role | None) -> bool:
        return role is not None and me.top_role > role

    stats = await get_user_trust_stats(guild.id, member.id)
    total = stats["total"]
    avg = stats["avg"]

    if avg is None:
        return

    should_trust = (total >= TRUSTED_MIN_VOUCHES and avg >= TRUSTED_MIN_AVG)
    should_restrict = (total >= RESTRICTED_MIN_VOUCHES and avg <= RESTRICTED_MAX_AVG)

    try:
        if restricted_role and can_manage(restricted_role):
            if should_restrict and restricted_role not in member.roles:
                await member.add_roles(restricted_role, reason="Trust gate: restricted (low avg rating)")
            if (not should_restrict) and restricted_role in member.roles:
                await member.remove_roles(restricted_role, reason="Trust gate: remove restricted (no longer meets criteria)")

        if trusted_role and can_manage(trusted_role):
            if should_trust and trusted_role not in member.roles:
                await member.add_roles(trusted_role, reason="Trust gate: trusted (high avg rating)")
            if (not should_trust) and trusted_role in member.roles:
                await member.remove_roles(trusted_role, reason="Trust gate: remove trusted (no longer meets criteria)")
    except discord.Forbidden:
        pass
    except Exception:
        pass


def build_vouches_embed(user: discord.Member, rows, total: int, page: int) -> discord.Embed:
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    embed = discord.Embed(
        title=f"Vouches for {user}",
        description=f"Total vouches: **{total}**",
        color=discord.Color.blurple()
    )
    embed.set_footer(text=f"Page {page + 1}/{total_pages} • Showing {PAGE_SIZE} per page")

    if not rows:
        embed.add_field(name="No vouches", value="No results on this page.", inline=False)
        return embed

    start_index = page * PAGE_SIZE
    for i, (vid, voucher_id, trader_id, middleman_id, rating, traded_item, created_at, suspicious) in enumerate(rows, start=1):
        voucher_mention = f"<@{voucher_id}>"
        trader_mention = f"<@{trader_id}>"
        middleman_mention = f"<@{middleman_id}>" if middleman_id else "None"
        stars = STAR * int(rating)
        flag = f" {WARN}" if suspicious else ""

        value = (
            f"**From:** {voucher_mention}\n"
            f"**Trader:** {trader_mention}\n"
            f"**Middleman:** {middleman_mention}\n"
            f"**Rating:** {stars}{flag}\n"
            f"**Item:** {traded_item}\n"
            f"**Date:** {created_at}\n"
            f"**ID:** `{vid}`"
        )
        embed.add_field(name=f"Vouch #{start_index + i}", value=value[:1024], inline=False)

    return embed


class VouchesPaginator(discord.ui.View):
    def __init__(self, *, requester_id: int, guild_id: int, target_member: discord.Member):
        super().__init__(timeout=180)
        self.requester_id = requester_id
        self.guild_id = guild_id
        self.target_member = target_member
        self.page = 0
        self.total = 0

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message(
                f"{CROSS} Only the person who ran this command can use these buttons.",
                ephemeral=True
            )
            return False
        return True

    def _set_button_state(self):
        total_pages = max(1, (self.total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.prev_btn.disabled = (self.page <= 0)
        self.next_btn.disabled = (self.page >= total_pages - 1)

    async def refresh(self, interaction: discord.Interaction):
        rows, total = await fetch_vouches_page(self.guild_id, self.target_member.id, self.page)
        self.total = total
        self._set_button_state()
        embed = build_vouches_embed(self.target_member, rows, self.total, self.page)
        await interaction.response.edit_message(
            embed=embed,
            view=self,
            allowed_mentions=discord.AllowedMentions(users=True)
        )

    @discord.ui.button(label="Prev", style=discord.ButtonStyle.secondary)
    async def prev_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.page > 0:
            self.page -= 1
        await self.refresh(interaction)

    @discord.ui.button(label="Next", style=discord.ButtonStyle.primary)
    async def next_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        total_pages = max(1, (self.total + PAGE_SIZE - 1) // PAGE_SIZE)
        if self.page < total_pages - 1:
            self.page += 1
        await self.refresh(interaction)

    async def on_timeout(self):
        for child in self.children:
            if isinstance(child, discord.ui.Button):
                child.disabled = True


# ============================================================
# ✅ NEW 3-STEP VOUCH FLOW (Trader -> Middleman -> Vouch For)
# ============================================================

class StepBaseView(discord.ui.View):
    """Locks interactions to the person who started /vouch."""
    def __init__(self, requester_id: int):
        super().__init__(timeout=180)
        self.requester_id = requester_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message(
                f"{CROSS} Only the person who started this vouch can use these menus.",
                ephemeral=True
            )
            return False
        return True


class TraderSelectStep(StepBaseView):
    def __init__(self, requester_id: int):
        super().__init__(requester_id)

        self.trader_select = discord.ui.UserSelect(
            placeholder="Step 1/3: Select the Trader",
            min_values=1,
            max_values=1
        )
        self.trader_select.callback = self.on_trader_selected
        self.add_item(self.trader_select)

    async def on_trader_selected(self, interaction: discord.Interaction):
        trader = self.trader_select.values[0]

        await interaction.response.edit_message(
            content=(
                f"✅ **Trader selected:** {trader.mention}\n\n"
                f"Step 2/3: Select a **Middleman** (optional) or press **Skip**."
            ),
            view=MiddlemanSelectStep(requester_id=self.requester_id, trader=trader),
            allowed_mentions=discord.AllowedMentions(users=True)
        )


class MiddlemanSelectStep(StepBaseView):
    def __init__(self, requester_id: int, trader: discord.Member):
        super().__init__(requester_id)
        self.trader = trader

        self.middleman_select = discord.ui.UserSelect(
            placeholder="Step 2/3: Select Middleman (optional)",
            min_values=0,
            max_values=1
        )
        self.middleman_select.callback = self.on_middleman_selected
        self.add_item(self.middleman_select)

    async def on_middleman_selected(self, interaction: discord.Interaction):
        middleman = self.middleman_select.values[0] if self.middleman_select.values else None
        await self._go_next(interaction, middleman)

    @discord.ui.button(label="Skip", style=discord.ButtonStyle.secondary)
    async def skip_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._go_next(interaction, None)

    async def _go_next(self, interaction: discord.Interaction, middleman: discord.Member | None):
        mid_text = middleman.mention if middleman else "None"

        await interaction.response.edit_message(
            content=(
                f"✅ **Trader:** {self.trader.mention}\n"
                f"✅ **Middleman:** {mid_text}\n\n"
                f"Step 3/3: Select who you are **vouching for**."
            ),
            view=VouchForSelectStep(
                requester_id=self.requester_id,
                trader=self.trader,
                middleman=middleman
            ),
            allowed_mentions=discord.AllowedMentions(users=True)
        )


class VouchForSelectStep(StepBaseView):
    def __init__(self, requester_id: int, trader: discord.Member, middleman: discord.Member | None):
        super().__init__(requester_id)
        self.trader = trader
        self.middleman = middleman

        self.vouchfor_select = discord.ui.UserSelect(
            placeholder="Step 3/3: Select who this vouch is for",
            min_values=1,
            max_values=1
        )
        self.vouchfor_select.callback = self.on_vouchfor_selected
        self.add_item(self.vouchfor_select)

    async def on_vouchfor_selected(self, interaction: discord.Interaction):
        vouched_user = self.vouchfor_select.values[0]
        await interaction.response.send_modal(VouchModal(self.trader, self.middleman, vouched_user))


# ---------- MODAL ----------
class VouchModal(discord.ui.Modal):
    def __init__(self, trader: discord.Member, middleman: discord.Member | None, vouched_user: discord.Member):
        super().__init__(title="Vouch")
        self.trader = trader
        self.middleman = middleman
        self.vouched_user = vouched_user

    rating = discord.ui.TextInput(
        label="Rating (1-5)",
        placeholder="Example: 5",
        max_length=1,
        required=True
    )

    traded_item = discord.ui.TextInput(
        label="What did you trade to them?",
        placeholder="Describe the item(s)",
        required=True
    )

    async def on_submit(self, interaction: discord.Interaction):
        # Validate rating
        try:
            stars = int(self.rating.value)
            if not 1 <= stars <= 5:
                raise ValueError
        except ValueError:
            await interaction.response.send_message(
                f"{CROSS} Rating must be a number between **1 and 5**.",
                ephemeral=True
            )
            return

        if interaction.guild is None:
            await interaction.response.send_message(
                f"{CROSS} This command can only be used in a server.",
                ephemeral=True
            )
            return

        # Requirement #8: Account age / join age checks
        now_utc = datetime.now(timezone.utc)
        if interaction.user.created_at:
            acct_age_days = (now_utc - interaction.user.created_at).days
            if acct_age_days < MIN_ACCOUNT_AGE_DAYS:
                await interaction.response.send_message(
                    f"{CROSS} Your account must be at least **{MIN_ACCOUNT_AGE_DAYS} days** old to submit vouches.",
                    ephemeral=True
                )
                return

        if interaction.user.joined_at:
            join_hours = (now_utc - interaction.user.joined_at).total_seconds() / 3600.0
            if join_hours < MIN_SERVER_JOIN_HOURS:
                await interaction.response.send_message(
                    f"{CROSS} You must be in this server for at least **{MIN_SERVER_JOIN_HOURS} hours** to submit vouches.",
                    ephemeral=True
                )
                return

        vouched_user_id = self.vouched_user.id

        # Fake vouch detection (#2)
        suspicious = await detect_suspicious_vouch(interaction.guild_id, vouched_user_id, interaction.user.id)

        # Build embed
        embed = discord.Embed(
            title=f"{STAR} Trade Vouch",
            color=discord.Color.purple()
        )
        embed.add_field(name="Rating", value=(STAR * stars) + (f" {WARN}" if suspicious else ""), inline=False)
        embed.add_field(name="Who did you trade with", value=self.trader.mention, inline=False)
        embed.add_field(name="Middleman used", value=self.middleman.mention if self.middleman else "None", inline=False)
        embed.add_field(name="What did you trade to them", value=self.traded_item.value, inline=False)
        embed.add_field(name="Vouch for", value=self.vouched_user.mention, inline=False)

        embed.set_footer(
            text=f"Vouch submitted by {interaction.user}",
            icon_url=interaction.user.display_avatar.url
        )

        # Save to DB
        created_at = utc_now_str()
        async with _db_lock:     async with await db_connect(DB_FILE) as db:
            await db.execute("""
                INSERT INTO vouches (
                    guild_id, vouched_user_id, voucher_user_id,
                    trader_user_id, middleman_user_id,
                    rating, traded_item, created_at, suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                interaction.guild_id,
                vouched_user_id,
                interaction.user.id,
                self.trader.id,
                self.middleman.id if self.middleman else None,
                stars,
                self.traded_item.value,
                created_at,
                suspicious
            ))
            await db.commit()

        # #11 DM receipt to vouched user
        try:
            dm = discord.Embed(
                title=f"{STAR} You received a new vouch!",
                description=f"Server: **{interaction.guild.name}**",
                color=discord.Color.green()
            )
            dm.add_field(name="From", value=interaction.user.mention, inline=False)
            dm.add_field(name="Rating", value=STAR * stars, inline=False)
            dm.add_field(name="Trader", value=self.trader.mention, inline=False)
            dm.add_field(name="Middleman", value=self.middleman.mention if self.middleman else "None", inline=False)
            dm.add_field(name="Item", value=self.traded_item.value, inline=False)
            if suspicious:
                dm.add_field(name="Notice", value=f"{WARN} This vouch was auto-flagged as suspicious.", inline=False)
            await self.vouched_user.send(embed=dm, allowed_mentions=discord.AllowedMentions(users=True))
        except Exception:
            pass

        # #15 Trust gate role assignment
        await apply_trust_gate(interaction.guild, self.vouched_user)

        await interaction.response.send_message(
            embed=embed,
            allowed_mentions=discord.AllowedMentions(users=True)
        )


# ---------- ONLINE STATUS ----------
_sent_online = False

@bot.event
async def on_ready():
    global _sent_online

    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="Vouchers and Servers, .gg/QHS9q6mFfE join for Help!"
        )
    )

    try:
        await init_db()
    except Exception as e:
        print(f"DB init error: {e}")

    if not _sent_online:
        _sent_online = True
        channel = bot.get_channel(STATUS_CHANNEL_ID)
        if channel:
            await channel.send("**AMP VOUCHER BOT CURRENTLY ONLINE** ✅")

    try:
        await bot.tree.sync()
    except Exception as e:
        print(f"Slash sync error: {e}")

    print(f"Logged in as {bot.user}")

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    # Avoid leaking stack traces to users
    log.exception("App command error: %s", error)

    msg = f"{CROSS} Something went wrong running that command."
    try:
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
    except Exception:
        pass

@bot.event
async def on_error(event, *args, **kwargs):
    # Catches event handler errors
    log.exception("Unhandled event error: %s", event)

# Optional: catch UI view errors (menus/buttons/modals)
async def _safe_send_ephemeral(interaction: discord.Interaction, text: str):
    try:
        if interaction.response.is_done():
            await interaction.followup.send(text, ephemeral=True)
        else:
            await interaction.response.send_message(text, ephemeral=True)
    except Exception:
        pass

# ---------- SLASH COMMANDS ----------
@bot.tree.command(name="vouch", description="Create a vouch form")
async def vouch(interaction: discord.Interaction):
    await interaction.response.send_message(
        "Step 1/3: Select the **Trader**.",
        view=TraderSelectStep(requester_id=interaction.user.id),
        ephemeral=True
    )

@bot.tree.command(name="ping", description="Check bot latency")
async def ping(interaction: discord.Interaction):
    latency_ms = round(bot.latency * 1000)
    await interaction.response.send_message(
        f"🏓 Pong! **{latency_ms} ms**",
        ephemeral=True
    )

@bot.tree.command(name="vouches", description="Pull up all saved vouches for a user")
@app_commands.describe(user="User to look up")
async def vouches(interaction: discord.Interaction, user: discord.Member):
    if interaction.guild is None:
        return await interaction.response.send_message(
            f"{CROSS} This command can only be used in a server.",
            ephemeral=True
        )

    view = VouchesPaginator(
        requester_id=interaction.user.id,
        guild_id=interaction.guild_id,
        target_member=user
    )
    rows, total = await fetch_vouches_page(interaction.guild_id, user.id, 0)
    view.total = total
    view._set_button_state()

    if total == 0:
        return await interaction.response.send_message(
            f"No vouches found for {user.mention}.",
            ephemeral=True
        )

    embed = build_vouches_embed(user, rows, total, 0)
    await interaction.response.send_message(
        embed=embed,
        view=view,
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions(users=True)
    )


# #1 TRUST COMMAND
@bot.tree.command(name="trust", description="Show vouch trust stats for a user")
@app_commands.describe(user="User to check")
async def trust(interaction: discord.Interaction, user: discord.Member):
    if interaction.guild is None:
        return await interaction.response.send_message(f"{CROSS} Server only.", ephemeral=True)

    stats = await get_user_trust_stats(interaction.guild_id, user.id)
    total = stats["total"]
    avg = stats["avg"]
    suspicious = stats["suspicious"]
    mm_count = stats["middleman_count"]
    mm_avg = stats["middleman_avg"]

    badges = []
    if total >= 25 and (avg or 0) >= 4.5:
        badges.append(f"{TROPHY} Trusted Trader")
    if suspicious >= 3:
        badges.append(f"{WARN} Suspicious Activity")
    if mm_count >= 10 and (mm_avg or 0) >= 4.5:
        badges.append(f"{CHECK} Reliable Middleman")

    embed = discord.Embed(
        title=f"Trust Report: {user}",
        color=discord.Color.gold()
    )
    embed.add_field(name="Total vouches", value=str(total), inline=True)
    embed.add_field(name="Average rating", value=(f"{avg:.2f}/5" if avg is not None else "N/A"), inline=True)
    embed.add_field(name="Suspicious flags", value=str(suspicious), inline=True)
    embed.add_field(name="Middleman vouches", value=str(mm_count), inline=True)
    embed.add_field(name="Middleman avg", value=(f"{mm_avg:.2f}/5" if mm_avg is not None else "N/A"), inline=True)
    embed.add_field(name="Badges", value=("\n".join(badges) if badges else "None"), inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


# #6 SOFTLOCK / SOFTUNLOCK
@bot.tree.command(name="softlock", description="Soft-lock the current channel (block @everyone from sending). Admin only.")
async def softlock(interaction: discord.Interaction):
    if interaction.guild is None or not isinstance(interaction.channel, discord.TextChannel):
        return await interaction.response.send_message(f"{CROSS} Use this in a server text channel.", ephemeral=True)

    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message(f"{CROSS} Admin only.", ephemeral=True)

    channel: discord.TextChannel = interaction.channel
    everyone = interaction.guild.default_role

    prev = channel.overwrites_for(everyone)
    _softlock_previous[channel.id] = prev

    new_overwrite = prev
    new_overwrite.send_messages = False
    new_overwrite.add_reactions = False
    new_overwrite.create_public_threads = False
    new_overwrite.create_private_threads = False

    try:
        await channel.set_permissions(everyone, overwrite=new_overwrite, reason="Softlock")
    except discord.Forbidden:
        return await interaction.response.send_message(f"{CROSS} I need permission to manage channel overwrites.", ephemeral=True)

    await interaction.response.send_message(f"{LOCK} Soft-locked {channel.mention}.", ephemeral=False)


@bot.tree.command(name="softunlock", description="Remove soft-lock and restore previous @everyone permissions. Admin only.")
async def softunlock(interaction: discord.Interaction):
    if interaction.guild is None or not isinstance(interaction.channel, discord.TextChannel):
        return await interaction.response.send_message(f"{CROSS} Use this in a server text channel.", ephemeral=True)

    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message(f"{CROSS} Admin only.", ephemeral=True)

    channel: discord.TextChannel = interaction.channel
    everyone = interaction.guild.default_role

    prev = _softlock_previous.get(channel.id)
    if prev is None:
        return await interaction.response.send_message(f"{CROSS} No saved softlock state for this channel.", ephemeral=True)

    try:
        await channel.set_permissions(everyone, overwrite=prev, reason="Softunlock")
    except discord.Forbidden:
        return await interaction.response.send_message(f"{CROSS} I need permission to manage channel overwrites.", ephemeral=True)

    _softlock_previous.pop(channel.id, None)
    await interaction.response.send_message(f"{CHECK} Soft-unlocked {channel.mention}.", ephemeral=False)


# #9 STATS
@bot.tree.command(name="stats", description="Show server-wide vouch stats")
async def stats(interaction: discord.Interaction):
    if interaction.guild is None:
        return await interaction.response.send_message(f"{CROSS} Server only.", ephemeral=True)

    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        cur = await db.execute("""
            SELECT COUNT(*), AVG(rating), SUM(suspicious)
            FROM vouches
            WHERE guild_id = ?
        """, (interaction.guild_id,))
        total, avg, suspicious_sum = await cur.fetchone()

        cur2 = await db.execute("""
            SELECT middleman_user_id, COUNT(*), AVG(rating)
            FROM vouches
            WHERE guild_id = ? AND middleman_user_id IS NOT NULL
            GROUP BY middleman_user_id
            ORDER BY COUNT(*) DESC
            LIMIT 5
        """, (interaction.guild_id,))
        top_middlemen = await cur2.fetchall()

    embed = discord.Embed(title="Server Vouch Stats", color=discord.Color.teal())
    embed.add_field(name="Total vouches", value=str(total or 0), inline=True)
    embed.add_field(name="Average rating", value=(f"{avg:.2f}/5" if avg is not None else "N/A"), inline=True)
    embed.add_field(name="Suspicious flags", value=str(suspicious_sum or 0), inline=True)

    if top_middlemen:
        lines = []
        for mm_id, cnt, mm_avg in top_middlemen:
            lines.append(f"<@{mm_id}> — **{cnt}** vouches • avg **{(mm_avg or 0):.2f}/5**")
        embed.add_field(name="Top Middlemen", value="\n".join(lines), inline=False)
    else:
        embed.add_field(name="Top Middlemen", value="No middleman data yet.", inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


# #10 LEADERBOARD
@bot.tree.command(name="leaderboard", description="Top traders by vouch count (and avg rating)")
async def leaderboard(interaction: discord.Interaction):
    if interaction.guild is None:
        return await interaction.response.send_message(f"{CROSS} Server only.", ephemeral=True)

    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        cur = await db.execute("""
            SELECT vouched_user_id, COUNT(*) AS c, AVG(rating) AS a
            FROM vouches
            WHERE guild_id = ?
            GROUP BY vouched_user_id
            ORDER BY c DESC, a DESC
            LIMIT 10
        """, (interaction.guild_id,))
        rows = await cur.fetchall()

    if not rows:
        return await interaction.response.send_message("No vouches yet.", ephemeral=True)

    embed = discord.Embed(title=f"{TROPHY} Vouch Leaderboard", color=discord.Color.gold())
    lines = []
    for idx, (uid, count, avg) in enumerate(rows, start=1):
        lines.append(f"**#{idx}** <@{uid}> — **{count}** vouches • avg **{(avg or 0):.2f}/5**")
    embed.description = "\n".join(lines)

    await interaction.response.send_message(embed=embed, ephemeral=True, allowed_mentions=discord.AllowedMentions(users=True))


# #12 EXPORT VOUCHES (CSV)
@bot.tree.command(name="exportvouches", description="Export vouches for a user as CSV (Admin only)")
@app_commands.describe(user="User to export vouches for")
async def exportvouches(interaction: discord.Interaction, user: discord.Member):
    if interaction.guild is None:
        return await interaction.response.send_message(f"{CROSS} Server only.", ephemeral=True)
    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message(f"{CROSS} Admin only.", ephemeral=True)

    async with _db_lock:     async with await db_connect(DB_FILE) as db:
        cur = await db.execute("""
            SELECT id, voucher_user_id, trader_user_id, middleman_user_id, rating, traded_item, created_at, suspicious
            FROM vouches
            WHERE guild_id = ? AND vouched_user_id = ?
            ORDER BY id DESC
        """, (interaction.guild_id, user.id))
        rows = await cur.fetchall()

    if not rows:
        return await interaction.response.send_message(f"No vouches found for {user.mention}.", ephemeral=True)

    csv_lines = ["id,vouched_user_id,voucher_user_id,trader_user_id,middleman_user_id,rating,traded_item,created_at,suspicious"]
    for r in rows:
        vid, voucher_id, trader_id, mm_id, rating, item, created_at, suspicious = r
        item_safe = str(item).replace('"', '""')
        csv_lines.append(
            f'{vid},{user.id},{voucher_id},{trader_id},{mm_id or ""},{rating},"{item_safe}","{created_at}",{suspicious}'
        )

    data = "\n".join(csv_lines).encode("utf-8")
    file = discord.File(fp=BytesIO(data), filename=f"vouches_{user.id}.csv")  # type: ignore

    await interaction.response.send_message(
        content=f"{CHECK} Export for {user.mention}:",
        file=file,
        ephemeral=True
    )


# ---------- MAXMUTE / UNMUTE ----------
@bot.tree.command(name="maxmute", description="Timeout (mute) a user for the maximum duration (Admin only).")
@app_commands.describe(user="User to max mute", reason="Reason for max mute")
async def maxmute(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason provided"):
    if interaction.guild is None:
        return await interaction.response.send_message(f"{CROSS} Server only.", ephemeral=True)

    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message(f"{CROSS} Admin only.", ephemeral=True)

    # staff immunity (#5)
    if any(role.id in PROTECTED_ROLE_IDS for role in user.roles):
        return await interaction.response.send_message(
            f"{CROSS} That user is protected (staff immunity).",
            ephemeral=True
        )

    me = interaction.guild.me  # type: ignore
    if me is None or not me.guild_permissions.moderate_members:
        return await interaction.response.send_message(
            f"{CROSS} I need the **Moderate Members** permission to timeout users.",
            ephemeral=True
        )

    if user.id == interaction.user.id:
        return await interaction.response.send_message(f"{CROSS} You can’t maxmute yourself.", ephemeral=True)

    if user.guild_permissions.administrator:
        return await interaction.response.send_message(f"{CROSS} I won’t maxmute an Administrator.", ephemeral=True)

    if interaction.guild.me and user.top_role >= interaction.guild.me.top_role:
        return await interaction.response.send_message(
            f"{CROSS} I can’t maxmute that user (role hierarchy).",
            ephemeral=True
        )

    duration = timedelta(days=28)
    try:
        await user.timeout(duration, reason=f"{reason} | Muted by {interaction.user} ({interaction.user.id})")
    except discord.Forbidden:
        return await interaction.response.send_message(
            f"{CROSS} I don't have permission to timeout that user.",
            ephemeral=True
        )
    except Exception as e:
        return await interaction.response.send_message(f"{CROSS} Failed to maxmute: `{e}`", ephemeral=True)

    embed = discord.Embed(
        title=f"{LOCK} Max Muted",
        description=f"{user.mention} has been timed out for **28 days**.",
        color=discord.Color.orange()
    )
    embed.add_field(name="Reason", value=reason, inline=False)
    embed.set_footer(text=f"Action by {interaction.user}")
    await interaction.response.send_message(embed=embed, allowed_mentions=discord.AllowedMentions(users=True))


@bot.tree.command(name="unmute", description="Remove a timeout from a user (Admin only).")
@app_commands.describe(user="User to unmute", reason="Reason for unmute")
async def unmute(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason provided"):
    if interaction.guild is None:
        return await interaction.response.send_message(f"{CROSS} Server only.", ephemeral=True)

    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message(f"{CROSS} Admin only.", ephemeral=True)

    me = interaction.guild.me  # type: ignore
    if me is None or not me.guild_permissions.moderate_members:
        return await interaction.response.send_message(
            f"{CROSS} I need the **Moderate Members** permission to unmute users.",
            ephemeral=True
        )

    if user.communication_disabled_until is None:
        return await interaction.response.send_message(f"{CROSS} {user.mention} is not muted.", ephemeral=True)

    if interaction.guild.me and user.top_role >= interaction.guild.me.top_role:
        return await interaction.response.send_message(
            f"{CROSS} I can’t unmute that user (role hierarchy).",
            ephemeral=True
        )

    try:
        await user.timeout(None, reason=f"{reason} | Unmuted by {interaction.user} ({interaction.user.id})")
    except discord.Forbidden:
        return await interaction.response.send_message(f"{CROSS} I don't have permission to unmute that user.", ephemeral=True)
    except Exception as e:
        return await interaction.response.send_message(f"{CROSS} Failed to unmute: `{e}`", ephemeral=True)

    embed = discord.Embed(
        title=f"{CHECK} User Unmuted",
        description=f"{user.mention} has been unmuted.",
        color=discord.Color.green()
    )
    embed.add_field(name="Reason", value=reason, inline=False)
    embed.set_footer(text=f"Action by {interaction.user}")
    await interaction.response.send_message(embed=embed, allowed_mentions=discord.AllowedMentions(users=True))

def _install_signal_handlers():
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return

    async def _graceful_close():
        log.info("Graceful shutdown requested")
        try:
            channel = bot.get_channel(STATUS_CHANNEL_ID)
            if channel:
                await channel.send("**AMP VOUCHER BOT CURRENTLY OFFLINE (Host restart/stop)**")
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
            # Windows
            pass

_install_signal_handlers()

# ---------- SHUTDOWN ----------
@bot.tree.command(name="shutdown", description="Shut down the bot (owner only)")
@app_commands.describe(code="Google Authenticator code")
async def shutdown(interaction: discord.Interaction, code: str):
    if interaction.user.id != OWNER_ID:
        await interaction.response.send_message(f"{CROSS} You are not authorized.", ephemeral=True)
        return

    totp = pyotp.TOTP(TOTP_SECRET)
    if not totp.verify(code):
        await interaction.response.send_message(f"{CROSS} Invalid Google Authenticator code.", ephemeral=True)
        return

    await interaction.response.send_message(f"{LOCK} Verified. Shutting down...")

    channel = bot.get_channel(STATUS_CHANNEL_ID)
    if channel:
        await channel.send("**AMP VOUCHER BOT CURRENTLY OFFLINE AND UNDER MAINTENANCE**")

    print("Shutting down bot...")
    await bot.close()
    sys.exit(0)


bot.run(TOKEN)



