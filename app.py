# ==========================================
# SigaChaves / Sentinela – (Supabase + space_id)
# Consolidado com:
# - Suporte a múltiplos espaços por mesmo key_number (space_id/UUID)
# - CSV Import (Espaços/Pessoas)
# - Painel de Tokens (revogar)
# - Recibo PDF por transação
# - Remover chave / Excluir responsável
# - PIN (4–6 dígitos) por pessoa e validação no QR
# - Hash (SHA-256) das assinaturas
# - Status mostra Responsável (EM_USO/ATRASADA)
# - Rótulos legíveis (pessoas e autorizações)
# - UI com notas (bloco cinza com ícone)
# - QR com ?sid=... (fallback para ?key=... quando necessário)
# ==========================================
import os, io, uuid, zipfile, secrets, string, base64
from datetime import datetime, date, time, timezone

from typing import Optional, Tuple, List, Dict
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image
from streamlit_drawable_canvas import st_canvas
import qrcode
from supabase import create_client, Client
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib.units import mm


# ---------------- Config -------------------
st.set_page_config(page_title="SigaChaves – Controle", layout="wide")
APP_TITLE  = "SigaChaves – Unidade Rondon"
CATEGORIES = ["Sala", "Sala de Aula", "Laboratório", "Secretaria", "Coordenação", "Copa"]


# Fundo personalizado
st.markdown("""
<style>
/* ===== Fundo aplicado na raiz do app ===== */
html, body, [data-testid="stAppViewContainer"] {
  background-image: url("https://i.postimg.cc/4xgNnkfX/Untitled-design.png") !important;
  background-size: cover !important;
  background-position: center center !important;
  background-repeat: no-repeat !important;
}

/* Cabeçalho transparente */
[data-testid="stHeader"] { background: rgba(0,0,0,0) !important; }

/* Sidebar translúcida (opcional) */
[data-testid="stSidebar"] {
  background: rgba(255,255,255,0.86) !important;
  backdrop-filter: blur(2px);
}

/* Container principal – sem fundo, para não esconder a imagem */
.block-container {
  padding-top: 1.2rem;
  background: transparent !important;   /* <— era aqui que cobria sua imagem */
  border-radius: 16px;
  box-shadow: none;                      /* remova/ou ajuste se quiser sombra */
}

/* Esconde menu/rodapé/Manage App */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header { visibility: hidden; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap: .5rem; }
.stTabs [data-baseweb="tab"] {
  background: #F5F7FB; padding: .5rem 1rem; border-radius: .75rem; font-weight: 600;
}
.stTabs [aria-selected="true"] { background: #E3F2FD; }

/* Badges */
.badge { display:inline-block; padding: .18rem .5rem; border-radius: .5rem;
  font-size: .85rem; font-weight: 600; color: #fff; line-height: 1.2; }
.badge-ok{background:#4CAF50;} .badge-use{background:#2196F3;}
.badge-late{background:#F44336;} .badge-off{background:#9E9E9E;}

/* Tabela listrada */
.table-clean { border-collapse: collapse; width: 100%; }
.table-clean th { background:#EDEFF5; text-align:left; padding:.6rem; font-weight:700; }
.table-clean td { background:#fff; padding:.55rem; border-top:1px solid #F0F2F6; }
.table-clean tr:nth-child(even) td { background:#FAFBFE; }

/* Botões por classe */
.btn-primary  button { background:#2196F3 !important; color:#fff !important; border:0 !important; }
.btn-success  button { background:#4CAF50 !important; color:#fff !important; border:0 !important; }
.btn-warning  button { background:#FF9800 !important; color:#fff !important; border:0 !important; }
.btn-danger   button { background:#F44336 !important; color:#fff !important; border:0 !important; }
.btn-secondary button{ background:#607D8B !important; color:#fff !important; border:0 !important; }
.btn-primary  button:hover,
.btn-success  button:hover,
.btn-warning  button:hover,
.btn-danger   button:hover,
.btn-secondary button:hover { filter: brightness(0.95); }

/* Download buttons dentro das classes */
.btn-primary  .stDownloadButton button,
.btn-success  .stDownloadButton button,
.btn-warning  .stDownloadButton button,
.btn-danger   .stDownloadButton button,
.btn-secondary .stDownloadButton button {
  background: inherit !important; color: #fff !important; border: 0 !important;
}

/* Danger */
#danger button { background:#F44336 !important; color:#fff !important; border:0 !important; }
#danger button:hover { filter: brightness(0.95); }
</style>
""", unsafe_allow_html=True)


ADMIN_PASS = st.secrets.get("STREAMLIT_ADMIN_PASS", os.getenv("STREAMLIT_ADMIN_PASS", ""))
BASE_URL   = st.secrets.get("BASE_URL", os.getenv("BASE_URL", "")).strip()

SUPABASE_URL              = st.secrets.get("SUPABASE_URL", os.getenv("SUPABASE_URL", ""))
SUPABASE_SERVICE_ROLE_KEY = st.secrets.get("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""))

CUTOFF_HOUR_FOR_OVERDUE      = int(os.getenv("CUTOFF_HOUR_FOR_OVERDUE", st.secrets.get("CUTOFF_HOUR_FOR_OVERDUE", "23")))
TOKEN_TTL_MINUTES            = int(os.getenv("TOKEN_TTL_MINUTES",     st.secrets.get("TOKEN_TTL_MINUTES", "30")))
QR_CHECK_AUTH_ON_CHECKOUT    = str(os.getenv("QR_CHECK_AUTH_ON_CHECKOUT", st.secrets.get("QR_CHECK_AUTH_ON_CHECKOUT", "false"))).lower() == "true"

STATUS_MAP = {
    "DISPONÍVEL": '<span class="badge badge-ok">DISPONÍVEL</span>',
    "EM_USO":     '<span class="badge badge-use">EM USO</span>',
    "ATRASADA":   '<span class="badge badge-late">ATRASADA</span>',
    "INATIVA":    '<span class="badge badge-off">INATIVA</span>',
}

# ---------------- Utils --------------------
def supa() -> Client:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        st.error("Configure SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY em Secrets.")
        st.stop()
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

#def now_utc() -> datetime.datetime:
#    return datetime.datetime.now(datetime.timezone.utc)
  
def now_utc() -> datetime:
    return datetime.now(timezone.utc)
                        
def to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO(); img.save(buf, format="PNG"); buf.seek(0); return buf.read()

def make_qr(data: str) -> Image.Image:
    qr = qrcode.QRCode(version=2, box_size=8, border=2)
    qr.add_data(data); qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img.convert("RGB")

def build_url(base_url: str, params: dict) -> str:
    base = (base_url or "").rstrip("/")
    if not base: return ""
    query = "&".join(f"{k}={v}" for k, v in params.items() if v is not None and v != "")
    return f"{base}/?{query}" if query else f"{base}/"

def gen_token_str(n: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))

def decode_bytea(x) -> Optional[bytes]:
    if x is None: return None
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, str):
        try: return base64.b64decode(x)
        except Exception: return None
    return None

def encode_bytea(x: Optional[bytes]) -> Optional[str]:
    if not x: return None
    try: return base64.b64encode(x).decode("ascii")
    except Exception: return None

def sha256_hex(b: Optional[bytes]) -> Optional[str]:
    if not b: return None
    return hashlib.sha256(b).hexdigest()

def has_signature(canvas_image_data) -> bool:
    try:
        if canvas_image_data is None: return False
        arr = np.array(canvas_image_data).astype("uint8")
        if arr.ndim != 3 or arr.shape[2] < 3: return False
        rgb = arr[:, :, :3]
        non_white = np.any(rgb < 250, axis=2)
        return bool(np.sum(non_white) > 50)
    except Exception:
        return False

def person_label(row: pd.Series) -> str:
    idc = (row.get("id_code") or "").strip() or "-"
    ph  = (row.get("phone") or "").strip() or "-"
    return f"{row['name']} • {idc} • {ph}"

def fmt_date(dt_iso: Optional[str]) -> str:
    if not dt_iso: return "—"
    try:
        d = pd.to_datetime(dt_iso)
        return d.strftime("%d/%m/%Y")
    except Exception:
        return str(dt_iso)

def authorization_label(row: pd.Series, spaces_df: pd.DataFrame) -> str:
    keyn = row.get("key_number")
    memo = (row.get("memo_number") or "").strip() or "s/ nº"
    vf   = fmt_date(row.get("valid_from"))
    vt   = fmt_date(row.get("valid_to"))
    room = ""
    try:
        r = spaces_df[spaces_df["key_number"] == keyn]
        if not r.empty:
            room = f" — {r.iloc[0].get('room_name', '')}"
    except Exception:
        pass
    return f"Chave {keyn}{room} • Memo {memo} • {vf} → {vt}"

def space_label(row: pd.Series) -> str:
    kn  = row.get("key_number")
    rn  = row.get("room_name") or ""
    loc = row.get("location") or ""
    cat = row.get("category") or ""
    extra = f" • {loc}" if loc else ""
    return f"Chave {kn} — {rn}{extra} ({cat})"

def render_status_table(df: pd.DataFrame):
    if df.empty:
        st.info("Sem registros.")
        return
    view = df.copy()
    view["Responsável"] = view.apply(
        lambda r: (r.get("taken_by_name") or "") if r.get("status") in ["EM_USO","ATRASADA"] else "",
        axis=1
    )
    view = view.rename(columns={
        "key_number":"Chave",
        "room_name":"Sala/Lab",
        "location":"Local",
        "category":"Categoria",
        "status":"Status"
    })
    view["Status"] = view["Status"].map(lambda s: STATUS_MAP.get(str(s), str(s)))
    html = view[["Chave","Sala/Lab","Local","Categoria","Status","Responsável"]].to_html(
        escape=False, index=False, classes="table-clean"
    )
    st.markdown(html, unsafe_allow_html=True)

# --------- Data access (Supabase) ----------
def add_space(key_number: Optional[int], room_name: str, location: str = "", category: str = "Sala"):
    s = supa()
    s.table("spaces").insert({
        # space_id é gerado pelo DB (gen_random_uuid) — ou já existe
        "key_number": key_number,
        "room_name": room_name,
        "location": location,
        "is_active": True,
        "category": category
    }).execute()

def list_spaces(active_only: bool = True) -> pd.DataFrame:
    s = supa()
    q = s.table("spaces").select("*").order("key_number", desc=False)
    if active_only:
        q = q.eq("is_active", True)
    data = q.execute().data or []
    if not data:
        return pd.DataFrame(columns=["space_id","key_number","room_name","location","is_active","category"])
    return pd.DataFrame(data)

def update_space_by_id(space_id: str, room_name: str, location: str, is_active: bool, category: str = "Sala", key_number: Optional[int] = None):
    s = supa()
    payload = {
        "room_name": room_name,
        "location": location,
        "is_active": bool(is_active),
        "category": category
    }
    if key_number is not None:
        payload["key_number"] = key_number
    s.table("spaces").update(payload).eq("space_id", space_id).execute()

def delete_space_by_id(space_id: str) -> Tuple[bool, str]:
    s = supa()
    tx = s.table("transactions").select("id").eq("space_id", space_id).limit(1).execute().data
    if tx:
        return False, "Não é possível remover: existem transações vinculadas a este espaço."
    s.table("spaces").delete().eq("space_id", space_id).execute()
    return True, "Espaço removido."

def space_by_id(space_id: str) -> Optional[pd.Series]:
    s = supa()
    data = s.table("spaces").select("*").eq("space_id", space_id).limit(1).execute().data
    if not data: return None
    return pd.Series(data[0])

# persons
def add_person(name: str, id_code: str = "", phone: str = "", pin: Optional[str] = None):
    s = supa()
    payload = {
        "name": name,
        "id_code": id_code,
        "phone": phone,
        "is_active": True
    }
    if pin:
        payload["pin"] = pin
    s.table("persons").insert(payload).execute()

def list_persons(active_only: bool = True) -> pd.DataFrame:
    s = supa()
    q = s.table("persons").select("*").order("name")
    if active_only:
        q = q.eq("is_active", True)
    data = q.execute().data or []
    return pd.DataFrame(data)

def update_person(pid: str, name: str, id_code: str, phone: str, is_active: bool, pin: Optional[str] = None):
    s = supa()
    payload = {"name": name, "id_code": id_code, "phone": phone, "is_active": bool(is_active)}
    if pin is not None:
        payload["pin"] = pin if pin else None
    s.table("persons").update(payload).eq("id", pid).execute()

def delete_person(pid: str) -> Tuple[bool, str]:
    s = supa()
    try:
        try:
            s.table("authorization_people").delete().eq("person_id", pid).execute()
        except Exception:
            pass
        s.table("persons").delete().eq("id", pid).execute()
        return True, "Responsável excluído."
    except Exception:
        return False, "Não foi possível excluir (verifique vínculos/permite CASCADE)."

def get_person(pid: str) -> Optional[pd.Series]:
    s = supa()
    data = s.table("persons").select("*").eq("id", pid).limit(1).execute().data
    if not data: return None
    return pd.Series(data[0])

# authorizations
def _date_to_utc_start_iso(d: Optional[date]) -> Optional[str]:
    if not d:
        return None
    return datetime.combine(d, time.min, tzinfo=timezone.utc).isoformat()

def _date_to_utc_end_iso(d: Optional[date]) -> Optional[str]:
    if not d:
        return None
    return datetime.combine(d, time.max, tzinfo=timezone.utc).isoformat()


def add_authorization_by_space(space_id: str,
                               key_number: int,
                               memo_number: str,
                               valid_from: Optional[date],
                               valid_to: Optional[date]) -> str:
    """Cria autorização para um espaço específico (fecha JSON corretamente)."""
    s = supa()
    payload = {
        "space_id": str(space_id),
        "key_number": int(key_number),
        "memo_number": (memo_number or "").strip(),
        "valid_from": _date_to_utc_start_iso(valid_from),
        "valid_to": _date_to_utc_end_iso(valid_to),
    }
    res = s.table("authorizations").insert(payload).execute()
    return res.data[0]["id"]

def list_authorizations_by_space(space_id:str=None, key_number:int=None) -> pd.DataFrame:
    s = supa()
    q = s.table("authorizations").select("*").order("created_at", desc=True)
    if space_id is not None:
        q = q.eq("space_id", space_id)
    elif key_number is not None:
        q = q.eq("key_number", key_number)
    data = q.execute().data or []
    return pd.DataFrame(data)

def add_person_to_authorization(authorization_id:str, person_id:str):
    s = supa()
    s.table("authorization_people").insert({
        "authorization_id": authorization_id,
        "person_id": person_id
    }).execute()

def list_authorized_people_now_by_space(space_id:str) -> pd.DataFrame:
    s = supa()
    now = now_utc().isoformat()
    auths = s.table("authorizations").select("id").eq("space_id", space_id)\
        .or_(f"valid_from.is.null,valid_from.lte.{now}")\
        .or_(f"valid_to.is.null,valid_to.gte.{now}")\
        .execute().data or []
    if not auths: return pd.DataFrame()
    auth_ids = [a["id"] for a in auths]
    links = s.table("authorization_people").select("person_id").in_("authorization_id", auth_ids).execute().data or []
    if not links: return pd.DataFrame()
    person_ids = list({l["person_id"] for l in links})
    people = s.table("persons").select("*").in_("id", person_ids).eq("is_active", True).execute().data or []
    return pd.DataFrame(people)

#tokens (com space_id)
def create_qr_token(action: str, key_number: int, person_id: Optional[str], ttl_minutes: int = TOKEN_TTL_MINUTES ) -> Tuple[str, datetime]:
    assert action in ("retirar", "devolver")
    token = gen_token_str(28)
    exp = now_utc() + datetime.timedelta(minutes=int(ttl_minutes))
    s = supa()
    s.table("qr_tokens").insert({
        "token": token,
        "action": action,
        "space_id": space_id,
        "key_number": key_number,
        "person_id": person_id,
        "expires_at": exp.isoformat(),
    }).execute()
  
    return token, exp

  
def validate_qr_token(token: str, action: str, space_id: str, person_id: Optional[str] = None) -> Tuple[bool, str]:
    s = supa()
    data = s.table("qr_tokens").select("*").eq("token", token).limit(1).execute().data
    if not data: return False, "Token inválido."
    row = data[0]
    if row["action"] != action: return False, "Token não corresponde a esta operação."
    if row.get("space_id") != space_id: return False, "Token não corresponde a este espaço."
    if person_id is not None and row.get("person_id") != person_id: return False, "Token não corresponde à pessoa."
    if row.get("used_at"): return False, "Token já utilizado."
    try:
        if now_utc() > datetime.datetime.fromisoformat(row["expires_at"].replace("Z","+00:00")):
            return False, "Token expirado."
    except Exception:
        return False, "Falha na validação do token."
    return True, ""

def consume_qr_token(token: str):
    s = supa()
    s.table("qr_tokens").update({"used_at": now_utc().isoformat()}).eq("token", token).is_("used_at", "null").execute()

def list_tokens(status: str = "ativos") -> pd.DataFrame:
    s = supa()
    now = now_utc().isoformat()
    q = s.table("qr_tokens").select("*")
    if status == "ativos":
        q = q.is_("used_at","null").gte("expires_at", now)
    elif status == "expirados":
        q = q.is_("used_at","null").lt("expires_at", now)
    elif status == "usados":
        q = q.not_.is_("used_at","null")
    data = q.order("created_at", desc=True).limit(500).execute().data or []
    return pd.DataFrame(data)

def revoke_token(token: str) -> None:
    consume_qr_token(token)

# transactions (por space_id)
def get_space_by_id(space_id: str) -> Optional[dict]:
    s = supa()
    res = s.table("spaces").select("*").eq("space_id", str(space_id)).limit(1).execute().data
    return res[0] if res else None

def has_open_checkout_by_space(space_id: str) -> bool:
    s = supa()
    data = (
        s.table("transactions")
         .select("id")
         .eq("space_id", str(space_id))
         .is_("checkin_time", "null")
         .order("checkout_time", desc=True)
         .limit(1)
         .execute()
         .data
    )
    return bool(data)

def space_is_active_by_id(space_id: str) -> bool:
    s = supa()
    data = (
        s.table("spaces")
         .select("space_id")
         .eq("space_id", str(space_id))
         .eq("is_active", True)
         .limit(1)
         .execute()
         .data
    )
    return bool(data)


# --- Open checkout por space_id (usa ISO 8601 e base64) ---

def open_checkout_by_space(
    space_id: str,
    name: str,
    id_code: str,
    phone: str,
    due_time: Optional[datetime],
    signature_png: Optional[bytes],
) -> Tuple[bool, str]:
    """
    Abre retirada para um espaço específico (PK = space_id).
    - Evita duplicidade (já em uso).
    - Serializa datas como ISO 8601 (UTC).
    - Assinatura (PNG) em base64.
    - Mantém key_number no registro (se existir no espaço).
    """
    # valida espaço
    sp = get_space_by_id(space_id)
    if not sp:
        return False, "Espaço não encontrado."
    if not sp.get("is_active", False):
        return False, "Espaço inativo. Ative-o em Cadastros → Espaços."

    # valida nome
    name = (name or "").strip()
    if not name:
        return False, "Informe o nome de quem está retirando a chave."

    # já em uso?
    if has_open_checkout_by_space(space_id):
        return False, "Esta chave já está EM USO. Faça a devolução antes de nova retirada."

    # prepara campos
    key_number = sp.get("key_number")  # opcional (pode ser None)
    sig_out_b64 = encode_bytea(signature_png) if signature_png else None

    payload = {
        "space_id": str(space_id),
        "key_number": int(key_number) if key_number is not None else None,
        "taken_by_name": name,
        "taken_by_id": (id_code or "").strip(),
        "taken_phone": (phone or "").strip(),
        "checkout_time": datetime.now(timezone.utc).isoformat(),
        "due_time": due_time.isoformat() if due_time else None,
        "checkin_time": None,
        "status": "EM_USO",
        "signature_out": sig_out_b64,
        "signature_in": None,
    }

    try:
        s = supa()
        res = s.table("transactions").insert(payload).execute()
        return True, res.data[0]["id"]
    except Exception:
        return False, "Não foi possível registrar a retirada."

def do_checkin_by_space(space_id: str, signature_png: Optional[bytes]) -> Tuple[bool, str]:
    sp = space_by_id(space_id)
    if sp is None or not bool(sp.get("is_active", True)):
        return False, "Espaço não está cadastrado/ativo."
    s = supa()
    open_tx = s.table("transactions").select("id").eq("space_id", space_id)\
        .is_("checkin_time","null").order("checkout_time", desc=True).limit(1).execute().data
    if not open_tx: return False, "Não há retirada em aberto para este espaço."
    tid = open_tx[0]["id"]
    sig_in_b64  = encode_bytea(signature_png) if signature_png else None
    sig_in_hash = sha256_hex(signature_png) if signature_png else None

    s.table("transactions").update({
        "checkin_time": now_utc().isoformat(),
        "status": "DEVOLVIDA",
        "signature_in": sig_in_b64,
        "signature_in_hash": sig_in_hash
    }).eq("id", tid).execute()
    return True, tid

def list_transactions(start: Optional[datetime] = None,
                      end: Optional[datetime] = None) -> pd.DataFrame:
    s = supa()
    q = s.table("transactions").select("*").order("checkout_time", desc=True)
    if start:
        q = q.gte("checkout_time", start.isoformat())
    data = q.execute().data or []
    df = pd.DataFrame(data)

    if end and not df.empty:
        def row_in(r):
            # considera checkin_time (se houver) ou checkout_time
            ct_raw = r.get("checkin_time") or r.get("checkout_time")
            try:
                ct = pd.to_datetime(ct_raw)
            except Exception:
                return False
            # normaliza sem tz pra comparar com 'end'
            return ct.tz_localize(None) <= end.replace(tzinfo=None)
        df = df[df.apply(row_in, axis=1)]

    return df

def list_status() -> pd.DataFrame:
    df_space = list_spaces(active_only=True)
    if df_space.empty:
        return pd.DataFrame(columns=["space_id","key_number","room_name","location","category","status","checkout_time","due_time","checkin_time","taken_by_name"])

    s = supa()
    sids = df_space["space_id"].tolist()
    tx_all: List[Dict] = []
    chunk = 200
    for i in range(0, len(sids), chunk):
        sub = sids[i:i+chunk]
        data = s.table("transactions").select("space_id,checkout_time,due_time,checkin_time,status,taken_by_name")\
            .in_("space_id", sub).order("checkout_time", desc=True).execute().data or []
        tx_all.extend(data)
    df_tx = pd.DataFrame(tx_all)

    if not df_tx.empty:
        df_tx["checkout_time_dt"] = pd.to_datetime(df_tx["checkout_time"])
        df_tx = df_tx.sort_values(["space_id","checkout_time_dt"], ascending=[True, False])\
                     .groupby("space_id", as_index=False).first()
    else:
        df_tx = pd.DataFrame(columns=["space_id","checkout_time","due_time","checkin_time","status","taken_by_name"])

    df = df_space.merge(
        df_tx[["space_id","checkout_time","due_time","checkin_time","taken_by_name"]],
        on="space_id", how="left"
    )

    def compute_status(row):
        if pd.isna(row["checkout_time"]):
            return "DISPONÍVEL"
        if pd.isna(row["checkin_time"]):
            now = datetime.datetime.now()
            if pd.notna(row["due_time"]):
                try:
                    due = pd.to_datetime(str(row["due_time"]))
                    if now > due.to_pydatetime().replace(tzinfo=None):
                        return "ATRASADA"
                except Exception:
                    pass
            try:
                co = pd.to_datetime(str(row["checkout_time"])).to_pydatetime().replace(tzinfo=None)
                limit = co.replace(hour=CUTOFF_HOUR_FOR_OVERDUE, minute=0, second=0, microsecond=0)
                if limit < co: limit += datetime.timedelta(days=1)
                if now > limit: return "ATRASADA"
            except Exception:
                pass
            return "EM_USO"
        return "DISPONÍVEL"

    df["status"] = df.apply(compute_status, axis=1)
    return df[[
        "space_id","key_number","room_name","location","category",
        "status","checkout_time","due_time","checkin_time","taken_by_name"
    ]].sort_values(["key_number","room_name"])

# ------- Recibo PDF (por transação) --------
def get_transaction(tid: str) -> Optional[dict]:
    s = supa()
    data = s.table("transactions").select("*").eq("id", tid).limit(1).execute().data
    if not data: return None
    return data[0]

def get_space_by_tx(tx: dict) -> Optional[dict]:
    s = supa()
    sid = tx.get("space_id")
    if not sid: return None
    data = s.table("spaces").select("*").eq("space_id", sid).limit(1).execute().data
    if not data: return None
    return data[0]

def render_pdf_receipt(tx: dict) -> bytes:
    sp = get_space_by_tx(tx) or {}
    key_number = sp.get("key_number", tx.get("key_number", ""))
    room = sp.get("room_name", "")
    loc  = sp.get("location", "")
    cat  = sp.get("category", "")

    out_sig = decode_bytea(tx.get("signature_out"))
    in_sig  = decode_bytea(tx.get("signature_in"))

    buf = io.BytesIO()
    c = pdf_canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(20*mm, h-25*mm, "Sentinela – Recibo de Movimentação de Chave")

    c.setFont("Helvetica", 11)
    y = h-40*mm
    def line(lbl, val):
        nonlocal y
        c.drawString(20*mm, y, f"{lbl}: {val}"); y -= 8*mm

    line("ID da transação", tx.get("id",""))
    line("Chave", f"{key_number} – {room}")
    line("Localização / Categoria", f"{loc} / {cat}")
    line("Responsável", tx.get("taken_by_name",""))
    line("ID / SIAPE", tx.get("taken_by_id",""))
    line("Telefone", tx.get("taken_phone",""))
    line("Retirada em", str(tx.get("checkout_time","")).replace("T"," ").replace("Z",""))
    line("Prazo", str(tx.get("due_time","")).replace("T"," ").replace("Z",""))
    line("Devolução em", str(tx.get("checkin_time","")).replace("T"," ").replace("Z",""))
    line("Status", tx.get("status",""))

    y -= 5*mm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20*mm, y, "Assinaturas")
    y -= 10*mm
    c.setFont("Helvetica", 10)

    if out_sig:
        try:
            img_out = Image.open(io.BytesIO(out_sig)).convert("RGB")
            out_path = io.BytesIO(); img_out.save(out_path, format="PNG"); out_path.seek(0)
            c.drawImage(out_path, 20*mm, y-30*mm, width=60*mm, height=30*mm, preserveAspectRatio=True, mask='auto')
            c.drawString(20*mm, y-32*mm, "Retirada")
        except Exception:
            c.drawString(20*mm, y, "(sem assinatura de retirada)")
    else:
        c.drawString(20*mm, y, "(sem assinatura de retirada)")

    if in_sig:
        try:
            img_in = Image.open(io.BytesIO(in_sig)).convert("RGB")
            in_path = io.BytesIO(); img_in.save(in_path, format="PNG"); in_path.seek(0)
            c.drawImage(in_path, 100*mm, y-30*mm, width=60*mm, height=30*mm, preserveAspectRatio=True, mask='auto')
            c.drawString(100*mm, y-32*mm, "Devolução")
        except Exception:
            c.drawString(100*mm, y, "(sem assinatura de devolução)")
    else:
        c.drawString(100*mm, y, "(sem assinatura de devolução)")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()

# ------------------ UI ----------------------
st.title(APP_TITLE)

with st.sidebar:
    st.header("Acesso")
    typed_pass = st.text_input("Senha de admin", type="password", key="admin_pass",
                               help="Necessária para operar retiradas/devoluções, cadastros e QRs.")
    is_admin = (ADMIN_PASS != "" and typed_pass == ADMIN_PASS)
    if ADMIN_PASS and is_admin:
        st.success("Admin autenticado.")
    elif ADMIN_PASS and not is_admin:
        st.caption("Modo público: sem operações; relatórios e QR.")
    else:
        st.info("Defina STREAMLIT_ADMIN_PASS em Secrets (produção).")

with st.sidebar:
    st.header("Configuração de QR")
    base_url = BASE_URL or st.text_input("Base URL (para QRs)", value="http://localhost:8501",
                                         help="Defina BASE_URL em Secrets para fixar permanentemente.")

# Query params: ?sid=... (preferido) | fallback: ?key=... (deprecado), ?action=retirar|devolver, ?pid=..., ?token=...
qp = st.query_params
def _get1(x): return x[0] if isinstance(x, list) else x
qp_sid    = _get1(qp.get("sid"))
qp_key    = _get1(qp.get("key"))   # fallback
qp_action = _get1(qp.get("action"))
qp_pid    = _get1(qp.get("pid"))
qp_token  = _get1(qp.get("token"))
if qp_action not in ("retirar","devolver","info"): qp_action = None

# Se vier sid, usamos space_id. Se vier só key, fluxo público tentará resolver lista (ou gestor escolhe).
public_qr_return   = (not is_admin) and (qp_action == "devolver") and (qp_sid or (qp_key and str(qp_key).isdigit()))
public_qr_checkout = (not is_admin) and (qp_action == "retirar")  and (qp_sid or (qp_key and str(qp_key).isdigit())) and qp_pid

# Abas
if is_admin:
    tab_op, tab_cad, tab_rep, tab_qr, tab_tokens, tab_pdf = st.tabs([
        "Operação (Gestor)","Cadastros (Admin)","Relatórios (Admin)","QR Codes (Admin)","Tokens","Recibos PDF"
    ])
else:
    if public_qr_checkout and public_qr_return:
        tab_pub_checkout, tab_pub_return, tab_pub = st.tabs(["Retirada (QR)","Devolução (QR)","Relatórios públicos"])
    elif public_qr_checkout:
        tab_pub_checkout, tab_pub = st.tabs(["Retirada (QR)","Relatórios públicos"])
    elif public_qr_return:
        tab_pub_return, tab_pub = st.tabs(["Devolução (QR)","Relatórios públicos"])
    else:
        tab_pub, = st.tabs(["Relatórios públicos"])

# -------- Operação (Gestor) --------
if is_admin:
    with tab_op:
        st.subheader("Status das chaves")
        cats = ["Todas"] + CATEGORIES
        sel_cat = st.selectbox("Filtrar por categoria", cats, index=0, key="op_cat")
        df_status = list_status()
        if sel_cat != "Todas":
            df_status = df_status[df_status["category"] == sel_cat]
        render_status_table(df_status)
        atrasadas = (df_status["status"] == "ATRASADA").sum()
        if atrasadas: st.error(f"⚠️ {atrasadas} chave(s) ATRASADA(s).")

        st.markdown("---")
        st.subheader("Retirar / Devolver (Gestor)")

        modos = ["Retirar","Devolver"]
        modo = st.radio("Ação", modos, horizontal=True, index=0 if (qp_action in (None,"retirar")) else 1, key="op_modo")

        # Seleção do espaço por rótulo (suporta múltiplos com mesmo key_number)
        df_spaces_all = list_spaces(active_only=False)
        if df_spaces_all.empty:
            st.error("Cadastre espaços.")
            st.stop()

        key_filter = st.number_input("Filtrar por Nº da chave (opcional)", min_value=0, step=1, value=0, key="op_key_filter")
        if key_filter and int(key_filter) > 0:
            df_opts = df_spaces_all[df_spaces_all["key_number"] == int(key_filter)]
            if df_opts.empty:
                st.warning("Nenhum espaço com este número.")
        else:
            df_opts = df_spaces_all

        df_opts = df_opts.copy()
        df_opts["__label__"] = df_opts.apply(space_label, axis=1)
        sel_label = st.selectbox("Selecione o espaço", options=df_opts["__label__"].tolist(), key="op_space_select")
        sel_row   = df_opts[df_opts["__label__"] == sel_label].iloc[0]
        sel_sid   = sel_row["space_id"]
        sel_keyn  = sel_row.get("key_number")

        st.caption(f"Sala/Lab: **{sel_row.get('room_name','')}** • Localização: {sel_row.get('location','')} • Categoria: {sel_row.get('category','Sala')}")

        # Pessoas autorizadas (se houver)
        df_authorized_now = list_authorized_people_now_by_space(sel_sid)
        df_persons = df_authorized_now if not df_authorized_now.empty else list_persons(active_only=True)

        # Dados do responsável
        st.markdown("**Dados do responsável**")
        use_registry = st.checkbox("Usar cadastro de responsável", value=True, key="op_use_registry")

        if use_registry and not df_persons.empty:
            df_persons = df_persons.copy()
            df_persons["__label__"] = df_persons.apply(person_label, axis=1)
            sel_plab = st.selectbox("Responsável (cadastro)", options=["-- selecione --"] + df_persons["__label__"].tolist(), key="op_sel_person")
            if sel_plab != "-- selecione --":
                prow = df_persons[df_persons["__label__"] == sel_plab].iloc[0]
                taken_by_name  = st.text_input("Nome", value=prow["name"], key="op_nome")
                taken_by_id    = st.text_input("SIAPE / Matrícula", value=prow.get("id_code",""), key="op_idcode")
                taken_by_phone = st.text_input("Telefone", value=prow.get("phone",""), key="op_phone")
            else:
                taken_by_name  = st.text_input("Nome", value="", key="op_nome_blank")
                taken_by_id    = st.text_input("SIAPE / Matrícula", value="", key="op_idcode_blank")
                taken_by_phone = st.text_input("Telefone", value="", key="op_phone_blank")
        else:
            taken_by_name  = st.text_input("Nome", value="", key="op_nome_manual")
            taken_by_id    = st.text_input("SIAPE / Matrícula", value="", key="op_idcode_manual")
            taken_by_phone = st.text_input("Telefone", value="", key="op_phone_manual")

        # Prazo
        due_time = None
        if modo == "Retirar":
            due_choice = st.selectbox("Prazo de devolução", ["Hoje 12:00","Hoje 18:00","Outro","Sem prazo"], key="op_due_choice")
            if due_choice == "Hoje 12:00":
                today = date.today() due_time = datetime.combine(today, time(12,0, tzinfo=timezone.utc))
            elif due_choice == "Hoje 18:00":
                today = date.today() due_time = datetime.combine(today, time(18,0, tzinfo=timezone.utc))
            elif due_choice == "Outro":
                due_time = st.datetime_input("Selecione data/hora prevista (UTC)", key="op_due_dt")
            else:
                due_time = None

        # Assinatura + Ações do gestor
        if modo == "Retirar":
            st.caption("Assinatura do responsável (quem retira)")
            canvas_out = st_canvas(fill_color="rgba(0,0,0,0)", stroke_width=2, stroke_color="#000000",
                                   background_color="#FFFFFF", height=180, width=500, drawing_mode="freedraw", key="sig_out")
            col_g, col_t = st.columns([1,1])
            with col_g:
                st.markdown('<div class="btn-success">', unsafe_allow_html=True)
                if st.button("Confirmar retirada", key="btn_checkout"):
                    if not has_signature(canvas_out.image_data):
                        st.warning("Assinatura obrigatória de quem retira a chave.")
                    else:
                        sig_bytes = None
                        try:
                            img = Image.fromarray((canvas_out.image_data).astype("uint8"))
                            sig_bytes = to_png_bytes(img)
                        except Exception:
                            sig_bytes = None
                        ok, msg = open_checkout_by_space(sel_sid, taken_by_name, taken_by_id, taken_by_phone, due_time, sig_bytes)
                        if ok:
                            st.success(f"Espaço (chave {sel_keyn}) entregue. Protocolo: {msg}")
                        else:
                            st.error(msg)
                st.markdown('</div>', unsafe_allow_html=True)
            with col_t:
                st.markdown("**QR de Retirada (pessoa específica, token)**")
                dfp_all = list_persons(active_only=True)
                if dfp_all.empty:
                    st.info("Cadastre pessoas para gerar QR de retirada.")
                else:
                    dfp_all = dfp_all.copy()
                    dfp_all["__label__"] = dfp_all.apply(person_label, axis=1)
                    sel_p_for_qr_lab = st.selectbox("Pessoa", options=dfp_all["__label__"].tolist(), key="qr_checkout_person_admin")
                    pid_val2 = dfp_all[dfp_all["__label__"] == sel_p_for_qr_lab].iloc[0]["id"]

                    df_auth_now = list_authorized_people_now_by_space(sel_sid)
                    if not df_auth_now.empty and not (df_auth_now["id"] == pid_val2).any():
                        st.warning("Pessoa não consta autorizada agora para este espaço (cadastre em Autorizações).")
                    if st.button("Gerar QR de Retirada (token único)", key="qr_checkout_make"):
                        token, exp = create_qr_token("retirar", sel_sid, sel_keyn, pid_val2, TOKEN_TTL_MINUTES)
                        url_checkout = build_url(base_url, {"sid": sel_sid, "action": "retirar", "pid": pid_val2, "token": token})
                        img_checkout = make_qr(url_checkout)
                        st.image(img_checkout, width="content")
                        st.caption(url_checkout)
                        st.caption(f"Expira: {exp.astimezone().strftime('%d/%m/%Y %H:%M')} (validade {TOKEN_TTL_MINUTES} min)")
                        st.download_button("Baixar QR (PNG)", data=to_png_bytes(img_checkout),
                                           file_name=f"qr_retirar_{sel_sid[:8]}_{pid_val2[:8]}.png",
                                           key="qr_checkout_dl")
        else:
            st.caption("Assinatura – Devolução da chave (Gestor)")
            canvas_in = st_canvas(fill_color="rgba(0,0,0,0)", stroke_width=2, stroke_color="#000000",
                                  background_color="#FFFFFF", height=180, width=500, drawing_mode="freedraw", key="sig_in")
            if st.button("Confirmar devolução", key="btn_checkin"):
                sig_bytes = None
                if canvas_in.image_data is not None:
                    try:
                        img = Image.fromarray((canvas_in.image_data).astype("uint8"))
                        sig_bytes = to_png_bytes(img)
                    except Exception:
                        sig_bytes = None
                ok, msg = do_checkin_by_space(sel_sid, sig_bytes)
                if ok:
                    st.success(f"Espaço (chave {sel_keyn}) devolvido. Protocolo: {msg}")
                else:
                    st.error(msg)

# -------- Relatórios Públicos --------
def render_public_reports():
    st.subheader("Status das chaves")
    cats = ["Todas"] + CATEGORIES
    sel_cat = st.selectbox("Filtrar por categoria", cats, index=0, key="pub_cat")
    df_status = list_status()
    if sel_cat != "Todas":
        df_status = df_status[df_status["category"] == sel_cat]
    st.dataframe(df_status[["key_number","room_name","location","category","status","taken_by_name"]], width="stretch")
    atrasadas = (df_status["status"] == "ATRASADA").sum()
    if atrasadas: st.error(f"⚠️ {atrasadas} chave(s) ATRASADA(s).")

    st.markdown("---")
    st.subheader("Últimas movimentações")
    df_tx = list_transactions()
    cols = ["key_number","taken_by_name","checkout_time","due_time","checkin_time","status"]
    cols = [c for c in cols if c in df_tx.columns]
    st.dataframe(df_tx[cols].head(200), width="stretch")

# -------- Devolução via QR (Público) --------
def render_public_qr_return(space_id: Optional[str], key_number_fallback: Optional[int], token: Optional[str]):
    st.subheader("Devolução de chave (via QR)")

    if not space_id and key_number_fallback:
        # último recurso: escolher espaço entre os que têm esse key_number
        df_spaces = list_spaces(active_only=True)
        df_opts = df_spaces[df_spaces["key_number"] == int(key_number_fallback)].copy()
        if df_opts.empty:
            st.error("Chave não cadastrada/ativa."); return
        df_opts["__label__"] = df_opts.apply(space_label, axis=1)
        sel_label = st.selectbox("Selecione o espaço", options=df_opts["__label__"].tolist(), key="pub_ret_space_sel")
        space_id = df_opts[df_opts["__label__"] == sel_label].iloc[0]["space_id"]

    if not space_id:
        st.error("Espaço inválido."); return

    sp = space_by_id(space_id)
    if sp is None or not bool(sp.get("is_active", True)):
        st.error("Espaço não cadastrado/ativo."); return

    if token:
        ok, msg = validate_qr_token(token, "devolver", space_id, None)
        if not ok: st.error(msg); return

    st.caption(f"Chave **{sp.get('key_number','')}** • {sp.get('room_name','')} • {sp.get('location','')} • {sp.get('category','')}")

    st.caption("Assine para confirmar a devolução")
    canvas_in = st_canvas(fill_color="rgba(0,0,0,0)", stroke_width=2, stroke_color="#000000",
                          background_color="#FFFFFF", height=180, width=500, drawing_mode="freedraw", key="sig_in_public")
    if st.button("Confirmar devolução", key="btn_checkin_public"):
        sig_bytes = None
        if canvas_in.image_data is not None:
            try:
                img = Image.fromarray((canvas_in.image_data).astype("uint8"))
                sig_bytes = to_png_bytes(img)
            except Exception:
                sig_bytes = None
        ok, msg = do_checkin_by_space(space_id, sig_bytes)
        if ok:
            if token: consume_qr_token(token)
            st.success(f"Chave {sp.get('key_number','')} devolvida. Protocolo: {msg}")
        else:
            st.error(msg)

# -------- Retirada via QR (Público) ---------
def render_public_qr_checkout(space_id: Optional[str], key_number_fallback: Optional[int], pid: str, token: Optional[str]):
    st.subheader("Retirada de chave (via QR)")

    if not space_id and key_number_fallback:
        df_spaces = list_spaces(active_only=True)
        df_opts = df_spaces[df_spaces["key_number"] == int(key_number_fallback)].copy()
        if df_opts.empty:
            st.error("Chave não cadastrada/ativa."); return
        df_opts["__label__"] = df_opts.apply(space_label, axis=1)
        sel_label = st.selectbox("Selecione o espaço", options=df_opts["__label__"].tolist(), key="pub_chk_space_sel")
        space_id = df_opts[df_opts["__label__"] == sel_label].iloc[0]["space_id"]

    if not space_id:
        st.error("Espaço inválido."); return

    sp = space_by_id(space_id)
    if sp is None or not bool(sp.get("is_active", True)):
        st.error("Espaço não cadastrado/ativo."); return

    if not token:
        st.error("Token ausente. Gere um novo QR com o gestor."); return
    ok, msg = validate_qr_token(token, "retirar", space_id, pid)
    if not ok:
        st.error(msg); return

    # Autorização
    if QR_CHECK_AUTH_ON_CHECKOUT:
        df_auth_now = list_authorized_people_now_by_space(space_id)
        if df_auth_now.empty or not (df_auth_now["id"] == pid).any():
            st.error("Você não está autorizado(a) a retirar esta chave neste período.")
            return
        prow = df_auth_now[df_auth_now["id"] == pid].iloc[0]
    else:
        person = get_person(pid)
        if person is None or (("is_active" in person.index) and (not bool(person["is_active"]))):
            st.error("Pessoa não encontrada ou inativa."); return
        prow = person

    st.caption(f"Chave **{sp.get('key_number','')}** • {sp.get('room_name','')} • {sp.get('location','')} • {sp.get('category','')}")

    st.markdown("**Responsável**")
    taken_by_name  = st.text_input("Nome", value=prow["name"], disabled=True)
    taken_by_id    = st.text_input("SIAPE / Matrícula", value=prow.get("id_code",""), disabled=True)
    taken_by_phone = st.text_input("Telefone", value=prow.get("phone",""), disabled=True)

    st.markdown("**Prazo de devolução (opcional)**")
    due_opt = st.selectbox("Prazo", ["Hoje 18:00","Sem prazo"], index=0)
    if due_opt == "Hoje 18:00":
        today = datetime.date.today()
        due_time = datetime.datetime.combine(today, datetime.time(18,0, tzinfo=datetime.timezone.utc))

    else:
        due_time = None

    user_pin = st.text_input("PIN de verificação (fornecido no cadastro)", type="password", max_chars=6, key="qr_pin")

    st.caption("Assinatura do responsável (quem retira)")
    canvas_out = st_canvas(fill_color="rgba(0,0,0,0)", stroke_width=2, stroke_color="#000000",
                           background_color="#FFFFFF", height=180, width=500, drawing_mode="freedraw", key="sig_out_public")
    if st.button("Confirmar retirada", key="btn_checkout_public"):
        expected_pin = str(prow.get("pin","") or "")
        if not expected_pin:
            st.error("PIN não configurado para esta pessoa. Procure o gestor.")
            return
        if (user_pin or "").strip() != expected_pin:
            st.error("PIN incorreto.")
            return
        if not has_signature(canvas_out.image_data):
            st.warning("Assinatura obrigatória de quem retira a chave.")
            return

        sig_bytes = None
        try:
            img = Image.fromarray((canvas_out.image_data).astype("uint8"))
            sig_bytes = to_png_bytes(img)
        except Exception:
            sig_bytes = None
        ok, msg = open_checkout_by_space(space_id, prow["name"], prow.get("id_code",""), prow.get("phone",""), due_time, sig_bytes)
        if ok:
            consume_qr_token(token)
            st.success(f"Retirada registrada. Protocolo: {msg}")
        else:
            st.error(msg)

# -------- Cadastros (Admin) --------
if is_admin:
    with tab_cad:
        st.subheader("Espaços (Chaves/Salas)")
        df_sp = list_spaces(active_only=False)
        if not df_sp.empty:
            # mostrar também space_id para debug (oculto em produção, se quiser)
            st.dataframe(df_sp, width="stretch")
        else:
            st.info("Nenhum espaço cadastrado.")

        st.markdown("**Adicionar espaço (novo)**")
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1: sp_key = st.number_input("Nº da chave (pode repetir)", min_value=0, step=1, key="space_key_add")
        with c2: sp_name = st.text_input("Nome da Sala/Lab", key="space_name_add")
        with c3: sp_loc = st.text_input("Localização (opcional)", key="space_loc_add")
        with c4: sp_cat = st.selectbox("Categoria", CATEGORIES, key="space_cat_add")
        with c5:
            st.caption(" ")
            if st.button("Salvar novo espaço", key="space_save"):
                if sp_name.strip():
                    add_space(int(sp_key) if sp_key>0 else None, sp_name.strip(), sp_loc.strip(), sp_cat)
                    st.success("Espaço criado.")
                else:
                    st.error("Informe o nome da Sala/Lab.")

        st.markdown("---")
        st.markdown("**Atualizar/Ativar/Desativar (por espaço)**")
        if not df_sp.empty:
            df_spx = df_sp.copy()
            df_spx["__label__"] = df_spx.apply(space_label, axis=1)
            sel_lab_upd = st.selectbox("Selecione o espaço", options=df_spx["__label__"].tolist(), key="space_sel_edit")
            row_upd = df_spx[df_spx["__label__"] == sel_lab_upd].iloc[0]
            edt_name = st.text_input("Nome", value=row_upd["room_name"], key="space_edit_name")
            edt_loc  = st.text_input("Localização", value=row_upd.get("location",""), key="space_edit_loc")
            edt_cat  = st.selectbox("Categoria", CATEGORIES, index=max(0, CATEGORIES.index(row_upd.get("category","Sala"))), key="space_edit_cat")
            edt_keyn = st.number_input("Nº da chave (pode repetir)", min_value=0, step=1,
                                       value=int(row_upd.get("key_number") or 0), key="space_edit_keyn")
            edt_active = st.selectbox("Status", ["Ativo","Inativo"], index=0 if row_upd["is_active"] else 1, key="space_edit_active")
            if st.button("Aplicar atualização", key="space_status_apply"):
                update_space_by_id(
                    row_upd["space_id"], edt_name.strip(), edt_loc.strip(),
                    True if edt_active=="Ativo" else False, edt_cat, int(edt_keyn) if edt_keyn>0 else None
                )
                st.success("Espaço atualizado.")

        st.markdown("**Remover espaço** (definitivo)")
        if not df_sp.empty:
            df_spd = df_sp.copy()
            df_spd["__label__"] = df_spd.apply(space_label, axis=1)
            sel_lab_del = st.selectbox("Espaço para remover", options=df_spd["__label__"].tolist(), key="space_key_remove_lab")
            space_id_del = df_spd[df_spd["__label__"] == sel_lab_del].iloc[0]["space_id"]

            st.markdown('<div id="danger">', unsafe_allow_html=True)
            col_rm1, col_rm2 = st.columns([1, 3])
            with col_rm1:
                confirm_rm = st.checkbox("Confirmar remoção", key="space_remove_confirm")
            with col_rm2:
                if st.button("Remover espaço", key="space_remove_btn"):
                    if not confirm_rm:
                        st.warning("Marque “Confirmar remoção” para prosseguir.")
                    else:
                        ok, msg = delete_space_by_id(space_id_del)
                        (st.success if ok else st.error)(msg)
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("___")
        st.subheader("Responsáveis")
        df_pe = list_persons(active_only=False)
        st.dataframe(df_pe, width="stretch")

        st.markdown("**Adicionar responsável**")
        p1, p2, p3, p4 = st.columns(4)
        with p1: pn = st.text_input("Nome", key="add_nome")
        with p2: pidc = st.text_input("SIAPE / Matrícula", key="add_idcode")
        with p3: pph = st.text_input("Telefone", key="add_phone")
        with p4: ppin = st.text_input("PIN (4–6 dígitos, opcional)", key="add_pin")
        if st.button("Salvar responsável", key="add_person_btn"):
            if pn.strip():
                pin_clean = (ppin or "").strip()
                if pin_clean and not (pin_clean.isdigit() and 4 <= len(pin_clean) <= 6):
                    st.error("PIN inválido. Use apenas números (4 a 6 dígitos).")
                else:
                    add_person(pn.strip(), pidc.strip(), pph.strip(), pin_clean if pin_clean else None)
                    st.success("Responsável adicionado.")
            else:
                st.error("Informe o nome.")

        st.markdown("**Editar responsável**")
        if not df_pe.empty:
            df_pe = df_pe.copy()
            df_pe["__label__"] = df_pe.apply(person_label, axis=1)
            labels = df_pe["__label__"].tolist()
            label_to_pid = dict(zip(df_pe["__label__"], df_pe["id"]))
            sel_label = st.selectbox("Selecione", options=labels, key="edit_select")
            sel_pid   = label_to_pid[sel_label]
            prow      = df_pe[df_pe["id"] == sel_pid].iloc[0]

            en   = st.text_input("Nome", value=prow["name"], key="edit_nome")
            eidc = st.text_input("SIAPE / Matrícula", value=prow.get("id_code",""), key="edit_idcode")
            eph  = st.text_input("Telefone", value=prow.get("phone",""), key="edit_phone")
            epin = st.text_input("PIN (4–6 dígitos, opcional)", value=str(prow.get("pin","") or ""), key="edit_pin")
            est  = st.selectbox("Status", ["Ativo","Inativo"], index=0 if prow["is_active"] else 1, key="edit_status")

            if st.button("Atualizar responsável", key="edit_person_btn"):
                pin_clean = (epin or "").strip()
                if pin_clean and not (pin_clean.isdigit() and 4 <= len(pin_clean) <= 6):
                    st.error("PIN inválido. Use apenas números (4 a 6 dígitos).")
                else:
                    update_person(sel_pid, en.strip(), eidc.strip(), eph.strip(), True if est=="Ativo" else False, pin_clean if pin_clean else None)
                    st.success("Responsável atualizado.")

        st.markdown("**Excluir responsável**")
        if not df_pe.empty:
            df_pe = df_pe.copy()
            df_pe["__label__"] = df_pe.apply(person_label, axis=1)
            labels_del = df_pe["__label__"].tolist()
            label_to_pid_del = dict(zip(df_pe["__label__"], df_pe["id"]))
            sel_label_del = st.selectbox("Pessoa para excluir", options=labels_del, key="del_select")
            sel_pid_del   = label_to_pid_del[sel_label_del]

            st.markdown('<div class="btn-danger">', unsafe_allow_html=True)
            col_d1, col_d2 = st.columns([1,3])
            with col_d1:
                confirm_del = st.checkbox("Confirmar exclusão", key="del_confirm")
            with col_d2:
                if st.button("Excluir responsável", key="del_person_btn"):
                    if not confirm_del:
                        st.warning("Marque “Confirmar exclusão” para prosseguir.")
                    else:
                        ok, msg = delete_person(sel_pid_del)
                        if ok: st.success(msg)
                        else:  st.error(msg)
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("___")
        st.subheader("Autorizações por espaço")
        st.markdown(
            """
            <div style="background-color:#f5f5f5; padding:12px; border-radius:8px; color:#333; font-size:0.9rem; line-height:1.5;">
                <span style="font-size:1.2rem; margin-right:6px;">ℹ️</span>
                Neste espaço você pode adicionar somente pessoas que estarão vinculadas a 
                <b>memorando ou circular</b>, como <i>bolsistas, voluntários de laboratórios ou estagiários</i>.
            </div>
            """,
            unsafe_allow_html=True
        )

        df_sp_act = list_spaces(active_only=True)
        if df_sp_act.empty:
            st.info("Cadastre espaços ativos para criar autorizações.")
        else:
            # Seleciona o espaço (por rótulo)
            df_sel = df_sp_act.copy()
            df_sel["__label__"] = df_sel.apply(space_label, axis=1)
            sel_lab_space = st.selectbox("Espaço (para a autorização)", options=df_sel["__label__"].tolist(), key="auth_space_sel")
            sel_space_id  = df_sel[df_sel["__label__"] == sel_lab_space].iloc[0]["space_id"]
            sel_keyn      = df_sel[df_sel["__label__"] == sel_lab_space].iloc[0].get("key_number")

            memo = st.text_input("Nº do memorando/circular", key="auth_memo")
            col_af, col_at = st.columns(2)
            with col_af: vf = st.date_input("Válido de (opcional)", key="auth_from")
            with col_at: vt = st.date_input("Válido até (opcional)", key="auth_to")
            if st.button("Criar autorização", key="auth_create"):
                aid = add_authorization_by_space(sel_space_id, sel_keyn, memo.strip(), vf if vf else None, vt if vt else None)
                st.success(f"Autorização criada: {aid}")

            st.markdown("**Vincular pessoas à autorização**")
            df_auths = list_authorizations_by_space(sel_space_id)
            if df_auths.empty:
                st.info("Nenhuma autorização criada para este espaço.")
            else:
                df_auths = df_auths.copy()
                df_auths["__label__"] = df_auths.apply(lambda r: authorization_label(r, df_sp_act), axis=1)
                labels_auth = df_auths["__label__"].tolist()
                map_label_to_id = dict(zip(df_auths["__label__"], df_auths["id"]))

                sel_label_auth = st.selectbox("Selecione a autorização", options=labels_auth, key="auth_sel")
                sel_auth_id    = map_label_to_id[sel_label_auth]

                dfp = list_persons(active_only=True)
                if not dfp.empty:
                    dfp = dfp.copy()
                    dfp["__label__"] = dfp.apply(person_label, axis=1)
                    picked_labels = st.multiselect("Adicionar pessoas (ativas)", options=dfp["__label__"].tolist(), key="auth_people_sel")
                    if st.button("Adicionar à autorização", key="auth_people_add"):
                        for lab in picked_labels:
                            pid = dfp[dfp["__label__"] == lab].iloc[0]["id"]
                            add_person_to_authorization(sel_auth_id, pid)
                        st.success("Pessoas adicionadas.")

                # lista vinculados
                s = supa()
                df_link = s.table("authorization_people").select("person_id").eq("authorization_id", sel_auth_id).execute().data or []
                if df_link:
                    pids = [x["person_id"] for x in df_link]
                    ppl = s.table("persons").select("name,id_code,phone").in_("id", pids).execute().data or []
                    st.write("Vinculados:")
                    st.dataframe(pd.DataFrame(ppl), width="stretch")

        st.markdown("___")
        st.subheader("Importação CSV")
        st.markdown("**Pessoas** — colunas aceitas: `name`, `id_code` (opcional), `phone` (opcional), `pin` (opcional).")
        up_people = st.file_uploader("CSV de Pessoas", type=["csv"], key="csv_people")
        if up_people is not None:
            dfp = pd.read_csv(up_people).fillna("")
            if "name" not in dfp.columns:
                st.error("CSV inválido: coluna 'name' é obrigatória.")
            else:
                st.dataframe(dfp.head(), width="stretch")
                if st.button("Importar Pessoas", key="csv_people_import"):
                    for _, r in dfp.iterrows():
                        pin_val = str(r.get("pin","")).strip()
                        add_person(
                            str(r["name"]).strip(),
                            str(r.get("id_code","")).strip(),
                            str(r.get("phone","")).strip(),
                            pin_val if (pin_val.isdigit() and 4 <= len(pin_val) <= 6) else None
                        )
                    st.success(f"Importadas {len(dfp)} pessoas.")

        st.markdown("**Espaços** — colunas aceitas: `key_number` (opcional), `room_name`, `location` (opcional), `category` (opcional).")
        up_spaces = st.file_uploader("CSV de Espaços", type=["csv"], key="csv_spaces")
        if up_spaces is not None:
            dfs = pd.read_csv(up_spaces).fillna("")
            if "room_name" not in dfs.columns:
                st.error("CSV inválido: coluna 'room_name' é obrigatória.")
            else:
                if "category" not in dfs.columns: dfs["category"] = "Sala"
                dfs["category"] = dfs["category"].apply(lambda x: x if x in CATEGORIES else "Sala")
                st.dataframe(dfs.head(), width="stretch")
                if st.button("Importar Espaços", key="csv_spaces_import"):
                    for _, r in dfs.iterrows():
                        try:
                            kn = r.get("key_number", "")
                            kn = int(kn) if (str(kn).strip().isdigit() and int(kn)>=0) else None
                            add_space(kn, str(r["room_name"]).strip(),
                                      str(r.get("location","")).strip(), str(r.get("category","Sala")).strip() or "Sala")
                        except Exception:
                            pass
                    st.success(f"Importados {len(dfs)} espaços.")

# -------- Relatórios (Admin) --------
if is_admin:
    with tab_rep:
        st.subheader("Movimentações")
        colr1, colr2 = st.columns(2)
        with colr1: dt_start = st.date_input("Início (opcional)", key="rep_start")
        with colr2: dt_end   = st.date_input("Fim (opcional)", key="rep_end")
        start_dt = datetime.datetime.combine(dt_start, datetime.time.min, tzinfo=datetime.timezone.utc) if dt_start else None
        end_dt   = datetime.datetime.combine(dt_end,   datetime.time.max, tzinfo=datetime.timezone.utc) if dt_end   else None

        df_tx = list_transactions(start_dt, end_dt)
        st.dataframe(df_tx, width="stretch")

        total = len(df_tx)
        em_uso = sum(pd.isna(df_tx["checkin_time"])) if not df_tx.empty else 0
        atrasadas = 0
        if not df_tx.empty:
            for _, r in df_tx.iterrows():
                if pd.isna(r["checkin_time"]):
                    if pd.notna(r["due_time"]):
                        try:
                            if datetime.datetime.now() > pd.to_datetime(r["due_time"]).to_pydatetime().replace(tzinfo=None):
                                atrasadas += 1
                        except Exception: pass
                    else:
                        try:
                            co = pd.to_datetime(r["checkout_time"]).to_pydatetime().replace(tzinfo=None)
                            limit = co.replace(hour=CUTOFF_HOUR_FOR_OVERDUE, minute=0, second=0, microsecond=0)
                            if limit < co: limit += datetime.timedelta(days=1)
                            if datetime.datetime.now() > limit: atrasadas += 1
                        except Exception: pass
        m1, m2, m3 = st.columns(3)
        m1.metric("Movimentações", total)
        m2.metric("Em uso (abertas)", em_uso)
        m3.metric("Atrasadas (abertas)", atrasadas)
        if not df_tx.empty:
            st.download_button("Baixar CSV", data=df_tx.to_csv(index=False).encode("utf-8"), file_name="movimentacoes.csv", key="rep_csv_btn")

# -------- QR Codes (Admin) --------
if is_admin:
    with tab_qr:
        st.subheader("QR Codes por espaço (público – Devolução)")
        if not base_url: st.error("Defina a BASE_URL em Secrets/Sidebar para gerar QRs públicos.")
        df_sp_act = list_spaces(active_only=True)
        if df_sp_act.empty:
            st.info("Nenhum espaço ativo cadastrado.")
        else:
            use_token_return = st.checkbox("Usar token de uso único na Devolução", value=False, key="qr_return_use_token")
            df_sp_act = df_sp_act.copy()
            df_sp_act["__label__"] = df_sp_act.apply(space_label, axis=1)
            ids = st.multiselect("Selecione os espaços", options=df_sp_act["__label__"].tolist(),
                                 default=df_sp_act["__label__"].tolist()[:12], key="qr_ids")
            cols = st.number_input("Cartões por linha (sug.: 4)", min_value=1, max_value=6, value=4, key="qr_cols")
            images_for_zip = []
            if ids:
                rows = (len(ids) + cols - 1) // cols
                for r in range(rows):
                    cset = st.columns(int(cols))
                    for c, lab in enumerate(ids[r*int(cols):(r+1)*int(cols)]):
                        with cset[c]:
                            row = df_sp_act[df_sp_act["__label__"] == lab].iloc[0]
                            sid = row["space_id"]; keyn = row.get("key_number")
                            if use_token_return:
                                token, exp = create_qr_token("devolver", sid, keyn, None, TOKEN_TTL_MINUTES)
                                url = build_url(base_url, {"sid": sid, "action": "devolver", "token": token})
                                exp_txt = f" (expira {exp.astimezone().strftime('%d/%m %H:%M')})"
                            else:
                                url = build_url(base_url, {"sid": sid, "action": "devolver"})
                                exp_txt = ""
                            img = make_qr(url)
                            st.image(img, width="stretch")
                            st.caption(f"{lab}{exp_txt}")
                            st.caption(url)
                            images_for_zip.append((f"devolver_{sid[:8]}.png", to_png_bytes(img)))

                if images_for_zip:
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                        for fname, data in images_for_zip: zf.writestr(fname, data)
                    buf.seek(0)
                    st.download_button("Baixar todas em ZIP", data=buf.read(), file_name="qrcodes_devolucao.zip", key="qr_zip_btn")

        st.markdown("---")
        st.subheader("QR de Retirada (pessoa específica, com token)")
        dfp_all = list_persons(active_only=True)
        df_sp_act = list_spaces(active_only=True)
        if dfp_all.empty or df_sp_act.empty:
            st.info("Cadastre pessoas e espaços para gerar QR de retirada.")
        else:
            df_sp_act = df_sp_act.copy()
            df_sp_act["__label__"] = df_sp_act.apply(space_label, axis=1)
            sel_space_lab = st.selectbox("Espaço (retirada)", options=df_sp_act["__label__"].tolist(), key="qr_checkout_space_admin")
            sel_row_space = df_sp_act[df_sp_act["__label__"] == sel_space_lab].iloc[0]
            sel_sid = sel_row_space["space_id"]; sel_keyn = sel_row_space.get("key_number")

            dfp_all = dfp_all.copy()
            dfp_all["__label__"] = dfp_all.apply(person_label, axis=1)
            sel_person_label = st.selectbox("Responsável (retirada)", options=dfp_all["__label__"].tolist(), key="qr_checkout_person_admin2")
            pid_val2 = dfp_all[dfp_all["__label__"] == sel_person_label].iloc[0]["id"]

            if st.button("Gerar QR de Retirada (token único)", key="qr_checkout_make_admin"):
                token, exp = create_qr_token("retirar", sel_sid, sel_keyn, pid_val2, TOKEN_TTL_MINUTES)
                url_checkout = build_url(base_url, {"sid": sel_sid, "action": "retirar", "pid": pid_val2, "token": token})
                img_checkout = make_qr(url_checkout)
                st.image(img_checkout, width="content")
                st.caption(url_checkout)
                st.caption(f"Expira: {exp.astimezone().strftime('%d/%m/%Y %H:%M')} (validade {TOKEN_TTL_MINUTES} min)")
                st.download_button("Baixar QR (PNG)", data=to_png_bytes(img_checkout),
                                   file_name=f"qr_retirar_{sel_sid[:8]}_{pid_val2[:8]}.png",
                                   key="qr_checkout_dl_admin")

# -------- Tokens --------
if is_admin:
    with tab_tokens:
        st.subheader("Painel de Tokens")
        opt = st.radio("Filtrar", ["Ativos","Expirados","Usados"], horizontal=True, key="tok_filter")
        st.caption("• **Ativos**: não usados e dentro da validade • **Expirados**: não usados e prazo vencido • **Usados**: já consumidos")
        status_map = {"Ativos":"ativos", "Expirados":"expirados", "Usados":"usados"}
        df_tk = list_tokens(status_map[opt])
        if df_tk.empty:
            st.info("Nenhum token encontrado.")
        else:
            st.dataframe(df_tk, width="stretch")
            tok = st.text_input("Token para revogar", key="tok_revoke")
            st.markdown('<div class="btn-danger">', unsafe_allow_html=True)
            if st.button("Revogar token (marcar como usado)", key="tok_revoke_btn"):
                if tok.strip():
                    revoke_token(tok.strip())
                    st.success("Token revogado (marcado como usado).")
            st.markdown('</div>', unsafe_allow_html=True)

# -------- Recibos PDF --------
if is_admin:
    with tab_pdf:
        st.subheader("Gerar Recibo PDF por ID de transação")
        tid = st.text_input("ID da transação", key="pdf_tid")
        if st.button("Gerar PDF", key="pdf_make_btn"):
            if not tid.strip():
                st.error("Informe o ID da transação.")
            else:
                tx = get_transaction(tid.strip())
                if not tx:
                    st.error("Transação não encontrada.")
                else:
                    pdf_bytes = render_pdf_receipt(tx)
                    st.download_button("Baixar Recibo PDF", data=pdf_bytes, file_name=f"recibo_{tid.strip()}.pdf")

# -------- Público: Retirada/Devolução/Relatórios --------
if (not is_admin) and public_qr_checkout:
    with tab_pub_checkout:
        # preferir sid; se não vier, cair no fallback com key_number para seleção
        sid = qp_sid
        keyn = int(qp_key) if (qp_key and str(qp_key).isdigit()) else None
        render_public_qr_checkout(sid, keyn, qp_pid, qp_token)

if (not is_admin) and public_qr_return:
    with tab_pub_return:
        sid = qp_sid
        keyn = int(qp_key) if (qp_key and str(qp_key).isdigit()) else None
        render_public_qr_return(sid, keyn, qp_token)

if (not is_admin):
    with tab_pub:
        render_public_reports()






















