import asyncio
import time
import httpx
import json
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from datetime import datetime, timedelta
from google.protobuf import json_format

# ============= সব ফাইল একই ফোল্ডারে =============
try:
    import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    import GetOutfit_pb2
    print("✅ Proto files imported successfully")
except ImportError as e:
    print(f"❌ Proto import error: {e}")
    sys.exit(1)

# =============================================
# CONFIG
# =============================================

RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"

MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

# =============================================
# JWT TOKEN API
# =============================================

JWT_API_BASE = "https://ff-jwt-gen-api.lovable.app/api/public/token"

# =============================================
# ACCOUNTS FOR JWT
# =============================================

BD_CREDS = {
    "uid": "4423678500", 
    "password": "CKR_PRO_BOT_N7HRTDRKL"
}

IND_CREDS = {
    "uid": "7739182267", 
    "password": "507D3250C779A4E73A74B66998E99DD4ED95A6133A07151FC0411A225C405ADD"
}

BR_CREDS = {
    "uid": "7810756496",
    "password": "507D3250C779A4E73A74B66998E99DD4ED95A6133A07151FC0411A225C405ADD"
}

ACCOUNT_CREDENTIALS = {
    "BD": BD_CREDS,
    "IND": IND_CREDS,
    "BR": BR_CREDS
}

# =============================================
# 🌍 রিজন কনফিগ
# =============================================

REGION_CONFIG = {
    "BD": {"server_url": "https://clientbp.ppmainecoonghj.com", "release_version": "OB55"},
    "IND": {"server_url": "https://client.ind.freefiremobile.com", "release_version": "OB55"},
    "BR": {"server_url": "https://client.us.freefiremobile.com", "release_version": "OB55"}
}

LOGIN_URLS = {
    "BD": "https://loginbp.ppmainecoonghj.com",
    "IND": "https://loginbp.ppmainecoonghj.com",
    "BR": "https://loginbp.ppmainecoonghj.com"
}

REGION_PRIORITY = ["BD", "IND", "BR"]

# === Flask App ===
app = Flask(__name__)
CORS(app)

# =============================================
# In-Memory Token Cache (per container)
# =============================================

_token_cache = {}

# =============================================
# JWT Token Function
# =============================================

async def get_jwt_token_from_api(region: str):
    cred = ACCOUNT_CREDENTIALS.get(region)
    if not cred:
        return None

    url = f"{JWT_API_BASE}?uid={cred['uid']}&password={cred['password']}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                return None

            data = response.json()
            token = data.get("token")
            if not token:
                return None

            api_region = data.get("region", region)
            server_url = REGION_CONFIG.get(api_region, REGION_CONFIG["BD"])["server_url"]

            return {
                "token": f"Bearer {token}",
                "region": api_region,
                "server_url": server_url,
                "expires_at": time.time() + 25200
            }
    except Exception as e:
        print(f"❌ JWT API exception for {region}: {e}")
        return None

# =============================================
# Token Getter (with cache)
# =============================================

async def get_token(region: str):
    cached = _token_cache.get(region)
    if cached and cached.get('expires_at', 0) > time.time():
        return cached

    token_info = await get_jwt_token_from_api(region)

    if not token_info:
        token_info = await generate_token_backup(region)

    if token_info:
        _token_cache[region] = token_info
        return token_info

    return None

async def generate_token_backup(region: str):
    try:
        cred = ACCOUNT_CREDENTIALS.get(region, ACCOUNT_CREDENTIALS["BD"])
        account = f"uid={cred['uid']}&password={cred['password']}"

        token_val, open_id = await get_access_token(account)
        if not token_val or not open_id:
            return None

        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

        config = REGION_CONFIG.get(region, REGION_CONFIG["BD"])
        login_url = LOGIN_URLS.get(region, LOGIN_URLS["BD"])
        url = f"{login_url}/MajorLogin"

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': config['release_version']
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            if resp.status_code != 200:
                return None

            login_res = FreeFire_pb2.LoginRes()
            login_res.ParseFromString(resp.content)
            msg_json = json_format.MessageToJson(login_res)
            msg = json.loads(msg_json)

            return {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + 25200
            }
    except Exception as e:
        print(f"❌ Backup token error for {region}: {e}")
        return None

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Content-Type': "application/x-www-form-urlencoded"}

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(url, data=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("access_token"), data.get("open_id")
                await asyncio.sleep(1)
        except:
            await asyncio.sleep(1)
    return None, None

async def GetAccountInformation(uid, region):
    try:
        token_info = await get_token(region)
        if not token_info:
            return None

        actual_region = token_info.get('region', region)
        token = token_info['token']
        server_url = token_info['server_url']
        config = REGION_CONFIG.get(actual_region, REGION_CONFIG["BD"])

        payload = await json_to_proto(json.dumps({'a': uid, 'b': '7'}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': config['release_version']
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(server_url + '/GetPlayerPersonalShow', data=data_enc, headers=headers)

            if resp.status_code != 200:
                return None

            account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            account_info.ParseFromString(resp.content)
            result = json.loads(json_format.MessageToJson(account_info))

            result["region"] = actual_region
            return result

    except Exception as e:
        return None

# =============================================
# HELPER FOR DUO & BAN STATUS
# =============================================

async def fetch_external_api(url: str):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                return response.json()
    except Exception:
        pass
    return None

def ts_to_bst(ts):
    try:
        dt = datetime.fromtimestamp(int(ts)) + timedelta(hours=6)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (BST)"
    except:
        return "N/A"

# =============================================
# MAIN API
# =============================================

@app.route('/info')
def get_full_info():
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "UID required"}), 400

    try:
        uid_int = int(uid)
    except:
        return jsonify({"error": "Invalid UID"}), 400

    async def try_all_regions_parallel():
        tasks = []
        for region in REGION_PRIORITY:
            tasks.append(asyncio.create_task(GetAccountInformation(uid_int, region)))
        
        try:
            for coro in asyncio.as_completed(tasks, timeout=20):
                try:
                    data = await coro
                    if data:
                        for t in tasks:
                            if not t.done():
                                t.cancel()
                        return data
                except Exception:
                    continue
        except asyncio.TimeoutError:
            pass
        
        for t in tasks:
            if not t.done():
                t.cancel()
        return None

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        account_task = try_all_regions_parallel()
        duo_task = fetch_external_api(f"https://api-free-fire-dou-info-by-ckrpro.vercel.app/api/duo?uid={uid}")
        ban_task = fetch_external_api(f"https://amin-team-api.vercel.app/check_banned?player_id={uid}")
        
        account_data, duo_data, ban_data = loop.run_until_complete(
            asyncio.gather(account_task, duo_task, ban_task)
        )
        loop.close()
    except Exception as e:
        print(f"❌ Global error: {e}")
        account_data, duo_data, ban_data = None, None, None

    if not account_data:
        return jsonify({"error": "Player not found"}), 404

    used_region = account_data.get("region", "Unknown")

    basic = account_data.get("basicInfo", {})
    clan = account_data.get("clanBasicInfo", {})
    social = account_data.get("socialInfo", {})
    credit = account_data.get("creditScoreInfo", {})
    captain = account_data.get("captainBasicInfo", {})

    # Ban status resolution
    ban_status = "UNKNOWN"
    if ban_data and isinstance(ban_data, dict):
        ban_status = ban_data.get("status", "UNKNOWN")

    # Duo info checking
    formatted_duo = "Duo not found"
    if duo_data and isinstance(duo_data, dict):
        inner_data = duo_data.get("data")
        if inner_data and isinstance(inner_data, dict) and inner_data.get("partner_uid"):
            formatted_duo = inner_data

    response = {
        "status": "success",
        "server_used": used_region,
        "BanStatus": ban_status,
        "BasicInformation": {
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Region": basic.get("region", used_region),
            "Bio": social.get("signature", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Likes": basic.get("liked", "N/A"),
            "CreateDate": ts_to_bst(basic.get("createAt", 0)),
            "LastLoginDate": ts_to_bst(basic.get("lastLoginAt", 0))
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A"),
            "MaxMembers": clan.get("capacity", "N/A"),
            "LeaderName": captain.get("nickname", "N/A"),
            "LeaderUID": captain.get("accountId", "N/A"),
            "LeaderLevel": captain.get("level", "N/A")
        },
        "DuoInformation": formatted_duo,
        "DeveloperInfo": {
            "Dev": "ckrpro",
            "TikTok": "ckr unknown",
            "YouTube": "ckr unknown"
        }
    }

    return jsonify(response)

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "version": "OB55",
        "endpoint": "/info?uid=UID",
        "example": "/info?uid=2084018498",
        "priority": "BD → IND → BR",
        "Dev": "ckrpro",
        "TikTok": "ckr unknown",
        "YouTube": "ckr unknown"
    })

@app.route('/status')
def token_status():
    status = {}
    for region, info in _token_cache.items():
        expires_in = info['expires_at'] - time.time()
        status[region] = {"has_token": True, "expires_in": f"{expires_in/3600:.1f} hours"}
    return jsonify({"total_tokens": len(_token_cache), "tokens": status})

# =============================================
# Local dev entry point
# =============================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
