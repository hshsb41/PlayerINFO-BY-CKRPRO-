import asyncio
import time
import httpx
import json
import sys

from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from datetime import datetime, timedelta
from google.protobuf import json_format


# ============================================================
# CKRPRO FF — FREE FIRE INFO API
# ============================================================

try:
    import FreeFire_pb2
    import main_pb2
    import AccountPersonalShow_pb2

    print("✅ Proto files imported successfully")

except ImportError as e:
    print(f"❌ Proto import error: {e}")
    sys.exit(1)


# ============================================================
# CONFIG
# ============================================================

RELEASEVERSION = "OB55"

USERAGENT = (
    "Dalvik/2.1.0 (Linux; U; Android 14; "
    "CPH2095 Build/RKQ1.211119.001)"
)

MAIN_KEY = b"Yg&tc%DEuh6%Zc^8"
MAIN_IV = b"6oyZDr22E3ychjM%"


# ============================================================
# JWT API
# ============================================================

JWT_API_BASE = (
    "https://ff-jwt-gen-api.lovable.app/api/public/token"
)


# ============================================================
# ACCOUNT CREDENTIALS
# ============================================================

BD_CREDS = {
    "uid": "4423054565",
    "password": "CKR_PRO_BOT_WF9AMKXDI"
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


# ============================================================
# REGION CONFIG
# ============================================================

REGION_CONFIG = {

    "BD": {
        "server_url":
            "https://clientbp.ppmainecoonghj.com",
        "release_version":
            "OB55"
    },

    "IND": {
        "server_url":
            "https://client.ind.freefiremobile.com",
        "release_version":
            "OB55"
    },

    "BR": {
        "server_url":
            "https://client.us.freefiremobile.com",
        "release_version":
            "OB55"
    }
}


LOGIN_URLS = {

    "BD":
        "https://loginbp.ppmainecoonghj.com",

    "IND":
        "https://loginbp.ppmainecoonghj.com",

    "BR":
        "https://loginbp.ppmainecoonghj.com"
}


REGION_PRIORITY = [
    "BD",
    "IND",
    "BR"
]


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
# TOKEN CACHE
# ============================================================

_token_cache = {}


# ============================================================
# JWT TOKEN FROM API
# ============================================================

async def get_jwt_token_from_api(region):

    cred = ACCOUNT_CREDENTIALS.get(region)

    if not cred:
        return None

    url = (
        f"{JWT_API_BASE}"
        f"?uid={cred['uid']}"
        f"&password={cred['password']}"
    )

    headers = {
        "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36",

        "Accept":
            "application/json"
    }

    try:

        async with httpx.AsyncClient(
            timeout=10.0
        ) as client:

            response = await client.get(
                url,
                headers=headers
            )

            if response.status_code != 200:
                return None

            data = response.json()

            token = data.get("token")

            if not token:
                return None

            api_region = data.get(
                "region",
                region
            )

            config = REGION_CONFIG.get(
                api_region,
                REGION_CONFIG["BD"]
            )

            return {

                "token":
                    f"Bearer {token}",

                "region":
                    api_region,

                "server_url":
                    config["server_url"],

                "expires_at":
                    time.time() + 25200
            }

    except Exception as e:

        print(
            f"❌ JWT API error [{region}]: {e}"
        )

        return None


# ============================================================
# TOKEN GETTER
# ============================================================

async def get_token(region):

    cached = _token_cache.get(region)

    if (
        cached
        and cached.get(
            "expires_at",
            0
        ) > time.time()
    ):
        return cached

    token_info = await get_jwt_token_from_api(
        region
    )

    if not token_info:

        token_info = await generate_token_backup(
            region
        )

    if token_info:

        _token_cache[region] = token_info

        return token_info

    return None


# ============================================================
# BACKUP TOKEN
# ============================================================

async def generate_token_backup(region):

    try:

        cred = ACCOUNT_CREDENTIALS.get(
            region,
            ACCOUNT_CREDENTIALS["BD"]
        )

        account = (
            f"uid={cred['uid']}"
            f"&password={cred['password']}"
        )

        token_val, open_id = (
            await get_access_token(account)
        )

        if not token_val or not open_id:
            return None

        body = json.dumps({

            "open_id":
                open_id,

            "open_id_type":
                "4",

            "login_token":
                token_val,

            "orign_platform_type":
                "4"
        })

        proto_bytes = await json_to_proto(
            body,
            FreeFire_pb2.LoginReq()
        )

        payload = aes_cbc_encrypt(
            MAIN_KEY,
            MAIN_IV,
            proto_bytes
        )

        config = REGION_CONFIG.get(
            region,
            REGION_CONFIG["BD"]
        )

        login_url = LOGIN_URLS.get(
            region,
            LOGIN_URLS["BD"]
        )

        headers = {

            "User-Agent":
                USERAGENT,

            "Connection":
                "Keep-Alive",

            "Accept-Encoding":
                "gzip",

            "Content-Type":
                "application/octet-stream",

            "X-Unity-Version":
                "2018.4.11f1",

            "X-GA":
                "v1 1",

            "ReleaseVersion":
                config["release_version"]
        }

        async with httpx.AsyncClient(
            timeout=20.0
        ) as client:

            response = await client.post(
                f"{login_url}/MajorLogin",
                data=payload,
                headers=headers
            )

            if response.status_code != 200:
                return None

            login_res = (
                FreeFire_pb2.LoginRes()
            )

            login_res.ParseFromString(
                response.content
            )

            msg = json.loads(
                json_format.MessageToJson(
                    login_res
                )
            )

            token = msg.get(
                "token",
                ""
            )

            if not token:
                return None

            return {

                "token":
                    f"Bearer {token}",

                "region":
                    msg.get(
                        "lockRegion",
                        region
                    ),

                "server_url":
                    msg.get(
                        "serverUrl",
                        config["server_url"]
                    ),

                "expires_at":
                    time.time() + 25200
            }

    except Exception as e:

        print(
            f"❌ Backup token error "
            f"[{region}]: {e}"
        )

        return None


# ============================================================
# AES
# ============================================================

def pad(data):

    padding_length = (
        AES.block_size -
        len(data) % AES.block_size
    )

    return (
        data +
        bytes(
            [padding_length] *
            padding_length
        )
    )


def aes_cbc_encrypt(
    key,
    iv,
    plaintext
):

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    return cipher.encrypt(
        pad(plaintext)
    )


# ============================================================
# JSON → PROTO
# ============================================================

async def json_to_proto(
    json_data,
    proto_message
):

    json_format.ParseDict(
        json.loads(json_data),
        proto_message
    )

    return proto_message.SerializeToString()


# ============================================================
# ACCESS TOKEN
# ============================================================

async def get_access_token(account):

    url = (
        "https://ffmconnect.live.gop.garenanow.com/"
        "oauth/guest/token/grant"
    )

    payload = (
        account
        + "&response_type=token"
        + "&client_type=2"
        + "&client_secret="
        "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        + "&client_id=100067"
    )

    headers = {

        "User-Agent":
            USERAGENT,

        "Content-Type":
            "application/x-www-form-urlencoded"
    }

    for _ in range(2):

        try:

            async with httpx.AsyncClient(
                timeout=20.0
            ) as client:

                response = await client.post(
                    url,
                    data=payload,
                    headers=headers
                )

                if response.status_code == 200:

                    data = response.json()

                    return (
                        data.get(
                            "access_token"
                        ),
                        data.get(
                            "open_id"
                        )
                    )

                await asyncio.sleep(1)

        except Exception:

            await asyncio.sleep(1)

    return None, None


# ============================================================
# GET ACCOUNT INFORMATION
# ============================================================

async def GetAccountInformation(
    uid,
    region
):

    try:

        token_info = await get_token(
            region
        )

        if not token_info:
            return None

        actual_region = token_info.get(
            "region",
            region
        )

        token = token_info.get(
            "token"
        )

        server_url = token_info.get(
            "server_url"
        )

        config = REGION_CONFIG.get(
            actual_region,
            REGION_CONFIG["BD"]
        )

        payload = await json_to_proto(

            json.dumps({
                "a": uid,
                "b": "7"
            }),

            main_pb2.GetPlayerPersonalShow()
        )

        encrypted_data = aes_cbc_encrypt(
            MAIN_KEY,
            MAIN_IV,
            payload
        )

        headers = {

            "User-Agent":
                USERAGENT,

            "Connection":
                "Keep-Alive",

            "Accept-Encoding":
                "gzip",

            "Content-Type":
                "application/octet-stream",

            "Authorization":
                token,

            "X-Unity-Version":
                "2018.4.11f1",

            "X-GA":
                "v1 1",

            "ReleaseVersion":
                config["release_version"]
        }

        async with httpx.AsyncClient(
            timeout=15.0
        ) as client:

            response = await client.post(

                server_url +
                "/GetPlayerPersonalShow",

                data=encrypted_data,

                headers=headers
            )

            if response.status_code != 200:
                return None

            account_info = (
                AccountPersonalShow_pb2
                .AccountPersonalShowInfo()
            )

            account_info.ParseFromString(
                response.content
            )

            result = json.loads(
                json_format.MessageToJson(
                    account_info
                )
            )

            result["region"] = (
                actual_region
            )

            return result

    except Exception as e:

        print(
            f"❌ Account error "
            f"[{region}]: {e}"
        )

        return None


# ============================================================
# EXTERNAL API
# ============================================================

async def fetch_external_api(url):

    try:

        async with httpx.AsyncClient(
            timeout=5.0
        ) as client:

            response = await client.get(
                url
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return None


# ============================================================
# DATE FORMAT
# ============================================================

def ts_to_bst(ts):

    try:

        if not ts:
            return "N/A"

        dt = (
            datetime.fromtimestamp(
                int(ts)
            )
            + timedelta(hours=6)
        )

        return (
            dt.strftime(
                "%d %b %Y at %I:%M:%S %p"
            )
            + " (BST)"
        )

    except Exception:

        return "N/A"


# ============================================================
# /INFO
# ============================================================

@app.route("/info")
def get_full_info():

    uid = request.args.get(
        "uid"
    )

    if not uid:

        return jsonify({
            "error":
                "UID required"
        }), 400

    try:

        uid_int = int(uid)

    except Exception:

        return jsonify({
            "error":
                "Invalid UID"
        }), 400


    # --------------------------------------------------------
    # SEARCH ALL REGIONS
    # --------------------------------------------------------

    async def try_all_regions():

        tasks = []

        for region in REGION_PRIORITY:

            tasks.append(
                asyncio.create_task(
                    GetAccountInformation(
                        uid_int,
                        region
                    )
                )
            )

        try:

            for future in asyncio.as_completed(
                tasks,
                timeout=20
            ):

                try:

                    result = await future

                    if result:

                        for task in tasks:

                            if not task.done():
                                task.cancel()

                        return result

                except Exception:
                    continue

        except asyncio.TimeoutError:
            pass

        for task in tasks:

            if not task.done():
                task.cancel()

        return None


    # --------------------------------------------------------
    # RUN ASYNC
    # --------------------------------------------------------

    loop = asyncio.new_event_loop()

    try:

        asyncio.set_event_loop(
            loop
        )

        account_data = (
            loop.run_until_complete(
                asyncio.gather(
                    try_all_regions(),

                    fetch_external_api(
                        "https://api-free-fire-dou-info-by-ckrpro.vercel.app/"
                        f"api/duo?uid={uid}"
                    ),

                    fetch_external_api(
                        "https://amin-team-api.vercel.app/"
                        f"check_banned?player_id={uid}"
                    )
                )
            )
        )

        player_data = account_data[0]
        duo_data = account_data[1]
        ban_data = account_data[2]

    except Exception as e:

        print(
            f"❌ Global error: {e}"
        )

        player_data = None
        duo_data = None
        ban_data = None

    finally:

        loop.close()


    # --------------------------------------------------------
    # PLAYER NOT FOUND
    # --------------------------------------------------------

    if not player_data:

        return jsonify({
            "error":
                "Player not found"
        }), 404


    # ========================================================
    # ORIGINAL DATA
    # ========================================================

    used_region = player_data.get(
        "region",
        "Unknown"
    )

    basic = player_data.get(
        "basicInfo",
        {}
    ) or {}

    clan = player_data.get(
        "clanBasicInfo",
        {}
    ) or {}

    social = player_data.get(
        "socialInfo",
        {}
    ) or {}

    credit = player_data.get(
        "creditScoreInfo",
        {}
    ) or {}

    captain = player_data.get(
        "captainBasicInfo",
        {}
    ) or {}


    # ========================================================
    # BAN
    # ========================================================

    ban_status = "UNKNOWN"

    if isinstance(
        ban_data,
        dict
    ):

        ban_status = ban_data.get(
            "status",
            "UNKNOWN"
        )


    # ========================================================
    # DUO
    # ========================================================

    formatted_duo = (
        "Duo not found"
    )

    if isinstance(
        duo_data,
        dict
    ):

        inner_data = duo_data.get(
            "data"
        )

        if (
            isinstance(
                inner_data,
                dict
            )
            and inner_data.get(
                "partner_uid"
            )
        ):

            formatted_duo = inner_data


    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    response = {

        "status":
            "success",

        "server_used":
            used_region,

        "BanStatus":
            ban_status,


        # ====================================================
        # BASIC INFORMATION
        # ====================================================

        "BasicInformation": {

            "Name":
                basic.get(
                    "nickname",
                    "N/A"
                ),

            "UID":
                uid,

            "Region":
                basic.get(
                    "region",
                    used_region
                ),

            "Bio":
                social.get(
                    "signature",
                    "N/A"
                ),

            "HonorScore":
                credit.get(
                    "creditScore",
                    "N/A"
                ),

            "Level":
                basic.get(
                    "level",
                    "N/A"
                ),

            "Exp":
                basic.get(
                    "exp",
                    "N/A"
                ),

            "Likes":
                basic.get(
                    "liked",
                    "N/A"
                ),

            "CreateDate":
                ts_to_bst(
                    basic.get(
                        "createAt",
                        0
                    )
                ),

            "LastLoginDate":
                ts_to_bst(
                    basic.get(
                        "lastLoginAt",
                        0
                    )
                )
        },


        # ====================================================
        # GUILD
        # ====================================================

        "GuildInformation": {

            "GuildName":
                clan.get(
                    "clanName",
                    "No Guild"
                ),

            "GuildID":
                clan.get(
                    "clanId",
                    "N/A"
                ),

            "GuildLevel":
                clan.get(
                    "clanLevel",
                    "N/A"
                ),

            "LiveMembers":
                clan.get(
                    "memberNum",
                    "N/A"
                ),

            "MaxMembers":
                clan.get(
                    "capacity",
                    "N/A"
                ),

            "LeaderName":
                captain.get(
                    "nickname",
                    "N/A"
                ),

            "LeaderUID":
                captain.get(
                    "accountId",
                    "N/A"
                ),

            "LeaderLevel":
                captain.get(
                    "level",
                    "N/A"
                )
        },


        # ====================================================
        # DUO
        # ====================================================

        "DuoInformation":
            formatted_duo,


        # ====================================================
        # DEVELOPER
        # ====================================================

        "DeveloperInfo": {

            "Dev":
                "ckrpro",

            "TikTok":
                "ckr unknown",

            "YouTube":
                "ckr unknown"
        }
    }


    return jsonify(
        response
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "status":
            "running",

        "name":
            "CKRPRO FF",

        "version":
            "OB55",

        "endpoint":
            "/info?uid=UID",

        "example":
            "/info?uid=2084018498",

        "priority":
            "BD → IND → BR",

        "Dev":
            "ckrpro",

        "TikTok":
            "ckr unknown",

        "YouTube":
            "ckr unknown"
    })


# ============================================================
# STATUS
# ============================================================

@app.route("/status")
def token_status():

    status = {}

    for region, info in _token_cache.items():

        expires_in = (
            info["expires_at"]
            - time.time()
        )

        status[region] = {

            "has_token":
                True,

            "expires_in":
                f"{expires_in / 3600:.1f} hours"
        }

    return jsonify({

        "total_tokens":
            len(_token_cache),

        "tokens":
            status
    })


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    print(
        "=========================================="
    )

    print(
        "🚀 CKRPRO FF API"
    )

    print(
        "📡 /info?uid=UID"
    )

    print(
        "🌍 BD → IND → BR"
    )

    print(
        "=========================================="
    )

    app.run(
        host="0.0.0.0",
        port=5004,
        debug=False
    )