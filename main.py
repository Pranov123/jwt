from fastapi import FastAPI
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timezone
from fastapi.responses import JSONResponse

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-g1pfewmy.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
def verify_token(req: TokenRequest):
    token = req.token

    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE
        )

        # expiry check (extra safety)
        if "exp" in payload:
            if datetime.now(timezone.utc).timestamp() > payload["exp"]:
                return JSONResponse(
                    status_code=401,
                    content={"valid": False}
                )

        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud")
        }

    except JWTError:
        return JSONResponse(
            status_code=401,
            content={"valid": False}
        )