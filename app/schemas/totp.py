from pydantic import BaseModel, Field


class TOTPSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_data_uri: str
    backup_codes: list[str]


class TOTPEnableRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6)


class TOTPDisableRequest(BaseModel):
    password: str
    totp_code: str = Field(min_length=6, max_length=6)
