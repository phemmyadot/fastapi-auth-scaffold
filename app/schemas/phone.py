from pydantic import BaseModel, Field


class SendOTPRequest(BaseModel):
    phone_number: str = Field(min_length=10, max_length=20)


class VerifyOTPRequest(BaseModel):
    otp_code: str = Field(min_length=6, max_length=6)
