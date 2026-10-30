"""
schemas/auth.py
================
Pydantic models for authentication endpoints.

Security hardening:
  - Password minimum length raised from 8 → 12 characters.
  - Complexity enforced: must contain at least one uppercase, one lowercase,
    one digit, and one special character.
  - UserRegisterAcceptedResponse added for the opaque 202 registration shape.
"""

import re
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Accepts any properly-formatted email including internal/enterprise domains
# (.local, .corp, .internal, .test, etc.)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    re.IGNORECASE,
)

# Special characters accepted for password complexity check
_SPECIAL_CHARS = set(r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~""")


def validate_password_complexity_rules(v: str) -> str:
    """
    Enforce complexity rules to resist brute-force and credential stuffing.
    Requirements:
      - Minimum 12 characters (enforced by Field min_length)
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character from the allowed set
      - Pattern & entropy checks (zxcvbn + character diversity check)
    """
    errors = []
    if not any(c.isupper() for c in v):
        errors.append("at least one uppercase letter")
    if not any(c.islower() for c in v):
        errors.append("at least one lowercase letter")
    if not any(c.isdigit() for c in v):
        errors.append("at least one digit (0-9)")
    if not any(c in _SPECIAL_CHARS for c in v):
        errors.append("at least one special character (!@#$%^&* etc.)")
    if errors:
        raise ValueError(
            "Password must contain: " + ", ".join(errors)
        )

    # Entropy & pattern resistance (preventing e.g. Aaaaaaaaaa1!)
    if len(set(v)) < 5:
        raise ValueError("Password entropy too low: must contain at least 5 unique characters")
    if any(v.count(c) > len(v) * 0.5 for c in set(v)):
        raise ValueError("Password entropy too low: contains excessively repetitive characters")

    try:
        import zxcvbn
        result = zxcvbn.zxcvbn(v)
        if result.get("score", 0) < 3:
            raise ValueError(
                f"Password is too easy to guess (entropy score {result.get('score', 0)}/4). Avoid dictionary words or common patterns."
            )
    except ImportError:
        raise ValueError(
            "zxcvbn is not installed! Password entropy checks cannot be enforced. "
            "Failing closed to prevent insecure registrations."
        )

    return v


class UserRegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=12,
        description=(
            "Password (min 12 chars, must contain uppercase, lowercase, "
            "digit, and special character)"
        ),
    )

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format — accepts internal/enterprise domains."""
        v = str(v).strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address format")
        return v

    @field_validator("password", mode="after")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        return validate_password_complexity_rules(v)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "analyst@example.com",
                "password": "C0rr3ct-H0rse!Batt3ry",
            }
        }
    )


class PasswordResetRequest(BaseModel):
    email: str = Field(..., description="User email address")

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format — accepts internal/enterprise domains."""
        v = str(v).strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address format")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "analyst@example.com",
            }
        }
    )


class PasswordResetResponse(BaseModel):
    message: str = (
        "If this email is associated with an active account, a password reset link has been dispatched."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": (
                    "If this email is associated with an active account, "
                    "a password reset link has been dispatched."
                )
            }
        }
    )


class PasswordResetConfirmRequest(BaseModel):
    token: str = Field(..., min_length=10, description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=12,
        description=(
            "New password (min 12 chars, must contain uppercase, lowercase, "
            "digit, and special character)"
        ),
    )

    @field_validator("new_password", mode="after")
    @classmethod
    def validate_new_password_complexity(cls, v: str) -> str:
        return validate_password_complexity_rules(v)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "new_password": "C0rr3ct-H0rse!Batt3ry-N3w",
            }
        }
    )


class PasswordResetConfirmResponse(BaseModel):
    message: str = (
        "Password has been reset successfully. You may now log in with your new password."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Password has been reset successfully. You may now log in with your new password."
            }
        }
    )


class UserRegisterAcceptedResponse(BaseModel):
    """
    Opaque 202 response for both new registrations and duplicate-email
    attempts (registration oracle prevention).
    The caller cannot distinguish between these two cases.
    """
    message: str = (
        "If this email is eligible for registration, your account has been created. "
        "You may now log in."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": (
                    "If this email is eligible for registration, "
                    "your account has been created. You may now log in."
                )
            }
        }
    )


class UserResponse(BaseModel):
    id: str
    email: str
    is_active: bool
    is_verified: bool = False

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
            }
        }
    )


class EmailVerificationRequest(BaseModel):
    email: str = Field(..., description="User email address")

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format — accepts internal/enterprise domains."""
        v = str(v).strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address format")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "analyst@example.com",
            }
        }
    )


class EmailVerificationResponse(BaseModel):
    message: str = (
        "If this email is associated with an eligible account, a verification link has been dispatched."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": (
                    "If this email is associated with an eligible account, "
                    "a verification link has been dispatched."
                )
            }
        }
    )


class EmailVerificationConfirmRequest(BaseModel):
    token: str = Field(..., min_length=10, description="Email verification token")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            }
        }
    )


class EmailVerificationConfirmResponse(BaseModel):
    message: str = (
        "Email has been successfully verified. You may now access all system features."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Email has been successfully verified. You may now access all system features."
            }
        }
    )
