"""
auth/routes.py
================
Authentication endpoints: register and login.


"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from jwt.exceptions import PyJWTError as JWTError
from config import settings
from auth.jwt import (
    create_access_token,
    revoke_token,
    create_password_reset_token,
    decode_password_reset_token,
    create_email_verification_token,
    decode_email_verification_token,
)
from auth.dependencies import OAuth2PasswordRequestForm, oauth2_scheme
from auth.security import (
    hash_password,
    verify_password_with_migration,
    check_account_lockout,
    record_failed_login,
    reset_failed_login,
    check_pwned_password,
    record_legacy_bcrypt_metric,
)
from database.database import get_db
from database.models import User
from schemas.auth import (
    TokenResponse,
    UserRegisterRequest,
    UserRegisterAcceptedResponse,
    PasswordResetRequest,
    PasswordResetResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    EmailVerificationRequest,
    EmailVerificationResponse,
    EmailVerificationConfirmRequest,
    EmailVerificationConfirmResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ─── Pre-computed dummy hash ────────────────────────────────────────────────
# Always run verify_password() against this hash when the looked-up user is
# None. bcrypt takes the same wall-clock time regardless of whether the user
# exists, so an attacker cannot enumerate valid accounts by measuring response
# latency.
#
# The hash is for the string "dummy-password-that-will-never-match" and was
# generated once with hash_password(). It never changes at runtime; it exists
# only to ensure the bcrypt work-factor is always paid.
_DUMMY_HASH: str = hash_password("dummy-password-scythe-timing-guard-v1")


def _send_verification_email(recipient_email: str, token: str) -> None:
    """Send email verification link via configured SMTP gateway."""
    smtp_host = getattr(settings, "SMTP_HOST", "")
    if not smtp_host:
        return
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    msg = MIMEMultipart()
    msg["From"] = getattr(settings, "SMTP_FROM", "noreply@scythe.local")
    msg["To"] = recipient_email
    msg["Subject"] = "Verify Your SCYTHE Email Address"

    body = (
        f"Please verify your email address for your SCYTHE account ({recipient_email}).\n\n"
        f"Your verification token is:\n{token}\n\n"
        f"This token is valid for 24 hours.\n"
        f"If you did not request this, please ignore this email."
    )
    msg.attach(MIMEText(body, "plain"))

    port = getattr(settings, "SMTP_PORT", 587)
    with smtplib.SMTP(smtp_host, port, timeout=10) as server:
        if getattr(settings, "SMTP_TLS", True):
            server.starttls()
        user = getattr(settings, "SMTP_USER", None)
        pwd = getattr(settings, "SMTP_PASSWORD", None)
        if user and pwd:
            server.login(user, pwd)
        server.send_message(msg)


def _dispatch_verification_token(email: str, token: str) -> None:
    """
    Dispatch verification token via email if SMTP is configured in production,
    otherwise log the token only in local development.
    """
    email_sent = False
    smtp_host = getattr(settings, "SMTP_HOST", "")
    if smtp_host and settings.is_production:
        try:
            _send_verification_email(email, token)
            email_sent = True
        except Exception as e:
            logger.error("Failed to send verification email to %s: %s", email, e)

    if not email_sent and not settings.is_production:
        logger.info(
            "[EMAIL_VERIFICATION_TOKEN] Generated email verification token for %s: %s (expires in 24 hours)",
            email,
            token,
        )
    elif not email_sent:
        logger.warning("Verification email unavailable for %s; token was not logged", email)


@router.post(
    "/register",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=UserRegisterAcceptedResponse,
)
def register(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> UserRegisterAcceptedResponse:
    """
    Register a new account.

    Always returns 202 Accepted with a generic message — never 409
    Conflict — so that unauthenticated callers cannot determine whether a
    given email address already exists in the system.
    """
    try:
        if check_pwned_password(payload.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password has appeared in public data breaches (k-anonymity HIBP check). Please choose a unique, unbreached password.",
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )

    email = (payload.email or "").lower().strip()
    existing = db.query(User).filter(User.email == email).first()

    # Always pay the bcrypt cost -- whether or not this email is already
    # registered -- so response timing cannot be used to distinguish the
    # two outcomes. The computed hash is simply discarded on the
    # duplicate-email path.
    hashed_password = hash_password(payload.password)

    if existing is not None:
        # Do NOT reveal that this email is already registered.
        # Return the same 202 shape so callers cannot tell the difference,
        # and (as of this fix) take the same amount of time to do it.
        _ = create_email_verification_token(user_id="dummy-user-id", email=email)
        logger.info("Registration attempted for existing email (returning 202 to caller)")
        return UserRegisterAcceptedResponse()

    user = User(
        email=email,
        hashed_password=hashed_password,
        is_verified=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("New user registered: %s", email)

    verification_token = create_email_verification_token(user_id=user.id, email=user.email)
    _dispatch_verification_token(user.email, verification_token)

    return UserRegisterAcceptedResponse()


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate and return a JWT access token.

    Timing-attack mitigation:
    verify_password_with_migration() is called unconditionally. When the user is not
    found we compare against _DUMMY_HASH, ensuring the bcrypt work-factor
    is always paid and response time does not leak whether the email exists.
    """
    email = (form_data.username or "").lower().strip()
    client_ip = request.client.host if request.client else None
    try:
        if check_account_lockout(email, client_ip):
            logger.warning("Login blocked for locked account: %s", email)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked due to excessive failed login attempts. Please try again later.",
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable",
        )

    user = db.query(User).filter(User.email == email).first()

    # Always run the password hash comparison — even when user is None —
    # so the response time is identical regardless of whether the account
    # exists. The result of the comparison is only used when user is not None.
    password_hash_to_check = user.hashed_password if user is not None else _DUMMY_HASH
    password_valid, needs_rehash = verify_password_with_migration(form_data.password, password_hash_to_check)

    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if user is None or not password_valid:
        record_failed_login(email, client_ip)
        raise invalid_credentials

    # is_active check BEFORE resetting lockout counters — an inactive user
    # with a known correct password must not be able to reset their lockout
    # counter (which would give them unlimited brute-force attempts once they
    # somehow become active again, and leaks that their password is correct).
    if hasattr(user, "is_active") and not user.is_active:
        # Return 401 (not 400) to avoid leaking that the account exists
        # and that the correct password was supplied.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    reset_failed_login(email, client_ip)

    # Automatic hash rotation: upgrade legacy hash to SHA-256 pre-hashed format on successful login
    if needs_rehash:
        record_legacy_bcrypt_metric()
        user.hashed_password = hash_password(form_data.password)
        db.commit()
        logger.warning(
            "[Legacy Bcrypt Alert] User %s authenticated via legacy truncated bcrypt path. "
            "Upgraded hash automatically. Monitor metric to disable ALLOW_LEGACY_BCRYPT once zero.",
            user.email,
        )

    access_token = create_access_token(data={"sub": user.id})
    return TokenResponse(access_token=access_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Response:
    """
    Revoke the current JWT bearer token.
    Adds the token's jti to the Redis blacklist with a TTL matching the token expiration,
    and persists to RevokedToken table in Postgres.
    """
    revoke_token(token, db=db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _send_password_reset_email(recipient_email: str, token: str) -> None:
    """Send password reset email via configured SMTP gateway."""
    smtp_host = getattr(settings, "SMTP_HOST", "")
    if not smtp_host:
        return
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    msg = MIMEMultipart()
    msg["From"] = getattr(settings, "SMTP_FROM", "noreply@scythe.local")
    msg["To"] = recipient_email
    msg["Subject"] = "SCYTHE Password Reset Request"

    body = (
        f"A password reset was requested for your SCYTHE account ({recipient_email}).\n\n"
        f"Your reset token is:\n{token}\n\n"
        f"This token is valid for 15 minutes.\n"
        f"If you did not request this, please ignore this email."
    )
    msg.attach(MIMEText(body, "plain"))

    port = getattr(settings, "SMTP_PORT", 587)
    with smtplib.SMTP(smtp_host, port, timeout=10) as server:
        if getattr(settings, "SMTP_TLS", True):
            server.starttls()
        user = getattr(settings, "SMTP_USER", None)
        pwd = getattr(settings, "SMTP_PASSWORD", None)
        if user and pwd:
            server.login(user, pwd)
        server.send_message(msg)


@router.post(
    "/password-reset/request",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=PasswordResetResponse,
)
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db),
) -> PasswordResetResponse:
    """
    Initiate a password reset request.

    Always returns 202 Accepted with a generic message to prevent account enumeration.
    Generates a cryptographically signed, 15-minute time-limited reset token.
    If an email gateway is configured in production, sends the reset token via email.
    In local development, the token may be logged for testing. Production never logs it.
    """
    email = (payload.email or "").lower().strip()
    user = db.query(User).filter(User.email == email).first()

    if user is not None and user.is_active:
        reset_token = create_password_reset_token(user_id=user.id, email=user.email)
        email_sent = False
        smtp_host = getattr(settings, "SMTP_HOST", "")
        if smtp_host and settings.is_production:
            try:
                _send_password_reset_email(user.email, reset_token)
                email_sent = True
            except Exception as e:
                logger.error("Failed to send password reset email to %s: %s", email, e)

        if not email_sent and not settings.is_production:
            logger.info(
                "[PASSWORD_RESET_TOKEN] Generated password reset token for %s: %s (expires in 15 minutes)",
                email,
                reset_token,
            )
        elif not email_sent:
            logger.warning("Password reset email unavailable for %s; token was not logged", email)
    else:
        # Constant-time mitigation: pay JWT generation cost for dummy subject
        _ = create_password_reset_token(user_id="dummy-user-id", email=email)
        logger.info("Password reset requested for non-existent or inactive email (returning 202 to caller)")

    return PasswordResetResponse()


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_200_OK,
    response_model=PasswordResetConfirmResponse,
)
def confirm_password_reset(
    request: Request,
    payload: PasswordResetConfirmRequest,
    db: Session = Depends(get_db),
) -> PasswordResetConfirmResponse:
    """
    Confirm password reset with token and new password.

    Validates token signature, expiration, and revocation status.
    Enforces password complexity and HIBP breach checks.
    Updates User.hashed_password, invalidates the reset token immediately,
    and clears any failed-login lockout counters.
    """
    # 1. Validate token
    try:
        token_payload = decode_password_reset_token(payload.token, db=db)
    except JWTError as e:
        logger.warning("Invalid password reset token rejected: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    user_id = token_payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    # 2. Check HaveIBeenPwned for breached password
    try:
        if check_pwned_password(payload.new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password has appeared in public data breaches (k-anonymity HIBP check). Please choose a unique, unbreached password.",
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )

    # 3. Find user
    # Serialize reset attempts for the same account. This prevents concurrent
    # submissions of one reset token from both passing the single-use check.
    user = db.query(User).filter(User.id == user_id).with_for_update().first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    # Recheck after acquiring the account lock so a concurrent request that
    # already consumed this token cannot also update the password.
    try:
        token_payload = decode_password_reset_token(payload.token, db=db)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    # 4. Hash new password and persist the password and token revocation together.
    user.hashed_password = hash_password(payload.new_password)
    if not revoke_token(payload.token, db=db, commit=False):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset could not be completed. Please retry.",
        )
    db.commit()

    # 6. Reset any failed login lockout counters for this account
    client_ip = request.client.host if request.client else None
    reset_failed_login(user.email, client_ip)

    logger.info("Password successfully reset for user %s", user.email)
    return PasswordResetConfirmResponse()


@router.post(
    "/verify-email/request",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=EmailVerificationResponse,
)
def request_email_verification(
    payload: EmailVerificationRequest,
    db: Session = Depends(get_db),
) -> EmailVerificationResponse:
    """
    Initiate an email verification request.

    Always returns 202 Accepted with a generic message to prevent account enumeration.
    Generates a cryptographically signed, 24-hour time-limited verification token.
    If an email gateway is configured in production, sends the verification token via email.
    In local development, a token may be logged for testing. Production never logs it.
    """
    email = (payload.email or "").lower().strip()
    user = db.query(User).filter(User.email == email).first()

    if user is not None and user.is_active and not user.is_verified:
        token = create_email_verification_token(user_id=user.id, email=user.email)
        _dispatch_verification_token(user.email, token)
    else:
        # Constant-time mitigation: pay JWT generation cost for dummy subject
        _ = create_email_verification_token(user_id="dummy-user-id", email=email)
        logger.info("Email verification requested for non-existent, inactive, or already-verified email (returning 202 to caller)")

    return EmailVerificationResponse()


@router.post(
    "/verify-email/confirm",
    status_code=status.HTTP_200_OK,
    response_model=EmailVerificationConfirmResponse,
)
def confirm_email_verification(
    payload: EmailVerificationConfirmRequest,
    db: Session = Depends(get_db),
) -> EmailVerificationConfirmResponse:
    """
    Confirm email verification using token.

    Validates token signature, expiration, audience, scope, and revocation status.
    Updates User.is_verified = True, and invalidates the verification token immediately
    in Redis and the database RevokedToken table so it cannot be reused.
    """
    try:
        token_payload = decode_email_verification_token(payload.token, db=db)
    except JWTError as e:
        logger.warning("Invalid email verification token rejected: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token.",
        )

    user_id = token_payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token.",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email verification token.",
        )

    user.is_verified = True
    db.commit()

    # Invalidate verification token so it is single-use
    revoke_token(payload.token, db=db)

    logger.info("Email successfully verified for user %s", user.email)
    return EmailVerificationConfirmResponse()