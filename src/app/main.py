from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from PIL import Image
import io
import torch

# Импорты из проекта
from app.model_loader import load_model
from app.image_utils import preprocess_image, postprocess_mask, decode_ade20k_mask
from app.auth import (
    Token,
    authenticate_user,
    create_access_token,
    get_current_active_user,
    check_role,
    fake_users_db
)


app = FastAPI(title="ML Model Serving - UperNet Segmentation")

# Загрузка модели
try:
    model = load_model()
except Exception as e:
    raise RuntimeError(f"Не удалось загрузить модель: {e}")


# === Модели данных для API ===
class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# === Эндпоинты ===
@app.get("/health")
def health_check():
    return {"status": "OK"}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_active_user)):
    return current_user


@app.post("/segment")
async def segment_image(
    file: UploadFile = File(...),
    current_user: dict = Depends(check_role("user"))  # Требуется роль 'user' или 'admin'
):
    try:
        image = Image.open(io.BytesIO(await file.read())).convert("RGB")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ошибка чтения изображения: {e}")

    pixel_values = preprocess_image(image)

    with torch.no_grad():
        outputs = model(pixel_values=pixel_values)

    mask = postprocess_mask(outputs)
    result_image = decode_ade20k_mask(mask)

    byte_io = io.BytesIO()
    result_image.save(byte_io, format='PNG')
    byte_io.seek(0)

    return StreamingResponse(byte_io, media_type="image/png")