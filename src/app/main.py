from fastapi import FastAPI, File, UploadFile
from fastapi.responses import StreamingResponse
from PIL import Image
import io
import torch

from app.model_loader import load_model
from app.image_utils import preprocess_image, postprocess_mask, decode_ade20k_mask

app = FastAPI(title="ML Model Serving - UperNet Segmentation")

# Загрузка модели
try:
    model = load_model()
except Exception as e:
    raise RuntimeError(f"Не удалось загрузить модель: {e}")

@app.get("/health")
def health_check():
    return {"status": "OK"}

@app.post("/segment")
async def segment_image(file: UploadFile = File(...)):
    try:
        image = Image.open(io.BytesIO(await file.read())).convert("RGB")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ошибка чтения изображения: {e}")

    # Предобработка
    pixel_values = preprocess_image(image)

    # Инференс
    with torch.no_grad():
        outputs = model(pixel_values=pixel_values)

    # Постобработка
    mask = postprocess_mask(outputs)
    result_image = decode_ade20k_mask(mask)

    # Подготавливаем к отправке
    byte_io = io.BytesIO()
    result_image.save(byte_io, format='PNG')
    byte_io.seek(0)

    return StreamingResponse(byte_io, media_type="image/png")