from PIL import Image
import numpy as np
from transformers import AutoImageProcessor

# Используем соответствующий процессор для UperNet + ConvNeXt
image_processor = AutoImageProcessor.from_pretrained("openmmlab/upernet-convnext-tiny")

def preprocess_image(image: Image.Image):
    """Обрабатывает изображение под формат модели"""
    inputs = image_processor(images=image, return_tensors="pt")
    return inputs.pixel_values  # возвращает тензор

def postprocess_mask(outputs):
    """Преобразует выход модели в маску классов"""
    logits = outputs.logits
    mask = logits.argmax(dim=1).squeeze().cpu().numpy()
    return mask

def decode_ade20k_mask(mask):
    """Преобразует маску ADE20K в цветное изображение"""
    ADE20K_COLORS = np.random.randint(0, 255, (150, 3), dtype=np.uint8)

    h, w = mask.shape
    color_mask = np.zeros((h, w, 3), dtype=np.uint8)
    for label in np.unique(mask):
        if label == 0:
            continue  # фон
        color_mask[mask == label, :] = ADE20K_COLORS[label % 150]
    return Image.fromarray(color_mask)