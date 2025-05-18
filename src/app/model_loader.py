import torch
from transformers import UperNetForSemanticSegmentation

def load_model(model_path: str = "models/upernet-convnext-tiny.pth"):
    """
    Загружает предобученную модель UperNet из файла
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Создаем модель с пустыми весами (архитектура)
    model = UperNetForSemanticSegmentation.from_pretrained(
        "openmmlab/upernet-convnext-tiny",
        num_labels=150,  # стандарт для ADE20K
        ignore_mismatched_sizes=True
    )

    # Загружаем сохранённые веса
    state_dict = torch.load(model_path, map_location=device)
    model.load_state_dict(state_dict)
    model.to(device)
    model.eval()

    return model