.DEFAULT_GOAL := help

help:
	@echo Available commands:
	@echo =============================
	@echo
	@echo install		- Install dependencies via Poetry
	@echo dev			- Start the development server
	@echo test			- Run tests (not implemented yet)
	@echo lint			- Check code style using flake8
	@echo format		- Format code using black and isort
	@echo shell			- Open a shell inside the Poetry environment
	@echo clean			- Clean temporary files and cache

install: ## Установить зависимости
	poetry install

dev: ## Запустить сервер в режиме разработки
	poetry run uvicorn src.app.main:app --reload --host 0.0.0.0 --port 8000

shell: ## Войти в оболочку Poetry
	poetry shell

lint: ## Проверить стиль кода
	poetry run flake8 src/

format: ## Форматировать код
	poetry run black src/
	poetry run isort src/

clean: ## Очистить __pycache__, .pyc и т.д.
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete