import os
import asyncio
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram import F
from parser import analyze_email
import logging

logging.basicConfig(level=logging.INFO)

load_dotenv()
telegram_api = os.getenv("TELEGRAM_BOT_TOKEN")

bot = Bot(token=telegram_api)
dp = Dispatcher()

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer("Привет! Я бот для проверки фишинговых писем. Отправь мне файл .eml, и я его проанализирую.")

@dp.message(F.document)
async def handle_document(message: types.Message):
    destination = None
    try:
        if not message.document.file_name.endswith(".eml"):
            await message.answer("Был отправлин файл неверного формата. Отправте файл формата .eml")
            return

        await message.answer("Анализирую письмо, подождите...")
        file_id = message.document.file_id
        file = await bot.get_file(file_id)
        destination = f"downloads/{message.document.file_name}"
        os.makedirs("downloads", exist_ok=True)
        await bot.download_file(file.file_path, destination)
        report = analyze_email(destination)
        await message.answer(report)
    finally:
        if os.path.exists(destination):
            os.remove(destination)


async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
