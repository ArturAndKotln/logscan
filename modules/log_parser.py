"""
Модуль для парсинга лог-файлов и извлечения артефактов
"""

import re
import logging
from typing import Dict, List, Set, Any

logger = logging.getLogger(__name__)


class LogParser:
    """Класс для парсинга лог-файлов"""

    def __init__(self):
        # Регулярные выражения для поиска артефактов
        self.ip_pattern = re.compile(
            r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        self.sha256_pattern = re.compile(
            r'\b[a-fA-F0-9]{64}\b'
        )

    def extract_artifacts(self, log_file_path: str) -> dict[str, list[Any]]:
        """
        Извлекает IP-адреса и SHA256 хэши из лог-файла

        Args:
            log_file_path: Путь к лог-файлу

        Returns:
            Словарь с найденными артефактами
        """
        artifacts = {
            'IP': set(),
            'HASH': set()
        }

        try:
            with open(log_file_path, 'r', encoding='utf-8') as file:
                content = file.read()

                # Поиск IP-адресов
                ip_addresses = self.ip_pattern.findall(content)
                artifacts['IP'].update(ip_addresses)

                # Поиск SHA256 хэшей
                sha256_hashes = self.sha256_pattern.findall(content)
                artifacts['HASH'].update(sha256_hashes)

                logger.info(f"Найдено IP-адресов: {len(ip_addresses)}")
                logger.info(f"Найдено SHA256 хэшей: {len(sha256_hashes)}")

        except UnicodeDecodeError:
            # Попробуем другие кодировки
            encodings = ['cp1251', 'latin-1', 'iso-8859-1']
            for encoding in encodings:
                try:
                    with open(log_file_path, 'r', encoding=encoding) as file:
                        content = file.read()

                        ip_addresses = self.ip_pattern.findall(content)
                        artifacts['IP'].update(ip_addresses)

                        sha256_hashes = self.sha256_pattern.findall(content)
                        artifacts['HASH'].update(sha256_hashes)

                        logger.info(f"Файл прочитан с кодировкой {encoding}")
                        break

                except UnicodeDecodeError:
                    continue

        # Преобразуем множества в списки для удобства
        return {
            'IP': list(artifacts['IP']),
            'HASH': list(artifacts['HASH'])
        }
