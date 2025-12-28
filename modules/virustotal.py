"""
Модуль для проверки артефактов через VirusTotal API
"""

import requests
import time
import json
import logging
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class VirusTotalChecker:
    """Класс для взаимодействия с VirusTotal API"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

        if not api_key:
            logger.warning("API ключ не указан. Используется mock-режим.")
            self.mock_mode = True
        else:
            self.mock_mode = False
            self.headers = {
                "x-apikey": api_key,
                "accept": "application/json"
            }

    def check_ip(self, ip_address: str) -> Dict:
        """Проверка IP-адреса через VirusTotal"""
        if self.mock_mode:
            return self._mock_check_ip(ip_address)

        try:
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0)
                }
            else:
                logger.warning(f"Ошибка при проверке IP {ip_address}: {response.status_code}")
                return {'malicious': 0, 'suspicious': 0, 'error': True}

        except requests.RequestException as e:
            logger.error(f"Сетевая ошибка при проверке IP: {e}")
            return {'malicious': 0, 'suspicious': 0, 'error': True}

    def check_hash(self, file_hash: str) -> Dict:
        """Проверка файлового хэша через VirusTotal"""
        if self.mock_mode:
            return self._mock_check_hash(file_hash)

        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'type': data.get('data', {}).get('attributes', {}).get('type_description', 'Unknown')
                }
            elif response.status_code == 404:
                logger.info(f"Хэш {file_hash} не найден в VirusTotal")
                return {'malicious': 0, 'suspicious': 0, 'not_found': True}
            else:
                logger.warning(f"Ошибка при проверке хэша {file_hash}: {response.status_code}")
                return {'malicious': 0, 'suspicious': 0, 'error': True}

        except requests.RequestException as e:
            logger.error(f"Сетевая ошибка при проверке хэша: {e}")
            return {'malicious': 0, 'suspicious': 0, 'error': True}

    def check_artifact(self, value: str, artifact_type: str) -> Dict:
        """
        Проверка артефакта

        Args:
            value: Значение артефакта (IP или хэш)
            artifact_type: Тип артефакта ('IP' или 'HASH')

        Returns:
            Словарь с результатами проверки
        """
        logger.info(f"Проверка {artifact_type}: {value}")

        if artifact_type == 'IP':
            result = self.check_ip(value)
            is_threat = result.get('malicious', 0) > 0 or result.get('suspicious', 0) > 0
            threat_level = self._calculate_threat_level(result)
        else:  # HASH
            result = self.check_hash(value)
            is_threat = result.get('malicious', 0) > 0
            threat_level = self._calculate_threat_level(result)

        return {
            'value': value,
            'type': artifact_type,
            'check_date': datetime.now().isoformat(),
            'is_threat': is_threat,
            'threat_level': threat_level,
            'details': result
        }

    def _calculate_threat_level(self, result: Dict) -> str:
        """Определение уровня угрозы"""
        malicious = result.get('malicious', 0)
        suspicious = result.get('suspicious', 0)

        if malicious > 5:
            return 'CRITICAL'
        elif malicious > 0:
            return 'HIGH'
        elif suspicious > 3:
            return 'MEDIUM'
        elif suspicious > 0:
            return 'LOW'
        else:
            return 'NONE'

    def _mock_check_ip(self, ip_address: str) -> Dict:
        """Mock-проверка IP-адреса"""
        # Имитация проверки с предопределенными результатами
        import random

        # Некоторые известные вредоносные IP для демонстрации
        malicious_ips = {
            '185.220.101.4': {'malicious': 15, 'suspicious': 3},
            '94.102.61.24': {'malicious': 8, 'suspicious': 2},
            '192.168.1.100': {'malicious': 0, 'suspicious': 0},
            '10.0.0.1': {'malicious': 0, 'suspicious': 1},
        }

        if ip_address in malicious_ips:
            return malicious_ips[ip_address]

        # Случайная генерация для других IP
        return {
            'malicious': random.randint(0, 2),
            'suspicious': random.randint(0, 5),
            'undetected': random.randint(10, 50),
            'harmless': random.randint(0, 20),
            'reputation': random.randint(-10, 100)
        }

    def _mock_check_hash(self, file_hash: str) -> Dict:
        """Mock-проверка файлового хэша"""
        import random

        # Некоторые известные вредоносные хэши для демонстрации
        malicious_hashes = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
                {'malicious': 0, 'suspicious': 0, 'type': 'Empty file'},
            'a' * 64: {'malicious': 12, 'suspicious': 3, 'type': 'Trojan'},
            'b' * 64: {'malicious': 0, 'suspicious': 1, 'type': 'PUA'},
        }

        if file_hash in malicious_hashes:
            return malicious_hashes[file_hash]

        # Случайная генерация для других хэшей
        malicious = random.randint(0, 3)
        return {
            'malicious': malicious,
            'suspicious': random.randint(0, 2),
            'undetected': random.randint(10, 40),
            'harmless': random.randint(0, 15),
            'type': random.choice(['EXE', 'DLL', 'PDF', 'DOC', 'Unknown'])
        }