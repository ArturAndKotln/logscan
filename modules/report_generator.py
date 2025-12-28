"""
Модуль для генерации отчетов в форматах CSV и JSON
"""

import csv
import json
import logging
import os
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Класс для генерации отчетов"""

    def generate_report(self, results: List[Dict], output_path: str,
                        report_format: str = 'csv') -> None:
        """
        Генерация отчета с автоматическим созданием директорий

        Args:
            results: Список результатов проверки
            output_path: Полный путь для сохранения отчета
            report_format: Формат отчета ('csv' или 'json')
        """
        try:
            # Создаем директорию, если она не существует
            directory = os.path.dirname(output_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                logger.debug(f"Создана директория: {directory}")

            if report_format == 'csv':
                self._generate_csv(results, output_path)
            elif report_format == 'json':
                self._generate_json(results, output_path)
            else:
                raise ValueError(f"Неподдерживаемый формат: {report_format}")

            logger.info(f"Отчет сохранен в: {os.path.abspath(output_path)}")

        except IOError as e:
            logger.error(f"Ошибка при записи файла отчета: {e}")
            raise

    def _generate_csv(self, results: List[Dict], output_path: str) -> None:
        """Генерация CSV отчета"""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'value',
                    'type',
                    'check_date',
                    'is_threat',
                    'threat_level',
                    'malicious_count',
                    'suspicious_count',
                    'harmless_count',
                    'undetected_count',
                    'reputation'
                ]

                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for result in results:
                    row = {
                        'value': result.get('value', ''),
                        'type': result.get('type', ''),
                        'check_date': result.get('check_date', ''),
                        'is_threat': result.get('is_threat', False),
                        'threat_level': result.get('threat_level', 'UNKNOWN'),
                        'malicious_count': result.get('details', {}).get('malicious', 0),
                        'suspicious_count': result.get('details', {}).get('suspicious', 0),
                        'harmless_count': result.get('details', {}).get('harmless', 0),
                        'undetected_count': result.get('details', {}).get('undetected', 0),
                        'reputation': result.get('details', {}).get('reputation', 0)
                    }
                    writer.writerow(row)

            logger.debug(f"CSV отчет создан: {output_path}")

        except Exception as e:
            logger.error(f"Ошибка при создании CSV отчета: {e}")
            raise

    def _generate_json(self, results: List[Dict], output_path: str) -> None:
        """Генерация JSON отчета"""
        try:
            report = {
                'generated_at': datetime.now().isoformat(),
                'total_artifacts': len(results),
                'threats_found': sum(1 for r in results if r.get('is_threat', False)),
                'safe_artifacts': sum(1 for r in results if not r.get('is_threat', False)),
                'summary': {
                    'ip_addresses': sum(1 for r in results if r.get('type') == 'IP'),
                    'hashes': sum(1 for r in results if r.get('type') == 'HASH'),
                    'critical_threats': sum(1 for r in results if r.get('threat_level') == 'CRITICAL'),
                    'high_threats': sum(1 for r in results if r.get('threat_level') == 'HIGH'),
                    'medium_threats': sum(1 for r in results if r.get('threat_level') == 'MEDIUM'),
                    'low_threats': sum(1 for r in results if r.get('threat_level') == 'LOW'),
                },
                'artifacts': results
            }

            with open(output_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(report, jsonfile, indent=2, ensure_ascii=False)

            logger.debug(f"JSON отчет создан: {output_path}")

        except Exception as e:
            logger.error(f"Ошибка при создании JSON отчета: {e}")
            raise