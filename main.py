#!/usr/bin/env python3
"""
Основной модуль утилиты logscan для анализа логов и проверки угроз
"""

import argparse
import logging
import sys
import os
from datetime import datetime
from modules.log_parser import LogParser
from modules.virustotal import VirusTotalChecker
from modules.report_generator import ReportGenerator


def setup_logging():
    """Настройка логирования"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logscan.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


def ensure_output_directory(output_path):
    """Создание директории для выходных файлов, если она не существует"""
    # Извлекаем директорию из полного пути
    directory = os.path.dirname(output_path)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            logger.info(f"Создана директория для результатов: {directory}")
        except Exception as e:
            logger.error(f"Не удалось создать директорию {directory}: {e}")
            raise


def get_default_output_filename(report_format='csv'):
    """Генерация имени файла по умолчанию с временной меткой"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"output/report_{timestamp}.{report_format}"


def main():
    """Основная функция утилиты"""
    parser = argparse.ArgumentParser(
        description='Утилита для анализа логов и проверки угроз',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py -log-file logs/sample.log
  python main.py -log-file logs/sample.log -api-key YOUR_API_KEY -format json
  python main.py -log-file logs/sample.log -output custom_report.csv -format csv
  python main.py -log-file logs/sample.log -output reports/myreport.json
        """
    )

    parser.add_argument(
        '-log-file',
        dest='log_file',
        required=True,
        help='Путь к лог-файлу для анализа'
    )

    parser.add_argument(
        '-api-key',
        dest='api_key',
        default=None,
        help='API ключ для VirusTotal (если не указан, используется mock)'
    )

    parser.add_argument(
        '-output',
        dest='output_file',
        default=None,  # Изменено: None вместо строки
        help='Путь к файлу отчета (если не указан, используется output/report_YYYYMMDD_HHMMSS.format)'
    )

    parser.add_argument(
        '-format',
        dest='report_format',
        choices=['csv', 'json'],
        default='csv',
        help='Формат отчета (csv или json)'
    )

    args = parser.parse_args()
    logger = setup_logging()

    try:
        logger.info("=" * 50)
        logger.info(f"Запуск LogScan - анализ лог-файла: {args.log_file}")
        logger.info("=" * 50)

        # 1. Проверка существования лог-файла
        if not os.path.exists(args.log_file):
            logger.error(f"Лог-файл не найден: {args.log_file}")
            sys.exit(1)

        # 2. Определение пути для сохранения отчета
        if args.output_file is None:
            # Используем путь по умолчанию
            args.output_file = get_default_output_filename(args.report_format)
            logger.info(f"Путь для отчета не указан, используется: {args.output_file}")
        else:
            # Проверяем расширение файла
            if not args.output_file.lower().endswith(('.csv', '.json')):
                # Добавляем расширение, если его нет
                args.output_file = f"{args.output_file}.{args.report_format}"
                logger.info(f"Добавлено расширение .{args.report_format} к имени файла")

        # 3. Создание директории для отчета, если необходимо
        ensure_output_directory(args.output_file)

        # 4. Парсинг лог-файла
        logger.info("Извлечение артефактов из логов...")
        parser_obj = LogParser()
        artifacts = parser_obj.extract_artifacts(args.log_file)

        # Статистика найденных артефактов
        total_artifacts = sum(len(values) for values in artifacts.values())
        logger.info(f"Найдено артефактов: {total_artifacts}")
        for artifact_type, values in artifacts.items():
            logger.info(f"  {artifact_type}: {len(values)} уникальных значений")

        if total_artifacts == 0:
            logger.warning("В лог-файле не найдено ни одного IP-адреса или SHA256 хэша")
            # Создаем пустой отчет
            results = []
        else:
            # 5. Проверка артефактов через VirusTotal
            logger.info("Проверка артефактов на наличие угроз...")
            if args.api_key:
                logger.info("Используется реальный API ключ VirusTotal")
                vt_checker = VirusTotalChecker(api_key=args.api_key)
            else:
                logger.warning("API ключ не указан, используется mock-режим")
                vt_checker = VirusTotalChecker(api_key=None)

            # Ограничиваем количество проверок для демонстрации
            max_checks = 50
            results = []
            checked_count = 0

            for artifact_type, values in artifacts.items():
                for value in values:
                    if checked_count >= max_checks:
                        logger.warning(f"Достигнут лимит проверок ({max_checks}). Остановка.")
                        break

                    logger.debug(f"Проверка {artifact_type}: {value}")
                    result = vt_checker.check_artifact(value, artifact_type)
                    results.append(result)
                    checked_count += 1

                if checked_count >= max_checks:
                    break

            logger.info(f"Проверено артефактов: {checked_count}")

        # 6. Генерация отчета
        logger.info(f"Генерация отчета в формате {args.report_format}...")
        report_gen = ReportGenerator()

        try:
            report_gen.generate_report(results, args.output_file, args.report_format)
            logger.info(f"Отчет успешно сохранен: {args.output_file}")

            # Вывод статистики
            if results:
                threats_found = sum(1 for r in results if r.get('is_threat', False))
                safe_count = len(results) - threats_found

                logger.info("=" * 50)
                logger.info("РЕЗУЛЬТАТЫ ПРОВЕРКИ:")
                logger.info(f"Всего проверено: {len(results)}")
                logger.info(f"Угроз обнаружено: {threats_found}")
                logger.info(f"Безопасных: {safe_count}")

                if threats_found > 0:
                    logger.warning("ВНИМАНИЕ: Обнаружены потенциальные угрозы!")
                    for result in results:
                        if result.get('is_threat'):
                            threat_level = result.get('threat_level', 'UNKNOWN')
                            logger.warning(f"  Угроза {threat_level}: {result.get('value')}")

                # Дополнительная информация об отчете
                try:
                    file_size = os.path.getsize(args.output_file)
                    logger.info(f"Размер отчета: {file_size / 1024:.2f} KB")
                except:
                    pass

        except Exception as e:
            logger.error(f"Ошибка при генерации отчета: {e}")
            # Пробуем сохранить в резервное расположение
            backup_file = f"report_backup.{args.report_format}"
            try:
                report_gen.generate_report(results, backup_file, args.report_format)
                logger.info(f"Отчет сохранен в резервное расположение: {backup_file}")
            except Exception as backup_error:
                logger.error(f"Не удалось сохранить отчет даже в резервное расположение: {backup_error}")
            sys.exit(1)

        logger.info("=" * 50)
        logger.info("Анализ завершен успешно!")
        logger.info("=" * 50)

    except FileNotFoundError as e:
        logger.error(f"Файл не найден: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Анализ прерван пользователем")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Произошла непредвиденная ошибка: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()