#!/usr/bin/env python3
"""
Веб-интерфейс для утилиты анализа логов LogScan
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, flash, jsonify
from werkzeug.utils import secure_filename
import tempfile

# Импорт модулей из CLI утилиты
from modules.log_parser import LogParser
from modules.virustotal import VirusTotalChecker
from modules.report_generator import ReportGenerator

# Настройка приложения
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-123')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Папки для загрузки и результатов
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('web_logscan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Вспомогательные функции
def allowed_file(filename):
    """Проверка допустимых расширений файлов"""
    allowed_extensions = {'log', 'txt', 'json', 'csv'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def process_log_file(file_path, api_key=None, report_format='json'):
    """Основная функция обработки лог-файла"""
    try:
        # 1. Парсинг лог-файла
        logger.info(f"Извлечение артефактов из {file_path}")
        parser = LogParser()
        artifacts = parser.extract_artifacts(file_path)

        # 2. Проверка через VirusTotal
        logger.info("Проверка артефактов через VirusTotal...")
        vt_checker = VirusTotalChecker(api_key=api_key)

        results = []
        for artifact_type, values in artifacts.items():
            for value in values[:50]:  # Ограничиваем для демонстрации
                result = vt_checker.check_artifact(value, artifact_type)
                results.append(result)

        # 3. Генерация отчета
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"report_{timestamp}.{report_format}"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)

        report_gen = ReportGenerator()
        report_gen.generate_report(results, output_path, report_format)

        # Статистика
        total_artifacts = len(results)
        threats_found = sum(1 for r in results if r['is_threat'])

        return {
            'success': True,
            'output_file': output_filename,
            'output_path': output_path,
            'total_artifacts': total_artifacts,
            'threats_found': threats_found,
            'results': results[:10],  # Первые 10 результатов для предпросмотра
            'artifacts_summary': {
                'IP': len(artifacts.get('IP', [])),
                'HASH': len(artifacts.get('HASH', []))
            }
        }

    except Exception as e:
        logger.error(f"Ошибка при обработке файла: {e}")
        return {
            'success': False,
            'error': str(e)
        }


# Маршруты Flask
@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Страница загрузки и анализа файла"""
    if request.method == 'POST':
        # Проверка наличия файла
        if 'logfile' not in request.files:
            flash('Файл не выбран', 'error')
            return redirect(request.url)

        file = request.files['logfile']

        if file.filename == '':
            flash('Файл не выбран', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Сохранение файла
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            logger.info(f"Файл сохранен: {file_path}")

            # Получение параметров
            api_key = request.form.get('api_key', '').strip()
            if not api_key:
                api_key = None
                flash('Используется mock-режим (без реального API ключа)', 'warning')

            report_format = request.form.get('format', 'json')

            # Обработка файла
            flash('Файл загружен. Начинаю анализ...', 'info')
            result = process_log_file(file_path, api_key, report_format)

            if result['success']:
                # Сохраняем результаты в сессии для отображения
                session_data = {
                    'filename': filename,
                    'output_file': result['output_file'],
                    'total_artifacts': result['total_artifacts'],
                    'threats_found': result['threats_found'],
                    'artifacts_summary': result['artifacts_summary'],
                    'results': result['results']
                }

                # Используем временный файл для хранения сессии
                import pickle
                session_file = os.path.join(tempfile.gettempdir(), f"logscan_{filename}.pkl")
                with open(session_file, 'wb') as f:
                    pickle.dump(session_data, f)

                return redirect(url_for('show_results', session_id=os.path.basename(session_file)))
            else:
                flash(f'Ошибка при обработке файла: {result["error"]}', 'error')
                return redirect(request.url)

        else:
            flash('Недопустимый формат файла. Разрешены: .log, .txt, .json, .csv', 'error')
            return redirect(request.url)

    return render_template('upload.html')


@app.route('/results/<session_id>')
def show_results(session_id):
    """Отображение результатов анализа"""
    try:
        session_file = os.path.join(tempfile.gettempdir(), session_id)

        if not os.path.exists(session_file):
            flash('Сессия не найдена или устарела', 'error')
            return redirect(url_for('upload_file'))

        import pickle
        with open(session_file, 'rb') as f:
            session_data = pickle.load(f)

        return render_template('results.html', **session_data)

    except Exception as e:
        logger.error(f"Ошибка при загрузке результатов: {e}")
        flash('Ошибка при загрузке результатов', 'error')
        return redirect(url_for('upload_file'))


@app.route('/download/<filename>')
def download_report(filename):
    """Скачивание отчета"""
    try:
        file_path = os.path.join(OUTPUT_FOLDER, filename)

        if not os.path.exists(file_path):
            flash('Файл отчета не найден', 'error')
            return redirect(url_for('index'))

        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json' if filename.endswith('.json') else 'text/csv'
        )

    except Exception as e:
        logger.error(f"Ошибка при скачивании файла: {e}")
        flash('Ошибка при скачивании файла', 'error')
        return redirect(url_for('index'))


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint для анализа (для AJAX запросов)"""
    try:
        if 'logfile' not in request.files:
            return jsonify({'error': 'Файл не предоставлен'}), 400

        file = request.files['logfile']

        if file.filename == '':
            return jsonify({'error': 'Имя файла пустое'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Недопустимый формат файла'}), 400

        # Сохранение во временный файл
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        file.save(temp_file.name)
        temp_file.close()

        # Получение параметров
        api_key = request.form.get('api_key', None)
        report_format = request.form.get('format', 'json')

        # Обработка
        result = process_log_file(temp_file.name, api_key, report_format)

        # Очистка временного файла
        os.unlink(temp_file.name)

        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Анализ завершен успешно',
                'data': {
                    'output_file': result['output_file'],
                    'total_artifacts': result['total_artifacts'],
                    'threats_found': result['threats_found'],
                    'download_url': url_for('download_report', filename=result['output_file'])
                }
            })
        else:
            return jsonify({'error': result['error']}), 500

    except Exception as e:
        logger.error(f"API ошибка: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/quick-scan', methods=['POST'])
def quick_scan():
    """Быстрая проверка текста из формы"""
    try:
        log_text = request.form.get('log_text', '')
        api_key = request.form.get('api_key', None)

        if not log_text.strip():
            return jsonify({'error': 'Введите текст лога для анализа'}), 400

        # Сохраняем текст во временный файл
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log', encoding='utf-8') as f:
            f.write(log_text)
            temp_path = f.name

        # Обработка
        result = process_log_file(temp_path, api_key, 'json')

        # Очистка
        os.unlink(temp_path)

        if result['success']:
            return jsonify({
                'success': True,
                'data': {
                    'total_artifacts': result['total_artifacts'],
                    'threats_found': result['threats_found'],
                    'results': result['results'][:5],  # Первые 5 результатов
                    'artifacts_summary': result['artifacts_summary']
                }
            })
        else:
            return jsonify({'error': result['error']}), 500

    except Exception as e:
        logger.error(f"Ошибка быстрого сканирования: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/report/<filename>')
def view_report(filename):
    """Просмотр отчета в браузере"""
    try:
        file_path = os.path.join(OUTPUT_FOLDER, filename)

        if not os.path.exists(file_path):
            flash('Отчет не найден', 'error')
            return redirect(url_for('index'))

        if filename.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)

            return render_template('report.html',
                                   report_data=report_data,
                                   filename=filename)

        elif filename.endswith('.csv'):
            import csv
            data = []
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)

            return render_template('report.html',
                                   report_data={'artifacts': data},
                                   filename=filename,
                                   is_csv=True)

    except Exception as e:
        logger.error(f"Ошибка при просмотре отчета: {e}")
        flash('Ошибка при загрузке отчета', 'error')
        return redirect(url_for('index'))


@app.route('/recent-reports')
def recent_reports():
    """Список последних отчетов"""
    try:
        reports = []
        for filename in os.listdir(OUTPUT_FOLDER):
            if filename.startswith('report_') and (filename.endswith('.json') or filename.endswith('.csv')):
                file_path = os.path.join(OUTPUT_FOLDER, filename)
                stats = os.stat(file_path)
                reports.append({
                    'filename': filename,
                    'created': datetime.fromtimestamp(stats.st_ctime),
                    'size': stats.st_size,
                    'type': 'JSON' if filename.endswith('.json') else 'CSV'
                })

        # Сортировка по дате создания (новые первые)
        reports.sort(key=lambda x: x['created'], reverse=True)

        return render_template('reports.html', reports=reports[:10])

    except Exception as e:
        logger.error(f"Ошибка при получении списка отчетов: {e}")
        flash('Ошибка при загрузке списка отчетов', 'error')
        return redirect(url_for('index'))


@app.errorhandler(413)
def too_large(e):
    """Обработка ошибки слишком большого файла"""
    flash('Файл слишком большой. Максимальный размер: 16MB', 'error')
    return redirect(url_for('upload_file'))


@app.errorhandler(404)
def page_not_found(e):
    """Обработка 404 ошибки"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """Обработка 500 ошибки"""
    logger.error(f"Внутренняя ошибка сервера: {e}")
    return render_template('500.html'), 500


if __name__ == '__main__':
    # Создаем необходимые папки
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Запуск приложения
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )