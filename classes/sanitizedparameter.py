from logging import INFO
import urllib.parse
import html
from mitmproxy import http
from requests_toolbelt.multipart import decoder
from classes.logmethod import log_setting

class SanitizedParameter:
    access_log = log_setting.log_setup('access', INFO)
    error_log = log_setting.log_setup('error', INFO)
    config_log = log_setting.log_setup('config', INFO)
    detection_log = log_setting.log_setup('detection', INFO)

    @staticmethod
    def check_parameter(flow):
        if flow.request.method != 'POST' and 'Content-Type' not in flow.request.headers:
            return
        content_type = flow.request.headers['Content-Type']
        if 'multipart/form-data' in content_type:
            idx = content_type.find('boundary=')
            if idx == -1:
                return
            for part in decoder.MultipartDecoder(flow.request.content, content_type).parts:
                # idxはfilenameが見つからないなら-1
                idx = str(part.headers).find('filename')
                # filenameが無かったら且つコンテンツがあったら
                if idx == -1 and part.content:
                    params = urllib.parse.parse_qs(part.text)
                    SanitizedParameter.process_params(params, flow)
        else:
            if 'filename' in flow.request.headers:
                return
            else:
                params = urllib.parse.parse_qs(flow.request.text)
                SanitizedParameter.process_params(params, flow)

    @staticmethod
    def process_params(params, flow):
        for key, values in params.items():
            for value in values:
                if SanitizedParameter.sql_error(value, flow):
                    sanitized_value = your_sanitization_function(value)
                    # 新しい MultiDict を作成
                    new_params = {
                        k: v if k != key else sanitized_value for k, v in params.items()}
                    # 新しい MultiDict をセットする
                    flow.request.text = urllib.parse.urlencode(
                        new_params, doseq=True)

    @staticmethod
    def sql_error(parameter, flow: http.HTTPFlow):
        client_ip = flow.client_conn.address[0] if flow.client_conn else "N/A"
        path = flow.request.path if flow.request else "N/A"
        target_strings = ['"', '=', "'", '\'', ';', '<', '>', 'script',
                          'and', 'or', 'AND', 'OR', '/', '-', '/*', '*/', '--']
        # 特定の文字列が入っていた場合
        for target in target_strings:
            if target in parameter:
                print(f"特定の文字列 {target} が含まれています。")
                SanitizedParameter.detection_log.info(
                    '接続元IPアドレス[%s]の送られてきたテキストデータに特定の文字列[%s]が含まれているのでサニタイジングをします。path[%s]', client_ip, target, path)
                return True
        # 入っていなかった場合
        print("特定の文字列は含まれていません。")
        return False

# この関数は適切なサニタイゼーション処理を行う必要があります
def your_sanitization_function(value):
    replacements = {
        "'": html.escape("'"),          # シングルクォートの削除
        '"': html.escape('"'),          # ダブルクォートの削除
        '-': html.escape('-'),          # コメントの削除
        '--': html.escape('--'),        # コメントの削除
        'OR': html.escape('OR'),        # キーワードの無効化
        'AND': html.escape('AND'),      # キーワードの無効化
        '/*': html.escape('/*'),        # コメントアウト文字の削除
        '*/': html.escape('*/'),        # コメントアウト文字の削除
        '#': html.escape('#'),          # フラグメントの置換
        '<': html.escape('<'),          # フラグメントの置換
        '>': html.escape('>'),          # フラグメントの置換
        ';': html.escape(';'),          # フラグメントの置換
        ':': html.escape(':'),          # フラグメントの置換
        '\'': html.escape('\''),        # フラグメントの置換
        '=': html.escape('='),          # フラグメントの置換
        # 他にも必要な置換を追加
    }
    for pattern, replacement in replacements.items():
        value = value.replace(pattern, replacement)
    return value
