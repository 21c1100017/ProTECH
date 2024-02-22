# custom_error_script.py
from mitmproxy import http
from logging import INFO
import os
from classes.logmethod import log_setting


class CustomError:
    custom_error_page = "<html><body><h1>Custom Error Page</h1></body></html>"
    current_directory = os.path.join(os.getcwd(), "classes")
    access_log = log_setting.log_setup('access', INFO)
    error_log = log_setting.log_setup('error', INFO)

    @staticmethod
    def load_custom_error_page(page, flow: http.HTTPFlow) -> str:
        try:
            with open(page, 'r') as file:
                return file.read()
        except Exception as e:
            CustomError.error_log.error(
                "カスタマイズエラーページの読み込みに失敗しました。接続元IPアドレス[%s] path[%s] エラー: %s",
                flow.client_conn.address[0] if flow.client_conn else "N/A",
                flow.request.path if flow.request else "N/A",
                str(e)
            )
            return CustomError.custom_error_page

    @staticmethod
    def response(flow: http.HTTPFlow) -> None:
        status_code = flow.response.status_code
        client_ip = flow.client_conn.address[0] if flow.client_conn else "N/A"
        path = flow.request.path if flow.request else "N/A"

        if status_code == 400:
            custom_error_page = CustomError.load_custom_error_page(
                os.path.join(CustomError.current_directory, "error_pages/invalid_request.html"), flow)
            CustomError.access_log.info(
                "ステータスコード[%s]が返されカスタマイズエラーページが返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                custom_error_page,
                {"Content-Type": "text/html"},
            )

        elif status_code == 401:
            CustomError.access_log.info(
                "ステータスコード[%s]が返され認証エラーページが返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                CustomError.custom_error_page,
                {"Content-Type": "text/html"},
            )

        elif status_code == 403:
            custom_error_page = CustomError.load_custom_error_page(
                os.path.join(CustomError.current_directory, "error_pages/forbidden.html"), flow)
            CustomError.access_log.warning(
                "ステータスコード[%s]が返されアクセス拒否エラーページが返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                custom_error_page,
                {"Content-Type": "text/html"},
            )

        elif status_code == 404:
            custom_error_page = CustomError.load_custom_error_page(
                os.path.join(CustomError.current_directory, "error_pages/not_found.html"), flow)
            CustomError.access_log.info(
                "ステータスコード[%s]が返されページが見つからないエラーページが返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                custom_error_page,
                {"Content-Type": "text/html"},
            )

        elif status_code == 408:
            CustomError.access_log.warning(
                "ステータスコード[%s]が返されタイムアウトエラーページが返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                CustomError.custom_error_page,
                {"Content-Type": "text/html"},
            )

        elif status_code == 500:
            CustomError.access_log.error(
                "ステータスコード[%s]が返され内部サーバーエラーページが返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                CustomError.custom_error_page,
                {"Content-Type": "text/html"},
            )

        elif status_code >= 400 and status_code < 600:
            CustomError.error_log.error(
                "対策をしていないステータスコード[%s]が返されました。接続元IPアドレス[%s] path[%s]", status_code, client_ip, path)
            flow.response = http.HTTPResponse.make(
                status_code,
                CustomError.custom_error_page,
                {"Content-Type": "text/html"},
            )
