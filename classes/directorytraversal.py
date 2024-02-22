from mitmproxy import http
import urllib.parse
from logging import INFO
from classes.customerror import CustomError
from classes.logmethod import LogSetting
from classes.configparmeter import ConfigParmeter
import os
from ipaddress import ip_network


class DirectoryTraversal:

    @staticmethod
    def url_check(flow, host_name, path):
        # ログのセットアップ
        client_ip = flow.client_conn.address[0]

        # もしエンコードされていた場合はデコードしてからの処理
        if "%" in path:
            path = urllib.parse.unquote(path)

        target_strings = ['../', '..\\', "%2e%2e%2f", '%2e%2e%5c', '..;', '..%00', "'\\'"]
        new_url = path

        DirectoryTraversal.access_control(flow, new_url)

        for target_string in target_strings:
            if target_string in new_url:
                detection_log = LogSetting.log_setup('detection', INFO)
                detection_log.warning(
                    "path[%s]に特殊な文字列を検知しました。接続IP[%s]", path, client_ip)
                # target_stringの部分で分けてtarget_string前の部分を選ぶ
                sanitized_path = new_url.split(target_string, 1)[0]
                sanitized_path = sanitized_path.rstrip('/')  # 末尾の / を削除
                # フルのURLを構築して設定
                new_url = host_name + sanitized_path
                # ディレクトリトラバーサルが検知されない場合はアクセス制御を行う
                DirectoryTraversal.access_control(flow, new_url)
                flow.response = http.HTTPResponse.make(
                    302,  # 302 Found (リダイレクト) ステータスコード
                    headers={"Location": new_url},
                    content=b"",
                )

    @staticmethod
    def access_control(flow, path):
        # ログのセットアップ
        access_log = LogSetting.log_setup('access', INFO)

        # config.iniを読み込む
        denied_path = ConfigParmeter.get_parameter(
            'Settings', 'denied_path', [])
        custom_error_content = CustomError.load_custom_error_page(
            os.path.join(CustomError.current_directory, "error_pages/forbidden.html"), flow)

        # config.iniからIPアドレス範囲を読み込む
        allowed_ip_ranges = ConfigParmeter.get_parameter(
            'Settings', 'allowed_ip_ranges', [])

        allowed_networks = [ip_network(ip_range)
                            for ip_range in allowed_ip_ranges]

        # アクセス制御と権限管理を実施
        if denied_path and path in denied_path:
            # active_method.info("アクセスできるpathかをチェックします。")
            # クライアントのIPアドレスが許可対象の範囲に含まれているか確認
            client_ip = flow.client_conn.address[0]
            if any(ip_address in allowed_network for allowed_network in allowed_networks for ip_address in ip_network(client_ip)):
                access_log.info(
                    "許可するIPアドレス[%s]の為アクセスを許可します。path[%s]", client_ip, path)
                print(
                    f"許可が必要なpath[{path}]に到達しましたが許可するIPアドレス[{client_ip}]の為アクセスを許可します:", path, client_ip)
            else:
                # ブロック対象のIPアドレス範囲に含まれている場合はアクセス拒否
                access_log.warning(
                    "許可が必要なpath[%s]に許可しないIPアドレス[%s]がpathに入ろうとしました。", path, client_ip)
                print(f"許可範囲{allowed_ip_ranges}")
                error_content = custom_error_content.encode('utf-8')
                flow.response = http.HTTPResponse.make(
                    403,  # 403 Forbidden
                    headers={"Content-Type": "text/html; charset=utf-8"},
                    content=error_content,
                )
        else:
            client_ip = flow.client_conn.address[0]
            access_log.info("許可するIP[%s]の為アクセスを許可します。path[%s]", client_ip, path)
