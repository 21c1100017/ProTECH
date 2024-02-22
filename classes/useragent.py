from logging import INFO
import re
from classes.logmethod import log_setting


class UserAgent:
    access_log = log_setting.log_setup('access', INFO)
    error_log = log_setting.log_setup('error', INFO)
    config_log = log_setting.log_setup('config', INFO)
    detection_log = log_setting.log_setup('detection', INFO)

    @staticmethod
    def get_user_agent(flow):
        # リクエストからユーザーエージェントを取得する
        return flow.request.headers.get("User-Agent", "N/A")

    @staticmethod
    def python_kill(flow, user_agent):
        client_ip = flow.client_conn.address[0] if flow.client_conn else "N/A"
        path = flow.request.path if flow.request else "N/A"
        # "python" を含むかどうかの正規表現パターン
        pattern = re.compile(r'python', re.IGNORECASE)  # 大文字小文字を区別しない

        if pattern.search(user_agent):
            user_agent.detection_log.warning(
                '接続元IPアドレス[%s]のuser-agentにpythonが含まれているので通信を止めます。path[%s]', client_ip, path)
            flow.intercept()
            return True
        else:
            # 何か他の処理（例: リダイレクトなど）を行いたい場合はここにコードを追加
            pass
            return False
