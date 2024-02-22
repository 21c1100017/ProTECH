import configparser
from logging import INFO
import os
import re
from threading import Lock
from classes.logmethod import LogSetting


class ConfigParmeter:
    access_log = LogSetting.log_setup('access', INFO)
    error_log = LogSetting.log_setup('error', INFO)
    config_log = LogSetting.log_setup('config', INFO)
    lock = Lock()

    @staticmethod
    def load_settings() -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, '..', 'config.ini')
        try:
            config.read(config_path)  # ここで設定を読み込む
            return config
        except Exception as e:
            # エラーが発生した場合のハンドリング
            ConfigParmeter.config_log.error(
                "設定ファイルの読み込み中にエラーが発生しました: %s", str(e))
            # エラー時には None を返すなど、適切な処理を行うことも考えられます
            return None  

    @staticmethod
    def get_parameter(section_name, key, fallback=None):
        with ConfigParmeter.lock:
            loaded_config = ConfigParmeter.load_settings()

        if fallback is not None:
            if isinstance(fallback, list):
                try:
                    parameter = loaded_config.get(
                        section_name, key, fallback=fallback)
                    if not parameter:
                        return fallback
                    else:
                        # 正規表現パターン
                        pattern = re.compile(
                            r"\s*,\s*|\s*'\s*|\s*\[\s*|\s*\]\s*")

                        # 正規表現パターンに基づいて分割
                        result = [p.strip("['").strip("']")
                                  for p in pattern.split(parameter) if p]
                        return result
                except Exception as e:
                    ConfigParmeter.config_log.error(
                        "パラメータの取得が出来ませんでした設定を確認し直してください: %s", str(e))
            else:
                if isinstance(fallback, int):
                    parameter = loaded_config.getint(
                        section_name, key, fallback=fallback)
                elif isinstance(fallback, str):
                    parameter = loaded_config.get(
                        section_name, key, fallback=fallback)
                else:
                    parameter = loaded_config.get(
                        section_name, key, fallback=fallback)

                # qualityが90以上なら85に変更
                if key == "quality" and isinstance(parameter, int) and parameter >= 90:
                    parameter = 85
                    ConfigParmeter.config_log.warning(
                        "qualityの値を85に書き換えます。config.iniから90以下に変更してください")
                return parameter

