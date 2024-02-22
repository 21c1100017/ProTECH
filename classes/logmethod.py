from logging import getLogger, FileHandler, Formatter
import os

class LogSetting:

    @staticmethod
    def log_setup(filename, level):
        # filenameの設定
        join_path = os.path.join("/var/log/protech", filename + ".log")

        # ロガーの作成
        logger = getLogger(filename)

        # ロガーの既存ハンドラーをクリア（同じハンドラーが複数回追加されるのを防ぐため）
        logger.handlers.clear()

        # フォーマット
        formatter = Formatter(
            '[%(levelname)s] time: %(asctime)s, message: %(message)s')

        # ファイルのpath指定(handlerは実際の出力の実行部分)
        handler = FileHandler(join_path)

        # 実行部分のレベルセット
        handler.setLevel(level)

        # ハンドラーにフォーマットをセット
        handler.setFormatter(formatter)

        # ログにレベルをセット
        logger.setLevel(level)

        # ロガーにハンドラーを追加
        logger.addHandler(handler)

        return logger
