from mitmproxy import http
from io import BytesIO
from PIL import Image
from logging import INFO
import re
from requests_toolbelt.multipart import decoder
from classes.logmethod import LogSetting
from classes.configparmeter import ConfigParmeter


class FileChecker:

    MAX_FILE_SIZE_UNCOMPRESSED = 2 * 1024 * 1024  # 2 MB未満はそのまま
    MAX_FILE_SIZE_COMPRESSED = 5 * 1024 * 1024  # 2 MB以上5 MB以下は圧縮して通す
    access_log = LogSetting.log_setup('access', INFO)
    error_log = LogSetting.log_setup('error', INFO)
    config_log = LogSetting.log_setup('config', INFO)

    @staticmethod
    def run(flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0] if flow.client_conn else "N/A"
        path = flow.request.path if flow.request else "N/A"
        if flow.request.method != 'POST' \
                and 'Content-Type' not in flow.request.headers:
            return
        content_type = flow.request.headers['Content-Type']
        if 'multipart/form-data' in content_type:
            print(f'multipart/form-data')
            idx = content_type.find('boundary=')
            print(f'idx = {str(idx)}')
            if idx == -1:
                return
            try:
                for part in decoder.MultipartDecoder(flow.request.content, content_type).parts:
                    idx = str(part.headers).find('filename')
                    if idx == -1 or part.content == b'':
                        continue
                    print(f'file found.')
                    before_file = after_file = part.content
                    # ファイルチェックの処理
                    while True:
                        result = FileChecker.check_file(after_file, flow)
                        print(f'file check code: {result}')
                        if result == 0:
                            flow.kill()
                            return
                        if result == 1:
                            break
                        if result == 2:
                            after_file = FileChecker.compress_file(after_file, flow)
                            continue
                    flow.request.content = flow.request.content.replace(
                        before_file, after_file)
            except Exception as e:
                print(f'exeception: {e}')
                FileChecker.access_log.error(
                    '接続元IPアドレス[%s]がファイルのチェックエラーによりコネクションを切断されました。path[%s]以下エラー文%s', client_ip, path, e)
                flow.kill()
                return
        else:
            try:
                # 'multipart/form-data' でない場合の処理
                # ファイルのチェック
                if 'filename' not in flow.request.headers:
                    return
                filename = flow.request.headers['filename']
                before_file = after_file = flow.request.content
                while True:
                    result = FileChecker.check_file(after_file, flow)
                    if result == 0:
                        flow.kill()
                        return
                    if result == 1:
                        break
                    if result == 2:
                        after_file = FileChecker.compress_file(after_file, flow)
                        continue
                flow.request.content = flow.request.content.replace(
                    before_file, after_file)
            except:
                #print("multitypeじゃない方のエラー")
                FileChecker.access_log.error(
                    '接続元IPアドレス[%s]がファイルのチェックエラーによりコネクションを切断されました。path[%s]', client_ip, path)
                flow.kill()

    # 0 -> エラー
    # 1 -> OK (圧縮スキップ)
    # 2 -> OK (圧縮対象)
    def check_file(file: bytes, flow: http.HTTPFlow) -> int:

        # ファイルサイズを確認
        file_size = len(file)
        file_type = None

        client_ip = flow.client_conn.address[0] if flow.client_conn else "N/A"
        path = flow.request.path if flow.request else "N/A"

        print(f"ファイルサイズ：{file_size}")

        if file_size > FileChecker.MAX_FILE_SIZE_COMPRESSED:
            FileChecker.access_log.warning(
                'ファイルサイズ[%s]が許容される最大サイズ[%s]を超えています。アップロードは拒否されました。接続元IPアドレス[%s]path[%s]', file_size, FileChecker.MAX_FILE_SIZE_COMPRESSED, client_ip, path)
            return 0

        # 画像形式のチェック
        if FileChecker.is_PNG(file):
            file_type = "PNG"
            print(f'画像の種類は：{file_type}です。')
            FileChecker.access_log.info(
                '接続元IPアドレス[%s]の送ったファイル形式は%sです。path[%s]', client_ip, file_type, path)

        if FileChecker.is_JPEG(file):
            file_type = "JPEG"
            print(f'画像の種類は：{file_type}です。')
            FileChecker.access_log.info(
                '接続元IPアドレス[%s]の送ったファイル形式は%sです。path[%s]', client_ip, file_type, path)

        if file_type is None:
            FileChecker.access_log.warning(
                '接続元IPアドレス[%s]の送ったファイル形式が不正です。path[%s]', client_ip, path)
            return 0

        if file_size <= FileChecker.MAX_FILE_SIZE_UNCOMPRESSED:
            FileChecker.access_log.info(
                '接続元IPアドレス[%s]の送ったファイルサイズが2MB以下なので圧縮はスキップされました。path[%s]', client_ip, path)
            return 1

        return 2

    def is_PNG(file: bytes) -> bool:
        if re.match(b'^\x89PNG', file[:4]) is not None:
            return True
        else:
            return False

    def is_JPEG(file: bytes) -> bool:
        if re.match(b'^\xff\xd8', file[:2]) is not None:
            return True
        else:
            return False

    # 画像の圧縮
    def compress_file(file: bytes, flow: http.HTTPFlow) -> bytes:
        client_ip = flow.client_conn.address[0] if flow.client_conn else "N/A"
        path = flow.request.path if flow.request else "N/A"
        # config.iniを読み込む
        pixel_count = ConfigParmeter.get_parameter(
            'Settings', 'pixel_count', 256)
        quality = ConfigParmeter.get_parameter('Settings', 'quality', 85)

        FileChecker.config_log.info('pixel_count[%s]を読み込みます', pixel_count)
        FileChecker.config_log.info('quality[%s]を読み込みます', quality)
        print(f"Loaded pixel_count: {pixel_count}")
        print(f"Loaded quality: {quality}")
        # 圧縮前の保存先
        with BytesIO(file) as image_buffer:
            # 圧縮後の保存先
            with BytesIO() as compressed_buffer:
                # image_buffer(圧縮前の保存場所)を開く
                with Image.open(image_buffer) as img:
                    # 第一引数で保存先(今回は圧縮後の保存先)、第二引数で保存形式、第三形式で品質
                    try:
                        if FileChecker.is_JPEG(file):
                            img.save(compressed_buffer,
                                     format='JPEG', quality=quality)
                        elif FileChecker.is_PNG(file):
                            img = img.quantize(pixel_count)
                            img.save(compressed_buffer, format='PNG')
                        else:
                            return False
                    except Exception as e:
                        print(f"Error during compression: {e}")
                        FileChecker.error_log.error(
                            '接続元IPアドレス[%s]の送ったファイルの圧縮にpath[%s]で失敗しました。以下エラー文です。[%s]', client_ip, path, e)
                        # エラーが発生した場合はFalseを返す
                        return False

                    compressed_file = compressed_buffer.getvalue()
                    compressed_size = len(compressed_file)
                    print(
                        f"ファイルサイズが\n{len(file)} -> {compressed_size}\nになりました。")
                    FileChecker.access_log.info(
                        '接続元IPアドレス[%s]の送ったファイルサイズが%s->%sになりました。path[%s]', client_ip, len(file), compressed_size, path)
                    return compressed_file
