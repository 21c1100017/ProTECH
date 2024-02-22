from mitmproxy import http
from urllib.parse import urlparse
from classes.filechecker import FileChecker
from classes.sanitizedparameter import SanitizedParameter
from classes.directorytraversal import DirectoryTraversal
from classes.customerror import CustomError
from classes.dos import FlowMonitor


def request(flow: http.HTTPFlow) -> None:

    # リクエストのURLを取得
    url = flow.request.url
    # URLを解析してスキームを取得
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme

    # URLを解析してホスト名を取得してスキームと連結
    parsed_url = urlparse(url)
    host_name = scheme + "://" + parsed_url.hostname

    path = flow.request.path
    DirectoryTraversal.url_check(flow, host_name, path)

    # ファイルチェック処理
    FileChecker().run(flow)

    # サニタイジング処理
    SanitizedParameter.check_parameter(flow)

    # DOS攻撃チェック
    FlowMonitor().request_check(flow)

def response(flow: http.HTTPFlow) -> None:

    # レスポンスが発生するたびに実行されるコード
    CustomError.response(flow)  # custom_errorクラスを呼び出す部分
