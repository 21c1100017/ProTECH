from logging import INFO
import time
from classes.logmethod import log_setting
from classes.configparmeter import config_parmeter


class FlowMonitor:
    # クラス変数として flow_count を初期化
    flow_count = {}

    def request_check(flow):
        ip = flow.client_conn.address[0]
        user_agent = flow.request.headers.get('User-Agent', '')
        # ログのセットアップ
        detection_log = log_setting.log_setup('detection', INFO)
        access_log = log_setting.log_setup('access', INFO)

        # config.iniを読み込む
        # 人間用の閾値
        human_threshold = config_parmeter.get_parameter(
            'Settings', 'human_threshold', 10)
        # スクリプト用の閾値
        script_threshold = config_parmeter.get_parameter(
            'Settings', 'script_threshold', 100)
        # アクセス拒否をする時間(秒)
        block_duration = config_parmeter.get_parameter(
            'Settings', 'lock_duration', 30)

        # 同じIPアドレスとUser-Agentが1分間にthreshold回以上アクセスした場合
        if (ip, user_agent) in FlowMonitor.flow_count:
            FlowMonitor.flow_count[(ip, user_agent)][0] += 1
            #print(f"今の回数は{FlowMonitor.flow_count}です")
            if FlowMonitor.flow_count[(ip, user_agent)][0] > script_threshold:
                # スクリプト用の閾値を超えたら flow.intercept()
                if FlowMonitor.flow_count[(ip, user_agent)][1] <= time.time():
                    del FlowMonitor.flow_count[(ip, user_agent)]
                else:
                    detection_log.warning(
                        "スクリプトで大量のアクセスをしている可能性があります。適切なアクセス制限を行ってください。接続元IPアドレス[%s] ユーザーエージェント[%s] ブロック時間 [%s] 秒", ip, user_agent, block_duration)
                    flow.intercept()
            elif FlowMonitor.flow_count[(ip, user_agent)][0] > human_threshold:
                # 人間用の閾値を超えたら flow.kill()
                if FlowMonitor.flow_count[(ip, user_agent)][1] <= time.time():
                    del FlowMonitor.flow_count[(ip, user_agent)]
                else:
                    detection_log.warning(
                        "人の手によって大量のアクセスをしている可能性があります。 適切なアクセス制限を行ってください。接続元IPアドレス[%s]ユーザーエージェント[%s] ブロック時間 [%s] 秒", ip, user_agent, block_duration)
                    flow.kill()
            else:
                # カウントがゼロになったらエントリを削除
                if FlowMonitor.flow_count[(ip, user_agent)][0] == 0:
                    del FlowMonitor.flow_count[(ip, user_agent)]
        else:
            # [カウント, ブロック解除時間] を格納したリストで初期化
            FlowMonitor.flow_count[(ip, user_agent)] = [
                1, time.time() + block_duration]
            access_log.info("接続したユーザー情報を記録します。[%s]", FlowMonitor.flow_count)
            print(f"新しいキーが作成されました{FlowMonitor.flow_count}")
