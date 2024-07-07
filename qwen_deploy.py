# -*- coding: utf8 -*-

# # ##调用 lmdeploy2.py 这个脚本部署的lmdeploy serve 的部署方式
# # ##部署方式如下
# import os
# #8卡运行
# os.environ['CUDA_VISIBLE_DEVICES'] = "0,1,2,3,4,5,6,7"
# os.system("nohup lmdeploy serve api_server /data/dx/lmdeploy_model/Qwen1.5-72B-Chat-AWQ --server-name 0.0.0.0 --server-port 9000 --tp 8 &")


### 使用 os.system 直接执行curl 命令,调用上面部署的服务
# import os
# os.system(
# """curl -X 'POST' \
#   'http://10.200.1.6:9000/v1/chat/interactive' \
#   -H 'accept: text/plain' \
#   -H 'Content-Type: application/json' \
#   -d '{
#   "prompt": "你好啊,介绍一下你自己",
#   "image_url": null,
#   "session_id": -1,
#   "interactive_mode": false,
#   "stream": true,
#   "stop": null,
#   "request_output_len": null,
#   "top_p": 0.8,
#   "top_k": 40,
#   "temperature": 0.8,
#   "repetition_penalty": 1,
#   "ignore_eos": false,
#   "skip_special_tokens": true,
#   "cancel": false,
#   "adapter_name": null
# }'"""
# )

from flask import Flask, Response, request, jsonify
app = Flask(__name__)
import subprocess, json

# 流式输出
@app.route('/qwen15_stream', methods=['POST'])
def qwen15_stream():
    def interaction(prompts):
        url = 'http://10.200.1.106:9000/v1/chat/interactive'
        headers = {
            'accept': 'text/plain',
            'Content-Type': 'application/json',
        }
        data = {
                "prompt": prompts,
                "image_url": None,
                "session_id": -1,
                "interactive_mode": False,
                "stream": True,
                "stop": None,
                "request_output_len": None,
                "top_p": 0.8,
                "top_k": 40,
                "temperature": 0.8,
                "repetition_penalty": 1,
                "ignore_eos": False,
                "skip_special_tokens": True,
                "cancel": False,
                "adapter_name": None
            }
        data_js = ""
        response = requests.post(url, headers=headers, data=json.dumps(data), stream=True)
        try:
            # 实时读取并处理stdout输出
            try:
                for line in response.iter_lines(decode_unicode=True):
                    print(line)
                    yield f"event: message\ndata: {line}\nretry: 10000\n\n"
            except:
                yield f"event: message\ndata: {'model failed'}\nretry: 10000\n\n"
            yield f"event: complete\ndata: \nretry: 10000\n\n"
            # 确保子进程正确结束
        except KeyboardInterrupt:
            print("Process terminated by user.")

    input_data = request.get_json()
    input = input_data["input"]
    if "history" in input_data:
        history = input_data["history"]
        try:
            history = history.replace("\n", "\\n")
            history = json.loads(history)
        except:
            print("json格式化失败，history的json格式不合法！")
            history = []
    else:
        history = []
    prompt0 = input
    prompt1 = "完成下面的最后一轮的对话。对话之间是用###区分的，只用回答对话的内容即可"
    if history:
        for i,v in history.items():
            v = v.replace("\n", "\\n")
            qa = re.findall(r'\[#.*?#\]', v)
            q = qa[0][2:-2]
            a = qa[1][2:-2]
            prompt1 = prompt1 + "###" + q + "###" + a
        prompt = prompt1 + "###" + input
    else:
        prompt = prompt0
    return Response(interaction(prompt), mimetype="text/event-stream")


## 非流式的方式获取数据
import requests
import time, re
@app.route('/qwen15_nostream', methods=['POST'])
def qwen15_no_stream():
    input_data = request.get_json()
    input = input_data["input"]
    if "history" in input_data:
        history = input_data["history"]
        try:
            history = history.replace("\n", "\\n")
            history = json.loads(history)
        except:
            print("json格式化失败，history的json格式不合法！")
            history = []
    else:
        history = []
    prompt0 = input
    prompt1 = "完成下面的最后一轮的对话。对话之间是用###区分的，只用回答对话的内容即可"
    url = "http://10.200.1.106:9000/v1/chat/interactive"
    headers = {"Content-Type": "application/json"}
    if history:
        for i,v in history.items():
            v = v.replace("\n", "\\n")
            qa = re.findall(r'\[#.*?#\]', v)
            q = qa[0][2:-2]
            a = qa[1][2:-2]
            prompt1 = prompt1 + "###" + q + "###" + a
        prompt = prompt1 + "###" + input
    else:
        prompt = prompt0
    data = {
      "prompt": prompt,
      "session_id": -1,
      "interactive_mode": "false",
      "stream": "false",
      "stop": "string",
      "top_p": 0.8,
      "top_k": 40,
      "temperature": 0.8,
      "repetition_penalty": 1,
      "ignore_eos": "false",
      "cancel": "false"
    }
    # 发送POST请求
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        response_data = response.json()
        res = response_data["text"]
        return res
    else:
        return f"请求失败，状态码：{response.status_code}"

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=8089, threaded=True)  # 测试环境
    app.run(host='0.0.0.0', port=8088, threaded=True)  # 正式环境
