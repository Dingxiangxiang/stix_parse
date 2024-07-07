import PyPDF2
import requests
from openai import OpenAI
import json, re
client = OpenAI(api_key="sk-83ab427e0ac74adeb102e0daa77a3ee7", base_url="https://api.deepseek.com")  # deepseek调用

mypdf = open('black-basta-parse.pdf',mode='rb')
pdf_document = PyPDF2.PdfReader(mypdf)
all_pages = []
for i in range(0,len(pdf_document.pages)):
    page_data = pdf_document.pages[i]
    text = page_data.extract_text()
    all_pages.append(text)

def generate_res_a(a):
    """
    每4页进行一次模型分析，每次前进一页，3页的交叉
    """
    res_a = []
    for i in range(len(a) - 3):
        res_a.append(a[i:i+4])
    return res_a


def deepseek_chat(input):
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "user", "content": input},
        ],
        stream=False
    )
    return response.choices[0].message.content


url = "http://10.200.1.106:8088/qwen15_nostream"

base_prompt = """
"MITRE ATT&CK TACTICS AND TECHNIQUES" 是指 MITRE 公司创建的一个全球性的、开放的知识库，用于描述和分类网络攻击者使用的战术和技术。
ATT&CK 是 "Adversarial Tactics, Techniques, and Common Knowledge" 的缩写，它提供了一个框架，帮助安全专业人员理解和应对网络威胁。
IOCs,IOCs是"Indicators of Compromise"的缩写，这是一个网络安全领域的术语。 它指的是在系统或网络遭受攻击后留下的痕迹或证据，这些迹象可以用来检测是否发生过攻击，以及攻击的具体方式和范围。这些指标可能包括恶意软件的文件哈希值、异常的网络活动、特定的IP地址、域名、文件名或进程等。通过识别和分析IOCs，安全分析师可以更好地理解和响应网络安全威胁，以及防止未来的攻击。
"""
task1 = """
获取threat actor在Att&CK中各阶段所使用的Techniques，并获取Techniques和它所对应的ID，以json格式{"Technique Title":"{}","ID":"{}"},的形式输出,没有涉及Techniques，时返回None,json中不要私自添加其他字段
注意这些信息都在表格当中，不要在表格之外找, 没有的话直接返回None，不要输出别的内容，不要输出非json的数据
"""
result = {"Techniques":dict(), "IP":set(), "Domain":set(), "Hash":set()}
all_pages_split = generate_res_a(all_pages)

# 提取 ATT&CK 中的Techniques
for i in all_pages_split:
    knowledge_data = "\n".join(i)
    input =  "请记住以下知识\n" + knowledge_data + "完成下面的任务。{}".format(task1)
    res = requests.post(url, json={"input":input})
    print(res.text.replace("json", ""))
    res = res.text.replace("json", "")
    if res == "None":
        continue
    res = json.loads(res.strip("```"))
    print(res)
    for i in res:
        result["Techniques"].update({i["Technique Title"]:i["ID"]})
for i,v in result["Techniques"].items():
    print(i,v)


task2 = """
提取iocs中所涉及的文件的Hash值，以一定要用json的格式{"hash":"{}"}返回，{}里面填充具体的hash值，
请一定要注意以下几点：
1，hash值只存在表中Hash字段的信息下面
2，只提取hash数据，不要擅自添加新的字段,
3，没有找到Hash值时直接返回None，不要输出别的内容
4，注意hash值是64位的长度，有的表格里面hash值里面有换行\n，请忽略这个，把它拼接起来
"""
hash_set = set()
qwen_hash = set()
deep_seek_hash = set()
# 从通义千问中获取hash
for i in all_pages:
    input = "请记住以下知识\n" + i + "完成下面的任务。{}".format(task2)
    res = requests.post(url, json={"input":input}).text
    print(res)
    match = re.search(r'```json(.*?)```', res, re.S)
    if match:
        matched_text = match.group(1)
        try:
            res = json.loads(matched_text)
        except:
            continue
        print(res)
        if len(res) == 1:
            qwen_hash.add(res["hash"])
            continue
        for i in res:
            qwen_hash.add(i["hash"])
for i in qwen_hash:
    print(i)
# 从deepseek中获取hash
for i in all_pages:
    input = "请记住以下知识\n" + i + "完成下面的任务。{}".format(task2)
    res = deepseek_chat(input)
    print(res)
    match = re.search(r'```json(.*?)```', res, re.S)
    if match:
        matched_text = match.group(1)
        try:
            res = json.loads(matched_text)
        except:
            continue
        print(res)
        if len(res) == 1:
            deep_seek_hash.add(res["hash"])
            continue
        for i in res:
            deep_seek_hash.add(i["hash"])
for i in deep_seek_hash:
    print(i)
for i in qwen_hash:
    if (len(i) == 64) or (len(i) == 32):
        hash_set.add(i)
for i in deep_seek_hash:
    if (len(i) == 64) or (len(i) == 32):
        hash_set.add(i)  # 结果合并
for i in hash_set:
    result["Hash"].add(i)

task3 = """
提取iocs中所涉及的IP地址，以一定要用json的格式{"IP":"{}"}返回，{}里面填充具体的ip值，
请一定要注意以下几点：
1，只提取IP数据，不要擅自添加新的字段,
2，没有找到IP值时直接返回None，不要输出别的内容
"""
for i in all_pages:
    input = "请记住以下知识\n" + i + "完成下面的任务。{}".format(task3)
    res = requests.post(url, json={"input":input}).text  # 这个只需要通义千问就能解决
    print(res)
    match = re.search(r'```json(.*?)```', res, re.S)
    if match:
        matched_text = match.group(1)
        try:
            res = json.loads(matched_text)
        except:
            continue
        print(res)
        if len(res) == 1:
            try:
                result["IP"].add(res["IP"])
            except:
                result["IP"].add(res[0]["IP"])
            continue
        for i in res:
            result["IP"].add(i["IP"])
for i in result["IP"]:
    print(i)

task4 = """
提取iocs中所涉及的域名，以一定要用json的格式{"domain":"{}"}返回，{}里面填充具体的域名，
请一定要注意以下几点：
1，以上知识中域名的格式可能有问题，请自动转换成正常的域名
2，请正确识别域名信息，不要保存非正常格式的域名
3，没有找到域名时直接返回None，不要输出别的内容
4，不要将ip信息填进域名中

"""
for i in all_pages:
    input = "请记住以下知识\n" + i + "完成下面的任务。{}".format(task4)
    # res = requests.post(url, json={"input":input})
    # print(res.text)
    res = deepseek_chat(input)  # deepseek方案
    print(res)
    match = re.search(r'```json(.*?)```', res, re.S)
    if match:
        matched_text = match.group(1)
        try:
            res = json.loads(matched_text)
        except:
            continue
        print(res)
        if len(res) == 1:
            try:
                result["Domain"].add(res["domain"])
            except:
                result["Domain"].add(res[0]["domain"])
            continue
        for i in res:
            result["Domain"].add(i["domain"])
for i in result["Domain"]:
    print(i)

# 保存提取的信息结果：
out_f1 = open("out_extract_info.text", "w", encoding="utf-8")
for i,v in result.items():
    print(i, v)
    out_f1.write(i + "\n")
    if i == "Techniques":
        for m,n in v.items():
            out_f1.write(str(m)+ ":"+ str(n) + "\n")
    else:
        for j in v:
            out_f1.write(str(j)+ "\n")
    out_f1.write("\n")
    

