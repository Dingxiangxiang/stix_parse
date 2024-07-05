import pdfplumber
import pandas as pd
from stix2 import AttackPattern, MarkingDefinition, Indicator
import fitz  # PyMuPDF
from stix2 import Indicator, Identity
from stix2.v21 import TLP_WHITE, TLP_GREEN

def filter_none_line(table):
    """
    去除table list里面的空行
    :param table: 待处理的表
    :return: 返回新的表
    """
    new_table = []
    for line in table:
        len_line = len(line)
        cnt = 0
        for i in line:
            if not i:
                cnt += 1
        if cnt == len_line:
            continue
        else:
            new_table.append(line)
    return new_table


def format_table(table):
    """
    归一化table,返回处理好的DataFrame，经测试所有类型的表格数据，均可用以下方式进行归一化
    :param table: 待处理表格
    :return:归一化好的df_table
    """
    title = table[0]
    bodys = table[1:]
    title_new = []
    # 表头若为空的数据可以直接删除
    for i in title:
        if i:
            title_new.append(i)
    # bodys 需要按列进行处理，整列的数据需要删除，防止本身为空的数据被删除
    df_body = pd.DataFrame(bodys)
    df_body.dropna(axis=1, how='all', inplace=True)
    if len(table[0]) == 1:
        title_new = ["Domain"]  # 这个是可疑域名的表格，进行特殊处理，他只有一列数据
    df_body.columns = title_new
    return df_body


def get_form_data(file_path):
    """
    获取所有的表格信息
    :param file_path:
    :return:pdf中的所有表格
    """
    results = []
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            tables = page.extract_tables()
            for table in tables:
                table = filter_none_line(table)
                df_table = format_table(table)
                results.append(df_table)
    return results


def extract_links_and_text(pdf_path):
    """
    获取pdf中所有的超链接，以及超链接对应的文本文字
    :param pdf_path:待分析的pdf路径
    :return:返回所有超链接
    """
    # 打开PDF文件
    doc = fitz.open(pdf_path)
    text_and_links = {}
    # 遍历每一页
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        links = page.get_links()
        # 遍历每一个链接
        for link in links:
            if link['kind'] == fitz.LINK_URI:  # 只处理URI类型的链接
                # 获取链接的矩形区域
                rect = fitz.Rect(link['from'])
                # 获取矩形区域内的文本
                link_text = page.get_text("text", clip=rect)
                text_and_links[link_text.strip()] = link['uri']
    return text_and_links


def get_att_ck_json(stix_info):
    """
    生成 ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge)信息
    它是一个全球可访问的、基于真实世界观察的对抗战术和技术知识库。它提供了一个结构化的分类法，
    用于描述和理解网络攻击者在攻击过程中可能使用的战术和技术。
    :param stix_info:输入信息
    :return:stix_json
    """
    # 给定的字典，添加 object_marking_refs 字段
    marking1 = MarkingDefinition(
        id="marking-definition--479081c8-3a60-4eb8-b410-96a30f395def",
        definition_type="statement",
        definition={"statement": "Marking 1"})
    marking2 = MarkingDefinition(
        id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        definition_type="statement",
        definition={"statement": "Marking 2"})
    # 构造结构化信息
    d = {
        "name": stix_info["name"],
        "created_by_ref": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
        "object_marking_refs": [marking1.id, marking2.id],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": stix_info["external_id"],
                "url": stix_info["url"]
            }
        ]
    }
    attack_pattern = AttackPattern(**d)
    stix_json = attack_pattern.serialize(pretty=True)
    return stix_json


def get_iocs_fbi_json(value, type):
    """
    生成IOCs(Indicators of Compromise)信息,
    IOCs是指在网络攻击或数据泄露事件中，可以用来识别、检测或确认安全事件发生的各种迹象或证据。
    这些指标可能包括恶意软件的哈希值、恶意IP地址、恶意URL、被篡改的文件、异常的登录活动等。
    :param value: 文件的哈希值，MD5，url，域名，ipv4值，和type的取值有关
    :param type: 数据类型 "hash" "md5" "ipv4" "domain" "url"
    :return: stix_json
    """
    # 使用预定义的 TLP 标记
    marking_definition_1 = TLP_WHITE
    marking_definition_2 = TLP_GREEN
    # 创建 Identity 对象
    identity = Identity(
        id="identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
        name="Example Organization",
        identity_class="organization"
    )
    if type == "hash":
        # 创建 Indicator 对象
        indicator = Indicator(
            name="Malicious File Hash",
            indicator_types=["malicious-activity"],
            pattern="[file:hashes.'SHA-256' = '{}']".format(value),
            pattern_type="stix"
        )
        stix_json = indicator.serialize(pretty=True)
        return stix_json
    if type == "md5":
        # 创建 Indicator 对象
        indicator = Indicator(
            id="indicator--72c5d588-091d-4fe7-b028-03c116f9f21f",
            type="indicator",
            spec_version="2.1",
            pattern_type="stix",
            created="2024-05-10T19:49:50.000Z",
            modified="2024-05-10T19:49:50.000Z",
            object_marking_refs=[
                marking_definition_1,
                marking_definition_2
            ],
            name="File Indicator",
            indicator_types=["malicious-activity"],
            valid_from="2022-04-01T00:00:00Z",
            pattern="[(file:hashes.MD5 = '{}')]".format(value),
            created_by_ref=identity
        )
        stix_json = indicator.serialize(pretty=True)
        return stix_json

    if type == "ipv4":
        # 创建 Indicator 对象
        indicator = Indicator(
            id="indicator--fae92179-fd4e-489f-bdb7-956a37f90120",
            type="indicator",
            spec_version="2.1",
            pattern_type="stix",
            created="2024-05-10T19:49:50.000Z",
            modified="2024-05-10T19:49:50.000Z",
            object_marking_refs=[
                marking_definition_1,
                marking_definition_2
            ],
            name="IPv4 Indicator",
            indicator_types=["malicious-activity"],
            valid_from="2022-04-01T00:00:00Z",
            pattern="[ipv4-addr:value = '{}']".format(value),
            created_by_ref=identity
        )
        # 将 Indicator 对象转换为 JSON 格式
        stix_json = indicator.serialize(pretty=True)
        return stix_json

    if type == "domain":
        # 创建 Indicator 对象
        indicator = Indicator(
            id="indicator--a3930cdb-1a38-4cf0-9dd6-a453e86e5222",
            type="indicator",
            spec_version="2.1",
            pattern_type="stix",
            created="2024-05-10T19:49:50.000Z",
            modified="2024-05-10T19:49:50.000Z",
            object_marking_refs=[
                marking_definition_1,
                marking_definition_2
            ],
            name="FQDN Indicator",
            indicator_types=["malicious-activity"],
            valid_from="2022-04-01T00:00:00Z",
            pattern="[domain-name:value = '{}']".format(value),
            created_by_ref=identity
        )
        # 将 Indicator 对象转换为 JSON 格式
        stix_json = indicator.serialize(pretty=True)
        return stix_json

    if type == "url":
        # 创建 Indicator 对象
        indicator = Indicator(
            id="indicator--f7b213b8-99e8-48d5-94fa-f19ccd7ea428",
            type="indicator",
            spec_version="2.1",
            pattern_type="stix",
            created="2024-05-10T19:49:50.000Z",
            modified="2024-05-10T19:49:50.000Z",
            object_marking_refs=[
                marking_definition_1,
                marking_definition_2
            ],
            name="Url Indicator",
            indicator_types=["malicious-activity"],
            valid_from="2022-04-01T00:00:00Z",
            pattern="[url:value = '{}']".format(value),
            created_by_ref=identity
        )
        # 将 Indicator 对象转换为 JSON 格式
        stix_json = indicator.serialize(pretty=True)
        return stix_json
