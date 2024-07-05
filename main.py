import json
import re
from pdf_reader_utils import *
file_path = 'black-basta-parse.pdf'
forms = get_form_data(file_path)
text_and_links = extract_links_and_text(file_path)
pattern = {"ipv4-addr": set(), "domain-name": set(), "url": set()}  # 用于去重
result = {"objects": []}  # 最终的结果

# 开始遍历所有表格
for form in forms:
    Header = form.columns.tolist()
    if "Technique Title" in Header:
        for index, item in form.iterrows():
            name = item["Technique Title"].replace("\n", " ")
            id = item["ID"]
            url = text_and_links[item["ID"]]
            info = {"name": name, "external_id": id, "url": url}
            stix_json = get_att_ck_json(info)
            print(stix_json)
            result["objects"].append(json.loads(stix_json))
    if ("Hash" in Header) and ("Description" in Header):
        for index, item in form.iterrows():
            Hash_value = item["Hash"]
            stix_json = get_iocs_fbi_json(Hash_value, "hash")
            print(stix_json)
            result["objects"].append(json.loads(stix_json))
    if ("IP Address" in Header) and ("Description" in Header):
        # print(form)
        for index, item in form.iterrows():
            # 解析Description
            Description = item["Description"]
            Description = re.sub("\[\.\]", ".", Description)
            Description = [re.sub("\\n", "", i.strip()) for i in Description.split(",")]
            Description_new = []
            for i in Description:
                i = i.replace(".net", ".net ")
                i_split = i.split()
                for item_ in i_split:
                    Description_new.append(item_.strip("."))
            for i in Description_new:
                if len(i) < 200:
                    pattern["domain-name"].add(i)
                else:
                    pattern["url"].add(i)
            # 解析IP Address
            IP_Address = item["IP Address"]
            IP_Address = re.sub("\[\.\]", ".", IP_Address)
            pattern["ipv4-addr"].add(IP_Address)
    if ("Filename" in Header) and ("Hash" in Header):
        for index, item in form.iterrows():
            Hash = item["Hash"]
            Hash = Hash.replace("\n", "")
            if Hash:
                if len(Hash) < 50:
                    stix_json = get_iocs_fbi_json(Hash, "md5")
                    print(stix_json)
                    result["objects"].append(json.loads(stix_json))
                else:
                    stix_json = get_iocs_fbi_json(Hash, "hash")
                    print(stix_json)
                    result["objects"].append(json.loads(stix_json))
    if "Domain" in Header:
        for index, item in form.iterrows():
            Domain = item["Domain"]
            Domain = re.sub("\[\.\]", ".", Domain)
            pattern["domain-name"].add(Domain)

# 开始写入pattern里面的信息
for i, v in pattern.items():
    if i == "ipv4-addr":
        for j in v:
            stix_json = get_iocs_fbi_json(j, "ipv4")
            print(stix_json)
            result["objects"].append(json.loads(stix_json))
    if i == "domain-name":
        for j in v:
            stix_json = get_iocs_fbi_json(j, "domain")
            print(stix_json)
            result["objects"].append(json.loads(stix_json))
    if i == "url":
        for j in v:
            stix_json = get_iocs_fbi_json(j, "url")
            print(stix_json)
            result["objects"].append(json.loads(stix_json))

# 保存文件
filename = 'stix_json.json'
out_file = open(filename, "w")
json.dump(result, out_file, indent=4)
out_file.close()











