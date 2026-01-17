import pefile
import hashlib
import math
import os

""" def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):S
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy """

def get_file_features(file_path):
    #定义特征（默认0以免出错）
    features = {

        #结构特征
        "num_sections": 0, # 节区数
        "num_dlls": 0, # dll数
        "num_imports": 0, # 导入数函数数
        "num_rwe_sections": 0, # 可读可写可执行的节区数量

        #头部特征
        "is_ep_in_unexpected_section": 0, # 入口地址是否可疑
        "size_of_image": 0, # 程序加载后的总大小
        "characteristics": 0,  # 文件属性标志
        "dll_characteristics": 0, # DLL安全特性

        #统计特征
        "max_section_entropy": 0, # 最大节区熵值
        "avg_section_entropy": 0, # 平均节区熵值
        "dangerous_api_count": 0, # 危险API计数

        #文本特征
        "api_list": "" # 导入的api
    }

    # 恶意软件常用的敏感API关键词
    DANGEROUS_APIS = [
        'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 
        'InternetOpen', 'HttpSendRequest', 'Crypto', 'ControlService', 
        'EnumProcesses', 'GetProcAddress', 'LoadLibrary'
    ]

    try:
        with open(file_path, "rb") as f:
            content = f.read()
            if not content: return None

        pe = pefile.PE(file_path)
        
        # 提取头部信息
        features["num_sections"] = len(pe.sections)
        features["size_of_image"] = pe.OPTIONAL_HEADER.SizeOfImage
        features["characteristics"] = pe.FILE_HEADER.Characteristics
        features["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics

        # 提取节区熵值与权限
        entropies = []
        rwe_count = 0
        for section in pe.sections:
            e = section.get_entropy()
            entropies.append(e)
            
            # 检查是否有 RWE (Read-Write-Execute) 权限
            if (section.Characteristics & 0x20000000) and \
               (section.Characteristics & 0x40000000) and \
               (section.Characteristics & 0x80000000):
                rwe_count += 1
        
        features["max_section_entropy"] = max(entropies) if entropies else 0
        features["avg_section_entropy"] = sum(entropies)/len(entropies) if entropies else 0
        features["num_rwe_sections"] = rwe_count

        # 提取导入表信息
        apis = []
        dangerous_count = 0
        dll_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', 'ignore')
                        apis.append(api_name)
                        # 统计危险API
                        if any(d_api in api_name for d_api in DANGEROUS_APIS):
                            dangerous_count += 1
        
        features["num_dlls"] = dll_count
        features["num_imports"] = len(apis)
        features["dangerous_api_count"] = dangerous_count
        features["api_list"] = " ".join(apis)

        #如果入口地址不在text区的范围内，则标为1，记为可疑
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        va = pe.sections[0].VirtualAddress  # text区的入口地址
        size = pe.sections[0].Misc_VirtualSize #text区的大小

        if ep < va or ep >= (va + size):
            features["is_ep_in_unexpected_section"] = 1
        else:
            features["is_ep_in_unexpected_section"] = 0

        pe.close()
        return features
    except Exception:
        print(f"出错！")


if __name__ == "__main__":
    print("这是提取模块，请运行 main.py")
