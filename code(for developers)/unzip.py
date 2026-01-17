import os
import zipfile
import struct
import config
from typing import Optional


def is_pe_file(filename:Optional[str],content:bytes) -> bool:
    """
    根据文件内容判断是否为PE文件(优先采用内容判断)
    """
    if len(content) < 64:  # 长度至少为64B
        return False

    if content[:2] != b'MZ':  # 必须以MZ开头
        return False

    pe_offset = struct.unpack("<I", content[0x3C:0x40])[0]

    if pe_offset + 4 > len(content): # 防越界
        return False

    if content[pe_offset:pe_offset + 4] != b'PE\x00\x00': # 检查pe签名
        return False

    if filename: # 通过文件名判断，即使扩展不对，但是内容是PE也返回True
        lower = filename.lower()
        executable_exts = (
            ".exe", ".dll", ".sys", ".scr",
            ".com", ".cpl", ".ocx"
        )
        if os.path.splitext(lower)[1] in executable_exts:
            return True
        
    return True

def batch_unzip_malware(root_dir, dest_dir, password=b"infected"):
    #如果目标保存文件夹不存在，则创建
    if not os.path.exists(config.dest_dir):
        os.makedirs(config.dest_dir)
    
    count = 0
    # 遍历目录结构
    for root, dirs, files in os.walk(config.root_dir):
        for file in files:
            if file.endswith(".zip"):
                zip_path = os.path.join(root, file)
                try:
                    with zipfile.ZipFile(zip_path) as zf:
                        # 获取zip内的文件列表
                        for member in zf.namelist():
                            if not member.endswith('/'):
                                # 解压并重命名防止冲突
                                zf.extract(member, path=config.dest_dir, pwd=password)
                                count += 1
                                print(f"已提取: {member}")
                except Exception as e:
                    print(f"解压 {file} 失败: {e}")
    
    # 根据解压目录保留PE文件
    for root, dirs, files in os.walk(config.dest_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    if not is_pe_file(file, content):
                        os.remove(file_path)
                        print(f"已删除非PE文件: {file_path}")
            except Exception as e:
                print(f"处理文件 {file_path} 失败: {e}")

if __name__ == "__main__":
    print("这是自动解压模块，请运行 main.py")