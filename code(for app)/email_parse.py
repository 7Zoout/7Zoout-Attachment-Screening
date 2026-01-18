import email
import os
import sys
import struct
from email import policy
from typing import Optional

#根据文件内容判断是否为PE文件(优先采用内容判断)
def is_pe_file(filename:Optional[str],content:bytes) -> bool:
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



#遍历邮件的每个部分，找到邮件的附件 
def parse(email_path):

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    temp_path = os.path.join(os.path.dirname(BASE_DIR), 'temp_attachment')

    # 预先设置保存附件的文件夹
    filename = os.path.basename(email_path)
    name, _ = os.path.splitext(filename)
    savepath = os.path.join(temp_path, name)
    if not os.path.exists(savepath):
        os.makedirs(savepath) 

    with open(email_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)


    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            content = part.get_payload(decode=True)
            
            # 判断附件是否为PE文件并保存附件至目标文件夹
            if is_pe_file(filename, content):
                filepath = os.path.join(savepath, filename)
                with open(filepath, 'wb') as f_out:
                    f_out.write(content)
    return savepath

if __name__ == "__main__":
    print("这是邮件附件提取模块，请运行detection.py")