import os
from email.message import EmailMessage
import config

#生成用于测试的良性eml文件和恶意eml文件

def create_test_eml(payload_path, output_eml_path, subject):
    
    """
    将本地的一个.exe 文件封装进一封 .eml 邮件中
    """

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = "sender@test.com"
    msg['To'] = "receiver@test.com"
    msg.set_content("你好，这是附件中的测试程序，请查收。")

    # 读取本地的 PE 文件
    if not os.path.exists(payload_path):
        print(f"错误：找不到文件 {payload_path}")
        return

    with open(payload_path, 'rb') as f:
        file_data = f.read()
        file_name = os.path.basename(payload_path)

    # 添加附件
    msg.add_attachment(
        file_data,
        maintype='application',
        subtype='octet-stream',
        filename=file_name
    )

    # 保存为.eml
    with open(config.email_path + '\\' + output_eml_path, 'wb') as f:
        f.write(msg.as_bytes())
    print(f"成功生成邮件: {output_eml_path}")

if __name__ == "__main__":
    print("这是生成测试邮件模块，请运行main.py")