import joblib
import os
from email_parse import parse
from extractor import get_file_features
import pandas as pd 
import shutil


#根据训练的贝叶斯模型判断输入邮件的附件是否为恶意邮件

def email_test(email_path,rule_path,nb_path):

    #提取邮件中的
    savepath = parse(email_path)

    #加载处理规则和朴素贝叶斯模型
    process = joblib.load(rule_path)
    model = joblib.load(nb_path)

    print("\n开始对邮件附件进行恶意检测：")

    #遍历保存附件的文件夹，提取特征并进行预测
    for root, dirs, files in os.walk(savepath):
        for file in files:
            file_path = os.path.join(root, file)
            features = get_file_features(file_path)# 提取特征
            df_test = pd.DataFrame([features])  # 转换为DataFrame
            X_test = process.transform(df_test)  # 使用已保存的处理规则进行转换
            prediction = model.predict_proba(X_test)[0][1]  # 获取恶意类的概率

            print(f"文件: {file} 的恶意概率为: {prediction:.4f}")
            if prediction >=0.9:
                print("该文件特征高度匹配已知恶意软件模式，判定为恶意文件\n")
            elif prediction >=0.7 and prediction < 0.9:
                print("该文件检测到大量典型攻击行为特征，极有可能是恶意文件，拦截建议：高\n")
            elif prediction >=0.3 and prediction < 0.7:
                print("该文件发现少量异常特征，可能为恶意文件，建议在沙箱或隔离环境中运行\n")
            else:
                print("该文件未检测到明显恶意特征，似乎是安全的\n")
    
    #完成预测后就删除保存附件的文件夹
    #shutil.rmtree(savepath)

if __name__ == "__main__":
    print("这是附件检测模块，请运行main.py")
