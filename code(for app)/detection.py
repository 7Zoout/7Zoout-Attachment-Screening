import joblib
import os
from email_parse import parse
from extractor import get_file_features
import pandas as pd 
import shutil


#根据训练的贝叶斯模型判断输入邮件的附件是否为恶意邮件

def email_test(email_path,process,model)    :

    #提取邮件中的
    savepath = parse(email_path)

    print("\n开始对邮件附件进行恶意检测：")

    #遍历保存附件的文件夹，提取特征并进行预测
    for root, dirs, files in os.walk(savepath):
        for file in files:

            results = []

            file_path = os.path.join(root, file)
            features = get_file_features(file_path)# 提取特征
            df_test = pd.DataFrame([features])  # 转换为DataFrame
            X_test = process.transform(df_test)  # 使用已保存的处理规则进行转换
            prediction = model.predict_proba(X_test)[0][1]  # 获取恶意类的概率
            results.append({"name": os.path.basename(file), "prob": prediction , "features": features})

    #完成预测后就删除保存附件的文件夹
    shutil.rmtree(savepath)
    return results

if __name__ == "__main__":
    print("这是附件检测模块，请运行app.py")
