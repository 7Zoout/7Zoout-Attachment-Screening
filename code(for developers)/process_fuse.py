import pandas as pd
import joblib
import os
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder

def process_fuse(csv,rule_path,matrix_path):
    df = pd.read_csv(csv) # 载入
    
    # 数据型特征(使用MinMaxScaler)
    list1 = ["num_sections","num_dlls","num_imports","num_rwe_sections","is_ep_in_unexpected_section","size_of_image","max_section_entropy","avg_section_entropy","dangerous_api_count"]

    # 类别型代码(使用独热编码)
    list2 = ["characteristics","dll_characteristics"]

    # 文本型(使用TF-IDF)
    list3 = "api_list"

    # 填补缺失的值以免影响结果
    df[list1] = df[list1].fillna(0)
    df[list2] = df[list2].fillna(0)
    df[list3] = df[list3].fillna("empty")

    process = ColumnTransformer(# 三通道转换器
        transformers=[
            ('num',MinMaxScaler(),list1),
            ('cat',OneHotEncoder(handle_unknown='ignore'),list2),# 如果出现未曾出现的组合则全标为0
            ('text',TfidfVectorizer(max_features=1000),list3),
        ]
    )

    print("正在执行三通道特征融合")
    X = process.fit_transform(df)
    y = df['label'] # 样本标签

    joblib.dump(process,rule_path)
    joblib.dump({"X":X,"y":y},matrix_path)

    print(f"融合成功！已生成规则和新矩阵！目前总维度为：{X.shape[1]}")
    return X,y
    


if __name__ == "__main__":
    print("这是特征处理与融合模块，请运行 main.py")