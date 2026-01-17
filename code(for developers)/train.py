import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

def train(matrix_path,nb_save_path,rf_save_path):
    data = joblib.load(matrix_path)

    # 分配训练集和数据集
    X_train,X_test,y_train,y_test = train_test_split(
        data['X'],
        data['y'],
        test_size=0.2,
        random_state=66
    )

    # 朴素贝叶斯
    nb = MultinomialNB()
    nb.fit(X_train,y_train)
    y_predict1 = nb.predict(X_test)
    print("朴素贝叶斯训练报告：\n",)
    print(classification_report(
        y_test,
        y_predict1,
        target_names=["良性", "恶意"]
    ))

    # 随机森林(设置对比)
    rf = RandomForestClassifier(n_estimators=100)# 设置为100棵决策树
    rf.fit(X_train,y_train)
    y_predict2 = rf.predict(X_test)
    print("随机森林训练报告：\n",)
    print(classification_report(
        y_test,
        y_predict2,
        target_names=["良性", "恶意"]
    ))

    joblib.dump(nb, nb_save_path)
    joblib.dump(rf, rf_save_path)

if __name__ == "__main__":
    print("这是训练模块，请运行 main.py")