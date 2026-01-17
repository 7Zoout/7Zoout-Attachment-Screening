import warnings
import joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import train_test_split

# 忽略警告信息
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)



# 设置支持中文的字体
plt.rcParams['font.sans-serif'] = ['SimHei'] # 设置显示中文
plt.rcParams['axes.unicode_minus'] = False   # 设置正常显示负号



def Graph_make(model1,model2,model3,model4):
    #加载数据
    top_n = 20 # 显示20个最重要特征
    nb = joblib.load(model1)# 加载朴素贝叶斯训练模型
    rf = joblib.load(model2)# 加载随机森林训练模型
    data = joblib.load(model3)# 加载融合矩阵
    process = joblib.load(model4)# 加载处理规则
    X, y = data['X'], data['y']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=66)#和训练数据时一样划分数据集以恢复训练环境



    """ 
    分析朴素贝叶斯的特征重要性 
    """
    # 计算每个特征的权重
    feature_names = process.get_feature_names_out()
    ratios = np.exp(nb.feature_log_prob_[1]) / np.exp(nb.feature_log_prob_[0])

    # 获取最重要的特征
    top_idxs = np.argsort(ratios)[-top_n:]
    top_names = [feature_names[i] for i in top_idxs]
    top_values = ratios[top_idxs]

    # 绘制图像
    plt.figure(figsize=(10, 8))
    plt.barh(top_names, top_values, color='skyblue')
    plt.title('朴素贝叶斯特征重要性 (Top {})'.format(top_n))
    plt.xlabel('重要性比率 (恶意/良性)')
    plt.ylabel('特征名称')
    plt.tight_layout()
    plt.savefig(r"D:\StudyFile\毕业设计\image\朴素贝叶斯最重要特征.png")
    print("已生成特征重要性图：朴素贝叶斯最重要特征.png")



    """ 
    输出混淆矩阵图像
    """
    # 预测标签
    y_pred = nb.predict(X)
    cm = confusion_matrix(y, y_pred)

    # 绘制混淆矩阵
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['良性', '恶意'], yticklabels=['良性', '恶意'])
    plt.title('朴素贝叶斯混淆矩阵')
    plt.xlabel('预测标签')
    plt.ylabel('真实标签')
    plt.savefig("D:/StudyFile/毕业设计/image/朴素贝叶斯混淆矩阵.png")
    print("已生成混淆矩阵图：朴素贝叶斯混淆矩阵.png")



    
    """
    输出朴素贝叶斯和随机森林的算法性能图
    """
    labels = ['准确率', '精确率', '召回率', 'F1得分']
    nb_scores = [0.91, 0.86, 0.96, 0.91]  # 朴素贝叶斯
    rf_scores = [0.94, 0.93, 0.95, 0.94]  # 随机森林

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, nb_scores, width, label='朴素贝叶斯', color='#3498db')
    rects2 = ax.bar(x + width/2, rf_scores, width, label='随机森林', color='#e74c3c')

    ax.set_ylabel('得分')
    ax.set_title('模型表现对比')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0.8, 1.0) # 聚焦在差异区间
    ax.legend()

    plt.savefig(r"D:\StudyFile\毕业设计\image\模型表现对比.png", dpi=300)
    print("已生成对比图：模型表现对比.png")



    """ 
    输出ROC曲线图
    """
    # 取所有测试样本恶意的概率
    nb_probs = nb.predict_proba(X_test)[:, 1]
    rf_probs = rf.predict_proba(X_test)[:, 1]

    #计算ROC曲线上的各个点
    nb_fpr, nb_tpr, _ = roc_curve(y_test, nb_probs)
    rf_fpr, rf_tpr, _ = roc_curve(y_test, rf_probs)

    # 计算AUC面积
    nb_auc = auc(nb_fpr, nb_tpr)
    rf_auc = auc(rf_fpr, rf_tpr)

    # 绘制ROC曲线
    plt.figure(figsize=(8, 6))
    plt.plot(nb_fpr, nb_tpr, color='red', lw=2, label='朴素贝叶斯 (AUC = {nb_auc:0.2f})'.format(nb_auc=nb_auc))
    plt.plot(rf_fpr, rf_tpr, color='blue', lw=2, label='随机森林 (AUC = {rf_auc:0.2f})'.format(rf_auc=rf_auc))

    #绘制对角基准线
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('假阳性率')
    plt.ylabel('真阳性率')
    plt.title('Receiver Operating Characteristic (ROC) 曲线对比')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.savefig(r"D:\StudyFile\毕业设计\image\ROC曲线对比.png", dpi=300)
    print("已生成ROC曲线图：ROC曲线对比.png")

if __name__ == "__main__":
    print("这是图像生成模块，请运行main.py")