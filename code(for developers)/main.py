from collect_benign import is_pe_file
from collect_benign import collect_samples
from unzip import batch_unzip_malware
from extractor import get_file_features
from make_csv import build_dataset
from process_fuse import process_fuse
from train import train
from Graph import Graph_make
from detection import email_test
from generate_eml import create_test_eml
import config
import os

'''
这是功能整合模块，请通过手动注释执行需要的功能
'''

r""" # 1.收集良性样本
collect_samples(SOURCES, DESTINATION, limit=300) """ 


r""" # 2.解压恶意文件压缩包
batch_unzip_malware(res_path, des_path,password=b"infected") """


r""" # 3.提取特征生成csv文件
build_dataset(MAL_DIR, BEN_DIR, OUT_FILE) """


r""" # 4.处理数据并执行数据融合
process_fuse(csv_path,rule_save_path,matrix_save_path) """


r""" # 5.训练数据集
train(matrix_path,nb_save_path,rf_save_path) """


r""" # 6.生成图像
Graph_make(config.nb_save_path, config.rf_save_path,config.matrix_save_path, config.rule_save_path)
#分别为朴素贝叶斯模型路径，随机森林模型路径，融合矩阵路径，处理规则路径 """


r""" #7.生成测试邮件
benign_exe = r"C:\Windows\System32\notepad.exe"
create_test_eml(benign_exe, "良性.eml", "这是一封正常的办公邮件") """


r""" #8.通过邮件检测附件
email_test(r"D:\StudyFile\毕业设计\email\良性.eml",config.rule_save_path,config.nb_save_path) """