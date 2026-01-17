"""
项目路径配置文件
将所有与路径相关的常量集中放在这里，供 `main.py` 导入使用。
"""

# 良性样本源文件与目标路径
SOURCES = None
DESTINATION = None

# 恶意样本压缩包源文件与目标路径
res_path = None
des_path = None

# 数据集及生成样本路径
MAL_DIR = None
BEN_DIR = None
OUT_FILE = None

# 样本来源路线和处理规则，融合矩阵保存路径
csv_path = None
rule_save_path = None
matrix_save_path = None

# 训练模型保存路径
matrix_path = None
nb_save_path = None
rf_save_path = None

# 附件路径
attachment_path = None

__all__ = [
    'SOURCES','DESTINATION','res_path','des_path',
    'MAL_DIR','BEN_DIR','OUT_FILE','csv_path',
    'rule_save_path','matrix_save_path','matrix_path',
    'nb_save_path','rf_save_path','attachment_path'
]
