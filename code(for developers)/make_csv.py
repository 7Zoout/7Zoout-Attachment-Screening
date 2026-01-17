import csv
import os
#导入工具函数
from extractor import get_file_features

def build_dataset(malware_dir, benign_dir, output_csv):
    # 定义表头
    fieldnames = ["num_sections","dll_characteristics","max_section_entropy","num_dlls","dangerous_api_count","num_rwe_sections","characteristics","is_ep_in_unexpected_section","avg_section_entropy", "num_imports","size_of_image","api_list","label"]
    dataset = []

    # 辅助内部函数：处理特定文件夹
    def scan_folder(folder_path, label_value):
        label_name = "恶意" if label_value == 1 else "良性"
        print(f"--- 正在开始扫描{label_name}样本目录: {folder_path} ---")
        
        count = 0
        # 遍历目录
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                # 只处理可能是程序的文件
                if file.lower().endswith(('.exe', '.dll', '.bin')):
                    file_full_path = os.path.join(root, file)
                    features = get_file_features(file_full_path)
                    
                    if features:
                        features["label"] = label_value # 添加分类标签
                        dataset.append(features)
                        count += 1
                        if count % 10 == 0:
                            print(f"已成功提取 {count} 个{label_name}样本...")
                            
        print(f"扫描完成！共提取{label_name}样本数: {count}\n")

    # 1. 扫描恶意文件夹
    scan_folder(malware_dir, 1)
    
    # 2. 扫描良性文件夹
    scan_folder(benign_dir, 0)

    # 3. 将结果写入CSV文件
    print(f"正在将 {len(dataset)} 条数据写入 {output_csv}...")
    try:
        with open(output_csv, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader() # 写入表头
            for row in dataset:
                writer.writerow(row) # 写入每一行特征
        print("数据集构建完成！")
    except Exception as e:
        print(f"写入CSV失败: {e}")



if __name__ == "__main__":
    print("这是提取特征模块，请运行 main.py")