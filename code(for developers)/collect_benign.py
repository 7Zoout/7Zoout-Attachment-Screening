import os
import shutil
import pefile

def is_pe_file(file_path):
    #检查是否为有效的PE文件
    try:
        pe = pefile.PE(file_path)
        pe.close()
        return True
    except:
        return False

def collect_samples(src_dirs, dest_dir, limit=300):
    #如果目标保存文件夹不存在，则创建
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    
    #循环扫描源文件夹里的pe文件
    count = 0
    for src in src_dirs:
        print(f"正在扫描目录: {src}")
        for root, dirs, files in os.walk(src):
            for file in files:
                if file.lower().endswith('.exe'):
                    full_path = os.path.join(root, file)
                    # 检查是否为PE并复制
                    if is_pe_file(full_path):
                        try:
                            # 避免文件名冲突
                            dest_path = os.path.join(dest_dir, f"benign_{count}_{file}")
                            shutil.copy2(full_path, dest_path)
                            count += 1
                            if count % 50 == 0:
                                print(f"已收集 {count} 个良性样本...")
                        except:
                            continue
                
                if count >= limit:
                    print(f"已达到预设限制 {limit}，停止收集。")
                    return

if __name__ == "__main__":
    print("这是自动提取良性样本模块，请运行 main.py")