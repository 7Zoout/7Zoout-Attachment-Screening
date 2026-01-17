import streamlit as st
import os
import joblib
import pandas as pd
import time

# 导入你自定义的模块
# 这里的路径处理是为了确保在 Streamlit Cloud 运行时能正确找到这些 py 文件
import sys
sys.path.append(os.path.dirname(__file__))

from extractor import get_file_features
from email_parse import extract_attachment_from_eml

# --- 1. 路径配置 (适配你的 GitHub 仓库结构) ---
# 获取当前 code 文件夹的绝对路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 定位到父目录下的 model 文件夹
MODEL_DIR = os.path.join(os.path.dirname(BASE_DIR), "model")
# 定位到父目录下的 image 文件夹
IMAGE_DIR = os.path.join(os.path.dirname(BASE_DIR), "image")

# --- 2. 页面配置 ---
st.set_page_config(page_title="邮件附件恶意软件筛查系统", layout="wide", page_icon="🛡️")

# 自定义 CSS 提升美观度
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stAlert { border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- 3. 侧边栏：模型管理与系统信息 ---
with st.sidebar:
    st.title("⚙️ 系统控制面板")
    st.info("当前版本: V1.0 (学术版)")
    
    # 模型选择
    st.subheader("🤖 模型选择")
    model_choice = st.radio("选择分类算法", ["朴素贝叶斯 (主推)", "随机森林 (对比)"])
    
    # 模式切换
    st.divider()
    st.subheader("🕹️ 运行模式")
    mode = st.toggle("模式切换：主动筛查 / 被动监听", value=True)
    mode_text = "主动筛查" if mode else "被动监听"
    st.write(f"当前模式: **{mode_text}**")

# --- 4. 辅助函数：加载核心模型 ---
@st.cache_resource # 使用缓存，避免重复加载模型导致网页卡顿
def load_resources(choice):
    # 注意：文件名需与你仓库里的中文名保持完全一致
    preprocessor_path = os.path.join(MODEL_DIR, "处理规则.pkl")
    
    if choice == "朴素贝叶斯 (主推)":
        model_path = os.path.join(MODEL_DIR, "朴素贝叶斯数据集.pkl") # 假设你存模型的文件名
    else:
        model_path = os.path.join(MODEL_DIR, "随机森林数据集.pkl")
        
    prep = joblib.load(preprocessor_path)
    model = joblib.load(model_path)
    return prep, model

# --- 5. 主界面逻辑 ---
st.title(f"🛡️ 邮件附件恶意软件筛查系统 - {mode_text}")

if mode: # 主动筛查模式
    st.write("请上传待检测的电子邮件 (.eml) 或可执行附件 (.exe)")
    
    uploaded_file = st.file_uploader("选择文件", type=["eml", "exe"])
    
    if uploaded_file:
        # 保存上传的文件到临时路径
        temp_path = os.path.join(BASE_DIR, "temp_upload_file")
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # 准备进度条
        with st.status("🔍 系统正在深度扫描中...", expanded=True) as status:
            # 1. 加载模型
            st.write("正在调取分类模型...")
            prep, model = load_resources(model_choice)
            
            # 2. 判断文件类型并提取
            st.write("正在解析文件结构与提取特征...")
            files_to_check = []
            if uploaded_file.name.endswith(".eml"):
                # 邮件解析逻辑
                temp_extract_dir = os.path.join(BASE_DIR, "extracted")
                extracted = extract_attachment_from_eml(temp_path, temp_extract_dir)
                files_to_check.extend(extracted)
            else:
                files_to_check.append(temp_path)
            
            # 3. 执行预测
            results = []
            for f in files_to_check:
                feat = get_file_features(f)
                if feat:
                    df = pd.DataFrame([feat])
                    X = prep.transform(df)
                    prob = model.predict_proba(X)[0][1]
                    results.append({"name": os.path.basename(f), "prob": prob, "features": feat})
            
            status.update(label="扫描任务完成！", state="complete", expanded=False)

        # 4. 展示结果
        if not results:
            st.warning("未在邮件中发现可疑附件。")
        else:
            for res in results:
                st.divider()
                c1, c2 = st.columns([1, 3])
                with c1:
                    st.write(f"**附件名称:** {res['name']}")
                    score = res['prob']
                    if score > 0.7:
                        st.error(f"风险评分: {score:.2f}")
                        st.markdown("### 🚫 判定：恶意软件")
                    elif score > 0.3:
                        st.warning(f"风险评分: {score:.2f}")
                        st.markdown("### ⚠️ 判定：可疑文件")
                    else:
                        st.success(f"风险评分: {score:.2f}")
                        st.markdown("### ✅ 判定：安全")
                
                with c2:
                    st.expander("查看关键判定依据").write(res['features'])
                    # 这里以后可以加入我们昨天做的“特征重要性图表”

else: # 被动监听模式 (占位)
    st.warning("📡 被动监听模式需要连接 IMAP 邮箱服务器，目前正在开发中...")
    st.image(os.path.join(IMAGE_DIR, "朴素贝叶斯混淆矩阵.png"), caption="系统历史检测效能监控")
