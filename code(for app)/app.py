import streamlit as st
import os
import joblib
import pandas as pd
import time
import shutil
from extractor import get_file_features
from email_parse import parse
from email_parse import is_pe_file
from detection import email_test
import sys



sys.path.append(os.path.dirname(__file__))



#        路径配置
# 获取当前 code 文件夹的绝对路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 定位到父目录下的 model 文件夹
MODEL_DIR = os.path.join(os.path.dirname(BASE_DIR), "model")
# 定位到父目录下的 image 文件夹
IMAGE_DIR = os.path.join(os.path.dirname(BASE_DIR), "image")



#        页面配置
st.set_page_config(page_title="邮件附件恶意软件筛查系统", layout="wide", page_icon="🛡️")

# 自定义 CSS 提升美观度
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stAlert { border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)




#         侧边栏
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




#          加载核心模型
@st.cache_resource # 使用缓存，避免重复加载模型导致网页卡顿
def load_resources(choice):
    preprocessor_path = os.path.join(MODEL_DIR, "处理规则.pkl")
    
    if choice == "朴素贝叶斯 (主推)":
        model_path = os.path.join(MODEL_DIR, "朴素贝叶斯数据集.pkl") 
    else:
        model_path = os.path.join(MODEL_DIR, "随机森林数据集.pkl")
        
    prep = joblib.load(preprocessor_path)
    model = joblib.load(model_path)
    return prep, model




#           主界面逻辑
st.title(f"🛡️ 邮件附件恶意软件筛查系统 - {mode_text}")

if mode: # 主动筛查模式
    st.write("请上传待检测的电子邮件 (.eml)")
    
    uploaded_file = st.file_uploader("选择文件", type=["eml"])
    
    if uploaded_file:
        # 保存上传的邮件到临时文件夹中
        temp_dir = os.path.join(os.path.dirname(BASE_DIR), "temp_email")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, "uploaded_email.eml")

        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        #    准备进度条
        with st.status("🔍 系统正在深度扫描中...", expanded=True) as status:
            # 1. 加载模型
            st.write("正在调取分类模型...")
            prep, model = load_resources(model_choice)
            
            # 2. 判断文件类型并提取
            st.write("正在解析文件结构与提取特征...")
            # 3. 执行预测
            results = email_test(email_path=temp_path,process=prep,model=model)

            if os.path.exists(temp_path):
                os.remove(temp_path)

            status.update(label="扫描任务完成！", state="complete", expanded=False)
            

        #     展示结果
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

else: # 被动监听模式 (占位)
    st.warning("📡 被动监听模式需要连接 IMAP 邮箱服务器，目前正在开发中...")
    st.image(os.path.join(IMAGE_DIR, "朴素贝叶斯混淆矩阵.png"), caption="系统历史检测效能监控")
