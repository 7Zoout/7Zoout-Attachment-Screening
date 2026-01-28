import streamlit as st
import os
import joblib
import pandas as pd
import time
import sys
import imaplib
import email
from email.header import decode_header
from email.policy import default

# 导入自定义模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from extractor import get_file_features
from email_parse import parse, is_pe_file
from detection import email_test

# --- 1. 路径与环境配置 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")
IMAGE_DIR = os.path.join(PROJECT_ROOT, "image")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# --- 2. 页面与风格配置 ---
st.set_page_config(page_title="邮件附件恶意软件筛查系统", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    div.row-widget.stRadio > div{flex-direction:row;}
    .stCode { background-color: #0e1117 !important; color: #00ff00 !important; font-size: 0.8rem !important; }
    .stExpander { border: 1px solid #d1d5db; border-radius: 8px; margin-bottom: 5px; }
    </style>
    """, unsafe_allow_html=True)

# --- 3. 初始化 Session State ---
def init_states():
    if 'active_results_ui' not in st.session_state: st.session_state.active_results_ui = []
    if 'passive_results_ui' not in st.session_state: st.session_state.passive_results_ui = []
    if 'listening' not in st.session_state: st.session_state.listening = False
    if 'last_processed_id' not in st.session_state: st.session_state.last_processed_id = None

init_states()

# --- 4. 核心逻辑函数 ---

def log_to_file(mode, msg):
    filename = "active_logs.txt" if mode == "active" else "passive_logs.txt"
    filepath = os.path.join(LOG_DIR, filename)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def reset_system():
    st.session_state.listening = False
    st.session_state.active_results_ui = []
    st.session_state.passive_results_ui = []
    st.session_state.last_processed_id = None
    st.toast("系统实时数据已全面清除", icon="🗑️")
    time.sleep(0.5)
    st.rerun()

@st.cache_resource 
def load_resources(choice):
    prep_path = os.path.join(MODEL_DIR, "处理规则.pkl")
    model_name = "朴素贝叶斯数据集.pkl" if "朴素贝叶斯" in choice else "随机森林数据集.pkl"
    return joblib.load(prep_path), joblib.load(os.path.join(MODEL_DIR, model_name))

def get_email_subject(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=default)
            subject = msg.get('Subject', '无主题')
            if subject:
                decoded = decode_header(subject)[0]
                if isinstance(decoded[0], bytes):
                    return decoded[0].decode(decoded[1] or 'utf-8')
                return str(decoded[0])
    except: return "未知邮件"

def get_analysis_report(features, prob):
    reports = []
    if features.get('max_section_entropy', 0) > 7.2:
        reports.append("🚩 **高熵值异常**：检测到节区数据高度混淆，这是加密载荷或强力加壳的典型特征。")
    if features.get('num_rwe_sections', 0) > 0:
        reports.append("🚩 **危险权限**：发现同时具备读、写、执行权限的节区，极易被用于存放并运行恶意代码。")
    if features.get('is_ep_in_unexpected_section', 0) == 1:
        reports.append("🚩 **入口点重定向**：程序执行起点不在常规代码段，存在被劫持风险。")
    if features.get('dangerous_api_count', 0) > 2:
        reports.append(f"🚩 **敏感意图**：命中了 {features['dangerous_api_count']} 个涉及进程注入或下载的高危API。")
    if features.get('has_signature', 1) == 0:
        reports.append("🚩 **身份不明**：该程序缺失合法的数字签名，来源无法验证。")
    if features.get('num_dlls', 5) < 3:
        reports.append("🚩 **低依赖性**：导入库异常稀少，符合恶意软件追求高移植性的特点。")
    if features.get('num_sections', 0) > 8:
        reports.append("🚩 **结构异常**：节区数量异常偏多，常用于隐藏分段载荷。")
    if features.get('has_signature', 0) == 1:
        reports.append("✅ **签名校验成功**：文件拥有合法的数字签名。")
    if features.get('has_gui_libs', 0) == 1:
        reports.append("✅ **应用特征**：检测到标准图形界面库引用，符合常规软件特征。")
    if features.get('num_imports', 0) > 100:
        reports.append("✅ **逻辑复杂度高**：拥有庞大的API调用链，多见于正常商用软件。")
    return reports

def render_result_item(item):
    p = item['prob']
    icon = "🔴" if p > 0.8 else ("🟡" if p > 0.5 else "🟢")
    res_text = '恶意' if p > 0.8 else ('可疑' if p > 0.5 else '良性')
    summary = f"（邮件名：{item['subject']}，附件名：{item['name']}，判定结果：{res_text}）"
    
    with st.expander(f"{icon} {item.get('time', '')} {summary}"):
        c1, c2 = st.columns([1, 2])
        with c1:
            st.metric("风险评分", f"{p:.2f}")
            if p > 0.8: st.error("确定恶意")
            elif p > 0.5: st.warning("高度可疑")
            else: st.success("初步安全")
        with c2:
            reasons = get_analysis_report(item['features'], p)
            if reasons:
                for r in reasons: st.write(r)
            else:
                st.write("未触发特定告警。")
            with st.expander("特征快照"): st.json(item['features'])

# --- 5. 侧边栏 ---
with st.sidebar:
    st.title("🛡️ 基于朴素贝叶斯的电子邮件附件恶意软件筛查")
    model_choice = st.radio("算法引擎", ["朴素贝叶斯 (主推)", "随机森林 (对比)"], horizontal=True)
    st.divider()
    mode_selection = st.radio("运行模式", ["主动筛查", "被动监听"], horizontal=True)
    mode = (mode_selection == "主动筛查")
    if st.button("🗑️ 清除所有系统数据", use_container_width=True, type="primary"):
        reset_system()

# --- 6. 主界面 ---
st.title(f"系统运行状态：{mode_selection}")
tab_main, tab_metrics, tab_history = st.tabs(["🔍 核心筛查", "📈 性能指标", "📜 运行日志"])

with tab_main:
    if mode:  # 主动模式
        st.markdown("### 📤 主动文件扫描")
        uploaded_file = st.file_uploader("上传 .eml 邮件进行筛查", type=["eml"])
        
        if uploaded_file:
            temp_path = os.path.join(PROJECT_ROOT, "temp_active.eml")
            with open(temp_path, "wb") as f: f.write(uploaded_file.getbuffer())
            
            with st.status("🚀 正在执行全流水线深度分析...", expanded=True) as status:
                st.write("1. 正在解析邮件元数据...")
                subject = get_email_subject(temp_path)
                st.write("2. 正在剥离附件并提取特征...")
                prep, model = load_resources(model_choice)
                results = email_test(email_path=temp_path, process=prep, model=model)
                st.write("3. 正在比对模型进行风险评估...")
                if results:
                    for res in results:
                        res['subject'], res['time'] = subject, time.strftime("%H:%M:%S")
                        st.session_state.active_results_ui.insert(0, res)
                        res_t = '恶意' if res['prob'] > 0.8 else ('可疑' if res['prob'] > 0.5 else '良性')
                        log_to_file("active", f"（邮件名：{subject}，附件名：{res['name']}，判定结果：{res_t}）")
                else: log_to_file("active", f"（邮件名：{subject}，判定结果：无附件）")
                if os.path.exists(temp_path): os.remove(temp_path)
                status.update(label="✨ 扫描分析完成", state="complete", expanded=False)

        st.write("---")
        if st.session_state.active_results_ui:
            for item in st.session_state.active_results_ui: render_result_item(item)

    else:  # 被动监听模式
        st.markdown("### 📡 实时自动化监听")
        with st.expander("📧 监听配置", expanded=not st.session_state.listening):
            c1, c2, c3 = st.columns([2, 2, 1])
            m_u = c1.text_input("邮箱", key="m_u")
            m_a = c2.text_input("授权码", type="password", key="m_a")
            m_h = c3.text_input("IMAP服务器", value="imap.qq.com", key="m_h")

        if not st.session_state.listening:
            if st.button("🟢 开启自动监测", use_container_width=True):
                if m_u and m_a:
                    try:
                        mail = imaplib.IMAP4_SSL(m_h, 993)
                        mail.login(m_u, m_a); mail.select("INBOX")
                        _, msgs = mail.search(None, 'ALL')
                        st.session_state.last_processed_id = msgs[0].split()[-1].decode() if msgs[0] else None
                        mail.logout(); st.session_state.listening = True; st.rerun()
                    except Exception as e: st.error(f"连接失败: {e}")
        else:
            if st.button("🔴 停止监测服务", use_container_width=True):
                st.session_state.listening = False; st.rerun()

        st.write("---")
        with st.container(height=500, border=True):
            if not st.session_state.passive_results_ui: st.caption("等待新邮件...")
            else:
                for item in st.session_state.passive_results_ui: render_result_item(item)

with tab_metrics:
    st.header("🔬 模型评价指标")
    c1, c2 = st.columns(2)
    with c1:
        st.image(os.path.join(IMAGE_DIR, "朴素贝叶斯混淆矩阵.png"), caption="混淆矩阵")
        st.image(os.path.join(IMAGE_DIR, "ROC曲线对比.png"), caption="ROC对比")
    with c2:
        st.image(os.path.join(IMAGE_DIR, "朴素贝叶斯最重要特征.png"), caption="特征权重")
        st.image(os.path.join(IMAGE_DIR, "模型表现对比.png"), caption="算法对比")

with tab_history:
    col_l1, col_l2 = st.columns(2)
    with col_l1:
        st.subheader("📝 主动模式日志")
        log_path_a = os.path.join(LOG_DIR, "active_logs.txt")
        if os.path.exists(log_path_a):
            with open(log_path_a, "r", encoding="utf-8") as f: st.code(f.read())
    with col_l2:
        st.subheader("📝 被动模式日志")
        log_path_p = os.path.join(LOG_DIR, "passive_logs.txt")
        if os.path.exists(log_path_p):
            with open(log_path_p, "r", encoding="utf-8") as f: st.code(f.read())
    
    # 新增：一键清除物理日志文件按钮
    st.write("---")
    if st.button("🗑️ 一键清除本地物理日志文件", use_container_width=True):
        for fname in ["active_logs.txt", "passive_logs.txt"]:
            p = os.path.join(LOG_DIR, fname)
            if os.path.exists(p):
                with open(p, 'w', encoding='utf-8') as f: pass 
        st.toast("本地日志文件内容已全部排空")
        time.sleep(0.5)
        st.rerun()

# --- 7. 后台监听逻辑 ---
if st.session_state.listening and not mode:
    st.toast("正在监测邮箱新动态...", icon="🔍")
    try:
        mail = imaplib.IMAP4_SSL(st.session_state.m_h, 993)
        mail.login(st.session_state.m_u, st.session_state.m_a)
        mail.select("INBOX"); _, msgs = mail.search(None, 'ALL')
        if msgs[0]:
            curr_id = msgs[0].split()[-1].decode()
            if curr_id != st.session_state.last_processed_id:
                st.toast("⚡ 发现新邮件！正在检测...", icon="🚀")
                _, data = mail.fetch(curr_id, '(RFC822)')
                temp_p = "passive_detect.eml"
                with open(temp_p, "wb") as f: f.write(data[0][1])
                subj = get_email_subject(temp_p)
                prep_obj, model_obj = load_resources(model_choice)
                results = email_test(email_path=temp_p, process=prep_obj, model=model_obj)
                st.session_state.last_processed_id = curr_id
                if results:
                    st.toast("🛡️ 检测完成", icon="✅")
                    for r in results:
                        r['time'], r['subject'] = time.strftime("%H:%M:%S"), subj
                        st.session_state.passive_results_ui.insert(0, r)
                        res_tx = '恶意' if r['prob'] > 0.5 else '良性'
                        log_to_file("passive", f"（邮件名：{subj}，附件名：{r['name']}，判定结果：{res_tx}）")
                if os.path.exists(temp_p): os.remove(temp_p)
                mail.logout(); st.rerun()
        mail.logout()
    except: pass
    time.sleep(5); st.rerun()

st.divider()
st.caption("毕业设计：基于朴素贝叶斯的邮件附件恶意软件筛查系统 | 开发者：Zoout")