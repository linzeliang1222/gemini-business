"""
Gemini Business 认证工具类
抽取注册和登录服务的公共逻辑，遵循 DRY 原则

艹，把重复代码都提取到这里了，别再写重复的SB代码了！
"""
import json
import time
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, parse_qs
from datetime import datetime

import requests
import urllib3

from core.config import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("gemini.auth_utils")


class GeminiAuthConfig:
    """认证配置类（从统一配置模块加载）"""

    def __init__(self):
        # 从统一配置模块读取
        self.mail_api = config.basic.mail_api
        self.admin_key = config.basic.mail_admin_key
        self.email_domains = config.basic.email_domain  # 改为数组
        self.google_mail = config.basic.google_mail
        self.login_url = config.security.login_url

    def validate(self) -> bool:
        """验证配置是否完整"""
        required = [self.mail_api, self.admin_key, self.google_mail, self.login_url]
        return all(required)


class GeminiAuthHelper:
    """Gemini 认证辅助工具"""

    # XPath 配置（公共）
    XPATH = {
        "email_input": "/html/body/c-wiz/div/div/div[1]/div/div/div/form/div[1]/div[1]/div/span[2]/input",
        "continue_btn": "/html/body/c-wiz/div/div/div[1]/div/div/div/form/div[2]/div/button",
        "verify_btn": "/html/body/c-wiz/div/div/div[1]/div/div/div/form/div[2]/div/div[1]/span/div[1]/button",
        "resend_code_btn": "/html/body/c-wiz/div/div/div[1]/div/div/div/form/div[2]/div/div[2]/span/div[1]/button"
    }

    def __init__(self, config: GeminiAuthConfig):
        self.config = config

    def get_verification_code(self, email: str, timeout: int = 30) -> Optional[str]:
        """获取验证码（公共方法）"""
        logger.info(f"⏳ 等待验证码 [{email}]...")
        start = time.time()

        while time.time() - start < timeout:
            try:
                r = requests.get(
                    f"{self.config.mail_api}/admin/mails?limit=20&offset=0",
                    headers={"x-admin-auth": self.config.admin_key},
                    timeout=10,
                    verify=False
                )
                if r.status_code == 200:
                    emails = r.json().get('results', {})
                    for mail in emails:
                        if mail.get("address") == email and mail.get("source") == self.config.google_mail:
                            logger.info(f"📩 找到邮件 [{mail.get('id')}]，正在提取验证码...")
                            code = None
                            mail_id = mail.get("id")
                            
                            # 优先从 metadata 中获取验证码（AI 提取）
                            try:
                                metadata_str = mail.get("metadata")
                                if metadata_str:
                                    metadata = json.loads(metadata_str)
                                    if metadata and "ai_extract" in metadata and metadata["ai_extract"].get("result"):
                                        code = metadata["ai_extract"]["result"]
                                        logger.info(f"✅ 从 metadata 获取验证码: {code}")
                            except Exception as e:
                                logger.warning(f"⚠️ metadata 解析失败: {e}")
                            
                            # 如果 metadata 为空，从 raw 中提取验证码
                            if not code:
                                raw = mail.get("raw", "")
                                if raw:
                                    import re
                                    # Step 1: 去掉 quoted-printable 软换行（行尾的 = 表示续行）
                                    clean_raw = re.sub(r'=\r?\n', '', raw)
                                    
                                    # Step 2: 解码 quoted-printable 的 =XX（如 =3D 是 =）
                                    def decode_qp(match):
                                        hex_val = match.group(1)
                                        return chr(int(hex_val, 16))
                                    clean_raw = re.sub(r'=([0-9A-Fa-f]{2})', decode_qp, clean_raw)
                                    
                                    # Step 3: 去掉转义的引号
                                    clean_raw = clean_raw.replace('\\"', '"')
                                    
                                    # 优先匹配 HTML 中的 verification-code span 标签内容
                                    # 格式: <span class="verification-code" ...>SHCNXF</span>
                                    html_match = re.search(r'class\s*=\s*["\']?verification-code["\']?[^>]*>([A-Z0-9]{6})<', clean_raw, re.IGNORECASE)
                                    if html_match:
                                        code = html_match.group(1)
                                        logger.info(f"✅ 从 HTML span 提取验证码: {code}")
                                    else:
                                        # 备用：匹配验证码格式（6位大写字母+数字，前后有换行或特殊字符）
                                        text_match = re.search(r'(?:验证码[为是：:\s]*|verification code[:\s]*)[\r\n\s]*([A-Z0-9]{6})[\r\n\s]', clean_raw, re.IGNORECASE)
                                        if text_match:
                                            code = text_match.group(1)
                                            logger.info(f"✅ 从文本提取验证码: {code}")
                            
                            if code:
                                # 获取验证码后立即删除邮件，避免后续刷新时误取旧验证码
                                if mail_id:
                                    try:
                                        requests.delete(
                                            f"{self.config.mail_api}/admin/mails/{mail_id}",
                                            headers={"x-admin-auth": self.config.admin_key},
                                            timeout=10,
                                            verify=False
                                        )
                                        logger.info(f"🗑️ 已删除邮件 [{mail_id}]")
                                    except Exception as e:
                                        logger.warning(f"⚠️ 删除邮件失败 [{mail_id}]: {e}")
                                
                                return code
            except:
                pass
            time.sleep(2)

        logger.warning(f"验证码超时 [{email}]")
        return None

    def perform_email_verification(
        self,
        driver,
        wait,
        email: str,
        retry_enabled: bool = False,
        max_code_retries: int = 3,
        retry_interval: int = 5
    ) -> Dict[str, Any]:
        """
        执行邮箱验证流程（公共方法）
        从输入邮箱到验证码验证完成

        Args:
            driver: WebDriver 实例
            wait: WebDriverWait 实例
            email: 邮箱地址
            retry_enabled: 是否启用验证码重试（从配置读取）
            max_code_retries: 验证码获取失败后的重试次数（从配置读取）
            retry_interval: 重试间隔秒数（从配置读取）

        返回: {
            "success": bool,
            "error": str|None,
            "error_type": str|None  # "pin_input_not_found" 表示验证码输入框未出现
        }
        """
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC

            # 1. 输入邮箱
            inp = wait.until(EC.element_to_be_clickable((By.XPATH, self.XPATH["email_input"])))
            inp.click()
            inp.clear()
            for c in email:
                inp.send_keys(c)
                time.sleep(0.02)

            # 2. 点击继续
            time.sleep(0.5)
            btn = wait.until(EC.element_to_be_clickable((By.XPATH, self.XPATH["continue_btn"])))
            driver.execute_script("arguments[0].click();", btn)
            time.sleep(2)

            # 3. 等待验证码输入框出现
            try:
                wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='pinInput']")))
            except Exception as e:
                logger.warning(f"⚠️ 验证码输入框未出现")
                return {
                    "success": False,
                    "error": "验证码输入框未出现",
                    "error_type": "pin_input_not_found"
                }

            # 4. 获取验证码
            code = self.get_verification_code(email)

            # 如果验证码超时且启用了重试，尝试点击重新发送按钮重试
            if not code and retry_enabled and max_code_retries > 0:
                for attempt in range(max_code_retries):
                    logger.info(f"🔄 验证码超时，点击重新发送 ({attempt + 1}/{max_code_retries})...")
                    try:
                        resend_btn = wait.until(EC.element_to_be_clickable((By.XPATH, self.XPATH["resend_code_btn"])))
                        driver.execute_script("arguments[0].click();", resend_btn)
                        logger.info("✅ 已点击重新发送验证码按钮")
                    except Exception as e:
                        logger.warning(f"⚠️ 重新发送验证码按钮点击失败: {e}")

                    time.sleep(retry_interval)  # 使用配置的重试间隔
                    code = self.get_verification_code(email)
                    if code:
                        logger.info(f"✅ 重试后成功获取验证码")
                        break

            if not code:
                return {
                    "success": False,
                    "error": "验证码超时",
                    "error_type": "code_timeout"
                }

            # 5. 输入验证码
            time.sleep(1)
            try:
                pin = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='pinInput']")))
                pin.click()
                time.sleep(0.1)
                for c in code:
                    pin.send_keys(c)
                    time.sleep(0.05)
            except:
                try:
                    span = driver.find_element(By.CSS_SELECTOR, "span[data-index='0']")
                    span.click()
                    time.sleep(0.2)
                    driver.switch_to.active_element.send_keys(code)
                except Exception as e:
                    return {
                        "success": False,
                        "error": f"验证码输入失败: {e}",
                        "error_type": "code_input_failed"
                    }

            # 6. 点击验证按钮
            time.sleep(0.5)
            try:
                vbtn = driver.find_element(By.XPATH, self.XPATH["verify_btn"])
                driver.execute_script("arguments[0].click();", vbtn)
            except:
                for btn in driver.find_elements(By.TAG_NAME, "button"):
                    if '验证' in btn.text:
                        driver.execute_script("arguments[0].click();", btn)
                        break

            return {"success": True, "error": None, "error_type": None}

        except Exception as e:
            return {"success": False, "error": str(e), "error_type": "unknown"}

    def extract_config_from_workspace(self, driver) -> Dict[str, Any]:
        """
        从工作台页面提取配置信息（公共方法）

        返回: {"success": bool, "config": dict|None, "error": str|None}
        """
        try:
            time.sleep(3)  # 等待页面完全加载
            cookies = driver.get_cookies()
            url = driver.current_url
            parsed = urlparse(url)

            # 解析 config_id
            path_parts = url.split('/')
            config_id = None
            for i, p in enumerate(path_parts):
                if p == 'cid' and i + 1 < len(path_parts):
                    config_id = path_parts[i + 1].split('?')[0]
                    break

            cookie_dict = {c['name']: c for c in cookies}
            ses_cookie = cookie_dict.get('__Secure-C_SES', {})
            host_cookie = cookie_dict.get('__Host-C_OSES', {})
            csesidx = parse_qs(parsed.query).get('csesidx', [None])[0]

            if not all([ses_cookie.get('value'), host_cookie.get('value'), csesidx, config_id]):
                return {"success": False, "config": None, "error": "配置数据不完整"}

            config_data = {
                "csesidx": csesidx,
                "config_id": config_id,
                "secure_c_ses": ses_cookie.get('value'),
                "host_c_oses": host_cookie.get('value'),
                "expires_at": datetime.fromtimestamp(
                    ses_cookie.get('expiry', 0) - 43200
                ).strftime('%Y-%m-%d %H:%M:%S') if ses_cookie.get('expiry') else None
            }

            return {"success": True, "config": config_data, "error": None}

        except Exception as e:
            return {"success": False, "config": None, "error": str(e)}

    def wait_for_workspace(self, driver, timeout: int = 30, max_crash_retries: int = 3) -> bool:
        """
        等待进入工作台（公共方法，带崩溃重试）

        Args:
            driver: Selenium WebDriver 实例
            timeout: 等待超时时间（秒）
            max_crash_retries: 崩溃后最大重试次数
            
        返回: True 表示成功进入，False 表示超时或失败
        """
        crash_count = 0
        workspace_url = "https://business.gemini.google/"
        
        for _ in range(timeout):
            time.sleep(1)
            try:
                # 检查页面是否崩溃
                page_source = driver.page_source
                is_crashed = 'crashed' in page_source.lower() or 'aw, snap' in page_source.lower()
                
                if is_crashed:
                    crash_count += 1
                    logger.warning(f"⚠️ 等待工作台时页面崩溃，尝试开新标签页 (崩溃 {crash_count}/{max_crash_retries})")
                    if crash_count >= max_crash_retries:
                        logger.error("❌ 页面崩溃次数过多，放弃重试")
                        return False
                    
                    # 开新标签页并切换
                    if self._recover_from_crash(driver, workspace_url):
                        time.sleep(3)
                        continue
                    else:
                        return False
                
                url = driver.current_url
                if 'business.gemini.google' in url and '/cid/' in url:
                    return True
                    
            except Exception as e:
                error_msg = str(e).lower()
                if 'crash' in error_msg or 'tab' in error_msg or 'target window' in error_msg:
                    crash_count += 1
                    logger.warning(f"⚠️ 等待工作台时检测到崩溃: {e} (崩溃 {crash_count}/{max_crash_retries})")
                    if crash_count >= max_crash_retries:
                        logger.error("❌ 页面崩溃次数过多，放弃重试")
                        return False
                    
                    if self._recover_from_crash(driver, workspace_url):
                        time.sleep(3)
                        continue
                    else:
                        return False
                # 其他异常继续等待
                
        return False
    
    def _recover_from_crash(self, driver, target_url: str) -> bool:
        """
        从崩溃中恢复：开新标签页访问目标URL
        
        艹，崩溃的标签页刷新没用，得开新的！
        """
        try:
            # 获取当前所有窗口句柄
            original_handles = driver.window_handles
            
            # 开新标签页
            driver.execute_script("window.open('');")
            time.sleep(0.5)
            
            # 获取新窗口句柄
            new_handles = driver.window_handles
            new_handle = None
            for handle in new_handles:
                if handle not in original_handles:
                    new_handle = handle
                    break
            
            if not new_handle:
                logger.error("❌ 无法创建新标签页")
                return False
            
            # 切换到新标签页
            driver.switch_to.window(new_handle)
            
            # 关闭旧的崩溃标签页
            for handle in original_handles:
                try:
                    driver.switch_to.window(handle)
                    driver.close()
                except:
                    pass
            
            # 切回新标签页
            driver.switch_to.window(new_handle)
            
            # 访问目标URL
            driver.get(target_url)
            time.sleep(3)
            
            logger.info("✅ 已通过新标签页恢复")
            return True
            
        except Exception as e:
            logger.error(f"❌ 恢复失败: {e}")
            return False


class GeminiAuthFlow:
    """
    统一的 Gemini 认证流程类
    艹，把注册和登录的重复代码都整合到这里了！

    支持两种模式：
    - register: 注册模式（创建临时邮箱 + 输入姓名）
    - login: 登录模式（使用已有邮箱）
    """

    # 姓名池（注册用）
    NAMES = [
        "James Smith", "John Johnson", "Robert Williams", "Michael Brown", "William Jones",
        "David Garcia", "Mary Miller", "Patricia Davis", "Jennifer Rodriguez", "Linda Martinez"
    ]

    def __init__(self, auth_config: GeminiAuthConfig, auth_helper: GeminiAuthHelper):
        self.config = auth_config
        self.helper = auth_helper

    def execute(
        self,
        mode: str,
        email: Optional[str] = None,
        email_creator=None,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        执行统一认证流程

        Args:
            mode: "register" 或 "login"
            email: 登录模式必填，注册模式会自动创建
            email_creator: 注册模式必填，用于创建临时邮箱的回调函数
            max_retries: 最大重试次数

        返回: {
            "success": bool,
            "email": str|None,
            "config": dict|None,
            "error": str|None
        }
        """
        if mode not in ["register", "login"]:
            return {"success": False, "email": None, "config": None, "error": f"不支持的模式: {mode}"}

        if mode == "login" and not email:
            return {"success": False, "email": None, "config": None, "error": "登录模式必须提供 email"}

        if mode == "register" and not email_creator:
            return {"success": False, "email": None, "config": None, "error": "注册模式必须提供 email_creator"}

        # 重试逻辑
        for attempt in range(max_retries):
            # 注册模式：每次重试创建新邮箱
            if mode == "register":
                email = email_creator()
                if not email:
                    return {"success": False, "email": None, "config": None, "error": "无法创建邮箱"}

            logger.info(f"🚀 [{mode.upper()}] 尝试 {attempt + 1}/{max_retries}: {email}")

            # 执行单次认证
            result = self._execute_once(mode, email)

            # 成功则直接返回
            if result["success"]:
                return result

            # 检查错误类型
            error_type = result.get("error_type")

            # 如果是验证码输入框未出现，需要重试
            if error_type == "pin_input_not_found":
                logger.warning(f"[{mode.upper()}] 邮件没有正常发送，准备重试 ({attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
            else:
                # 其他错误不重试，直接返回
                logger.error(f"❌ [{mode.upper()}] 认证失败: {result.get('error')}")
                return result

        # 重试耗尽
        return {
            "success": False,
            "email": email,
            "config": None,
            "error": f"重试 {max_retries} 次后仍然失败"
        }

    def _execute_once(self, mode: str, email: str) -> Dict[str, Any]:
        """
        执行单次认证流程（不含重试）

        返回: {
            "success": bool,
            "email": str,
            "config": dict|None,
            "error": str|None,
            "error_type": str|None
        }
        """
        driver = None
        try:
            # 延迟导入 selenium
            import undetected_chromedriver as uc
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.common.keys import Keys
            import os
            import random
        except ImportError as e:
            return {
                "success": False,
                "email": email,
                "config": None,
                "error": f"Selenium 未安装: {e}",
                "error_type": "import_error"
            }

        try:
            # 1. 配置并启动 Chrome
            options = uc.ChromeOptions()
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-software-rasterizer')
            options.add_argument('--disable-extensions')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--js-flags=--max-old-space-size=512')
            options.add_argument('--disable-background-networking')
            options.add_argument('--disable-default-apps')
            options.add_argument('--disable-sync')

            # 指定Chrome二进制路径
            chrome_binary = os.environ.get('CHROME_BIN', '/usr/bin/google-chrome-stable')
            if os.path.exists(chrome_binary):
                options.binary_location = chrome_binary
            elif os.path.exists('/usr/bin/google-chrome'):
                options.binary_location = '/usr/bin/google-chrome'

            # 指定 chromedriver 路径（避免 ARM64 架构下自动下载 AMD64 版本）
            driver_path = None
            if os.path.exists('/usr/bin/chromedriver'):
                driver_path = '/usr/bin/chromedriver'

            if driver_path:
                driver = uc.Chrome(options=options, driver_executable_path=driver_path, use_subprocess=True)
            else:
                driver = uc.Chrome(options=options, use_subprocess=True)
            wait = WebDriverWait(driver, 30)

            # 2. 访问登录页
            driver.get(self.config.login_url)
            time.sleep(2)

            # 3. 执行邮箱验证流程
            from core.config import config as app_config
            retry_config = app_config.retry
            verify_result = self.helper.perform_email_verification(
                driver,
                wait,
                email,
                retry_enabled=retry_config.verification_retry_enabled,
                max_code_retries=retry_config.max_verification_retries,
                retry_interval=retry_config.verification_retry_interval_seconds
            )
            if not verify_result["success"]:
                return {
                    "success": False,
                    "email": email,
                    "config": None,
                    "error": verify_result["error"],
                    "error_type": verify_result.get("error_type")
                }

            # 4. 注册模式：输入姓名
            if mode == "register":
                time.sleep(2)
                selectors = [
                    "input[formcontrolname='fullName']",
                    "input[placeholder='全名']",
                    "input[placeholder='Full name']",
                    "input#mat-input-0",
                ]
                name_inp = None
                for _ in range(30):
                    for sel in selectors:
                        try:
                            name_inp = driver.find_element(By.CSS_SELECTOR, sel)
                            if name_inp.is_displayed():
                                break
                        except:
                            continue
                    if name_inp and name_inp.is_displayed():
                        break
                    time.sleep(1)

                if name_inp and name_inp.is_displayed():
                    name = random.choice(self.NAMES)
                    name_inp.click()
                    time.sleep(0.2)
                    name_inp.clear()
                    for c in name:
                        name_inp.send_keys(c)
                        time.sleep(0.02)
                    time.sleep(0.3)
                    name_inp.send_keys(Keys.ENTER)
                    time.sleep(1)
                else:
                    return {
                        "success": False,
                        "email": email,
                        "config": None,
                        "error": "未找到姓名输入框",
                        "error_type": "name_input_not_found"
                    }

            # 5. 等待进入工作台
            if not self.helper.wait_for_workspace(driver, timeout=30):
                return {
                    "success": False,
                    "email": email,
                    "config": None,
                    "error": "未跳转到工作台",
                    "error_type": "workspace_timeout"
                }

            # 6. 提取配置（带重试机制处理 tab crashed）
            extract_result = self.extract_config_with_retry(driver, max_retries=3)
            if not extract_result["success"]:
                return {
                    "success": False,
                    "email": email,
                    "config": None,
                    "error": extract_result["error"],
                    "error_type": "extract_config_failed"
                }

            config_data = extract_result["config"]
            logger.info(f"✅ [{mode.upper()}] 认证成功: {email}")
            return {
                "success": True,
                "email": email,
                "config": config_data,
                "error": None,
                "error_type": None
            }

        except Exception as e:
            logger.error(f"❌ [{mode.upper()}] 认证异常 [{email}]: {e}")
            return {
                "success": False,
                "email": email,
                "config": None,
                "error": str(e),
                "error_type": "unknown"
            }
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass


    def extract_config_with_retry(self, driver, max_retries: int = 3) -> Dict[str, Any]:
        """
        带重试机制的配置提取（处理 tab crashed 问题）
        
        艹，Google 工作台页面经常崩溃，这个方法会自动重试
        
        Args:
            driver: Selenium WebDriver 实例
            max_retries: 最大重试次数，默认3次
            
        返回: {"success": bool, "config": dict|None, "error": str|None}
        """
        extract_result = None
        last_error = None
        
        for attempt in range(max_retries):
            try:
                # 检查页面是否崩溃
                page_source = driver.page_source
                if 'crashed' in page_source.lower() or 'aw, snap' in page_source.lower():
                    logger.warning(f"⚠️ 页面崩溃，尝试刷新 (尝试 {attempt + 1}/{max_retries})")
                    driver.refresh()
                    time.sleep(3)
                    continue
                
                extract_result = self.helper.extract_config_from_workspace(driver)
                if extract_result["success"]:
                    return extract_result
                else:
                    last_error = extract_result["error"]
                    logger.warning(f"⚠️ 提取配置失败: {last_error}，尝试刷新 (尝试 {attempt + 1}/{max_retries})")
                    driver.refresh()
                    time.sleep(3)
                    
            except Exception as e:
                error_msg = str(e).lower()
                if 'crash' in error_msg or 'tab' in error_msg:
                    logger.warning(f"⚠️ 检测到页面崩溃: {e}，尝试刷新 (尝试 {attempt + 1}/{max_retries})")
                    try:
                        driver.refresh()
                        time.sleep(3)
                    except:
                        # 如果刷新也失败，尝试重新访问工作台
                        try:
                            driver.get("https://business.gemini.google/")
                            time.sleep(5)
                        except:
                            pass
                else:
                    last_error = str(e)
                    logger.warning(f"⚠️ 提取配置异常: {e}，尝试刷新 (尝试 {attempt + 1}/{max_retries})")
                    try:
                        driver.refresh()
                        time.sleep(3)
                    except:
                        pass
        
        return {"success": False, "config": None, "error": last_error or "提取配置失败（已重试）"}

