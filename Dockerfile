# Dockerfile for Gemini Business API（带注册功能）
# 使用 uv 管理依赖，包含 Chrome/Chromium + Xvfb 支持注册功能
FROM python:3.11-slim

# 获取目标架构
ARG TARGETARCH

WORKDIR /app

# 先安装基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 根据架构添加 Chrome 源（仅 amd64）
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg && \
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list; \
    fi

# 安装浏览器、Xvfb 和必要的依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    xvfb \
    x11-utils \
    $(if [ "$TARGETARCH" = "amd64" ]; then echo "google-chrome-stable"; else echo "chromium chromium-driver"; fi) \
    && rm -rf /var/lib/apt/lists/*

# 安装 uv
RUN pip install --no-cache-dir uv

# 复制依赖配置文件
COPY pyproject.toml uv.lock ./

# 使用 uv 同步依赖
RUN uv sync --frozen --no-dev

# 复制项目文件
COPY main.py .
COPY core ./core
COPY util ./util
COPY templates ./templates
COPY static ./static

# 创建数据目录
RUN mkdir -p ./data/images

# 声明数据卷
VOLUME ["/app/data"]

# 创建 Xvfb 启动脚本
RUN printf '#!/bin/bash\n\
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null\n\
Xvfb :99 -screen 0 1920x1080x24 &\n\
sleep 1\n\
export DISPLAY=:99\n\
# 根据实际安装的浏览器设置 CHROME_BIN\n\
if [ -f /usr/bin/google-chrome-stable ]; then\n\
    export CHROME_BIN=/usr/bin/google-chrome-stable\n\
elif [ -f /usr/bin/chromium ]; then\n\
    export CHROME_BIN=/usr/bin/chromium\n\
fi\n\
echo "Xvfb started on :99"\n\
echo "Browser: $CHROME_BIN"\n\
exec "$@"\n' > /app/start-xvfb.sh && chmod +x /app/start-xvfb.sh

# 设置环境变量
ENV DISPLAY=:99
# 设置时区为东八区（北京时间）
ENV TZ=Asia/Shanghai

# 使用 Xvfb 启动脚本作为 entrypoint
ENTRYPOINT ["/app/start-xvfb.sh"]

# 启动主服务
CMD ["uv", "run", "python", "-u", "main.py"]
