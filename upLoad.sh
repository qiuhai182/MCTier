#!/bin/bash

git pull

git add --all -- ':!nul'

# 无变更时跳过提交与推送（避免触发 pre-commit 钩子产生多余输出）
if git diff --cached --quiet; then
    echo "没有新的变更，无需上传"
    exit 0
fi

git commit -m "快捷上传最新可执行文件、代码"
git push
