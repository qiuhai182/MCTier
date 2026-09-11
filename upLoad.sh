#!/bin/bash

git pull gitee master
git pull github master
git pull
python convert_to_utf8.py --strip-bom
git add --all -- ':!nul'
git commit -m "快捷上传最新可执行文件、代码"
git push gitee master
git push github master
