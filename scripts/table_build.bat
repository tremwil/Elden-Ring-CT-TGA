set /p ver=<VERSION
set ver_sem=%ver:~0,-1%.%ver:~-1%
python .\ce2fs\ce2fs.py -i .\CheatTable -o .\dist\ER_TGA_v%ver_sem%.CT
echo 1245620 >.\dist\steam_appid.txt