# QQ旋风解析种子
 基于python3.5，通过QQ旋风（qqxuanfeng）模拟登陆并调用其服务器资源解析种子

## 使用方式
1. 在qqxuanfeng_torrent_parse.py文件中修改user和password

         user = 'QQ帐号'
         password = 'QQ密码'

2. 运行qqxuanfeng_torrent_parse.py

         python qqxuanfeng_torrent_parse.py

3. 在运行过程中输入要解析的种子的名字（将运行程序和种子放在同一目录）

## Q&A
1. **qqxuanfeng_torrent_parse.py**主要把代码进行了整理，更易于理解和使用，但是由于现在腾讯服务器出了问题，所以暂时无法完整解析种子（目前包括登录和部分解析），缺失的部分会在以后其服务器恢复后会更新
2. **QQ旋风最终版种子解析.py**实现的是完整版解析种子，由于当时写的匆忙代码比较乱，且使用需要修改比较多的地方，不推荐使用它（同样是服务器问题，能使用的部分都已经在qqxuanfeng_torrent_parse.py中了），保存在这里可用于参考整个流程。

**QQ旋风最终版种子解析.py 2016/4/20 效果**
![github](http://7xryau.com1.z0.glb.clouddn.com/github%E6%88%AA%E5%9B%BE%E4%B8%8A.png)
![github](http://7xryau.com1.z0.glb.clouddn.com/github%E6%88%AA%E5%9B%BE%E4%B8%8B.png)
