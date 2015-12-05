# red
====  
A DECAF plugin which is used to bypass blue.exe

## Description
セキュリティキャンプ全国大会2015，解析トラック15・16-D「仮想化技術を用いたマルウェア解析」課題プログラム`blue.exe`の仮想化検知回避プラグイン

## Usage
```
(qemu) load_plugin <your_path>/DECAF/decaf/plugins/red/red.so
(qemu) red blue.exe
```

## Install
```
$ cd <your_path>/DECAF/decaf/plugins
$ git clone https://github.com/poppycompass/red.git
$ cd red
$ ./configure --decaf-path=<your_path>/DECAF/decaf/
$ make
```
## Author
[poppycompass](https://github.com/poppycompass)
