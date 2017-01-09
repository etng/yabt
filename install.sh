#!/bin/bash
yum -y update
yum makecache
yum groupinstall -y 'development tools'
yum install -y vim zlib-dev openssl-devel sqlite-devel bzip2-devel xz-libs supervisor epel-release
yum install nginx
chkconfig --level 345 nginx on
chkconfig --level 345 supervisord on
export PYTHON_VERSION=2.7.12
wget http://ftp.osuosl.org/pub/blfs/conglomeration/Python/Python-${PYTHON_VERSION}.tar.xz
#wget http://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz
xz -d Python-${PYTHON_VERSION}.tar.xz
tar -xvf Python-${PYTHON_VERSION}.tar
cd Python-${PYTHON_VERSION}
./configure --prefix=/usr/local 
make && make altinstall && cd -
export PATH="/usr/local/bin:$PATH"
ln -s /usr/local/bin/python{2.7,}
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
echo done
curl https://bootstrap.pypa.io/get-pip.py |python -
mkdir ~/.pip
cat <<EOT > ~/.vimrc
colorscheme desert
set hls
set nu
set expandtab
set smarttab
set smartindent
set cursorline
set fileencodings=utf-8,gbk
set shiftwidth=4
set tabstop=4
set bs=2
set list
set paste
set fileencodings=utf-8,ucs-bom,gb18030,gbk,gb2312,cp936
set termencoding=utf-8
set encoding=utf-8
nnoremap <leader>l :ls<CR>:b<space>
filetype plugin indent on
syntax on
set noai
EOT

pip install requests ipython ipdb bs4 scrapy flask uwsgi redis bencode 

cd /opt/
wget -c http://download.redis.io/redis-stable.tar.gz
tar -zxvf redis-stable.tar.gz
cp redis-stable/utils/install_server.sh{,.bak}
cp /root/yabt/install_redis.sh redis-stable/utils/install_server.sh
cd redis-stable && make V=1 MALLOC=jemalloc && make install && cd utils && ./install_server.sh
cd /opt/
rm -fr redis-stable*
cd /root/yabt/
mv /etc/nginx/conf.d/default.conf{,.bak}
cat supervisor.conf >> /etc/supervisor.conf
cp nginx.conf /etc/nginx/conf.d/yabt.conf
/etc/init.d/supervisord restart

