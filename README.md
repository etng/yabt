## requirements

```
pip install -r requirements.txt
```

## run

```
python mybt.py
```
## deploy

```
cp supervisor.conf /etc/supervisord.d/yabt.conf
cp nginx.conf /etc/nginx.d/yabt.conf
supervisorctl update
```
