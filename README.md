**Airnalyze**

Airnalyze is a Flask-based web application for monitoring and managing network-related data (devices, users, guests, blacklist/whitelist, etc.).

*Features*

* User authentication (login/register)
* Dashboard overview
* Device tracking
* Guest and user management
* Blacklist / whitelist system
* Network monitoring tools

*Tech Stack*

* Python (Flask)
* HTML / CSS / Jinja2 templates
* SQLite database

*Installation*

```
git clone https://github.com/Kanaguro/Airnalyze.git
cd Airnalyze
pip install -r requirements.txt
```

*Run the App*

```
python app.py
```

Then open:

```
http://127.0.0.1:5000
```

*Notes*

* Do not commit `wifi_monitor.db`
* Make sure `.gitignore` is properly set
* Recommended to use a virtual environment

*Status*

For Deployment (Updates needed if necessary)
