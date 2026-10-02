# CSCE 465 - Protect Agent Messages with Classic Cryptography

## Preparation

To set up this lab, we must create a python environment with OpenSSL, cryptography and pytest libraries. We run the following batch of commands:
```python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

Verified with:

`python3 --version`
> Python 3.12.3

`openssl version`
> OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)

`pip show cryptography pytest`
> Name: cryptography
Version: 49.0.0
Summary: cryptography is a package which provides cryptographic recipes and primitives to Python developers.
Home-page: https://github.com/pyca/cryptography
Author: 
Author-email: The Python Cryptographic Authority and individual contributors <cryptography-dev@python.org>
License-Expression: Apache-2.0 OR BSD-3-Clause
Location: /mnt/c/Users/Jared/OneDrive/VSCode/Senior-Fall/465/CSCE-465-HW2/.venv/lib/python3.12/site-packages
Requires: cffi
Required-by: 
---
> Name: pytest
Version: 9.1.1
Summary: pytest: simple powerful testing with Python
Home-page: https://docs.pytest.org/en/latest/
Author: Brianna Laugher, Bruno Oliveira, Floris Bruynooghe, Freya Bruhin, Holger Krekel, Others (See AUTHORS), Ronny Pfannschmidt
Author-email: 
License-Expression: MIT
Location: /mnt/c/Users/Jared/OneDrive/VSCode/Senior-Fall/465/CSCE-465-HW2/.venv/lib/python3.12/site-packages
Requires: iniconfig, packaging, pluggy, pygments
Required-by: 


As part of Task 2, a ffdhe3072 parameter file needs to be generated. To do this, we run `openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem`. We verify it is correct with `openssl dhparam -in ffdhe3072.pem -text -noout | head -3`.
> DH Parameters: (3072 bit)
GROUP: ffdhe3072