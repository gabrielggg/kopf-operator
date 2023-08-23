FROM python:3.11
ADD . /src
RUN pip install kopf cryptography
CMD kopf run /src/kopffile.py --verbose
