FROM python:3.7.4-alpine3.10


WORKDIR /root/.analyzor

ADD check.py /root/.analyzor
ADD Pipfile /root/.analyzor
ADD Pipfile.lock /root/.analyzor
ADD Pipfile.lock /root/.analyzor
ADD welt.de.20190912.txt /root/.analyzor/zones.txt

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile

ENTRYPOINT [ "python", "check.py", "zones.txt", "www.welt.de" ]