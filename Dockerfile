FROM python:3-alpine

COPY . .

RUN pip install pipenv \
  && pipenv install --deploy --system --ignore-pipfile

ENTRYPOINT ["python", "check.py"]
CMD ["zonefile_sample", "welt.de", "console"]
