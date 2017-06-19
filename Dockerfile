FROM python:3.5-alpine
MAINTAINER Anders Borud "anders.borud@sesam.io"


# Install app dependencies
RUN mkdir /code
COPY . /code
WORKDIR /code

RUN pip3 install -r requirements.txt


ENTRYPOINT ["python3", "deploy.py"]
