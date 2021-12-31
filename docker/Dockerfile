FROM tensorflow/tensorflow:latest-gpu

LABEL maintainer="chen.junbao@outlook.com"

ADD ./requirements.txt /sa/requirements.txt
ADD ./secret-sharing /sa/secret-sharing

WORKDIR /sa

RUN ["apt", "install", "-y", "git"]
RUN ["pip", "install", "-r", "requirements.txt"]
RUN ["pip", "install", "git+file:///sa/secret-sharing"]
