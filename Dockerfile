FROM python:3.7.3-stretch


COPY requirements.txt /tmp/

RUN pip install -r /tmp/requirements.txt
WORKDIR /app
COPY app.py .
COPY templates ./templates
COPY entrypoint.sh .

RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser
VOLUME ["/home/appuser"]
ENV FLASK_CONFIG_FILE=/home/appuser/config.cfg
ENTRYPOINT ["/app/entrypoint.sh"]
CMD [ "" ]

