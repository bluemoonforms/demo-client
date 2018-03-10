FROM tiangolo/uwsgi-nginx-flask:python3.6

ENV FLASK_APP=/app/main.py \
    PYTHONPATH=/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ADD ./app /app

# Install the new entry-point script
COPY secrets-entrypoint.sh /usr/local/bin/secrets-entrypoint.sh

# Overwrite the entry-point script
ENTRYPOINT ["secrets-entrypoint.sh"]
CMD ["/usr/bin/supervisord"]
