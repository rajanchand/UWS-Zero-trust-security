server {
    listen 80;
    server_name <your_domain_or_ip>;

    location / {
        proxy_pass http://127.0.0.1:8000;  # Change to http://212.227.39.216:8000 if needed
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}