# [decomp.me](https://decomp.me)

[![Discord Server][discord-badge]][discord]

[discord]: https://discord.gg/sutqNShRRs
[discord-badge]: https://img.shields.io/discord/897066363951128586?color=%237289DA&logo=discord&logoColor=ffffff

A collaborative decompilation and reverse engineering website, built with Next.js and Django.

## Directory structure
```
frontend/
  public/        ; Static files
  src/           ; React/Typescript sourcecode

backend/
  compilers/     ; Compiler binaries and configuration
  coreapp/       ; API Django app
    migrations/  ; Database migrations (generated by Django)
  decompme/      ; Main Django app

.env             ; Default configuration
.env.local       ; Local configuration overrides (not checked-in)
```

## Setup

See [DOCKER.md](DOCKER.md) for instructions on how to run the project in a Docker container.

Dependencies:
- Python >=3.8
- Node.js
- [Yarn](https://yarnpkg.com/getting-started/install)

---

- Create a file to hold environment variables:
```shell
touch .env.local
```

### Frontend
```shell
cd frontend
```

- Install dependencies
```shell
yarn
```

- Start the development webserver
```shell
yarn dev
```

- Access the site via [http://localhost:8080](http://localhost:8080)

### Backend
```shell
cd backend
```

- Set up a virtual environment (optional)
```shell
python3 -m virtualenv venv
source venv/bin/activate
```

- Install dependencies
```shell
pip install -r requirements.txt
./compilers/download.sh
```

- Set up the database
```shell
python manage.py migrate
```

- Start the API server
```shell
python manage.py runserver
```

---

The following setup sections are optional.

### GitHub authentication

- [Register a new OAuth application](https://github.com/settings/applications/new)
    - "Homepage URL" should be the URL you access the frontend on (e.g. `http://localhost:8080`)
    - "Authorization callback URL" should be the same as the homepage URL, but with `/login` appended

- Edit `.env.local`:
    - Set `GITHUB_CLIENT_ID` to the application client ID
    - Set `GITHUB_CLIENT_SECRET` to the application client secret (do **not** share this)

### Running inside an nginx proxy

Running decomp.me using nginx as a proxy better emulates the production environment and can avoid cookie-related issues.

- Install nginx

- Create an nginx site configuration (typically `/etc/nginx/sites-available/local.decomp.me`)
```nginx
server {
    listen 80;
    listen [::]:80;
    client_max_body_size 5M;

    server_name local.decomp.me www.local.decomp.me;

    location / {
        try_files $uri @proxy_frontend;
    }

    location /api {
        try_files $uri @proxy_api;
    }
    location /admin {
        try_files $uri @proxy_api;
    }
    location /static {
        try_files $uri @proxy_api;
    }

    location @proxy_api {
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Url-Scheme $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8000;
    }

    location @proxy_frontend {
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Url-Scheme $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

- Enable the site
```shell
ln -s /etc/nginx/sites-available/local.decomp.me /etc/nginx/sites-enabled/local.decomp.me
```

- Add the following lines to `/etc/hosts`:
```
127.0.0.1	    local.decomp.me
127.0.0.1	    www.local.decomp.me
```

- Edit `.env.local`:
    - Set `API_BASE=/api`
    - Set `ALLOWED_HOSTS=local.decomp.me`

- If you set up GitHub authentication, change the application URLs to `http://local.decomp.me` and `http://local.decomp.me/login`

- Restart nginx, the frontend, and the backend

- Access the site via [http://local.decomp.me](http://local.decomp.me)

### Sandbox jail

There is support for running subprocesses within [`nsjail`](https://github.com/google/nsjail).

This is controlled by the `SANDBOX` settings, and is disabled by default in the development `.env` but is enabled inside the `backend` Docker container.

To enable it locally outside of the Docker container:

- Build or install `nsjail` locally. Example instructions for Ubuntu:
    - `apt-get install autoconf bison flex gcc g++ git libprotobuf-dev libnl-route-3-dev libtool make pkg-config protobuf-compiler`
    - `git clone --recursive --branch=3.0 https://github.com/google/nsjail`
    - `cd nsjail && make`
- Enable `unprivileged_userns_clone`
    - Temporary: `sudo sysctl -w kernel.unprivileged_userns_clone=1`
    - Permanent: `echo 'kernel.unprivileged_userns_clone=1' | sudo tee -a /etc/sysctl.d/00-local-userns.conf && sudo service procps restart`

- Edit `.env.local`:
    - Set `USE_SANDBOX_JAIL=on`
    - Set `SANDBOX_NSJAIL_BIN_PATH` to the absolute path of the `nsjail` binary built above

## Deployment

- Backend - same as in development, just set DEBUG=true
- Frontend - multiple options:
    - Self-hosted - `yarn build && yarn start` with nginx proxy to filter /api/* to the backend
    - [Deploy with Vercel](https://vercel.com/new)

## Contributing

Contributions are very much welcome! You may want to [join our Discord server](https://discord.gg/sutqNShRRs).

### Storybook

Use `yarn storybook` to run a Storybook instance on [http://localhost:6006](http://localhost:6006). This is useful for testing UI components in isolation.

### Linting

- Check frontend
```shell
cd frontend
yarn lint
```

- Autofix frontend
```shell
cd frontend
yarn lint --fix
```

- Check backend
```shell
cd backend
mypy
```

### Updating the database

If you modify any database models (`models.py`), you'll need to run the following to update the database:
```shell
python manage.py makemigrations
python manage.py migrate
```

## License
decomp.me uses the MIT license. All dependencies may contain their own licenses, which decomp.me respects.
