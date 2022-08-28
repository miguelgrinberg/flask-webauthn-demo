# Flask WebAuthn Demo

This is a fully functional example that shows how to implement second-factor
authentication through biometric or hardware key verification in a Flask
application.

## Setup

- Clone this repository and change into the top-level directory
- Set up virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

- Create the database:

```bash
flask create-db
```

- Start the application:

```bash
flask run
```

The application should now be ready to use at `http://localhost:5000`.
