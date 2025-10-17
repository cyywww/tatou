# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/nharrand/tatou.git
```

Note that you should probably fork the repo and clone your own repo.


### Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
. .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run the unit tests
python -m pytest
```

### Deploy

From the root of the directory:

```bash
# Create a file to set environement variables like passwords.
cp sample.env .env

# Edit .env and pick the passwords you want

# Rebuild the docker image and deploy the containers
docker compose up --build -d

# Monitor logs in realtime 
docker compose logs -f

# Test if the API is up
http -v :5000/healthz

# Open your browser at 127.0.0.1:5000 to check if the website is up.
```

## Security Monitoring and Logging

### Security Features

- **Attack Detection**: Real-time monitoring of suspicious activities and potential security threats
- **Security Logging**: Comprehensive logging of all security events and system activities

### Security Logs

The system maintains several types of security logs:

- `logs/monitor.log` - Real-time attack monitoring and detection logs
- `logs/recovery.log` - System recovery operations and status logs
- Security events are logged with timestamps and detailed information

### Monitoring Configuration

Security monitoring is configured in `server/src/security_log_config.py` and can be customized for different environments. The monitoring system:

- Runs continuous checks for potential attacks
- Logs all security events with detailed timestamps
- Provides automated recovery mechanisms
- Maintains audit trails for security analysis

### Viewing Security Logs

To monitor security events in real-time:

```bash
# View monitoring logs
tail -f logs/monitor.log

# View recovery logs  
tail -f logs/recovery.log

# View all security logs
tail -f logs/*.log
```



