# Airflow Configuration: Version 2.4 vs 2.10

## Authentication & Authorization

### Airflow 2.4

```ini
[api]
# API authentication backends (comma-separated list)
auth_backends = airflow.api.auth.backend.session

[webserver]
# UI authentication via Flask-AppBuilder
rbac = True  # This was deprecated even in 2.4
authenticate = True
auth_backend = airflow.contrib.auth.backends.password_auth

# Security settings
secret_key = your-secret-key
```

**Architecture**:
- Separate authentication for UI (Flask-AppBuilder) and API (`auth_backends`)
- Security manager extended from `flask_appbuilder.security.sqla.manager.SecurityManager`
- Custom auth via extending `AirflowSecurityManager`

---

### Airflow 2.10

```ini
[core]
# Unified authentication manager (NEW in 2.9+)
auth_manager = airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager

[api]
# Kept for backward compatibility, but auth_manager takes precedence
auth_backends = airflow.api.auth.backend.session

[webserver]
# secret_key still required
secret_key = your-secret-key

# These are now handled by auth_manager:
# - authenticate (removed)
# - auth_backend (removed)
# - rbac (removed - always True)
```

**Architecture**:
- Unified authentication via `auth_manager`
- Implements `airflow.auth.managers.base_auth_manager.BaseAuthManager`
- More modular and extensible
- Better separation of concerns

---

## Core Configuration Changes

### 1. Database

**Airflow 2.4**:
```ini
[core]
sql_alchemy_conn = postgresql+psycopg2://user:pass@localhost/airflow
sql_alchemy_pool_enabled = True
sql_alchemy_pool_size = 5
```

**Airflow 2.10**:
```ini
[database]
# Section renamed from [core] for database configs
sql_alchemy_conn = postgresql+psycopg2://user:pass@localhost/airflow
sql_alchemy_pool_enabled = True
sql_alchemy_pool_size = 5
sql_alchemy_pool_recycle = 1800

# New options
load_default_connections = True
check_migrations = True
```

---

### 2. Executor Configuration

**Airflow 2.4**:
```ini
[core]
executor = LocalExecutor
parallelism = 32
dag_concurrency = 16
max_active_runs_per_dag = 16
```

**Airflow 2.10**:
```ini
[core]
executor = LocalExecutor
parallelism = 32

# Moved to separate sections
[scheduler]
max_tis_per_query = 512

# dag_concurrency renamed
max_active_tasks_per_dag = 16  # Was dag_concurrency
max_active_runs_per_dag = 16
```

---

### 3. Logging Configuration

**Airflow 2.4**:
```ini
[logging]
base_log_folder = /path/to/logs
remote_logging = False
remote_log_conn_id = 
remote_base_log_folder = 
```

**Airflow 2.10**:
```ini
[logging]
base_log_folder = /path/to/logs
remote_logging = False

# Enhanced remote logging options
remote_log_conn_id = 
remote_base_log_folder = 
log_processor_filename_template = {{ filename }}.log
log_filename_template = dag_id={{ ti.dag_id }}/run_id={{ ti.run_id }}/task_id={{ ti.task_id }}/{{ ts }}.log

# New: Colored logs
colored_console_log = True
colored_log_format = [%%(blue)s%%(asctime)s%%(reset)s] {%%(blue)s%%(filename)s:%%(reset)s%%(lineno)d} %%(log_color)s%%(levelname)s%%(reset)s - %%(log_color)s%%(message)s%%(reset)s
```

---

### 4. Scheduler Configuration

**Airflow 2.4**:
```ini
[scheduler]
job_heartbeat_sec = 5
scheduler_heartbeat_sec = 5
num_runs = -1
min_file_process_interval = 30
dag_dir_list_interval = 300
```

**Airflow 2.10**:
```ini
[scheduler]
# More granular control
scheduler_heartbeat_sec = 5
scheduler_health_check_threshold = 30

# DAG parsing improvements
min_file_process_interval = 30
dag_dir_list_interval = 300
parsing_processes = 2  # Parallel DAG parsing

# New options
max_tis_per_query = 512
use_job_schedule = True
allow_trigger_in_future = False
standalone_dag_processor = False  # NEW: Separate DAG processor
```

---

### 5. Webserver Configuration

**Airflow 2.4**:
```ini
[webserver]
web_server_host = 0.0.0.0
web_server_port = 8080
web_server_worker_timeout = 120
workers = 4

# Session config
secret_key = your-secret-key
session_lifetime_minutes = 43200
```

**Airflow 2.10**:
```ini
[webserver]
web_server_host = 0.0.0.0
web_server_port = 8080
web_server_worker_timeout = 120
workers = 4

# Enhanced session management
secret_key = your-secret-key
session_lifetime_minutes = 43200
session_backend = database  # NEW: database or securecookie
session_backend_url = 

# New UI features
navbar_color = #fff
page_size = 100
auto_refresh_interval = 3

# Security headers (NEW)
x_frame_enabled = True
cookie_secure = False
cookie_samesite = Lax
```

---

### 6. Metrics & Monitoring

**Airflow 2.4**:
```ini
[metrics]
statsd_on = False
statsd_host = localhost
statsd_port = 8125
statsd_prefix = airflow
```

**Airflow 2.10**:
```ini
[metrics]
statsd_on = False
statsd_host = localhost
statsd_port = 8125
statsd_prefix = airflow

# New metrics options
metrics_block_list =  # Comma-separated list of metrics to block
metrics_allow_list =  # Comma-separated list of metrics to allow
stat_name_handler =  # Custom stat name handler

# New: OpenTelemetry support
otel_on = False
otel_host = localhost
otel_port = 4318
otel_prefix = airflow
otel_ssl_active = False
```

---

### 7. Secrets Backend

**Airflow 2.4**:
```ini
[secrets]
backend = 
backend_kwargs = 
```

**Airflow 2.10**:
```ini
[secrets]
backend = 
backend_kwargs = 

# New: Multiple secrets backends (comma-separated)
backends = airflow.providers.hashicorp.secrets.vault.VaultBackend,airflow.secrets.local_filesystem.LocalFilesystemBackend

# Each backend can have separate config sections
[secrets.backend.vault]
connections_path = connections
variables_path = variables
config_path = config
url = http://127.0.0.1:8200
token = your-token
```

---

### 8. Task Execution

**Airflow 2.4**:
```ini
[core]
default_task_retries = 0
default_task_execution_timeout = None
killed_task_cleanup_time = 60
```

**Airflow 2.10**:
```ini
[core]
default_task_retries = 0
default_task_execution_timeout = None
killed_task_cleanup_time = 60

# New task options
task_adoption_timeout = 600
task_queued_timeout = 600

# Task logging verbosity
task_log_reader = task  # NEW: task or file.task

[operators]
# NEW section for operator defaults
default_owner = airflow
default_cpus = 1
default_ram = 512
default_disk = 512
default_gpus = 0
```

---

## Major Feature Additions in 2.10

### 1. **Internal API (AIP-44)**

```ini
[core]
# Enable internal API for distributed setups
internal_api_url = http://localhost:8080
internal_api_secret_key = your-internal-api-secret

[api]
enable_experimental_api = False  # Removed in 2.10
```

### 2. **Dataset-Driven Scheduling**

```ini
[scheduler]
# Dataset-aware scheduling
schedule_after_task_execution = True
```

### 3. **Dag Processor Separation**

```ini
[scheduler]
# Run DAG processor as separate process
standalone_dag_processor = True
parsing_processes = 2
```

### 4. **Enhanced Security**

```ini
[webserver]
# Content Security Policy
content_security_policy = default-src 'self'; script-src 'self' 'unsafe-inline'

# Rate limiting
rate_limit = 

# CSRF protection
enable_csrf = True
```

---

## Deprecated & Removed Configurations

### Removed in 2.10

```ini
# These no longer work:
[webserver]
rbac = True  # Always True now, config removed
authenticate = True  # Handled by auth_manager
auth_backend = ...  # Replaced by auth_manager

[core]
store_dag_code = True  # Always True now
store_serialized_dags = True  # Always True now

[api]
enable_experimental_api = False  # Experimental API removed
```

### Deprecated (still work but will be removed)

```ini
[api]
auth_backends = ...  # Use auth_manager instead

[core]
sql_alchemy_conn = ...  # Use [database] section instead
```

---

## Migration Path: 2.4 → 2.10

### Step 1: Update Authentication

**Old (2.4)**:
```python
from airflow.www.security import AirflowSecurityManager

class CustomSecurityManager(AirflowSecurityManager):
    pass
```

**New (2.10)**:
```python
from airflow.auth.managers.base_auth_manager import BaseAuthManager
from airflow.providers.fab.auth_manager.fab_auth_manager import FabAuthManager

class CustomAuthManager(FabAuthManager):
    pass
```

### Step 2: Update Configuration

```ini
# Add to airflow.cfg
[core]
auth_manager = your_module.CustomAuthManager

# Remove old configs
# [webserver]
# auth_backend = ...  # Remove this
```

### Step 3: Database Migration

```bash
# Backup database
airflow db backup

# Run migrations
airflow db migrate

# Check version
airflow db check
```

---

## Summary of Key Changes

| Feature | Airflow 2.4 | Airflow 2.10 |
|---------|-------------|--------------|
| **Auth Architecture** | Separate UI/API auth | Unified `auth_manager` |
| **RBAC** | Optional (`rbac=True`) | Always enabled |
| **Database Config** | `[core]` section | `[database]` section |
| **DAG Parsing** | Scheduler-only | Can be separate process |
| **Internal API** | Not available | Available for distributed setups |
| **Datasets** | Not available | Full support |
| **OpenTelemetry** | Not available | Full support |
| **Security Headers** | Basic | Enhanced CSP, CSRF |

