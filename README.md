# OSH Logger

A simple Python logging library for chat applications, with support for both
local development and Google Cloud Platform (GCP) environments.

## Features

- **Dual Environment Support**: Automatically detects and configures logging for
  local development and GCP environments
- **Colored Local Output**: Beautiful, colored terminal output with proper text
  wrapping in local development environment
- **Structured GCP Logging**: Labelled logs and structured output on GCP, with ability to filter by a Logger instance's name
- **Thread-Safe**: Supports logging with thread IDs for concurrent applications
- **Configurable Timestamps**: Enable/disable timestamps as needed

## Installation

### Basic Installation

```bash
pip install oshtools
```

### With Google Cloud Support

```bash
pip install oshtools[gcp]
```

## Quick Start

```python
from osh import Logger

# Create a separate logger instance for each module
logger = Logger("main")

# Pass in a thread ID to the contructor
# The thread ID is a unique identifier that can help trace requests on GCP
logger = Logger("utils", "123")

# Basic logging
logger.log("Application started")
logger.info("Processing complete")
logger.debug("Debug information")
logger.warn("Warning message")
logger.error("Error occurred")

# Log and add a thread ID dynamically
logger.log("Processing request", thread_id="thread-123")

# Structured logging (useful for GCP)
logger.struct_log("User action", user_id="123", action="login", level=logging.INFO)
```

## Environment Detection

The logger automatically detects the environment:

- **GCP Environment**: Detected by presence of `K_SERVICE` or
  `GOOGLE_CLOUD_PROJECT` environment variables
- **Local Environment**: Uses colored terminal output with proper formatting

## Log Types

The logger supports several log types with different colors and levels:

- `log()` - General information (cyan)
- `info()` - Informational messages (blue)
- `runtime()` - Runtime information (bright magenta)
- `think()` - Thinking/processing logs (light blue)
- `debug()` - Debug information (green)
- `warn()` - Warnings (yellow)
- `error()` - Errors (red)
- `critical()` - Critical errors (bright red)

## Configuration

### Timestamps

```python
logger = Logger("my-app")
logger.set_timestamps(False)  # Disable timestamps
logger.set_timestamps(True)   # Enable timestamps
```

### Log Levels

```python
import logging
logger = Logger("my-app", level=logging.DEBUG)
```

## Google Cloud Platform Integration

When running in GCP (Cloud Run, App Engine, etc.), the logger automatically:

- Uses Google Cloud Logging handlers
- Adds structured metadata and labels
- Includes logger names and thread IDs in labels
- Maintains local CLI formatting for debugging

## Requirements

- Python 3.8+
- `google-cloud-logging` (optional, for GCP support)

## License

MIT License
