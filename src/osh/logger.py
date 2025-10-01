import json
import os
import sys
import textwrap
from typing import Any, Dict, Optional

import structlog

IS_GCP_ENVIRONMENT = bool(os.getenv("K_SERVICE")) or bool(
    os.getenv("GOOGLE_CLOUD_PROJECT")
)
IS_TTY = sys.stdout.isatty()

CYAN_BG = "\033[46m"
GREEN_BG = "\033[42m"
YELLOW_BG = "\033[43m"
RED_BG = "\033[41m"
LIGHTBLUE_BG = "\033[104m"
BRIGHT_MAGENTA_BG = "\033[105m"
BLUE_BG = "\033[44m"
BLACK_FG = "\033[30m"
RESET = "\033[0m"
BRIGHT_RED_BG = "\033[101m"

METHOD_TO_COLOR_BG = {
    "log": CYAN_BG,
    "info": BLUE_BG,
    "runtime": BRIGHT_MAGENTA_BG,
    "think": LIGHTBLUE_BG,
    "debug": GREEN_BG,
    "warning": YELLOW_BG,
    "error": RED_BG,
    "critical": BRIGHT_RED_BG,
}


def add_custom_log_type(
    logger: Any, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add custom log type if not already present.

    Args:
        logger: The logger instance
        method_name: The method name
        event_dict: The event dictionary

    Returns:
        Dict[str, Any]: The event dictionary with custom_log_type added
    """
    if "custom_log_type" not in event_dict:
        event_dict["custom_log_type"] = method_name
    return event_dict


def add_logger_name(
    logger: Any, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add logger name to event dict.

    Args:
        logger: The logger instance
        method_name: The method name
        event_dict: The event dictionary

    Returns:
        Dict[str, Any]: The event dictionary with logger_name added
    """
    if hasattr(logger, "_logger_name"):
        event_dict["logger_name"] = logger._logger_name
    return event_dict


class ColoredConsoleRenderer:
    """Renderer for colored console output with formatting similar to original logger.

    Attributes:
        logger_display_name: The formatted display name of the logger
        enable_timestamps: Whether to show timestamps
    """

    def __init__(self, logger_display_name: str, enable_timestamps: bool = False):
        """Initialize the ColoredConsoleRenderer.

        Args:
            logger_display_name: The formatted display name of the logger
            enable_timestamps: Whether to show timestamps
        """
        self.logger_display_name = logger_display_name
        self.enable_timestamps = enable_timestamps

    def __call__(self, logger: Any, name: str, event_dict: Dict[str, Any]) -> str:
        """Render the log event with colors and formatting.

        Args:
            logger: The logger instance
            name: The method name
            event_dict: The event dictionary

        Returns:
            str: The formatted log message
        """
        # Extract standard fields
        timestamp_str = ""
        if self.enable_timestamps and "timestamp" in event_dict:
            timestamp_str = f"[{event_dict['timestamp']}] "

        custom_log_type = event_dict.get("custom_log_type", "log")
        color_bg = METHOD_TO_COLOR_BG.get(custom_log_type, CYAN_BG)

        # Get the main event message
        event_msg = event_dict.pop("event", "")

        # Handle JSON formatting for dicts/lists
        if isinstance(event_msg, (dict, list)):
            if IS_TTY:
                message_content = "\n" + json.dumps(event_msg, indent=2, ensure_ascii=False)
            else:
                message_content = json.dumps(event_msg, ensure_ascii=False)
        else:
            message_content = str(event_msg)

        header = f"{timestamp_str}{color_bg}{BLACK_FG}{self.logger_display_name}{RESET} "
        visual_header_length = len(timestamp_str) + len(self.logger_display_name) + 1

        # Get terminal width for wrapping
        import shutil
        term_width = shutil.get_terminal_size().columns
        available_width = term_width - visual_header_length

        # Wrap each line of the message
        lines = str(message_content).splitlines()
        if not lines:
            lines = [""]

        wrapped_lines = []
        for line in lines:
            if line.strip():
                wrapped = textwrap.fill(line, width=available_width)
                wrapped_lines.extend(wrapped.splitlines())
            else:
                wrapped_lines.append(line)

        indented_message = wrapped_lines[0]
        if len(wrapped_lines) > 1:
            padding_for_subsequent_lines = " " * visual_header_length
            for i in range(1, len(wrapped_lines)):
                indented_message += f"\n{padding_for_subsequent_lines}{wrapped_lines[i]}"

        formatted_log = header + indented_message

        # Handle exception info
        if "exception" in event_dict:
            padding_for_exception = " " * visual_header_length
            if indented_message and not indented_message.endswith("\n"):
                formatted_log += "\n"
            formatted_log += f"{padding_for_exception}Traceback (most recent call last):"

            exc_text = event_dict["exception"]
            for tb_line in exc_text.splitlines():
                available_width = term_width - len(padding_for_exception)
                while tb_line:
                    current_line = tb_line[:available_width]
                    formatted_log += f"\n{padding_for_exception}{current_line}"
                    tb_line = tb_line[available_width:]

        return formatted_log


class GCPStructuredRenderer:
    """Renderer for GCP Cloud Logging structured JSON output."""

    def __call__(self, logger: Any, name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Render the log event as structured JSON for GCP.

        Args:
            logger: The logger instance
            name: The method name
            event_dict: The event dictionary

        Returns:
            Dict[str, Any]: The structured log event
        """
        # Extract the message
        message = event_dict.pop("event", "")

        # Build structured payload
        structured_log = {
            "message": message,
            "severity": event_dict.pop("level", "INFO").upper(),
        }

        # Add all remaining fields as jsonPayload
        for key, value in event_dict.items():
            if key not in ("timestamp",):  # Skip timestamp, GCP adds its own
                structured_log[key] = value

        return structured_log


class Logger:
    """Structured logger with support for local colored output and GCP Cloud Logging.

    This logger uses structlog under the hood and provides:
    - Colored output with proper formatting for local development
    - Automatic GCP Cloud Logging integration
    - Support for arbitrary fields in log messages
    - Beautiful JSON formatting for complex data structures
    - Contextual logging with bind() method

    Attributes:
        _logger: The underlying structlog logger
        _logger_name: The raw name of the logger
        _display_name_formatted: The formatted display name
        _enable_timestamps: Whether timestamps are enabled for local output
    """

    def __init__(
        self,
        name: str,
        level: str = "DEBUG",
        **default_fields: Any,
    ):
        """Initialize the Logger.

        Args:
            name: The name of the logger
            level: The logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            **default_fields: Default fields to include in all logs
        """
        self._logger_name = name
        self._display_name_formatted = f"{name:<15}".upper()
        self._enable_timestamps = False

        # Build processor chain
        processors = [
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="%H:%M:%S", utc=False),
            add_logger_name,
            add_custom_log_type,
        ]

        # Choose renderer based on environment
        if IS_GCP_ENVIRONMENT:
            processors.append(GCPStructuredRenderer())
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(
                ColoredConsoleRenderer(
                    logger_display_name=self._display_name_formatted,
                    enable_timestamps=self._enable_timestamps,
                )
            )

        # Configure structlog
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )

        # Create logger instance
        self._logger = structlog.get_logger(name)

        # Bind default fields
        if default_fields:
            self._logger = self._logger.bind(**default_fields)

        # Store logger name for processor access
        self._logger._logger_name = name

    def set_timestamps(self, enabled: bool) -> None:
        """Enable or disable timestamps in log messages.

        Args:
            enabled: True to enable timestamps, False to disable
        """
        self._enable_timestamps = enabled

    def bind(self, **fields: Any) -> "Logger":
        """Create a new logger instance with additional bound fields.

        Args:
            **fields: Additional fields to include in all logs

        Returns:
            Logger: A new logger instance with the bound fields
        """
        new_logger = Logger(self._logger_name)
        # Copy the bound context
        new_logger._logger = self._logger.bind(**fields)
        new_logger._logger._logger_name = self._logger_name
        new_logger._enable_timestamps = self._enable_timestamps
        return new_logger

    def log(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'log' level.

        Args:
            *args: Message parts to log
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.info(message, custom_log_type="log", **kwargs)

    def info(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'info' level.

        Args:
            *args: Message parts to log
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.info(message, custom_log_type="info", **kwargs)

    def runtime(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'runtime' level.

        Args:
            *args: Message parts to log
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.info(message, custom_log_type="runtime", **kwargs)

    def think(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'think' level.

        Args:
            *args: Message parts to log
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.info(message, custom_log_type="think", **kwargs)

    def debug(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'debug' level.

        Args:
            *args: Message parts to log
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.debug(message, custom_log_type="debug", **kwargs)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'warning' level.

        Args:
            *args: Message parts to log
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.warning(message, custom_log_type="warning", **kwargs)

    def error(self, *args: Any, exc_info: bool = True, **kwargs: Any) -> None:
        """Log a message with the 'error' level.

        Args:
            *args: Message parts to log
            exc_info: Whether to include exception info
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.error(message, custom_log_type="error", exc_info=exc_info, **kwargs)

    def critical(self, *args: Any, exc_info: bool = True, **kwargs: Any) -> None:
        """Log a message with the 'critical' level.

        Args:
            *args: Message parts to log
            exc_info: Whether to include exception info
            **kwargs: Additional fields to include
        """
        message = " ".join(str(arg) for arg in args) if args else ""
        self._logger.critical(message, custom_log_type="critical", exc_info=exc_info, **kwargs)

    # Maintain backward compatibility
    def with_fields(self, **fields: Any) -> "Logger":
        """Alias for bind() to maintain backward compatibility.

        Args:
            **fields: Additional fields to include in all logs

        Returns:
            Logger: A new logger instance with the bound fields
        """
        return self.bind(**fields)
