import json
import logging
import os
import sys
import textwrap
from typing import Any

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

METHOD_TO_LOGGING_LEVEL = {
    "log": logging.INFO,
    "info": logging.INFO,
    "runtime": logging.INFO,
    "think": logging.INFO,
    "debug": logging.DEBUG,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


class LocalColorFormatter(logging.Formatter):
    """Custom formatter for adding color and formatting to log messages.

    Attributes:
        logger_display_name_formatted (str): The formatted display name of the logger.
        enable_timestamps_func (callable): A function to determine if timestamps should be enabled.
    """

    def __init__(
        self, logger_display_name_formatted: str, enable_timestamps_func, **kwargs
    ):
        """Initialize the LocalColorFormatter.

        Args:
            logger_display_name_formatted (str): The formatted display name of the logger.
            enable_timestamps_func (callable): A function to determine if timestamps should be enabled.
            **kwargs: Additional keyword arguments for the base Formatter class.
        """
        self.logger_display_name_formatted = logger_display_name_formatted
        self.enable_timestamps_func = enable_timestamps_func
        super().__init__(datefmt="%H:%M:%S", **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with color and additional information.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted log message.
        """
        timestamp_str = ""
        if self.enable_timestamps_func():
            s = self.formatTime(record, self.datefmt)
            timestamp_str = f"[{s}] "

        custom_log_type = getattr(record, "custom_log_type", record.levelname.lower())
        color_bg = METHOD_TO_COLOR_BG.get(custom_log_type, CYAN_BG)

        # Handle JSON formatting for dicts/lists
        if isinstance(record.msg, (dict, list)) and IS_TTY and not IS_GCP_ENVIRONMENT:
            try:
                message_content = "\n" + json.dumps(record.msg, indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                message_content = record.getMessage()
        else:
            message_content = record.getMessage()

        header = f"{timestamp_str}{color_bg}{BLACK_FG}{self.logger_display_name_formatted}{RESET} "
        visual_header_length = (
            len(timestamp_str) + len(self.logger_display_name_formatted) + 1
        )

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
            if line.strip():  # Only wrap non-empty lines
                wrapped = textwrap.fill(line, width=available_width)
                wrapped_lines.extend(wrapped.splitlines())
            else:
                wrapped_lines.append(line)

        indented_message = wrapped_lines[0]
        if len(wrapped_lines) > 1:
            padding_for_subsequent_lines = " " * visual_header_length
            for i in range(1, len(wrapped_lines)):
                indented_message += (
                    f"\n{padding_for_subsequent_lines}{wrapped_lines[i]}"
                )

        formatted_log = header + indented_message

        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            padding_for_exception = " " * visual_header_length
            if indented_message and not indented_message.endswith("\n"):
                formatted_log += "\n"
            formatted_log += (
                f"{padding_for_exception}Traceback (most recent call last):"
            )

            for tb_line in record.exc_text.splitlines():
                available_width = term_width - len(padding_for_exception)
                while tb_line:
                    current_line = tb_line[:available_width]
                    formatted_log += f"\n{padding_for_exception}{current_line}"
                    tb_line = tb_line[available_width:]
        return formatted_log


class AddFormattedCliOutputFilter(logging.Filter):
    """Filter to add formatted CLI output to log records.

    Attributes:
        local_color_formatter (LocalColorFormatter): The formatter used for CLI output.
    """

    def __init__(self, local_color_formatter: LocalColorFormatter, name=""):
        """Initialize the filter.

        Args:
            local_color_formatter (LocalColorFormatter): The formatter used for CLI output.
            name (str): The name of the filter.
        """
        super().__init__(name)
        self.local_color_formatter = local_color_formatter

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter the log record and add formatted CLI output.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to include the record, False otherwise.
        """
        formatted_string = self.local_color_formatter.format(record)
        if not hasattr(record, "extra_props"):
            record.extra_props = {}

        record.formatted_cli_output = formatted_string
        return True


class Logger(logging.Logger):
    """Custom logger class with support for local and GCP logging.

    Inherits from logging.Logger and adds:
    - Colored output with proper formatting for local development
    - Automatic GCP Cloud Logging integration
    - Support for arbitrary fields in log messages
    - Beautiful JSON formatting for complex data structures
    - Contextual logging with with_fields() method

    Attributes:
        raw_name (str): The raw name of the logger.
        display_name_formatted (str): The formatted display name of the logger.
        _enable_timestamps_local (bool): Flag to enable or disable timestamps locally.
        default_fields (Dict[str, Any]): Default fields to include in all log messages.
    """

    def __init__(
        self, name: str, level: int = logging.DEBUG, **fields: Any
    ):
        """Initialize the Logger.

        Args:
            name (str): The name of the logger.
            level (int): The logging level.
            **fields: Arbitrary fields to include in logs (e.g., thread_id="123").
        """
        super().__init__(name, level)
        self.raw_name = name
        self.display_name_formatted = f"{name:<15}".upper()
        self._enable_timestamps_local = False
        self.default_fields = fields

        self.setLevel(level)
        self.propagate = False

        if not self.handlers:
            if IS_GCP_ENVIRONMENT:
                try:
                    import google.cloud.logging as cloud_logging_v2

                    client = cloud_logging_v2.Client()
                    service_name_for_log = (
                        os.getenv("K_SERVICE", self.raw_name).lower().replace("-", "_")
                    )
                    gcp_log_name = f"python.{service_name_for_log}"
                    self._setup_gcp_handler(client, gcp_log_name, level)
                except ImportError:
                    sys.stderr.write(
                        "WARNING: google-cloud-logging library not found. GCP logging will not be fully structured. Falling back to local stdout.\n"
                    )
                    self._setup_local_handler(level)
                except Exception as e:
                    sys.stderr.write(
                        f"WARNING: Failed to set up GCP logging handler: {e}. Falling back to local stdout.\n"
                    )
                    self._setup_local_handler(level)
            else:
                self._setup_local_handler(level)

    def _get_enable_timestamps_local(self):
        """Get the local timestamp enable flag.

        Returns:
            bool: True if timestamps are enabled locally, False otherwise.
        """
        return self._enable_timestamps_local

    def _setup_local_handler(self, level_int: int):
        """Set up the local logging handler.

        Args:
            level_int (int): The logging level for the handler.
        """
        local_handler = logging.StreamHandler(sys.stdout)
        local_handler.setLevel(level_int)
        formatter = LocalColorFormatter(
            logger_display_name_formatted=self.display_name_formatted,
            enable_timestamps_func=self._get_enable_timestamps_local,
        )
        local_handler.setFormatter(formatter)
        self.addHandler(local_handler)

    def _setup_gcp_handler(self, client, gcp_log_name, level_int: int):
        """Set up the GCP logging handler.

        Args:
            client: The GCP logging client.
            gcp_log_name (str): The name of the GCP log.
            level_int (int): The logging level for the handler.
        """
        from google.cloud.logging_v2.handlers import CloudLoggingHandler

        gcp_handler = CloudLoggingHandler(client, name=gcp_log_name)
        gcp_handler.setLevel(level_int)

        def add_logger_name_label_filter(record: logging.LogRecord) -> bool:
            current_labels = getattr(record, "labels", {})
            if not isinstance(current_labels, dict):
                current_labels = {}
            current_labels["logger_name"] = self.raw_name
            record.labels = current_labels
            return True

        gcp_handler.addFilter(add_logger_name_label_filter)

        local_formatter_for_filter = LocalColorFormatter(
            logger_display_name_formatted=self.display_name_formatted,
            enable_timestamps_func=self._get_enable_timestamps_local,
        )
        cli_output_filter = AddFormattedCliOutputFilter(local_formatter_for_filter)
        gcp_handler.addFilter(cli_output_filter)

        self.addHandler(gcp_handler)

    def _format_json_message(self, data: Any) -> Any:
        """Return data as-is for JSON formatting by the formatter."""
        return data

    def _process_log_call(
        self,
        method_type: str,
        *args: Any,
        **kwargs: Any,
    ):
        """Process a log call with the specified method type.

        Args:
            method_type (str): The type of log method (e.g., 'log', 'error').
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        # Extract standard logging kwargs
        extra_data = kwargs.pop("extra_data", {}) or {}
        exc_info_val = kwargs.pop("exc_info", None)
        stack_info_val = kwargs.pop("stack_info", False)
        kwargs.pop("file", None)

        # Remaining kwargs are treated as fields
        call_fields = kwargs
        all_fields = {**self.default_fields, **call_fields}

        message_val: Any
        if len(args) == 1 and isinstance(args[0], (dict, list)):
            # Pass the raw data for JSON formatting in the formatter
            message_val = args[0]
        else:
            message_val = " ".join(str(arg) for arg in args)

        extra_payload_for_record = extra_data.copy()
        extra_payload_for_record["custom_log_type"] = method_type
        extra_payload_for_record.update(all_fields)

        if IS_GCP_ENVIRONMENT:
            labels = {
                "python_logger": self.raw_name,
            }
            # Add all fields as labels in GCP
            labels.update({str(k): str(v) for k, v in all_fields.items()})
            extra_payload_for_record["labels"] = labels

        if method_type in ["error", "critical"] and exc_info_val is None:
            exc_info_val = sys.exc_info() != (None, None, None)

        level_to_log = METHOD_TO_LOGGING_LEVEL[method_type]

        super().log(
            level_to_log,
            message_val,
            exc_info=exc_info_val,
            stack_info=stack_info_val,
            extra=extra_payload_for_record,
        )

    def log(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'log' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("log", *args, **kwargs)

    def info(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'info' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("info", *args, **kwargs)

    def runtime(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'runtime' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("runtime", *args, **kwargs)

    def think(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'think' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("think", *args, **kwargs)

    def debug(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'debug' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("debug", *args, **kwargs)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'warning' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("warning", *args, **kwargs)

    def error(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'error' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("error", *args, **kwargs)

    def critical(self, *args: Any, **kwargs: Any) -> None:
        """Log a message with the 'critical' level.

        Args:
            *args: Positional arguments for the log message.
            **kwargs: Keyword arguments and fields for the log message.
        """
        self._process_log_call("critical", *args, **kwargs)

    def set_timestamps(self, enabled: bool) -> None:
        """Enable or disable timestamps in log messages.

        Args:
            enabled (bool): True to enable timestamps, False to disable.
        """
        self._enable_timestamps_local = enabled
        if not IS_GCP_ENVIRONMENT and not IS_TTY:
            for handler in self.handlers:
                if isinstance(handler.formatter, logging.Formatter) and not isinstance(
                    handler.formatter, LocalColorFormatter
                ):
                    fmt_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                    if not self._enable_timestamps_local:
                        fmt_str = "%(name)s - %(levelname)s - %(message)s"
                    new_formatter = logging.Formatter(
                        fmt_str, datefmt="%Y-%m-%d %H:%M:%S"
                    )
                    handler.setFormatter(new_formatter)

    def struct_log(
        self,
        message: str,
        level: int = logging.INFO,
        _custom_type: str = "log",
        **fields,
    ) -> None:
        """Log a structured message with additional fields.

        Args:
            message (str): The log message.
            level (int): The logging level.
            _custom_type (str): The custom log type.
            **fields: Additional fields to include in the log.
        """
        # Merge default fields with provided fields
        all_fields = {**self.default_fields, **fields}

        payload = all_fields.copy()
        payload["custom_log_type"] = _custom_type

        if IS_GCP_ENVIRONMENT:
            labels = {
                "python_logger": self.raw_name,
            }
            # Add all fields as labels in GCP
            labels.update({str(k): str(v) for k, v in all_fields.items()})
            payload["labels"] = labels

        super().log(level, message, extra=payload)

    def with_fields(self, **fields: Any) -> 'Logger':
        """Create a new logger instance with additional default fields.

        Args:
            **fields: Additional fields to include in all logs from the returned logger.

        Returns:
            Logger: A new logger instance with the combined fields.
        """
        combined_fields = {**self.default_fields, **fields}
        new_logger = Logger(self.raw_name, self.level, **combined_fields)
        return new_logger
