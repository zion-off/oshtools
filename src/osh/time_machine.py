import asyncio
import time
from functools import wraps

from osh import Logger

logger = Logger("TIME MACHINE")


def get_class_name(args):
    """Helper function to extract the class name if the function is a method of a user-defined class."""
    if (
        args
        and hasattr(args[0], "__class__")
        and not isinstance(args[0], dict | list | tuple | set)
    ):
        return f"{args[0].__class__.__name__}."
    return ""


def time_machine(func):
    """Decorator to log the time a function takes to execute.
    Handles both synchronous and asynchronous functions.
    Logs the class name if the function is a method of a class.
    """

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        class_name = get_class_name(args)
        logger.runtime(
            f"Function '{class_name}{func.__name__}' executed in {elapsed_time:.4f} seconds."
        )
        return result

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        class_name = get_class_name(args)
        logger.runtime(
            f"Function '{class_name}{func.__name__}' executed in {elapsed_time:.4f} seconds."
        )
        return result

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper
