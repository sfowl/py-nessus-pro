import logging

LOG_LEVEL = logging.WARNING

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'ERROR': '\033[91m',  # Red
        'WARNING': '\033[93m',  # Yellow
        'INFO': '\033[34m',  # Blue
        'DEBUG': '\033[92m',  # Bright Green
        'SUCCESS': '\033[32m'  # Green
    }

    RESET_COLOR = '\033[0m'

    def format(self, record):
        log_level = record.levelname
        colored_prefix = f"{self.COLORS.get(log_level, '')}[!] {log_level}{self.RESET_COLOR}"

        if log_level == 'INFO':
            colored_prefix = f"{self.COLORS['INFO']}[-] INFO{self.RESET_COLOR}"
        elif log_level == 'DEBUG':
            colored_prefix = f"{self.COLORS['DEBUG']}[-] DEBUG{self.RESET_COLOR}"
        elif log_level == 'SUCCESS':
            colored_prefix = f"{self.COLORS['SUCCESS']}[+] SUCCESS{self.RESET_COLOR}"

        # Construct the log message
        log_message = super().format(record)

        # Include the colored prefix in the final log message
        formatted_message = f"{colored_prefix} - {log_message}"

        return formatted_message

class CustomLogger(logging.Logger):
    def success(self, msg, *args, **kwargs):
        if self.isEnabledFor(logging.SUCCESS):
            self._log(logging.SUCCESS, msg, args, **kwargs)
    
    def set_log_level(self, log_level):
        if log_level == "debug":
            logger.setLevel(logging.DEBUG)
        elif log_level == "info":
            logger.setLevel(logging.INFO)
        elif log_level == "success":
            logger.setLevel(logging.SUCCESS)
        elif log_level == "warning" or log_level == "warn":
            logger.setLevel(logging.WARNING)
        elif log_level == "error":
            logger.setLevel(logging.ERROR)
        elif log_level == "critical":
            logger.setLevel(logging.CRITICAL)


logging.SUCCESS = 25
logging.addLevelName(logging.SUCCESS, 'SUCCESS')

logger = CustomLogger(__name__)
logger.setLevel(LOG_LEVEL)

console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter('%(message)s'))
logger.addHandler(console_handler)
