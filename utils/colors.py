from rich.console import Console
from rich.theme import Theme

# Define a custom theme for consistent branding
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "header": "bold magenta",
    "highlight": "bold white",
    "dim": "dim white"
})

# Initialize the console with the theme
console = Console(theme=custom_theme)

class Colors:
    """
    Wrapper class to maintain backward compatibility where possible,
    but leveraging Rich for output.
    """
    # Legacy attributes mapped to empty strings or styles if needed
    # We encourage using the static methods instead.
    HEADER = ""
    OKBLUE = ""
    OKGREEN = ""
    WARNING = ""
    FAIL = ""
    ENDC = ""
    BOLD = ""
    UNDERLINE = ""
    
    # Legacy attributes for f-strings (deprecated but kept for safety)
    INFO = "[info]•[/info] "
    PLUS = "[success]✓[/success] "
    
    # Verbosity Control
    VERBOSE = False
    
    @staticmethod
    def print_info(msg):
        if Colors.VERBOSE:
            console.print(f"[info]•[/info] {msg}")

    @staticmethod
    def print_success(msg):
        console.print(f"[success]✓[/success] {msg}")

    @staticmethod
    def print_warning(msg):
        console.print(f"[warning]![/warning] {msg}")

    @staticmethod
    def print_error(msg):
        console.print(f"[error]✗[/error] {msg}")

    @staticmethod
    def print_header(msg):
        if Colors.VERBOSE:
            console.print(f"\n[header]━━━ {msg} ━━━[/header]")

# Backward compatibility functions
def print_info(msg):
    Colors.print_info(msg)

def print_success(msg):
    Colors.print_success(msg)

def print_warning(msg):
    Colors.print_warning(msg)

def print_error(msg):
    Colors.print_error(msg)

def print_header(msg):
    Colors.print_header(msg)
