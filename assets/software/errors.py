code_list = {
    0: "No error",
    2: "An exception occurred while building the packet",
    1: "No response to TCP packet",
    3: "Unexpected response to TCP packet",
    4: "Unknown error during TCP handshake",

}
class ReLanError(Exception):
    def __init__(self, code: int, error: Exception = None):
        self.code = code
        self.message = f"Error code {code}: {code_list.get(code, 'Unknown error')}"
        self.error = error
        super().__init__(self.message)
    def __str__(self):
        return self.message
    def __repr__(self):
        return self.message + f"\n{self.error}"
def raiseError(code: int, error: Exception = None):
    raise ReLanError(code, error)