code_list = {
    0: "No error",
    1: "No response to SYN packet",
    2: "An exception occurred while building the packet",
}
class ReLanError(Exception):
    def __init__(self, code: int):
        self.code = code
        self.message = f"Error code {code}: {code_list.get(code, 'Unknown error')}"
        super().__init__(self.message)
def raiseError(code: int):
    raise ReLanError(code)