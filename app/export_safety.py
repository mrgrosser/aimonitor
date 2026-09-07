"""Keep untrusted report text literal in spreadsheet exports."""
def csv_cell(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    if isinstance(value, str) and value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


class SafeCSVWriter:
    def __init__(self, writer): self.writer = writer
    def writerow(self, row): return self.writer.writerow([csv_cell(value) for value in row])
