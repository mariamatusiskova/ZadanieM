class Pair:
    def __init__(self, first_val, second_val):
        self.first_val = first_val
        self.second_val = second_val

    def __hash__(self):
        return hash((self.first_val, self.second_val))

    def __eq__(self, other):
        return self.first_val == other.first_val and self.second_val == other.second_val \
            or self.first_val == other.second_val and self.second_val == other.first_val