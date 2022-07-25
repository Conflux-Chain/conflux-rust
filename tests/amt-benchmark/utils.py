def parse_num(input: str):
    if input[-1] in ["k", "K"]:
        return int(input[:-1]) * 1000
    elif input[-1] in ["m", "M"]:
        return int(input[:-1]) * 1000000
    elif input[-1] in ["g", "G"]:
        return int(input[:-1]) * 1000000000
    else:
        return int(input)