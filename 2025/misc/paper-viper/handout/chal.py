import asteval

# With this many functions from numpy removed there definitely will not be a way for users to get to `type()`, which is a security risk
asteval.astutils.NUMPY_TABLE = {k: asteval.astutils.NUMPY_TABLE[k] for k in ["genfromtxt"]}

def get_input():
    print("Give input, end with a line of $END$")
    inp = ""
    while True:
        temp = input()
        if temp == "$END$":
            break
        inp += temp +"\n"
    return inp

def nope(text):
    if not text.isascii():
        quit("Sorry, only ascii!")
    if any([text.find(x) >= 0 for x in ["yt", "ty", "rm", "uf", "**"]]):
        quit('Sorry, those bigrams just give me bad vibes!')

def main():
    inp = get_input()
    nope(inp)
    asteval.Interpreter().eval(inp, raise_errors=True)

if __name__ == "__main__":
    main()
