import string

banner = r"""
 _______         _______ _______ _______ _______ _______ _      _________
(  ____ |\     /(  ____ (  ___  (       (       (  ____ ( (    /\__   __/
| (    )( \   / | (    \| (   ) | () () | () () | (    \|  \  ( |  ) (   
| (____)|\ (_) /| |     | |   | | || || | || || | (__   |   \ | |  | |   
|  _____) \   / | |     | |   | | |(_)| | |(_)| |  __)  | (\ \) |  | |   
| (        ) (  | |     | |   | | |   | | |   | | (     | | \   |  | |   
| )        | |  | (____/| (___) | )   ( | )   ( | (____/| )  \  |  | |   
|/         \_/  (_______(_______|/     \|/     \(_______|/    )_)  )_(   """.strip('\n')

print(banner + '\n\n')

print('Recently we made some budget cuts and had to let some developers go.')
print("Unfortunately, we realised too late that a large portion of our codebase is lacking comments.")
print("We've decided to crowd source the process of commenting our code.")
print("This program allows people from all over the internet to safely add comments to our codebase, so the remaining developers know what our code is doing.")

with open('code_to_comment.py', 'r') as rf:
    source = rf.read()
lines = source.split('\n')

print(f"\nHere's the code that we don't understand:\n```\n{source}\n```\n")
print("Would you be so kind to add useable comments?\n")

ALLOWED_CHARACTERS = string.ascii_letters + string.digits + string.punctuation + ' '

# Loop over lines and let user edit comments:
for i, line in enumerate(lines):
    if i == 0: # We ignore the shebang line of course
        continue
    if not line.lstrip().startswith('#'):
        continue
    print(f'Line {i} is a comment. Currently it is `{line}`. What would you like to append?')
    user_input = input('> ')
    if not all(c in ALLOWED_CHARACTERS for c in user_input):
        print('Make sure to not use any funky characters! We want readable comments!')
        continue
    new_line = line + user_input
    if len(new_line) > 72:
        print('Comment too long! Make sure to follow PEP-8!')
        continue
    lines[i] = new_line

# Write new file
new_python_file = '\n'.join(lines)
with open('commented_code.py', 'w') as wf:
    wf.write(new_python_file)

print(f"\nCommented code succesfully written to file. Here's the code:\n```\n{new_python_file}\n```\n")

# Let's make sure the file is not broken:
try:
    __import__('commented_code')
except SyntaxError as e:
    print('SyntaxError:', str(e))
    quit()

print('Yay, no errors! Thanks for commenting our code!')