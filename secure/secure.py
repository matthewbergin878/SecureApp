import re

txt = "https://www.google.com"
regex = r"\Ahttps://www[.](example.com|google.com)(/.*)*\Z"
x = re.search(regex, txt)
print(x)

a = "https://www.google.com"
b = r"\Ahttps://www[.](example.com|google.com).*"
print(re.search(b,a))
