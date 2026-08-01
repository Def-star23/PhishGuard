from services.heuristics.url_analysis import analyze_url
from services.heuristics.scoring import calculate_score,get_label

url = "http://paypa1-login.tk/verify"

result = analyze_url(url)
score = calculate_score(result)
label = get_label(score)

print(result)
print(score)
print(label)
