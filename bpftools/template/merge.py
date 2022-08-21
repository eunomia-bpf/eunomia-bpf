import json

result = []

with open(".output/package.json", "rb") as infile:
    result.append(json.load(infile))

with open("config.json", "rb") as infile:
    result.append(json.load(infile))

with open(".output/package.json", "wb") as outfile:
  json.dump(result, outfile)