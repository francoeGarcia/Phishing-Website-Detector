import pickle

with open("model.pkl", "rb") as f:
    obj = pickle.load(f)

print(type(obj))
print(obj if not hasattr(obj, "__len__") else f"length={len(obj)}")
if isinstance(obj, list):
    for i, item in enumerate(obj[:10]):
        print(i, type(item))